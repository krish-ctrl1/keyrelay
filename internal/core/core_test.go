package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keyrelay/keyrelay/internal/testutil"
)

const testSecret = "sk-live-TOPSECRET-123"

// ---- identity ----

func TestIdentityFromCertificate(t *testing.T) {
	ca := testutil.NewCA(t, "ca")
	tests := []struct {
		name    string
		uris    []string
		dns     []string
		want    WorkloadID
		wantErr bool
	}{
		{name: "spiffe", uris: []string{"spiffe://Demo.KeyRelay/agent/weather-bot"}, want: "spiffe://demo.keyrelay/agent/weather-bot"},
		{name: "trailing slash canonicalized", uris: []string{"spiffe://demo.keyrelay/agent/x/"}, want: "spiffe://demo.keyrelay/agent/x"},
		{name: "dns SAN ignored", uris: []string{"spiffe://d/a"}, dns: []string{"evil.example"}, want: "spiffe://d/a"},
		{name: "no URI SAN", dns: []string{"agent.local"}, wantErr: true},
		{name: "two URI SANs", uris: []string{"spiffe://d/a", "spiffe://d/b"}, wantErr: true},
		{name: "query rejected", uris: []string{"spiffe://d/a?x=1"}, wantErr: true},
		{name: "userinfo rejected", uris: []string{"spiffe://u@d/a"}, wantErr: true},
		{name: "dot segment rejected", uris: []string{"spiffe://d/a/../b"}, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			leaf := ca.IssueClient(t, tc.uris, tc.dns...)
			got, err := IdentityFromCertificate(leaf.Cert)
			if tc.wantErr {
				if !errors.Is(err, ErrInvalidIdentity) {
					t.Fatalf("want ErrInvalidIdentity, got %v (%q)", err, got)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
	if _, err := IdentityFromCertificate(nil); err == nil {
		t.Fatal("nil cert must fail")
	}
}

func TestParseWorkloadIDMatchesCertCanonicalForm(t *testing.T) {
	id, err := ParseWorkloadID("SPIFFE://DEMO.keyrelay/agent/weather-bot/")
	if err != nil || id != "spiffe://demo.keyrelay/agent/weather-bot" {
		t.Fatalf("got %q %v", id, err)
	}
	for _, bad := range []string{"", "weather-bot", "spiffe:opaque", "spiffe:///nohost"} {
		if _, err := ParseWorkloadID(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

// ---- secret redaction ----

func TestSecretNeverFormats(t *testing.T) {
	s := NewSecret(testSecret)
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	logger.Info("x", "secret", s, "wrapped", struct{ S Secret }{s})
	js, _ := json.Marshal(map[string]any{"s": s})
	outputs := []string{
		fmt.Sprint(s), fmt.Sprintf("%v %+v %#v %s %q %x", s, s, s, s, s, s),
		fmt.Sprintf("%+v", struct{ S Secret }{s}), string(js), buf.String(),
	}
	for _, o := range outputs {
		if strings.Contains(o, testSecret) {
			t.Fatalf("secret leaked via formatting: %s", o)
		}
	}
	if s.Reveal() != testSecret {
		t.Fatal("Reveal must return the value")
	}
}

// ---- authz / engine ----

type countingProvider struct {
	calls atomic.Int64
	delay time.Duration
	err   error
	value string
}

func (p *countingProvider) GetSecret(ctx context.Context, _ SecretRef) (Secret, error) {
	p.calls.Add(1)
	if p.delay > 0 {
		select {
		case <-time.After(p.delay):
		case <-ctx.Done():
			return Secret{}, ctx.Err()
		}
	}
	if p.err != nil {
		return Secret{}, p.err
	}
	return NewSecret(p.value), nil
}

func testRoutes(t *testing.T) []*Route {
	u, _ := url.Parse("https://api.example.com/v1")
	return []*Route{
		{
			Name: "weather", Upstream: u,
			Secret: SecretRef{Mount: "secret", Path: "keyrelay/weather", Key: "api_key"},
			Inject: InjectRule{Header: "Authorization", Prefix: "Bearer ", Strip: []string{"X-Api-Key"}},
			Allow:  []WorkloadID{"spiffe://demo.keyrelay/agent/weather-bot"},
		},
		{
			Name: "payments", Upstream: u,
			Secret: SecretRef{Mount: "secret", Path: "keyrelay/payments", Key: "api_key"},
			Inject: InjectRule{Header: "Authorization", Prefix: "Bearer "},
			Allow:  []WorkloadID{"spiffe://demo.keyrelay/workload/billing"},
		},
	}
}

func TestEngineDeniesBeforeTouchingSecrets(t *testing.T) {
	p := &countingProvider{value: testSecret}
	e, err := NewEngine(testRoutes(t), p)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		id     WorkloadID
		route  string
		status int
	}{
		{"spiffe://demo.keyrelay/agent/rogue", "weather", http.StatusForbidden},
		{"spiffe://demo.keyrelay/agent/weather-bot", "payments", http.StatusForbidden},
		{"spiffe://demo.keyrelay/agent/weather-bot", "nonexistent", http.StatusForbidden},
		{"", "weather", http.StatusUnauthorized},
	}
	for _, c := range cases {
		g, err := e.Authorize(c.id, c.route)
		if g != nil || AsError(err).Status != c.status {
			t.Errorf("%s -> %s: got grant=%v err=%v, want %d", c.id, c.route, g, err, c.status)
		}
	}
	if n := p.calls.Load(); n != 0 {
		t.Fatalf("secret provider called %d times for denied requests", n)
	}
	if _, err := e.Credential(context.Background(), nil); AsError(err).Status != http.StatusForbidden {
		t.Fatal("nil grant must be forbidden")
	}
}

func TestEngineCredential(t *testing.T) {
	p := &countingProvider{value: testSecret}
	e, _ := NewEngine(testRoutes(t), p)
	g, err := e.Authorize("spiffe://demo.keyrelay/agent/weather-bot", "weather")
	if err != nil {
		t.Fatal(err)
	}
	m, err := e.Credential(context.Background(), g)
	if err != nil {
		t.Fatal(err)
	}
	if m.Name != "Authorization" || m.Value.Reveal() != "Bearer "+testSecret {
		t.Fatalf("unexpected mutation %v", m)
	}

	p.err = errors.New("boom")
	if _, err := e.Credential(context.Background(), g); AsError(err).Status != http.StatusServiceUnavailable {
		t.Fatalf("vault failure must be 503, got %v", err)
	}
	p.err, p.value = nil, "bad\r\nX-Injected: 1"
	if _, err := e.Credential(context.Background(), g); AsError(err).Status != http.StatusBadGateway {
		t.Fatalf("unsafe credential must be 502, got %v", err)
	}
}

func TestNewEngineRejectsInvalidRoutes(t *testing.T) {
	r := testRoutes(t)
	r[1].Name = "weather"
	if _, err := NewEngine(r, &countingProvider{}); err == nil {
		t.Fatal("duplicate route accepted")
	}
	r = testRoutes(t)
	r[0].Allow = nil
	if _, err := NewEngine(r, &countingProvider{}); err == nil {
		t.Fatal("empty allowlist accepted")
	}
}

// ---- injector ----

func TestHeaderMutationStripsCallerValues(t *testing.T) {
	m, err := BuildMutation(InjectRule{Header: "Authorization", Prefix: "Bearer ", Strip: []string{"X-Api-Key"}}, NewSecret(testSecret))
	if err != nil {
		t.Fatal(err)
	}
	h := http.Header{}
	h["Authorization"] = []string{"Bearer KEYRELAY_MANAGED", "Basic Zm9vOmJhcg=="}
	h["authorization"] = []string{"non-canonical"}
	h.Set("X-Api-Key", "caller-key")
	h.Set("Accept", "application/json")
	m.ApplyTo(h)
	if got := h.Values("Authorization"); len(got) != 1 || got[0] != "Bearer "+testSecret {
		t.Fatalf("Authorization = %v", got)
	}
	if _, ok := h["authorization"]; ok {
		t.Fatal("non-canonical duplicate not stripped")
	}
	if h.Get("X-Api-Key") != "" || h.Get("Accept") != "application/json" {
		t.Fatalf("strip list wrong: %v", h)
	}
	if !m.Exposes("echo: "+testSecret) || m.Exposes("nothing here") {
		t.Fatal("Exposes mismatch")
	}
}

func TestBuildMutationRejectsUnsafeValues(t *testing.T) {
	for _, v := range []string{"", "a\nb", "a\rb", "a\x00b", "a\x7fb"} {
		if _, err := BuildMutation(InjectRule{Header: "Authorization"}, NewSecret(v)); !errors.Is(err, ErrInjection) {
			t.Errorf("%q accepted", v)
		}
	}
}

// ---- cache ----

func TestCacheSingleflightCollapsesConcurrentMisses(t *testing.T) {
	p := &countingProvider{value: testSecret, delay: 50 * time.Millisecond}
	c := NewCachingProvider(p, time.Minute)
	ref := SecretRef{Mount: "secret", Path: "a", Key: "k"}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, err := c.GetSecret(context.Background(), ref)
			if err != nil || s.Reveal() != testSecret {
				t.Errorf("got %v %v", s, err)
			}
		}()
	}
	wg.Wait()
	if n := p.calls.Load(); n != 1 {
		t.Fatalf("provider called %d times, want 1", n)
	}
}

func TestCacheTTLAndNoNegativeCaching(t *testing.T) {
	p := &countingProvider{value: testSecret}
	c := NewCachingProvider(p, time.Minute)
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }
	ref := SecretRef{Mount: "secret", Path: "a", Key: "k"}
	ctx := context.Background()

	_, _ = c.GetSecret(ctx, ref)
	_, _ = c.GetSecret(ctx, ref)
	if p.calls.Load() != 1 {
		t.Fatal("second call should hit cache")
	}
	now = now.Add(2 * time.Minute)
	_, _ = c.GetSecret(ctx, ref)
	if p.calls.Load() != 2 {
		t.Fatal("expired entry should refetch")
	}
	c.Invalidate(ref)
	p.err = errors.New("down")
	if _, err := c.GetSecret(ctx, ref); err == nil {
		t.Fatal("error expected")
	}
	p.err = nil
	if _, err := c.GetSecret(ctx, ref); err != nil {
		t.Fatal("errors must not be cached")
	}
	if p.calls.Load() != 4 {
		t.Fatalf("calls = %d", p.calls.Load())
	}
}

func TestCacheCallerCancellationDoesNotPoisonSharedFetch(t *testing.T) {
	p := &countingProvider{value: testSecret, delay: 50 * time.Millisecond}
	c := NewCachingProvider(p, time.Minute)
	ref := SecretRef{Mount: "secret", Path: "a", Key: "k"}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(5 * time.Millisecond); cancel() }()
	if _, err := c.GetSecret(ctx, ref); !errors.Is(err, context.Canceled) {
		t.Fatalf("want canceled, got %v", err)
	}
	s, err := c.GetSecret(context.Background(), ref)
	if err != nil || s.Reveal() != testSecret {
		t.Fatalf("second caller failed: %v", err)
	}
}

// ---- audit ----

func TestAuditEventShape(t *testing.T) {
	var buf bytes.Buffer
	NewAuditor(&buf).Record(Event{RequestID: "r1", WorkloadID: "spiffe://d/a", Route: "weather", Decision: "deny", Reason: ReasonForbidden, Status: 403})
	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if m["msg"] != "keyrelay.request" || m["workload_id"] != "spiffe://d/a" || m["status"].(float64) != 403 {
		t.Fatalf("unexpected audit record %v", m)
	}
}
