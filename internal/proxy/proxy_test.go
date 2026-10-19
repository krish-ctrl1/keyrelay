package proxy

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/keyrelay/keyrelay/internal/core"
	"github.com/keyrelay/keyrelay/internal/testutil"
)

const (
	weatherSecret  = "wx-live-SECRET-abc123"
	paymentsSecret = "pay-live-SECRET-xyz789"
	vaultToken     = "hvs.VAULT-TOKEN-DO-NOT-LOG"
	vaultSecretID  = "approle-SECRETID-DO-NOT-LOG"
	placeholder    = "Bearer KEYRELAY_MANAGED"

	weatherBot = "spiffe://demo.keyrelay/agent/weather-bot"
	billing    = "spiffe://demo.keyrelay/workload/billing"
	rogue      = "spiffe://demo.keyrelay/agent/rogue"
)

var sensitive = []string{weatherSecret, paymentsSecret, vaultToken, vaultSecretID}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

type upstreamSeen struct {
	mu      sync.Mutex
	hits    int
	headers http.Header
	host    string
	uri     string
}

type harness struct {
	t          *testing.T
	ca         *testutil.CA
	relay      *httptest.Server
	audit      *syncBuffer
	vaultReads atomic.Int64
	vaultLogin atomic.Int64
	vaultDown  atomic.Bool
	upstream   *httptest.Server
	seen       upstreamSeen
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{t: t, ca: testutil.NewCA(t, "keyrelay-test-ca"), audit: &syncBuffer{}}

	vault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.vaultDown.Load() {
			http.Error(w, "sealed", http.StatusServiceUnavailable)
			return
		}
		switch r.URL.Path {
		case "/v1/auth/approle/login":
			h.vaultLogin.Add(1)
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["secret_id"] != vaultSecretID {
				http.Error(w, "denied", http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{"client_token": vaultToken, "lease_duration": 600}})
		case "/v1/secret/data/keyrelay/weather", "/v1/secret/data/keyrelay/payments", "/v1/secret/data/keyrelay/echo":
			h.vaultReads.Add(1)
			if r.Header.Get("X-Vault-Token") != vaultToken {
				http.Error(w, "denied", http.StatusForbidden)
				return
			}
			v := weatherSecret
			if strings.HasSuffix(r.URL.Path, "payments") {
				v = paymentsSecret
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": map[string]any{"api_key": v}}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(vault.Close)

	h.upstream = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.seen.mu.Lock()
		h.seen.hits++
		h.seen.headers = r.Header.Clone()
		h.seen.host = r.Host
		h.seen.uri = r.URL.RequestURI()
		h.seen.mu.Unlock()
		if strings.HasPrefix(r.URL.Path, "/echo") {
			// A misbehaving upstream that reflects the credential.
			w.Header().Set("X-Debug-Auth", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(h.upstream.Close)
	upURL, _ := url.Parse(h.upstream.URL)

	dir := t.TempDir()
	vp, err := core.NewVaultProvider(core.VaultConfig{
		Address:      vault.URL,
		RoleID:       "role",
		SecretIDFile: testutil.WriteFile(t, dir, "secret_id", []byte(vaultSecretID)),
	})
	if err != nil {
		t.Fatal(err)
	}
	route := func(name, base, path string, allow ...core.WorkloadID) *core.Route {
		u := *upURL
		u.Path = base
		return &core.Route{
			Name: name, Upstream: &u,
			Secret: core.SecretRef{Mount: "secret", Path: path, Key: "api_key"},
			Inject: core.InjectRule{Header: "Authorization", Prefix: "Bearer ", Strip: []string{"X-Api-Key"}},
			Allow:  allow,
		}
	}
	deadUpstream, _ := url.Parse("https://127.0.0.1:1/")
	dead := route("dead", "/", "keyrelay/weather", weatherBot)
	dead.Upstream = deadUpstream
	engine, err := core.NewEngine([]*core.Route{
		route("weather", "/api", "keyrelay/weather", weatherBot),
		route("payments", "/pay", "keyrelay/payments", billing),
		route("echo", "/echo", "keyrelay/echo", weatherBot),
		dead,
	}, core.NewCachingProvider(vp, 0))
	if err != nil {
		t.Fatal(err)
	}

	srv, err := New(Options{
		Engine:    engine,
		Auditor:   core.NewAuditor(h.audit),
		Transport: UpstreamTransport(h.upstream.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs),
	})
	if err != nil {
		t.Fatal(err)
	}
	serverLeaf := h.ca.IssueServer(t)
	h.relay = httptest.NewUnstartedServer(srv)
	h.relay.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverLeaf.TLS},
		ClientCAs:    h.ca.Pool(),
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}
	h.relay.Config.ErrorLog = log.New(io.Discard, "", 0)
	h.relay.StartTLS()
	t.Cleanup(h.relay.Close)

	t.Cleanup(func() {
		out := h.audit.String()
		for _, s := range sensitive {
			if strings.Contains(out, s) {
				t.Errorf("audit log leaked sensitive value %q:\n%s", s, out)
			}
		}
	})
	return h
}

// client returns an HTTPS client presenting leaf (or no cert if nil).
func (h *harness) client(leaf *testutil.Leaf) *http.Client {
	cfg := &tls.Config{RootCAs: h.ca.Pool(), MinVersion: tls.VersionTLS12}
	if leaf != nil {
		cfg.Certificates = []tls.Certificate{leaf.TLS}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
}

func (h *harness) agent(uris ...string) *http.Client {
	return h.client(h.ca.IssueClient(h.t, uris))
}

func (h *harness) do(c *http.Client, method, path string, hdr map[string]string) (*http.Response, string) {
	h.t.Helper()
	req, _ := http.NewRequest(method, h.relay.URL+path, nil)
	req.Header.Set("Authorization", placeholder)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		h.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	for _, s := range sensitive {
		if strings.Contains(string(b), s) {
			h.t.Fatalf("response body leaked %q", s)
		}
		for k, vs := range resp.Header {
			for _, v := range vs {
				if strings.Contains(v, s) {
					h.t.Fatalf("response header %s leaked %q", k, s)
				}
			}
		}
	}
	return resp, string(b)
}

func (h *harness) upstreamHits() int {
	h.seen.mu.Lock()
	defer h.seen.mu.Unlock()
	return h.seen.hits
}

func TestAllowedRequestInjectsCredentialAndRewritesHost(t *testing.T) {
	h := newHarness(t)
	resp, body := h.do(h.agent(weatherBot), "GET", "/r/weather/v1/forecast?city=Paris", map[string]string{
		"X-Api-Key":       "caller-supplied",
		"X-Forwarded-For": "6.6.6.6",
	})
	if resp.StatusCode != http.StatusOK || body != `{"ok":true}` {
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
	if resp.Header.Get(HeaderRequestID) == "" {
		t.Error("missing request id")
	}
	h.seen.mu.Lock()
	defer h.seen.mu.Unlock()
	if got := h.seen.headers.Values("Authorization"); len(got) != 1 || got[0] != "Bearer "+weatherSecret {
		t.Fatalf("upstream Authorization = %v", got)
	}
	if h.seen.headers.Get("X-Api-Key") != "" {
		t.Error("strip-listed header reached upstream")
	}
	if h.seen.headers.Get("X-Forwarded-For") != "" {
		t.Error("caller X-Forwarded-For reached upstream")
	}
	upHost := strings.TrimPrefix(h.upstream.URL, "https://")
	if h.seen.host != upHost {
		t.Errorf("Host = %q, want %q", h.seen.host, upHost)
	}
	if h.seen.uri != "/api/v1/forecast?city=Paris" {
		t.Errorf("upstream URI = %q", h.seen.uri)
	}
	if !strings.Contains(h.audit.String(), `"decision":"allow"`) || !strings.Contains(h.audit.String(), weatherBot) {
		t.Errorf("audit missing allow record: %s", h.audit.String())
	}
}

func TestSecondWorkloadOnItsOwnRoute(t *testing.T) {
	h := newHarness(t)
	resp, _ := h.do(h.agent(billing), "POST", "/r/payments/v1/charges", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	h.seen.mu.Lock()
	defer h.seen.mu.Unlock()
	if h.seen.headers.Get("Authorization") != "Bearer "+paymentsSecret {
		t.Fatal("wrong credential injected")
	}
}

func TestForbiddenNeverTouchesVaultOrUpstream(t *testing.T) {
	h := newHarness(t)
	cases := []struct {
		name string
		c    *http.Client
		path string
		hdr  map[string]string
	}{
		{"not allowlisted", h.agent(rogue), "/r/weather/v1/forecast", nil},
		{"cross-route", h.agent(weatherBot), "/r/payments/v1/charges", nil},
		{"unknown route", h.agent(weatherBot), "/r/nonexistent/x", nil},
		{"invalid route name", h.agent(weatherBot), "/r/Weather/x", nil},
		{"no route prefix", h.agent(weatherBot), "/v1/forecast", nil},
		{"spoofed identity headers", h.agent(rogue), "/r/weather/v1/forecast", map[string]string{
			"X-KeyRelay-Workload-ID":  weatherBot,
			"X-Forwarded-Client-Cert": "URI=" + weatherBot,
			"X-SPIFFE-ID":             weatherBot,
		}},
	}
	var bodies []string
	for _, tc := range cases {
		resp, body := h.do(tc.c, "GET", tc.path, tc.hdr)
		if resp.StatusCode != http.StatusForbidden || resp.Header.Get(HeaderError) != core.ReasonForbidden {
			t.Errorf("%s: status=%d error=%q", tc.name, resp.StatusCode, resp.Header.Get(HeaderError))
		}
		var m map[string]string
		_ = json.Unmarshal([]byte(body), &m)
		bodies = append(bodies, m["error"])
	}
	for _, b := range bodies {
		if b != "forbidden" {
			t.Errorf("non-uniform 403 body: %v", bodies)
		}
	}
	if h.vaultLogin.Load() != 0 || h.vaultReads.Load() != 0 {
		t.Fatalf("vault touched on denied requests: logins=%d reads=%d", h.vaultLogin.Load(), h.vaultReads.Load())
	}
	if h.upstreamHits() != 0 {
		t.Fatalf("upstream reached %d times", h.upstreamHits())
	}
}

func TestIdentityFailuresAre401(t *testing.T) {
	h := newHarness(t)
	cases := map[string]*http.Client{
		"two URI SANs": h.agent(weatherBot, rogue),
		"no URI SAN":   h.client(h.ca.IssueClient(t, nil, "weather-bot.local")),
		"bad URI":      h.agent("spiffe://demo.keyrelay/agent/x?y=1"),
	}
	for name, c := range cases {
		resp, _ := h.do(c, "GET", "/r/weather/v1/forecast", nil)
		if resp.StatusCode != http.StatusUnauthorized || resp.Header.Get(HeaderError) != core.ReasonUnauthenticated {
			t.Errorf("%s: status=%d", name, resp.StatusCode)
		}
	}
	if h.vaultReads.Load() != 0 || h.upstreamHits() != 0 {
		t.Fatal("vault or upstream touched without identity")
	}
}

func TestTLSRejectsMissingOrUntrustedClientCert(t *testing.T) {
	h := newHarness(t)
	other := testutil.NewCA(t, "attacker-ca")
	untrusted := h.client(other.IssueClient(t, []string{weatherBot}))
	for name, c := range map[string]*http.Client{"no cert": h.client(nil), "untrusted CA": untrusted} {
		resp, err := c.Get(h.relay.URL + "/r/weather/v1/forecast")
		if err == nil {
			resp.Body.Close()
			t.Errorf("%s: request succeeded with status %d", name, resp.StatusCode)
		}
	}
	if h.vaultReads.Load() != 0 || h.upstreamHits() != 0 {
		t.Fatal("vault or upstream touched without mTLS")
	}
}

func TestPathEscapesRejected(t *testing.T) {
	h := newHarness(t)
	c := h.agent(weatherBot)
	for _, p := range []string{
		"/r/weather/../payments/v1",
		"/r/weather/%2e%2e/payments",
		"/r/weather/a%2Fb",
		"/r/weather/a%5cb",
	} {
		// net/http sends the parsed path verbatim; it does not clean dot segments.
		req, _ := http.NewRequest("GET", h.relay.URL+p, nil)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: status=%d, want 400", p, resp.StatusCode)
		}
	}
	if h.vaultReads.Load() != 0 || h.upstreamHits() != 0 {
		t.Fatal("path escape reached vault/upstream")
	}
}

func TestVaultUnavailableFailsClosed503(t *testing.T) {
	h := newHarness(t)
	h.vaultDown.Store(true)
	resp, _ := h.do(h.agent(weatherBot), "GET", "/r/weather/v1/forecast", nil)
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get(HeaderError) != core.ReasonCredentialUnavailable {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	if h.upstreamHits() != 0 {
		t.Fatal("request forwarded without credential")
	}
}

func TestUpstreamUnavailable502(t *testing.T) {
	h := newHarness(t)
	resp, _ := h.do(h.agent(weatherBot), "GET", "/r/dead/x", nil)
	if resp.StatusCode != http.StatusBadGateway || resp.Header.Get(HeaderError) != core.ReasonUpstreamError {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	if !strings.Contains(h.audit.String(), `"reason":"upstream_error"`) {
		t.Fatalf("audit missing upstream_error: %s", h.audit.String())
	}
}

func TestEchoedCredentialScrubbedFromResponse(t *testing.T) {
	h := newHarness(t)
	resp, _ := h.do(h.agent(weatherBot), "GET", "/r/echo/", nil) // do() fails the test on any leak
	if resp.StatusCode != http.StatusOK || resp.Header.Get("X-Debug-Auth") != "" {
		t.Fatalf("status=%d echo=%q", resp.StatusCode, resp.Header.Get("X-Debug-Auth"))
	}
}

func TestConcurrentRequests(t *testing.T) {
	h := newHarness(t)
	c := h.agent(weatherBot)
	var wg sync.WaitGroup
	var failures atomic.Int64
	for i := 0; i < 25; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := c.Get(h.relay.URL + "/r/weather/v1/forecast")
			if err != nil {
				failures.Add(1)
				return
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				failures.Add(1)
			}
		}()
	}
	wg.Wait()
	if failures.Load() != 0 {
		t.Fatalf("%d concurrent requests failed", failures.Load())
	}
	if h.vaultLogin.Load() != 1 {
		t.Fatalf("expected a single AppRole login, got %d", h.vaultLogin.Load())
	}
}
