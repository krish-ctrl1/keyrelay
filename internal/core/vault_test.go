package core

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keyrelay/keyrelay/internal/testutil"
)

const (
	fakeRoleID   = "role-123"
	fakeSecretID = "secret-id-SHOULD-NEVER-LEAK"
	fakeToken    = "hvs.TOKEN-SHOULD-NEVER-LEAK"
)

type fakeVault struct {
	logins  atomic.Int64
	reads   atomic.Int64
	revoked atomic.Bool // when true the current token is rejected once
	srv     *httptest.Server
}

func newFakeVault(t *testing.T) *fakeVault {
	fv := &fakeVault{}
	fv.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/approle/login":
			fv.logins.Add(1)
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["role_id"] != fakeRoleID || body["secret_id"] != fakeSecretID {
				http.Error(w, `{"errors":["invalid secret id `+body["secret_id"]+`"]}`, http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{"client_token": fakeToken, "lease_duration": 3600}})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/secret/data/"):
			fv.reads.Add(1)
			if r.Header.Get("X-Vault-Token") != fakeToken || fv.revoked.CompareAndSwap(true, false) {
				http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
				return
			}
			switch r.URL.Path {
			case "/v1/secret/data/keyrelay/weather":
				_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": map[string]any{"api_key": testSecret}}})
			case "/v1/secret/data/keyrelay/number":
				_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": map[string]any{"api_key": 42}}})
			default:
				http.NotFound(w, r)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(fv.srv.Close)
	return fv
}

func newTestVaultProvider(t *testing.T, addr, secretID string) *VaultProvider {
	dir := t.TempDir()
	p, err := NewVaultProvider(VaultConfig{
		Address:      addr,
		RoleIDFile:   testutil.WriteFile(t, dir, "role_id", []byte(fakeRoleID+"\n")),
		SecretIDFile: testutil.WriteFile(t, dir, "secret_id", []byte(secretID+"\n")),
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func assertNoLeak(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	for _, s := range []string{fakeSecretID, fakeToken, testSecret} {
		if strings.Contains(err.Error(), s) {
			t.Fatalf("error leaks sensitive value: %v", err)
		}
	}
}

func TestVaultAppRoleAndKVRead(t *testing.T) {
	fv := newFakeVault(t)
	p := newTestVaultProvider(t, fv.srv.URL, fakeSecretID)
	ref := SecretRef{Mount: "secret", Path: "keyrelay/weather", Key: "api_key"}
	for i := 0; i < 3; i++ {
		s, err := p.GetSecret(context.Background(), ref)
		if err != nil || s.Reveal() != testSecret {
			t.Fatalf("got %v %v", s, err)
		}
	}
	if fv.logins.Load() != 1 {
		t.Fatalf("token should be reused, logins=%d", fv.logins.Load())
	}
}

func TestVaultReloginOnRejectedToken(t *testing.T) {
	fv := newFakeVault(t)
	p := newTestVaultProvider(t, fv.srv.URL, fakeSecretID)
	ref := SecretRef{Mount: "secret", Path: "keyrelay/weather", Key: "api_key"}
	if _, err := p.GetSecret(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
	fv.revoked.Store(true)
	if s, err := p.GetSecret(context.Background(), ref); err != nil || s.Reveal() != testSecret {
		t.Fatalf("relogin failed: %v", err)
	}
	if fv.logins.Load() != 2 {
		t.Fatalf("logins=%d, want 2", fv.logins.Load())
	}
}

func TestVaultTokenExpiryTriggersLogin(t *testing.T) {
	fv := newFakeVault(t)
	p := newTestVaultProvider(t, fv.srv.URL, fakeSecretID)
	now := time.Unix(0, 0)
	p.now = func() time.Time { return now }
	ref := SecretRef{Mount: "secret", Path: "keyrelay/weather", Key: "api_key"}
	_, _ = p.GetSecret(context.Background(), ref)
	now = now.Add(time.Hour) // past 80% of the 3600s lease
	_, _ = p.GetSecret(context.Background(), ref)
	if fv.logins.Load() != 2 {
		t.Fatalf("logins=%d, want 2", fv.logins.Load())
	}
}

func TestVaultFailuresFailClosedWithoutLeaking(t *testing.T) {
	fv := newFakeVault(t)
	ctx := context.Background()

	bad := newTestVaultProvider(t, fv.srv.URL, "wrong-"+fakeSecretID)
	_, err := bad.GetSecret(ctx, SecretRef{Mount: "secret", Path: "keyrelay/weather", Key: "api_key"})
	if !errors.Is(err, ErrVault) {
		t.Fatalf("bad secret_id: %v", err)
	}
	assertNoLeak(t, err)

	p := newTestVaultProvider(t, fv.srv.URL, fakeSecretID)
	for _, ref := range []SecretRef{
		{Mount: "secret", Path: "keyrelay/missing", Key: "api_key"},
		{Mount: "secret", Path: "keyrelay/weather", Key: "nope"},
		{Mount: "secret", Path: "keyrelay/number", Key: "api_key"},
	} {
		_, err := p.GetSecret(ctx, ref)
		if !errors.Is(err, ErrVault) {
			t.Fatalf("%s: want ErrVault, got %v", ref, err)
		}
		assertNoLeak(t, err)
	}

	fv.srv.Close()
	down := newTestVaultProvider(t, fv.srv.URL, fakeSecretID)
	_, err = down.GetSecret(ctx, SecretRef{Mount: "secret", Path: "keyrelay/weather", Key: "api_key"})
	if !errors.Is(err, ErrVault) {
		t.Fatalf("unreachable vault: %v", err)
	}
	assertNoLeak(t, err)
}

func TestVaultDoesNotFollowRedirects(t *testing.T) {
	var leaked atomic.Bool
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Store(true) }))
	defer sink.Close()
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, sink.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer redir.Close()
	p := newTestVaultProvider(t, redir.URL, fakeSecretID)
	if _, err := p.GetSecret(context.Background(), SecretRef{Mount: "secret", Path: "x", Key: "k"}); err == nil {
		t.Fatal("expected failure")
	}
	if leaked.Load() {
		t.Fatal("vault client followed a redirect")
	}
}

func TestNewVaultProviderValidation(t *testing.T) {
	for _, cfg := range []VaultConfig{
		{Address: "not a url", RoleID: "r", SecretIDFile: "f"},
		{Address: "http://v:8200", SecretIDFile: "f"},
		{Address: "http://v:8200", RoleID: "r"},
	} {
		if _, err := NewVaultProvider(cfg); err == nil {
			t.Errorf("accepted %+v", cfg)
		}
	}
}
