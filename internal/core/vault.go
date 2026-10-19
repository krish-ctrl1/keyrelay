package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// ErrVault classifies all Vault failures. Messages built on it contain only
// HTTP status codes and SecretRef locations, never tokens, SecretIDs or
// secret values, and never Vault response bodies.
var ErrVault = errors.New("vault")

const maxVaultResponse = 1 << 20

// VaultConfig configures AppRole authentication and KV v2 reads.
type VaultConfig struct {
	Address      string // e.g. "http://vault:8200"
	Namespace    string // optional Vault Enterprise namespace
	AppRoleMount string // defaults to "approle"
	RoleID       string // either RoleID or RoleIDFile
	RoleIDFile   string
	SecretIDFile string // SecretID is only ever read from a file
	HTTPClient   *http.Client
}

// VaultProvider is a SecretProvider backed by HashiCorp Vault KV v2 with
// AppRole login. The Vault token lives only in memory and is re-acquired on
// expiry or when Vault rejects it.
type VaultProvider struct {
	cfg    VaultConfig
	base   *url.URL
	client *http.Client
	now    func() time.Time

	mu      sync.Mutex
	token   string
	expires time.Time
}

// NewVaultProvider validates cfg and returns a provider. It does not contact
// Vault until the first secret is requested.
func NewVaultProvider(cfg VaultConfig) (*VaultProvider, error) {
	base, err := url.Parse(cfg.Address)
	if err != nil || base.Host == "" || (base.Scheme != "http" && base.Scheme != "https") {
		return nil, fmt.Errorf("%w: invalid address", ErrVault)
	}
	if cfg.AppRoleMount == "" {
		cfg.AppRoleMount = "approle"
	}
	if cfg.RoleID == "" && cfg.RoleIDFile == "" {
		return nil, fmt.Errorf("%w: role_id or role_id_file is required", ErrVault)
	}
	if cfg.SecretIDFile == "" {
		return nil, fmt.Errorf("%w: secret_id_file is required", ErrVault)
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	// Never follow redirects: they could carry the token to another host.
	c := *client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &VaultProvider{cfg: cfg, base: base, client: &c, now: time.Now}, nil
}

// GetSecret implements SecretProvider.
func (v *VaultProvider) GetSecret(ctx context.Context, ref SecretRef) (Secret, error) {
	token, err := v.currentToken(ctx)
	if err != nil {
		return Secret{}, err
	}
	s, status, err := v.readKV(ctx, token, ref)
	if status == http.StatusForbidden || status == http.StatusUnauthorized {
		// Token revoked or expired early: log in again once.
		v.dropToken(token)
		if token, err = v.currentToken(ctx); err != nil {
			return Secret{}, err
		}
		s, _, err = v.readKV(ctx, token, ref)
	}
	return s, err
}

func (v *VaultProvider) currentToken(ctx context.Context) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.token != "" && (v.expires.IsZero() || v.now().Before(v.expires)) {
		return v.token, nil
	}
	token, ttl, err := v.login(ctx)
	if err != nil {
		return "", err
	}
	v.token = token
	v.expires = time.Time{}
	if ttl > 0 {
		// Renew well before the lease ends.
		v.expires = v.now().Add(ttl * 8 / 10)
	}
	return token, nil
}

func (v *VaultProvider) dropToken(token string) {
	v.mu.Lock()
	if v.token == token {
		v.token = ""
	}
	v.mu.Unlock()
}

func (v *VaultProvider) login(ctx context.Context) (string, time.Duration, error) {
	roleID := v.cfg.RoleID
	if roleID == "" {
		b, err := os.ReadFile(v.cfg.RoleIDFile)
		if err != nil {
			return "", 0, fmt.Errorf("%w: cannot read role_id file", ErrVault)
		}
		roleID = strings.TrimSpace(string(b))
	}
	sid, err := os.ReadFile(v.cfg.SecretIDFile)
	if err != nil {
		return "", 0, fmt.Errorf("%w: cannot read secret_id file", ErrVault)
	}
	body, _ := json.Marshal(map[string]string{
		"role_id":   roleID,
		"secret_id": strings.TrimSpace(string(sid)),
	})
	req, err := v.newRequest(ctx, http.MethodPost, "/v1/auth/"+escapePath(v.cfg.AppRoleMount)+"/login", bytes.NewReader(body))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	var out struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int64  `json:"lease_duration"`
		} `json:"auth"`
	}
	status, err := v.do(req, &out)
	if err != nil {
		return "", 0, fmt.Errorf("%w: approle login failed: %v", ErrVault, err)
	}
	if status != http.StatusOK || out.Auth.ClientToken == "" {
		return "", 0, fmt.Errorf("%w: approle login rejected (status %d)", ErrVault, status)
	}
	return out.Auth.ClientToken, time.Duration(out.Auth.LeaseDuration) * time.Second, nil
}

func (v *VaultProvider) readKV(ctx context.Context, token string, ref SecretRef) (Secret, int, error) {
	req, err := v.newRequest(ctx, http.MethodGet, "/v1/"+escapePath(ref.Mount)+"/data/"+escapePath(ref.Path), nil)
	if err != nil {
		return Secret{}, 0, err
	}
	req.Header.Set("X-Vault-Token", token)
	var out struct {
		Data struct {
			Data map[string]any `json:"data"`
		} `json:"data"`
	}
	status, err := v.do(req, &out)
	if err != nil {
		return Secret{}, status, fmt.Errorf("%w: read %s failed: %v", ErrVault, ref, err)
	}
	if status != http.StatusOK {
		return Secret{}, status, fmt.Errorf("%w: read %s rejected (status %d)", ErrVault, ref, status)
	}
	raw, ok := out.Data.Data[ref.Key]
	if !ok {
		return Secret{}, status, fmt.Errorf("%w: key missing at %s", ErrVault, ref)
	}
	val, ok := raw.(string)
	if !ok || val == "" {
		return Secret{}, status, fmt.Errorf("%w: key at %s is not a non-empty string", ErrVault, ref)
	}
	return NewSecret(val), status, nil
}

func (v *VaultProvider) newRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	u := *v.base
	u.Path = strings.TrimSuffix(u.Path, "/") + path
	u.RawPath = ""
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, fmt.Errorf("%w: build request", ErrVault)
	}
	if v.cfg.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", v.cfg.Namespace)
	}
	return req, nil
}

// do executes req and decodes a 200 JSON body into out. Transport errors are
// reduced to a generic message: *url.Error strings are safe (no headers), but
// we avoid surfacing response bodies entirely.
func (v *VaultProvider) do(req *http.Request, out any) (int, error) {
	resp, err := v.client.Do(req)
	if err != nil {
		return 0, errors.New("vault unreachable")
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxVaultResponse))
	if err != nil {
		return resp.StatusCode, errors.New("reading vault response")
	}
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return resp.StatusCode, errors.New("malformed vault response")
	}
	return resp.StatusCode, nil
}

func escapePath(p string) string {
	segs := strings.Split(strings.Trim(p, "/"), "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return strings.Join(segs, "/")
}
