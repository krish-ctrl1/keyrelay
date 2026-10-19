package config

import (
	"strings"
	"testing"
	"time"
)

func TestLoadExample(t *testing.T) {
	c, err := Load("testdata/valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if c.Cache.TTL != 30*time.Second || c.Vault.Timeout != 5*time.Second || c.Vault.AppRole.Mount != "approle" {
		t.Fatalf("defaults/durations wrong: %+v", c)
	}
	routes, err := c.CoreRoutes()
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 2 {
		t.Fatalf("routes=%d", len(routes))
	}
	w := routes[0]
	if w.Inject.Header != "Authorization" || w.Inject.Prefix != "Bearer " {
		t.Errorf("default inject wrong: %+v", w.Inject)
	}
	if string(w.Allow[0]) != "spiffe://demo.keyrelay/agent/weather-bot" {
		t.Errorf("allow not canonicalized: %v", w.Allow)
	}
	p := routes[1]
	if p.Inject.Header != "X-Api-Key" || p.Inject.Prefix != "" {
		t.Errorf("custom inject wrong: %+v", p.Inject)
	}
}

const base = `
tls: {cert_file: c, key_file: k, client_ca_file: ca}
vault: {address: "http://vault:8200", approle: {role_id_file: r, secret_id_file: s}}
`

func TestRejectsInvalid(t *testing.T) {
	cases := map[string]string{
		"insecure upstream": base + `
routes:
  - {name: a, upstream: "http://x", secret: {mount: m, path: p, key: k}, allow: ["spiffe://d/a"]}`,
		"empty allow": base + `
routes:
  - {name: a, upstream: "https://x", secret: {mount: m, path: p, key: k}, allow: []}`,
		"bad identity": base + `
routes:
  - {name: a, upstream: "https://x", secret: {mount: m, path: p, key: k}, allow: ["weather-bot"]}`,
		"duplicate": base + `
routes:
  - {name: a, upstream: "https://x", secret: {mount: m, path: p, key: k}, allow: ["spiffe://d/a"]}
  - {name: a, upstream: "https://y", secret: {mount: m, path: p, key: k}, allow: ["spiffe://d/a"]}`,
		"unknown field": base + `
routes:
  - {name: a, upstream: "https://x", secret: {mount: m, path: p, key: k}, allow: ["spiffe://d/a"], allow_all: true}`,
		"upstream with query": base + `
routes:
  - {name: a, upstream: "https://x/?k=v", secret: {mount: m, path: p, key: k}, allow: ["spiffe://d/a"]}`,
		"missing secret key": base + `
routes:
  - {name: a, upstream: "https://x", secret: {mount: m, path: p}, allow: ["spiffe://d/a"]}`,
		"no routes": base,
		"no tls":    `vault: {address: "http://v"}`,
	}
	for name, y := range cases {
		if _, err := Parse([]byte(y)); err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), "panic") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestInsecureUpstreamOptIn(t *testing.T) {
	_, err := Parse([]byte(base + `
routes:
  - {name: a, upstream: "http://x", allow_insecure_upstream: true, secret: {mount: m, path: p, key: k}, allow: ["spiffe://d/a"]}`))
	if err != nil {
		t.Fatal(err)
	}
}
