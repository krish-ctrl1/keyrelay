# KeyRelay v0.01

An open-source credential relay that lets AI agents and other workloads call external APIs without holding the API keys. The keys never sit in the agent's environment variables, in its memory, or in LLM traces.

```
 agent / workload                    KeyRelay                          Vault (KV v2)
 ┌───────────────┐  mTLS (client    ┌──────────────────────────┐ AppRole ┌──────────┐
 │ LangChain tool│  cert, 1 SAN URI)│ 1 verify cert → identity │────────▶│ api_key  │
 │ Authorization:│─────────────────▶│ 2 allowlist (id, route)  │◀────────└──────────┘
 │ Bearer        │                  │ 3 fetch secret (cache +  │
 │ KEYRELAY_     │◀─────────────────│   singleflight)          │  real key ┌──────────┐
 │ MANAGED       │  upstream resp   │ 4 strip + inject header  │──────────▶│ upstream │
 └───────────────┘  (no secret)     │ 5 reverse proxy, audit   │           │   API    │
                                    └──────────────────────────┘           └──────────┘
```

## How it works

1. The agent connects over mTLS. The listener uses `tls.RequireAndVerifyClientCert` against a dedicated client CA.
2. Identity is taken **only** from `r.TLS.PeerCertificates[0].URIs`, which must hold exactly one URI SAN (for example `spiffe://demo.keyrelay/agent/weather-bot`). KeyRelay canonicalizes it by lowercasing the scheme and host and rejecting userinfo, queries, fragments and dot segments. Headers such as `X-Forwarded-Client-Cert` are never consulted.
3. The request path `/r/<route>/<rest>` selects a route. If the `(workload_id, route)` pair is not explicitly allowlisted, KeyRelay returns **403 before it touches the cache or Vault**. An unknown route gets the same 403, so route names can't be probed.
4. The credential is read from Vault KV v2 using AppRole. A TTL cache with singleflight sits in front of Vault, and failures are never cached.
5. KeyRelay removes every caller-supplied value of the managed header and of any `strip` headers, case-insensitively. It then sets the real credential, points the request at the configured upstream, sets `Host` to the upstream host, and proxies it. If an upstream echoes the credential back in a response header, that header is dropped.
6. Each request emits one JSON audit line with request ID, workload, route, method, path, decision, reason, status and latency. The audit `Event` type has no field that could hold a credential.

### Failure modes (all fail closed)

| Condition | Status | `X-KeyRelay-Error` |
|---|---|---|
| No or untrusted client cert | TLS handshake failure | n/a |
| Zero or several URI SANs, malformed URI | 401 | `unauthenticated` |
| Not allowlisted, unknown route, bad route name | 403 | `forbidden` |
| Dot segments or encoded separators in path | 400 | `bad_request` |
| Vault unreachable, login rejected, secret missing | 503 | `credential_unavailable` |
| Credential has CR/LF/control characters | 502 | `credential_injection_failed` |
| Upstream unreachable | 502 | `upstream_error` |

## Repository layout

```
cmd/keyrelay-proxy        main: config → Vault → cache → engine → mTLS server
cmd/mock-upstream         demo "third-party API" that checks its own key
internal/core             transport-neutral: identity, authz, cache, Vault, injector, audit, engine
internal/proxy            mTLS listener + httputil.ReverseProxy (Rewrite) front end
internal/config           YAML loading/validation (unknown keys rejected)
internal/testutil         in-memory PKI for Go tests
sdk/python                keyrelay-langchain package (httpx + langchain-core)
deploy/vault              Vault dev-mode bootstrap script and policy
demo/keyrelay.yaml        demo relay config
scripts/                  gen-certs.sh (demo PKI), demo-calls.sh (positive/negative calls)
```

`internal/core` does not import `internal/proxy`. `Engine.Authorize` returns a `*Grant`, and `Engine.Credential(ctx, grant)` returns a `HeaderMutation` (headers to remove, header to set). The v0.02 Envoy `ext_proc` server can map that mutation directly onto Envoy's own `HeaderMutation` without changing `core`. Because `Credential` requires a `*Grant`, the type system enforces "authorize before fetching a secret".

## Quick start

Prerequisites: Go 1.22+, Python 3.10+, OpenSSL, and Docker with Compose v2 (Docker is needed for the demo only).

### Run all tests

```bash
go test -v -race ./...                     # Go unit + mTLS integration tests
make test-py                               # creates sdk/python/.venv, then runs pytest
# or by hand:
python3 -m venv sdk/python/.venv
sdk/python/.venv/bin/pip install -e 'sdk/python[test]'
(cd sdk/python && .venv/bin/pytest -v)
```

The Python suite includes `tests/test_e2e_relay.py`. It builds the real Go relay and drives it through the SDK and a LangChain tool, using a fake Vault and a fake upstream. It is skipped if `go` isn't on `PATH`.

### Start the demo

```bash
scripts/gen-certs.sh demo/certs            # demo PKI (or: make certs)
docker compose up -d --build               # vault, vault-init, mock-upstream, keyrelay
docker compose ps -a                       # vault-init should show "Exited (0)"
```

KeyRelay listens on `https://localhost:8443`. The mock upstream is **not** published, so the relay is the only way to reach it.

### Positive and negative calls

```bash
scripts/demo-calls.sh                      # runs every case below and checks logs for leaks
```

Or one call at a time:

```bash
C=demo/certs
# ✅ allowed: weather-bot → weather (upstream sees the real key, agent never does)
curl -s --cacert $C/ca.crt --cert $C/weather-bot.crt --key $C/weather-bot.key \
  -H 'Authorization: Bearer KEYRELAY_MANAGED' 'https://localhost:8443/r/weather/v1/forecast?city=Paris'

# ✅ allowed: billing workload → payments
curl -s --cacert $C/ca.crt --cert $C/billing.crt --key $C/billing.key \
  -X POST -d '{"amount":100}' https://localhost:8443/r/payments/v1/charges

# ❌ 403: rogue agent, valid cert but not allowlisted
curl -s --cacert $C/ca.crt --cert $C/rogue.crt --key $C/rogue.key https://localhost:8443/r/weather/v1/forecast

# ❌ 403: weather-bot trying another route
curl -s --cacert $C/ca.crt --cert $C/weather-bot.crt --key $C/weather-bot.key https://localhost:8443/r/payments/v1/charges

# ❌ 403: spoofed identity header is ignored
curl -s --cacert $C/ca.crt --cert $C/rogue.crt --key $C/rogue.key \
  -H 'X-KeyRelay-Workload-ID: spiffe://demo.keyrelay/agent/weather-bot' https://localhost:8443/r/weather/v1/forecast

# ❌ 401: certificate with two URI SANs
curl -s --cacert $C/ca.crt --cert $C/multi-san.crt --key $C/multi-san.key https://localhost:8443/r/weather/v1/forecast

# ❌ TLS failure: no client cert / cert from an untrusted CA
curl -s --cacert $C/ca.crt https://localhost:8443/r/weather/v1/forecast; echo "exit=$?"
curl -s --cacert $C/ca.crt --cert $C/untrusted.crt --key $C/untrusted.key https://localhost:8443/r/weather/v1/forecast; echo "exit=$?"
```

LangChain agent (allowed, then denied):

```bash
make demo-agent
# or: sdk/python/.venv/bin/python sdk/python/examples/langchain_agent.py [weather-bot|rogue]
```

Audit log and leak check:

```bash
docker compose logs keyrelay
docker compose logs | grep -E 'wx-live-DEMO|pay-live-DEMO' || echo "no credentials in logs"
```

### Stop and clean up

```bash
docker compose down -v --remove-orphans    # also deletes the AppRole bootstrap volume
rm -rf demo/certs bin                      # or: make clean
```

## Configuration

See [demo/keyrelay.yaml](demo/keyrelay.yaml). Per route:

```yaml
- name: weather                          # [a-z0-9][a-z0-9_-]{0,62}
  upstream: https://api.weather.example/v1   # credential bound to this URL
  allow_insecure_upstream: false         # http:// upstreams must opt in explicitly
  secret: { mount: secret, path: keyrelay/weather, key: api_key }
  inject:
    header: Authorization                # default
    prefix: "Bearer "                    # default when header is Authorization
    strip: [X-Api-Key]                   # extra caller headers to remove
  allow:
    - spiffe://example.org/agent/weather-bot
```

## Python SDK

See [sdk/python/README.md](sdk/python/README.md).

## Security notes and v0.01 limitations

- **The demo is not production.** Vault runs in dev mode, `vault-init` uses the root token, the relay talks to the mock upstream over plain HTTP on a private Docker network, and the demo server key is world-readable so the non-root container can read it from a bind mount.
- In production, deliver the AppRole SecretID through response wrapping or a platform secret mount, use short-lived workload certificates (for example from SPIRE), and use `https` upstreams.
- KeyRelay drops upstream *response headers* that echo the credential, but it does not scan response *bodies*. An upstream that reflects the key in its body would leak it to the caller.
- Possession of a workload's private key *is* that workload's identity. Protect agent keys as you would any other credential, and prefer short lifetimes.
- No rate limiting or per-route method/path policy yet. Authorization is per `(workload, route)`.
