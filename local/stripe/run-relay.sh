#!/usr/bin/env bash
# Terminal 3: builds and runs KeyRelay natively. Audit log = one JSON line per request.
set -euo pipefail
cd "$(dirname "$0")/../.."
command -v go >/dev/null || { echo "Install Go: brew install go"; exit 1; }
[ -f local/stripe/.bootstrap/secret_id ] || { echo "Run local/stripe/vault-setup.sh first."; exit 1; }
[ -f demo/certs/stripe-agent.crt ] || { echo "Run: make certs && local/stripe/gen-agent-cert.sh"; exit 1; }
go build -o bin/keyrelay-proxy ./cmd/keyrelay-proxy
exec bin/keyrelay-proxy -config local/stripe/keyrelay.local.yaml
