#!/usr/bin/env bash
# Terminal 2: creates the AppRole KeyRelay logs in with, scoped by
# deploy/vault/keyrelay-policy.hcl to read-only on secret/keyrelay/*.
set -euo pipefail
cd "$(dirname "$0")/../.."
export VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=local-root-token
for _ in $(seq 1 20); do vault status >/dev/null 2>&1 && break; sleep 0.5; done
vault status >/dev/null 2>&1 || { echo "Vault isn't running. Start local/stripe/vault-dev.sh first."; exit 1; }

vault auth list -format=json | grep -q '"approle/"' || vault auth enable approle >/dev/null
vault policy write keyrelay-proxy deploy/vault/keyrelay-policy.hcl >/dev/null
vault write auth/approle/role/keyrelay-proxy \
  token_policies=keyrelay-proxy token_ttl=15m token_max_ttl=1h \
  secret_id_ttl=24h secret_id_num_uses=0 >/dev/null

B=local/stripe/.bootstrap
mkdir -p "$B" && chmod 700 "$B" && rm -f "$B/role_id" "$B/secret_id"
umask 077
vault read  -field=role_id   auth/approle/role/keyrelay-proxy/role-id     > "$B/role_id"
vault write -f -field=secret_id auth/approle/role/keyrelay-proxy/secret-id > "$B/secret_id"
echo "AppRole ready ($B). Next: local/stripe/load-key.sh stripe && local/stripe/load-key.sh anthropic"
