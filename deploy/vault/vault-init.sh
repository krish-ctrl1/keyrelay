#!/bin/sh
# Seeds the dev-mode Vault for the demo and issues KeyRelay's AppRole
# credentials into the shared /bootstrap volume. DEMO ONLY.
set -eu

until vault status >/dev/null 2>&1; do sleep 1; done

# Dev mode mounts KV v2 at secret/.
vault kv put -mount=secret keyrelay/weather  api_key="$WEATHER_API_KEY"  >/dev/null
vault kv put -mount=secret keyrelay/payments api_key="$PAYMENTS_API_KEY" >/dev/null

vault auth list -format=json | grep -q '"approle/"' || vault auth enable approle >/dev/null
vault policy write keyrelay-proxy /deploy/keyrelay-policy.hcl >/dev/null
vault write auth/approle/role/keyrelay-proxy \
  token_policies=keyrelay-proxy token_ttl=15m token_max_ttl=1h \
  secret_id_ttl=24h secret_id_num_uses=0 >/dev/null

umask 077
vault read  -field=role_id   auth/approle/role/keyrelay-proxy/role-id     > /bootstrap/role_id
vault write -f -field=secret_id auth/approle/role/keyrelay-proxy/secret-id > /bootstrap/secret_id
# The relay runs as distroless "nonroot" (65532).
chown 65532:65532 /bootstrap/role_id /bootstrap/secret_id
chmod 0400 /bootstrap/role_id /bootstrap/secret_id

echo "vault-init: KV secrets written, AppRole issued (values not printed)"
