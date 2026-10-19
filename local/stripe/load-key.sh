#!/usr/bin/env bash
# Puts an API key into Vault. Input is hidden; the key never touches disk,
# env vars, or shell history.   Usage: load-key.sh stripe|anthropic
set -euo pipefail
export VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=local-root-token
which="${1:-}"
case "$which" in
  stripe)    hint="sk_test_… or rk_test_…" ;;
  anthropic) hint="sk-ant-…" ;;
  *) echo "usage: $0 stripe|anthropic"; exit 1 ;;
esac
read -rsp "$which API key ($hint): " KEY; echo
case "$which:$KEY" in
  stripe:sk_test_*|stripe:rk_test_*|anthropic:sk-ant-*) ;;
  stripe:sk_live_*|stripe:rk_live_*)
    [ "${ALLOW_LIVE:-}" = 1 ] || { echo "Refusing a LIVE Stripe key. Use test mode (or ALLOW_LIVE=1)."; exit 1; } ;;
  *) echo "That doesn't look like a $which key."; exit 1 ;;
esac
printf %s "$KEY" | vault kv put -mount=secret "keyrelay/$which" api_key=- >/dev/null
unset KEY
echo "$which key stored at secret/keyrelay/$which (not printed)."
