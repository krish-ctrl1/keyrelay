#!/usr/bin/env bash
# Runs positive and negative calls against the running demo and verifies the
# demo credentials never appear in responses or container logs.
set -uo pipefail

RELAY="${RELAY:-https://localhost:8443}"
CERTS="${CERTS:-demo/certs}"
SECRETS=(wx-live-DEMO-7f3a9c2e1b pay-live-DEMO-4d8e6b0a5c)
fails=0
body="$(mktemp)"; trap 'rm -f "$body"' EXIT

# Wait for the relay to accept TLS connections.
for _ in $(seq 1 60); do
  curl -s -o /dev/null --cacert "$CERTS/ca.crt" --cert "$CERTS/weather-bot.crt" --key "$CERTS/weather-bot.key" "$RELAY/" && break
  sleep 1
done

call() { # description expected identity path [extra curl args...]
  local desc="$1" want="$2" who="$3" path="$4"; shift 4
  local auth=()
  [ "$who" != none ] && auth=(--cert "$CERTS/$who.crt" --key "$CERTS/$who.key")
  local code; : >"$body"
  code="$(curl -s -o "$body" -w '%{http_code}' --cacert "$CERTS/ca.crt" ${auth[@]+"${auth[@]}"} \
    -H "Authorization: Bearer KEYRELAY_MANAGED" "$@" "$RELAY$path" 2>/dev/null)" || code="tls-rejected"
  [ "$code" = "000" ] && code="tls-rejected"
  local mark="PASS"
  [ "$code" = "$want" ] || { mark="FAIL"; fails=$((fails+1)); }
  for s in "${SECRETS[@]}"; do grep -q "$s" "$body" && { mark="LEAK"; fails=$((fails+1)); }; done
  printf '%-4s %-62s want=%-12s got=%-12s %s\n' "$mark" "$desc" "$want" "$code" "$(head -c 160 "$body" | tr -d '\n')"
}

echo "== positive =="
call "weather-bot -> weather"                      200 weather-bot "/r/weather/v1/forecast?city=Paris"
call "billing workload -> payments (POST)"         200 billing     "/r/payments/v1/charges" -X POST -d '{"amount":100}'
call "weather-bot + caller X-Api-Key (stripped)"   200 weather-bot "/r/weather/v1/forecast?city=Oslo" -H "X-Api-Key: attacker"

echo "== negative =="
call "rogue agent -> weather (not allowlisted)"     403 rogue       "/r/weather/v1/forecast"
call "weather-bot -> payments (cross-route)"        403 weather-bot "/r/payments/v1/charges"
call "weather-bot -> unknown route"                 403 weather-bot "/r/admin/secrets"
call "rogue + spoofed identity headers"             403 rogue       "/r/weather/v1/forecast" \
  -H "X-KeyRelay-Workload-ID: spiffe://demo.keyrelay/agent/weather-bot" \
  -H "X-Forwarded-Client-Cert: URI=spiffe://demo.keyrelay/agent/weather-bot"
call "cert with two URI SANs"                       401 multi-san   "/r/weather/v1/forecast"
call "path traversal"                               400 weather-bot "/r/weather/../payments/v1/charges" --path-as-is
call "no client certificate"                        tls-rejected none "/r/weather/v1/forecast"
call "cert from untrusted CA"                       tls-rejected untrusted "/r/weather/v1/forecast"

echo "== leak check (container logs) =="
if command -v docker >/dev/null; then
  logs="$(docker compose logs keyrelay mock-upstream vault-init 2>&1)"
  leaked=0
  for s in "${SECRETS[@]}"; do grep -q "$s" <<<"$logs" && leaked=1; done
  if [ $leaked = 0 ]; then echo "PASS no demo credential in keyrelay/mock-upstream/vault-init logs"
  else echo "LEAK demo credential found in logs"; fails=$((fails+1)); fi
fi

echo
[ $fails = 0 ] && echo "all demo checks passed" || { echo "$fails demo check(s) failed"; exit 1; }
