#!/usr/bin/env bash
# Mints mTLS client certs for the Stripe agent (allowed) and a rogue agent
# (not allowed), signed by the demo CA from scripts/gen-certs.sh.
set -euo pipefail
cd "$(dirname "$0")/../../demo/certs" 2>/dev/null || { echo "Run 'make certs' first."; exit 1; }
mint() { # name spiffe-path
  local ext; ext="$(mktemp)"
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\nsubjectAltName=URI:spiffe://demo.keyrelay/%s\n' "$2" >"$ext"
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1.key" 2>/dev/null
  openssl req -new -key "$1.key" -subj "/CN=$1" -out "$1.csr" 2>/dev/null
  openssl x509 -req -in "$1.csr" -CA ca.crt -CAkey ca.key -CAcreateserial -days 30 -sha256 \
    -extfile "$ext" -out "$1.crt" 2>/dev/null
  rm -f "$1.csr" "$ext" ca.srl; chmod 600 "$1.key"
}
mint stripe-agent agent/stripe-agent
[ -f rogue.crt ] || mint rogue agent/rogue
echo "stripe-agent cert: $(openssl x509 -in stripe-agent.crt -noout -ext subjectAltName | tail -1 | xargs)"
