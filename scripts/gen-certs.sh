#!/usr/bin/env bash
# Generates a demo PKI for KeyRelay. DEMO ONLY - not for production use.
#
#   scripts/gen-certs.sh [OUT_DIR]   (default: demo/certs)
#
# Produces:
#   ca.crt / ca.key                  trusted client+server CA
#   keyrelay.crt / keyrelay.key      relay server cert (DNS keyrelay, localhost; IP 127.0.0.1)
#   weather-bot.{crt,key}            spiffe://demo.keyrelay/agent/weather-bot   (allowed: weather)
#   billing.{crt,key}                spiffe://demo.keyrelay/workload/billing    (allowed: payments)
#   rogue.{crt,key}                  spiffe://demo.keyrelay/agent/rogue         (allowed: nothing)
#   multi-san.{crt,key}              two URI SANs                               (rejected: 401)
#   untrusted-ca.crt, untrusted.{crt,key}  weather-bot SAN signed by another CA (rejected at TLS)
set -euo pipefail

OUT="${1:-demo/certs}"
mkdir -p "$OUT"
cd "$OUT"
DAYS=30
TRUST_DOMAIN="demo.keyrelay"

key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null; }

ca() { # name cn
  key "$1.key"
  openssl req -x509 -new -key "$1.key" -sha256 -days "$DAYS" -subj "/CN=$2" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" -out "$1.crt" 2>/dev/null
}

leaf() { # name ca cn eku san
  local ext; ext="$(mktemp)"
  cat >"$ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=$4
subjectAltName=$5
EOF
  key "$1.key"
  openssl req -new -key "$1.key" -subj "/CN=$3" -out "$1.csr" 2>/dev/null
  openssl x509 -req -in "$1.csr" -CA "$2.crt" -CAkey "$2.key" -CAcreateserial \
    -days "$DAYS" -sha256 -extfile "$ext" -out "$1.crt" 2>/dev/null
  rm -f "$1.csr" "$ext"
}

ca ca "KeyRelay Demo CA"
leaf keyrelay    ca keyrelay    serverAuth "DNS:keyrelay,DNS:localhost,IP:127.0.0.1"
leaf weather-bot ca weather-bot clientAuth "URI:spiffe://$TRUST_DOMAIN/agent/weather-bot"
leaf billing     ca billing     clientAuth "URI:spiffe://$TRUST_DOMAIN/workload/billing"
leaf rogue       ca rogue       clientAuth "URI:spiffe://$TRUST_DOMAIN/agent/rogue"
leaf multi-san   ca multi-san   clientAuth "URI:spiffe://$TRUST_DOMAIN/agent/weather-bot,URI:spiffe://$TRUST_DOMAIN/agent/rogue"

ca untrusted-ca "Attacker CA"
leaf untrusted untrusted-ca weather-bot clientAuth "URI:spiffe://$TRUST_DOMAIN/agent/weather-bot"

rm -f ./*.srl untrusted-ca.key
chmod 600 ./*.key
# The relay container runs as a non-root user and must read its key from a
# bind mount. Demo only.
chmod 644 keyrelay.key
echo "certificates written to $(pwd)"
