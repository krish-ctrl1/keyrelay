#!/usr/bin/env bash
# Terminal 1: an in-memory dev Vault on localhost. LOCAL TESTING ONLY.
# Everything is lost when you stop it; re-run vault-setup.sh and load-key.sh.
command -v vault >/dev/null || { echo "Install Vault: brew tap hashicorp/tap && brew install hashicorp/tap/vault"; exit 1; }
exec vault server -dev -dev-root-token-id=local-root-token -dev-listen-address=127.0.0.1:8200
