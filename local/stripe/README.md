# LangChain agent → Stripe, with every API key in Vault behind KeyRelay

```
stripe_agent.py (LangChain + Claude)       holds ONLY its mTLS cert
   │ mTLS, placeholder creds
   ▼
KeyRelay  127.0.0.1:8443 ──AppRole──▶ Vault 127.0.0.1:8200 (Homebrew, dev mode)
   ├─ /r/anthropic → api.anthropic.com   (injects x-api-key)
   └─ /r/stripe    → api.stripe.com      (injects Authorization: Bearer)
```

## One-time
    brew tap hashicorp/tap && brew install hashicorp/tap/vault
    brew install go
    make venv && sdk/python/.venv/bin/pip install langchain-anthropic
    # certs are already in demo/certs; to redo: make certs && local/stripe/gen-agent-cert.sh

## Each session (three terminals, from the repo root)
    T1:  local/stripe/vault-dev.sh
    T2:  local/stripe/vault-setup.sh
         local/stripe/load-key.sh stripe
         local/stripe/load-key.sh anthropic
    T3:  local/stripe/run-relay.sh

## Try it
    sdk/python/.venv/bin/python local/stripe/stripe_agent.py
    sdk/python/.venv/bin/python local/stripe/stripe_agent.py "Show my last 5 charges"
    sdk/python/.venv/bin/python local/stripe/stripe_agent.py --as rogue   # model OK, Stripe 403

## Notes
- Use a Stripe *restricted* test key (rk_test_) with Read on Balance, Customers,
  Charges. KeyRelay has no per-method/path policy yet; the key's scope is the limit.
- Tools are read-only GETs. Stripe POSTs are form-encoded, so `create_keyrelay_tool`
  (which sends JSON) won't work for writes yet.
- The dev Vault is in memory: after stopping it, re-run T2.
- Don't run `make demo-up` at the same time (both use port 8443).
