# KeyRelay may only read the credentials it relays.
path "secret/data/keyrelay/*" {
  capabilities = ["read"]
}
