# keyrelay-langchain

A Python SDK for [KeyRelay](../../README.md). It binds an agent's mTLS client certificate to `httpx` clients and LangChain `StructuredTool`s. The SDK always sends `Authorization: Bearer KEYRELAY_MANAGED`, which satisfies client libraries that insist on a non-empty API key. KeyRelay strips that placeholder and injects the real secret from Vault.

```bash
pip install -e 'sdk/python[test]'
```

## Calling a route

```python
from keyrelay_langchain import KeyRelayClient, KeyRelayIdentity, KeyRelayError

identity = KeyRelayIdentity(cert="weather-bot.crt", key="weather-bot.key", ca_cert="ca.crt")
# or KeyRelayIdentity.from_env()  -> KEYRELAY_CERT / KEYRELAY_KEY / KEYRELAY_CA_CERT

with KeyRelayClient("https://localhost:8443", identity) as relay:
    r = relay.get("weather", "/v1/forecast", params={"city": "Paris"})
    print(r.json())
```

- If KeyRelay itself refuses a request (`X-KeyRelay-Error` header present), the client raises `KeyRelayError(status_code, reason, request_id)`. Errors from the upstream API come back as ordinary responses.
- Any `Authorization` header the caller passes is overwritten with the placeholder. An agent can't forward its own key, or one it was tricked into using by prompt injection.
- Route names and paths are checked locally, so dot segments and backslashes fail early. The client ignores proxy environment variables and does not follow redirects.
- `AsyncKeyRelayClient` provides the same API with `async`/`await`.

## LangChain tool

```python
from pydantic import BaseModel
from keyrelay_langchain import create_keyrelay_tool

class Forecast(BaseModel):
    city: str

tool = create_keyrelay_tool(
    client=relay, name="get_forecast", description="Weather forecast for a city",
    route="weather", path="/v1/forecast", args_schema=Forecast,
)
tool.invoke({"city": "Paris"})          # -> 'HTTP 200: {...}'
```

`{placeholders}` in `path` are filled from tool arguments and percent-encoded as a single path segment. Other arguments become query parameters for `GET` and `DELETE`, or a JSON body for `POST`, `PUT` and `PATCH`. The tool returns only the status and body, never request headers, so no credential can reach the model or its traces. If KeyRelay refuses the request, the tool returns a short message instead of raising.

## Third-party SDKs

Any SDK that accepts a custom `httpx` client can go through KeyRelay:

```python
from keyrelay_langchain import mtls_http_client, MANAGED_PLACEHOLDER

http_client = mtls_http_client(identity)
# e.g. SomeSDK(base_url="https://keyrelay:8443/r/<route>", api_key=MANAGED_PLACEHOLDER, http_client=http_client)
```

## Tests

```bash
cd sdk/python && pytest -v          # the e2e tests need `go` and `openssl` on PATH
```
