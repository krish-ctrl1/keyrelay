from __future__ import annotations

import asyncio

import httpx
import pytest

from keyrelay_langchain import (
    AsyncKeyRelayClient,
    KeyRelayClient,
    KeyRelayError,
    KeyRelayIdentity,
    route_path,
)

DUMMY = KeyRelayIdentity(cert="unused.crt", key="unused.key", ca_cert="unused-ca.crt")


class Recorder:
    def __init__(self, response: httpx.Response | None = None):
        self.requests: list[httpx.Request] = []
        self.response = response or httpx.Response(200, json={"ok": True})

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.response


def make_client(rec: Recorder, **kw) -> KeyRelayClient:
    return KeyRelayClient("https://relay.test:8443", DUMMY, transport=httpx.MockTransport(rec), **kw)


def test_sends_managed_placeholder_and_route_url():
    rec = Recorder()
    with make_client(rec) as c:
        resp = c.get("weather", "/v1/forecast", params={"city": "Paris"})
    assert resp.json() == {"ok": True}
    req = rec.requests[0]
    assert str(req.url) == "https://relay.test:8443/r/weather/v1/forecast?city=Paris"
    assert req.headers.get_list("authorization") == ["Bearer KEYRELAY_MANAGED"]


def test_caller_supplied_credentials_are_overridden():
    rec = Recorder()
    with make_client(rec) as c:
        c.post("weather", "x", headers={"AUTHORIZATION": "Bearer sk-real-leaked", "X-Trace": "1"}, json={"a": 1})
    req = rec.requests[0]
    assert req.headers.get_list("authorization") == ["Bearer KEYRELAY_MANAGED"]
    assert req.headers["x-trace"] == "1"
    assert "sk-real-leaked" not in str(req.headers)


def test_custom_managed_header():
    rec = Recorder()
    with make_client(rec, managed_header="X-Api-Key", managed_scheme="") as c:
        c.get("payments")
    assert rec.requests[0].headers["x-api-key"] == "KEYRELAY_MANAGED"


@pytest.mark.parametrize("status,reason", [(401, "unauthenticated"), (403, "forbidden"), (503, "credential_unavailable"), (502, "upstream_error")])
def test_relay_refusals_raise(status, reason):
    rec = Recorder(httpx.Response(status, headers={"X-KeyRelay-Error": reason, "X-KeyRelay-Request-ID": "rid1"}, json={"error": reason}))
    with make_client(rec) as c, pytest.raises(KeyRelayError) as ei:
        c.get("weather")
    assert ei.value.status_code == status
    assert ei.value.reason == reason
    assert ei.value.request_id == "rid1"


def test_upstream_errors_pass_through():
    rec = Recorder(httpx.Response(404, json={"error": "no such city"}))
    with make_client(rec) as c:
        assert c.get("weather", "/v1/forecast").status_code == 404


@pytest.mark.parametrize("route", ["Weather", "../x", "", "a/b", "-x"])
def test_invalid_route_names(route):
    with pytest.raises(ValueError):
        route_path(route, "/")


@pytest.mark.parametrize("path", ["../payments", "a/./b", "a/../../b", "a\\b"])
def test_path_escapes_rejected(path):
    with pytest.raises(ValueError):
        route_path("weather", path)


def test_route_path_ok():
    assert route_path("weather") == "/r/weather/"
    assert route_path("weather", "/v1/x") == "/r/weather/v1/x"


def test_client_ignores_proxy_env(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://evil-proxy:3128")
    rec = Recorder()
    with make_client(rec) as c:
        assert c._http.trust_env is False
        assert c._http.follow_redirects is False


def test_async_client():
    rec = Recorder()

    async def go():
        async with AsyncKeyRelayClient("https://relay.test:8443", DUMMY, transport=httpx.MockTransport(rec)) as c:
            return await c.get("weather", "/v1/forecast")

    assert asyncio.run(go()).status_code == 200
    assert rec.requests[0].headers["authorization"] == "Bearer KEYRELAY_MANAGED"


def test_identity_from_env(monkeypatch):
    monkeypatch.setenv("KEYRELAY_CERT", "/c")
    monkeypatch.setenv("KEYRELAY_KEY", "/k")
    monkeypatch.setenv("KEYRELAY_CA_CERT", "/ca")
    assert KeyRelayIdentity.from_env() == KeyRelayIdentity("/c", "/k", "/ca")
    monkeypatch.delenv("KEYRELAY_KEY")
    with pytest.raises(ValueError, match="KEYRELAY_KEY"):
        KeyRelayIdentity.from_env()
