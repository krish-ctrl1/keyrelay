"""The SDK really presents the agent certificate over a real TLS socket."""

from __future__ import annotations

import json
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

from keyrelay_langchain import KeyRelayClient, KeyRelayIdentity


@pytest.fixture()
def mtls_server(pki):
    seen: list[dict] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            peer = self.connection.getpeercert()
            sans = [v for k, v in peer.get("subjectAltName", ()) if k == "URI"]
            seen.append({"sans": sans, "auth": self.headers.get_all("Authorization"), "path": self.path})
            body = json.dumps({"ok": True}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(pki / "keyrelay.crt", pki / "keyrelay.key")
    ctx.load_verify_locations(pki / "ca.crt")
    ctx.verify_mode = ssl.CERT_REQUIRED

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"https://localhost:{srv.server_address[1]}", seen
    srv.shutdown()
    srv.server_close()


def test_presents_client_certificate(mtls_server, identity_for):
    url, seen = mtls_server
    with KeyRelayClient(url, identity_for("weather-bot")) as c:
        assert c.get("weather", "/v1/forecast").json() == {"ok": True}
    assert seen == [{
        "sans": ["spiffe://demo.keyrelay/agent/weather-bot"],
        "auth": ["Bearer KEYRELAY_MANAGED"],
        "path": "/r/weather/v1/forecast",
    }]


def test_untrusted_client_certificate_rejected(mtls_server, pki):
    url, seen = mtls_server
    ident = KeyRelayIdentity(cert=str(pki / "untrusted.crt"), key=str(pki / "untrusted.key"), ca_cert=str(pki / "ca.crt"))
    with KeyRelayClient(url, ident) as c, pytest.raises(httpx.TransportError):
        c.get("weather")
    assert seen == []


def test_server_verified_against_ca(mtls_server, pki):
    url, _ = mtls_server
    # Trusting the wrong CA must fail server verification.
    ident = KeyRelayIdentity(cert=str(pki / "weather-bot.crt"), key=str(pki / "weather-bot.key"), ca_cert=str(pki / "untrusted-ca.crt"))
    with KeyRelayClient(url, ident) as c, pytest.raises(httpx.ConnectError):
        c.get("weather")
