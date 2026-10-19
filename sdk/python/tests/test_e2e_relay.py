"""End-to-end: Python SDK + LangChain tool -> real Go keyrelay-proxy (mTLS)
-> fake Vault (AppRole + KV v2) -> fake upstream API.

Skipped automatically when `go` is not on PATH."""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest
from pydantic import BaseModel

from keyrelay_langchain import KeyRelayClient, KeyRelayError, create_keyrelay_tool

from .conftest import REPO_ROOT

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.skipif(shutil.which("go") is None, reason="go toolchain not available"),
]

WEATHER_KEY = "wx-live-E2E-SECRET-0001"
PAYMENTS_KEY = "pay-live-E2E-SECRET-0002"
VAULT_TOKEN = "hvs.E2E-TOKEN-0003"
ROLE_ID = "e2e-role"
SECRET_ID = "e2e-SECRETID-0004"
SENSITIVE = [WEATHER_KEY, PAYMENTS_KEY, VAULT_TOKEN, SECRET_ID]


def _serve(handler_cls) -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class _Quiet(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, status: int, obj) -> None:
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class FakeVault(_Quiet):
    reads = 0

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if self.path == "/v1/auth/approle/login" and body == {"role_id": ROLE_ID, "secret_id": SECRET_ID}:
            return self._json(200, {"auth": {"client_token": VAULT_TOKEN, "lease_duration": 600}})
        self._json(400, {"errors": ["denied"]})

    def do_GET(self):
        FakeVault.reads += 1
        if self.headers.get("X-Vault-Token") != VAULT_TOKEN:
            return self._json(403, {"errors": ["permission denied"]})
        data = {
            "/v1/secret/data/keyrelay/weather": {"api_key": WEATHER_KEY},
            "/v1/secret/data/keyrelay/payments": {"api_key": PAYMENTS_KEY},
        }.get(self.path)
        if data is None:
            return self._json(404, {"errors": []})
        self._json(200, {"data": {"data": data}})


class FakeUpstream(_Quiet):
    seen: list[dict] = []

    def _handle(self):
        expected = {"/weather": WEATHER_KEY, "/payments": PAYMENTS_KEY}
        key = next((v for p, v in expected.items() if self.path.startswith(p)), None)
        auth = self.headers.get_all("Authorization") or []
        FakeUpstream.seen.append({"path": self.path, "auth": auth, "host": self.headers["Host"]})
        if key is None or auth != [f"Bearer {key}"]:
            return self._json(401, {"authenticated": False})
        self._json(200, {"authenticated": True, "path": self.path})

    do_GET = do_POST = _handle


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def relay(pki, tmp_path_factory):
    work = tmp_path_factory.mktemp("relay")
    binary = work / "keyrelay-proxy"
    subprocess.run(["go", "build", "-o", str(binary), "./cmd/keyrelay-proxy"], cwd=REPO_ROOT, check=True)

    vault, upstream = _serve(FakeVault), _serve(FakeUpstream)
    (work / "role_id").write_text(ROLE_ID)
    (work / "secret_id").write_text(SECRET_ID)
    port = _free_port()
    up = f"http://127.0.0.1:{upstream.server_address[1]}"
    (work / "config.yaml").write_text(f"""
listen: "127.0.0.1:{port}"
tls:
  cert_file: {pki / 'keyrelay.crt'}
  key_file: {pki / 'keyrelay.key'}
  client_ca_file: {pki / 'ca.crt'}
vault:
  address: http://127.0.0.1:{vault.server_address[1]}
  approle:
    role_id_file: {work / 'role_id'}
    secret_id_file: {work / 'secret_id'}
cache:
  ttl: 30s
routes:
  - name: weather
    upstream: {up}/weather
    allow_insecure_upstream: true
    secret: {{mount: secret, path: keyrelay/weather, key: api_key}}
    allow: [spiffe://demo.keyrelay/agent/weather-bot]
  - name: payments
    upstream: {up}/payments
    allow_insecure_upstream: true
    secret: {{mount: secret, path: keyrelay/payments, key: api_key}}
    allow: [spiffe://demo.keyrelay/workload/billing]
""")
    log = (work / "relay.log").open("w+")
    proc = subprocess.Popen([str(binary), "-config", str(work / "config.yaml")], stdout=log, stderr=subprocess.STDOUT)
    deadline = time.time() + 20
    while time.time() < deadline:
        if proc.poll() is not None:
            log.seek(0)
            pytest.fail(f"relay exited early:\n{log.read()}")
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.1)
    else:
        pytest.fail("relay did not start")

    yield f"https://localhost:{port}", work / "relay.log"

    proc.terminate()
    proc.wait(timeout=10)
    log.close()
    vault.shutdown()
    upstream.shutdown()
    logs = (work / "relay.log").read_text()
    for s in SENSITIVE:
        assert s not in logs, f"relay log leaked {s!r}"


def _assert_clean(resp: httpx.Response) -> None:
    blob = resp.text + json.dumps(dict(resp.headers))
    for s in SENSITIVE:
        assert s not in blob


def test_allowed_agent_reaches_upstream_with_real_key(relay, identity_for):
    url, _ = relay
    FakeUpstream.seen.clear()
    with KeyRelayClient(url, identity_for("weather-bot")) as c:
        resp = c.get("weather", "/v1/forecast", params={"city": "Paris"})
    _assert_clean(resp)
    assert resp.status_code == 200 and resp.json()["authenticated"] is True
    assert FakeUpstream.seen[-1]["auth"] == [f"Bearer {WEATHER_KEY}"]
    assert FakeUpstream.seen[-1]["path"] == "/weather/v1/forecast?city=Paris"


def test_workload_on_its_own_route(relay, identity_for):
    url, _ = relay
    with KeyRelayClient(url, identity_for("billing")) as c:
        resp = c.post("payments", "/v1/charges", json={"amount": 100})
    _assert_clean(resp)
    assert resp.status_code == 200


@pytest.mark.parametrize("who,route,status,reason", [
    ("rogue", "weather", 403, "forbidden"),
    ("weather-bot", "payments", 403, "forbidden"),
    ("billing", "weather", 403, "forbidden"),
    ("weather-bot", "nonexistent", 403, "forbidden"),
    ("multi-san", "weather", 401, "unauthenticated"),
])
def test_denials(relay, identity_for, who, route, status, reason):
    url, _ = relay
    reads_before = FakeVault.reads
    with KeyRelayClient(url, identity_for(who)) as c, pytest.raises(KeyRelayError) as ei:
        c.get(route, "/v1/x", headers={"X-KeyRelay-Workload-ID": "spiffe://demo.keyrelay/agent/weather-bot"})
    assert (ei.value.status_code, ei.value.reason) == (status, reason)
    assert FakeVault.reads == reads_before, "vault touched for a denied request"


def test_untrusted_ca_rejected_at_tls(relay, pki):
    from keyrelay_langchain import KeyRelayIdentity

    url, _ = relay
    ident = KeyRelayIdentity(cert=str(pki / "untrusted.crt"), key=str(pki / "untrusted.key"), ca_cert=str(pki / "ca.crt"))
    with KeyRelayClient(url, ident) as c, pytest.raises(httpx.TransportError):
        c.get("weather")


class Forecast(BaseModel):
    city: str


def test_langchain_tool_end_to_end(relay, identity_for):
    url, log_path = relay
    with KeyRelayClient(url, identity_for("weather-bot")) as c:
        tool = create_keyrelay_tool(client=c, name="get_forecast", description="Weather forecast",
                                    route="weather", path="/v1/forecast", args_schema=Forecast)
        out = tool.invoke({"city": "Lisbon"})
    assert out.startswith("HTTP 200:") and '"authenticated": true' in out
    for s in SENSITIVE:
        assert s not in out
    # Audit records are emitted for every request.
    assert '"msg":"keyrelay.request"' in log_path.read_text()
