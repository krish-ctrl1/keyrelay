from __future__ import annotations

import asyncio
import json

import httpx
from pydantic import BaseModel, Field

from keyrelay_langchain import AsyncKeyRelayClient, KeyRelayClient, KeyRelayIdentity, create_keyrelay_tool

DUMMY = KeyRelayIdentity(cert="unused.crt", key="unused.key", ca_cert="unused-ca.crt")


class ForecastArgs(BaseModel):
    city: str = Field(description="City name")
    days: int | None = Field(default=None, description="Forecast length")


class ChargeArgs(BaseModel):
    customer: str
    amount_cents: int


def client_with(handler) -> KeyRelayClient:
    return KeyRelayClient("https://relay.test", DUMMY, transport=httpx.MockTransport(handler))


def test_get_tool_formats_path_and_query():
    seen = []

    def handler(req):
        seen.append(req)
        return httpx.Response(200, json={"temp_c": 18})

    tool = create_keyrelay_tool(
        client=client_with(handler), name="get_forecast", description="Get weather",
        route="weather", path="/v1/cities/{city}/forecast", args_schema=ForecastArgs,
    )
    out = tool.invoke({"city": "New York/../admin", "days": 3})
    assert out == 'HTTP 200: {"temp_c":18}'
    req = seen[0]
    # Path parameter is encoded as a single segment: no traversal possible.
    assert req.url.raw_path == b"/r/weather/v1/cities/New%20York%2F..%2Fadmin/forecast?days=3"
    assert req.headers["authorization"] == "Bearer KEYRELAY_MANAGED"


def test_post_tool_sends_json_body():
    seen = []

    def handler(req):
        seen.append(req)
        return httpx.Response(201, json={"id": "ch_1"})

    tool = create_keyrelay_tool(
        client=client_with(handler), name="charge", description="Charge a customer",
        route="payments", path="/v1/charges", method="post", args_schema=ChargeArgs,
    )
    assert tool.invoke({"customer": "c_1", "amount_cents": 500}).startswith("HTTP 201")
    assert json.loads(seen[0].content) == {"customer": "c_1", "amount_cents": 500}


def test_denial_is_reported_without_raising():
    def handler(req):
        return httpx.Response(403, headers={"X-KeyRelay-Error": "forbidden"}, json={"error": "forbidden"})

    tool = create_keyrelay_tool(
        client=client_with(handler), name="get_forecast", description="d",
        route="weather", path="/v1/{city}", args_schema=ForecastArgs,
    )
    assert tool.invoke({"city": "Paris"}) == "KeyRelay refused the request: 403 forbidden"


def test_transport_error_is_generic():
    def handler(req):
        raise httpx.ConnectError("boom", request=req)

    tool = create_keyrelay_tool(
        client=client_with(handler), name="t", description="d",
        route="weather", path="/", args_schema=ForecastArgs,
    )
    assert tool.invoke({"city": "x"}) == "KeyRelay request failed: ConnectError"


def test_output_truncated_and_schema_exposed():
    tool = create_keyrelay_tool(
        client=client_with(lambda r: httpx.Response(200, text="x" * 100)), name="t", description="d",
        route="weather", path="/", args_schema=ForecastArgs, max_response_chars=10,
    )
    assert tool.invoke({"city": "x"}) == "HTTP 200: xxxxxxxxxx...[truncated]"
    assert set(tool.args) == {"city", "days"}


def test_async_tool():
    rec = []

    def handler(req):
        rec.append(req)
        return httpx.Response(200, text="ok")

    tool = create_keyrelay_tool(
        client=client_with(handler), name="t", description="d", route="weather", path="/{city}",
        args_schema=ForecastArgs,
        async_client=AsyncKeyRelayClient("https://relay.test", DUMMY, transport=httpx.MockTransport(handler)),
    )
    assert asyncio.run(tool.ainvoke({"city": "Oslo"})) == "HTTP 200: ok"
    assert rec[0].url.path == "/r/weather/Oslo"
