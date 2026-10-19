"""Demo: a LangChain tool that calls the weather API through KeyRelay.

The agent process holds only its mTLS identity (cert + key). It has no
weather API key in its environment, memory, or tool output.

    python sdk/python/examples/langchain_agent.py              # as weather-bot (allowed)
    python sdk/python/examples/langchain_agent.py rogue        # as rogue (denied)

To hand the tool to a model, bind it as usual, e.g.
``ChatAnthropic(model="claude-sonnet-5-5").bind_tools([forecast_tool])``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from pydantic import BaseModel, Field

from keyrelay_langchain import KeyRelayClient, KeyRelayIdentity, create_keyrelay_tool

CERTS = Path(os.environ.get("KEYRELAY_CERT_DIR", Path(__file__).resolve().parents[3] / "demo" / "certs"))
RELAY = os.environ.get("KEYRELAY_URL", "https://localhost:8443")


class ForecastArgs(BaseModel):
    city: str = Field(description="City to get the forecast for")


def main(agent: str) -> None:
    identity = KeyRelayIdentity(
        cert=str(CERTS / f"{agent}.crt"),
        key=str(CERTS / f"{agent}.key"),
        ca_cert=str(CERTS / "ca.crt"),
    )
    assert "WEATHER_API_KEY" not in os.environ, "this agent must not hold the weather API key"

    with KeyRelayClient(RELAY, identity) as client:
        forecast_tool = create_keyrelay_tool(
            client=client,
            name="get_forecast",
            description="Get the weather forecast for a city.",
            route="weather",
            path="/v1/forecast",
            args_schema=ForecastArgs,
        )
        print(f"[{agent}] tool schema: {forecast_tool.args}")
        print(f"[{agent}] tool result: {forecast_tool.invoke({'city': 'Paris'})}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "weather-bot")
