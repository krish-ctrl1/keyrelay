"""A real LangChain agent that answers questions about your Stripe account.

Claude decides which Stripe tools to call. BOTH API keys (Anthropic and
Stripe) live only in Vault: the agent process holds nothing but its mTLS
certificate, and KeyRelay injects each key on the way out.

    python local/stripe/stripe_agent.py
    python local/stripe/stripe_agent.py "How much did I charge this week?"
    python local/stripe/stripe_agent.py --as rogue      # model allowed, Stripe denied
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from functools import cached_property
from pathlib import Path
from typing import Any, Optional

import anthropic
from langchain_anthropic import ChatAnthropic
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.tools import BaseTool
from pydantic import BaseModel, Field

from keyrelay_langchain import (
    MANAGED_PLACEHOLDER,
    KeyRelayClient,
    KeyRelayIdentity,
    create_keyrelay_tool,
)

REPO = Path(__file__).resolve().parents[2]
CERTS = Path(os.environ.get("KEYRELAY_CERT_DIR", REPO / "demo" / "certs"))
RELAY = os.environ.get("KEYRELAY_URL", "https://localhost:8443")
MODEL = os.environ.get("KEYRELAY_MODEL", "claude-sonnet-5-5")

SYSTEM = (
    "You are a read-only assistant for the user's Stripe account. Use the tools "
    "to answer. Stripe amounts are in the smallest currency unit (e.g. cents); "
    "convert them for the user. If a tool is refused, say so plainly."
)


# --------------------------------------------------------------------------- #
# Model: ChatAnthropic, routed through KeyRelay's "anthropic" route over mTLS.
# langchain-anthropic has no hook for a custom HTTP client, so we override the
# cached `_client` property to build the Anthropic SDK client ourselves.
# --------------------------------------------------------------------------- #
def relayed_chat_anthropic(
    identity: KeyRelayIdentity,
    relay: str = RELAY,
    *,
    transport: Any = None,  # test hook: a mock transport of the SDK's httpx flavour
    **kwargs: Any,
) -> ChatAnthropic:
    base = f"{relay}/r/anthropic"
    # Use the SDK's own client class: newer anthropic releases are built on
    # httpx2 and reject plain httpx clients.
    http_kwargs: dict[str, Any] = {"transport": transport} if transport else {"verify": identity.ssl_context()}

    class _RelayedChatAnthropic(ChatAnthropic):
        @cached_property
        def _client(self) -> anthropic.Anthropic:  # type: ignore[override]
            return anthropic.Anthropic(
                base_url=base,
                api_key=MANAGED_PLACEHOLDER,  # KeyRelay replaces x-api-key
                http_client=anthropic.DefaultHttpxClient(
                    timeout=120.0, trust_env=False, follow_redirects=False, **http_kwargs
                ),
                max_retries=self.max_retries,
            )

    kwargs.setdefault("model", MODEL)
    kwargs.setdefault("max_tokens", 1024)
    return _RelayedChatAnthropic(base_url=base, api_key=MANAGED_PLACEHOLDER, **kwargs)


# --------------------------------------------------------------------------- #
# Tools: read-only Stripe endpoints, called through KeyRelay's "stripe" route.
# --------------------------------------------------------------------------- #
class NoArgs(BaseModel):
    pass


class ListCustomersArgs(BaseModel):
    limit: int = Field(3, ge=1, le=10, description="How many customers to return (newest first)")
    email: Optional[str] = Field(None, description="Only customers with this exact email")


class ListChargesArgs(BaseModel):
    limit: int = Field(5, ge=1, le=20, description="How many charges to return (newest first)")
    customer: Optional[str] = Field(None, description="Only charges for this customer id (cus_...)")


def stripe_tools(client: KeyRelayClient) -> list[BaseTool]:
    common = dict(client=client, route="stripe", method="GET", max_response_chars=6000)
    return [
        create_keyrelay_tool(name="get_stripe_balance", description="Get the Stripe account balance.",
                             path="/v1/balance", args_schema=NoArgs, **common),
        create_keyrelay_tool(name="list_stripe_customers", description="List Stripe customers, newest first.",
                             path="/v1/customers", args_schema=ListCustomersArgs, **common),
        create_keyrelay_tool(name="list_stripe_charges", description="List recent Stripe charges, newest first.",
                             path="/v1/charges", args_schema=ListChargesArgs, **common),
    ]


# --------------------------------------------------------------------------- #
# Agent loop: model proposes tool calls, we run them, feed results back.
# --------------------------------------------------------------------------- #
def _text(msg: AIMessage) -> str:
    if isinstance(msg.content, str):
        return msg.content
    return "".join(b.get("text", "") for b in msg.content if isinstance(b, dict))


def run_agent(question: str, llm: ChatAnthropic, tools: list[BaseTool], max_steps: int = 6) -> str:
    by_name = {t.name: t for t in tools}
    model = llm.bind_tools(tools)
    messages: list[Any] = [SystemMessage(SYSTEM), HumanMessage(question)]
    for _ in range(max_steps):
        ai = model.invoke(messages)
        messages.append(ai)
        if not ai.tool_calls:
            return _text(ai)
        for call in ai.tool_calls:
            print(f"  → {call['name']}({json.dumps(call['args'])})")
            tool = by_name.get(call["name"])
            out = tool.invoke(call["args"]) if tool else f"unknown tool {call['name']}"
            print(f"    ← {out[:160]}{'…' if len(out) > 160 else ''}")
            messages.append(ToolMessage(content=out, tool_call_id=call["id"]))
    return "(stopped: too many tool steps)"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("question", nargs="?", default="What's my Stripe balance, and who are my 3 newest customers?")
    ap.add_argument("--as", dest="agent", default="stripe-agent", help="which demo cert to use")
    args = ap.parse_args()

    held = [k for k in os.environ if k.upper().startswith(("STRIPE", "ANTHROPIC_API_KEY"))]
    if held:
        print(f"Refusing to run: this agent must not hold API keys, but found {held}. Unset them.")
        return 1

    identity = KeyRelayIdentity(
        cert=str(CERTS / f"{args.agent}.crt"),
        key=str(CERTS / f"{args.agent}.key"),
        ca_cert=str(CERTS / "ca.crt"),
    )
    print(f"[{args.agent}] Q: {args.question}")
    with KeyRelayClient(RELAY, identity) as client:
        try:
            answer = run_agent(args.question, relayed_chat_anthropic(identity), stripe_tools(client))
        except anthropic.APIStatusError as e:
            reason = e.response.headers.get("x-keyrelay-error", "upstream")
            print(f"[{args.agent}] model call refused: HTTP {e.status_code} ({reason})")
            return 1
        except anthropic.APIConnectionError:
            print(f"[{args.agent}] cannot reach KeyRelay at {RELAY}. Is local/stripe/run-relay.sh running?")
            return 1
    print(f"[{args.agent}] A: {answer}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
