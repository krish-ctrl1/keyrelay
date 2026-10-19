"""LangChain StructuredTool factory for KeyRelay routes."""

from __future__ import annotations

import string
from typing import Any, Type
from urllib.parse import quote

import httpx
from langchain_core.tools import StructuredTool
from pydantic import BaseModel

from .client import AsyncKeyRelayClient, KeyRelayClient, KeyRelayError

_BODY_METHODS = {"POST", "PUT", "PATCH"}


def _split_args(path_template: str, kwargs: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    fields = {f for _, f, _, _ in string.Formatter().parse(path_template) if f}
    # Path parameters are percent-encoded as a single segment so model output
    # cannot add "/" or ".." to the URL.
    path = path_template.format(**{f: quote(str(kwargs[f]), safe="") for f in fields})
    rest = {k: v for k, v in kwargs.items() if k not in fields and v is not None}
    return path, rest


def _render(resp: httpx.Response, max_chars: int) -> str:
    text = resp.text
    if len(text) > max_chars:
        text = text[:max_chars] + "...[truncated]"
    return f"HTTP {resp.status_code}: {text}"


def create_keyrelay_tool(
    *,
    client: KeyRelayClient,
    name: str,
    description: str,
    route: str,
    path: str,
    args_schema: Type[BaseModel],
    method: str = "GET",
    async_client: AsyncKeyRelayClient | None = None,
    max_response_chars: int = 4000,
) -> StructuredTool:
    """Build a LangChain tool that calls ``route`` through KeyRelay.

    ``path`` may contain ``{placeholders}`` filled from tool arguments; other
    arguments become query parameters for GET/DELETE or a JSON body for
    POST/PUT/PATCH. The tool's output contains only the upstream status and
    body, never request headers, so no credential can appear in an LLM trace.
    """
    method = method.upper()

    def _kwargs(rest: dict[str, Any]) -> dict[str, Any]:
        return {"json": rest} if method in _BODY_METHODS else {"params": rest}

    def _run(**kwargs: Any) -> str:
        p, rest = _split_args(path, kwargs)
        try:
            resp = client.request(method, route, p, **_kwargs(rest))
        except KeyRelayError as e:
            return f"KeyRelay refused the request: {e.status_code} {e.reason}"
        except httpx.HTTPError as e:
            return f"KeyRelay request failed: {type(e).__name__}"
        return _render(resp, max_response_chars)

    async def _arun(**kwargs: Any) -> str:
        assert async_client is not None
        p, rest = _split_args(path, kwargs)
        try:
            resp = await async_client.request(method, route, p, **_kwargs(rest))
        except KeyRelayError as e:
            return f"KeyRelay refused the request: {e.status_code} {e.reason}"
        except httpx.HTTPError as e:
            return f"KeyRelay request failed: {type(e).__name__}"
        return _render(resp, max_response_chars)

    return StructuredTool.from_function(
        func=_run,
        coroutine=_arun if async_client is not None else None,
        name=name,
        description=description,
        args_schema=args_schema,
    )
