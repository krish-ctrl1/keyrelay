"""httpx clients bound to an agent's mTLS identity."""

from __future__ import annotations

import re
from typing import Any, Mapping

import httpx

from .identity import MANAGED_PLACEHOLDER, KeyRelayIdentity

_ROUTE_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
ERROR_HEADER = "x-keyrelay-error"
REQUEST_ID_HEADER = "x-keyrelay-request-id"


class KeyRelayError(Exception):
    """KeyRelay itself refused the request (401/403/400/502/503).

    Upstream API errors are *not* raised; they are returned as normal
    responses so the caller can inspect them."""

    def __init__(self, status_code: int, reason: str, request_id: str | None):
        self.status_code = status_code
        self.reason = reason
        self.request_id = request_id
        super().__init__(f"KeyRelay {status_code} {reason} (request_id={request_id})")


def route_path(route: str, path: str = "/") -> str:
    """Build ``/r/<route>/<path>``, rejecting anything that could escape the
    route (KeyRelay rejects these too; failing early gives clearer errors)."""
    if not _ROUTE_RE.match(route):
        raise ValueError(f"invalid route name {route!r}")
    path = path.lstrip("/")
    segments = path.split("?", 1)[0].split("/")
    if any(s in (".", "..") for s in segments) or "\\" in path:
        raise ValueError("path must not contain dot segments or backslashes")
    return f"/r/{route}/{path}"


def _managed_headers(header: str, scheme: str) -> dict[str, str]:
    value = f"{scheme} {MANAGED_PLACEHOLDER}".strip() if scheme else MANAGED_PLACEHOLDER
    return {header: value}


def _merge_headers(headers: Mapping[str, str] | None, managed: dict[str, str]) -> dict[str, str]:
    # The managed header always wins: an agent can never smuggle its own
    # credential (or a prompt-injected one) through the SDK.
    merged = {k: v for k, v in (headers or {}).items() if k.lower() not in {m.lower() for m in managed}}
    merged.update(managed)
    return merged


def _check(resp: httpx.Response) -> httpx.Response:
    reason = resp.headers.get(ERROR_HEADER)
    if reason:
        raise KeyRelayError(resp.status_code, reason, resp.headers.get(REQUEST_ID_HEADER))
    return resp


def mtls_http_client(identity: KeyRelayIdentity, **kwargs: Any) -> httpx.Client:
    """A bare mTLS-bound ``httpx.Client`` for third-party SDKs that accept a
    custom ``http_client`` (point their ``base_url`` at
    ``https://keyrelay:8443/r/<route>`` and pass ``api_key="KEYRELAY_MANAGED"``)."""
    kwargs.setdefault("trust_env", False)
    kwargs.setdefault("follow_redirects", False)
    if "transport" not in kwargs:
        kwargs["verify"] = identity.ssl_context()
    return httpx.Client(**kwargs)


def mtls_async_http_client(identity: KeyRelayIdentity, **kwargs: Any) -> httpx.AsyncClient:
    """Async variant of :func:`mtls_http_client`."""
    kwargs.setdefault("trust_env", False)
    kwargs.setdefault("follow_redirects", False)
    if "transport" not in kwargs:
        kwargs["verify"] = identity.ssl_context()
    return httpx.AsyncClient(**kwargs)


class KeyRelayClient:
    """Calls routes on a KeyRelay relay using the agent's mTLS identity.

    >>> client = KeyRelayClient("https://localhost:8443", KeyRelayIdentity.from_env())
    >>> client.get("weather", "/v1/forecast", params={"city": "Paris"}).json()
    """

    def __init__(
        self,
        base_url: str,
        identity: KeyRelayIdentity,
        *,
        timeout: float = 30.0,
        managed_header: str = "Authorization",
        managed_scheme: str = "Bearer",
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._managed = _managed_headers(managed_header, managed_scheme)
        kwargs: dict[str, Any] = {"base_url": base_url, "timeout": timeout}
        if transport is not None:
            kwargs["transport"] = transport
        self._http = mtls_http_client(identity, **kwargs)

    def request(self, method: str, route: str, path: str = "/", *, headers: Mapping[str, str] | None = None, **kwargs: Any) -> httpx.Response:
        resp = self._http.request(method, route_path(route, path), headers=_merge_headers(headers, self._managed), **kwargs)
        return _check(resp)

    def get(self, route: str, path: str = "/", **kwargs: Any) -> httpx.Response:
        return self.request("GET", route, path, **kwargs)

    def post(self, route: str, path: str = "/", **kwargs: Any) -> httpx.Response:
        return self.request("POST", route, path, **kwargs)

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "KeyRelayClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class AsyncKeyRelayClient:
    """Async variant of :class:`KeyRelayClient`."""

    def __init__(
        self,
        base_url: str,
        identity: KeyRelayIdentity,
        *,
        timeout: float = 30.0,
        managed_header: str = "Authorization",
        managed_scheme: str = "Bearer",
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._managed = _managed_headers(managed_header, managed_scheme)
        kwargs: dict[str, Any] = {"base_url": base_url, "timeout": timeout}
        if transport is not None:
            kwargs["transport"] = transport
        self._http = mtls_async_http_client(identity, **kwargs)

    async def request(self, method: str, route: str, path: str = "/", *, headers: Mapping[str, str] | None = None, **kwargs: Any) -> httpx.Response:
        resp = await self._http.request(method, route_path(route, path), headers=_merge_headers(headers, self._managed), **kwargs)
        return _check(resp)

    async def get(self, route: str, path: str = "/", **kwargs: Any) -> httpx.Response:
        return await self.request("GET", route, path, **kwargs)

    async def post(self, route: str, path: str = "/", **kwargs: Any) -> httpx.Response:
        return await self.request("POST", route, path, **kwargs)

    async def aclose(self) -> None:
        await self._http.aclose()

    async def __aenter__(self) -> "AsyncKeyRelayClient":
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()
