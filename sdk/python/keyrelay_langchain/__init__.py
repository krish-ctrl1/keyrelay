"""KeyRelay SDK: call external APIs through KeyRelay without holding their
credentials. The agent proves who it is with an mTLS client certificate;
KeyRelay injects the real credential server-side."""

from .client import (
    AsyncKeyRelayClient,
    KeyRelayClient,
    KeyRelayError,
    mtls_async_http_client,
    mtls_http_client,
    route_path,
)
from .identity import MANAGED_PLACEHOLDER, KeyRelayIdentity
from .tools import create_keyrelay_tool

__all__ = [
    "AsyncKeyRelayClient",
    "KeyRelayClient",
    "KeyRelayError",
    "KeyRelayIdentity",
    "MANAGED_PLACEHOLDER",
    "create_keyrelay_tool",
    "mtls_async_http_client",
    "mtls_http_client",
    "route_path",
]
__version__ = "0.0.1"
