"""Workload identity material (mTLS client certificate) for KeyRelay."""

from __future__ import annotations

import os
import ssl
from dataclasses import dataclass

MANAGED_PLACEHOLDER = "KEYRELAY_MANAGED"
"""Placeholder credential sent by agents. KeyRelay strips it and injects the
real secret, so SDKs that insist on a non-empty API key are satisfied without
the agent ever holding one."""


@dataclass(frozen=True)
class KeyRelayIdentity:
    """Paths to the agent's client certificate, private key and the CA that
    signed the KeyRelay server certificate."""

    cert: str
    key: str
    ca_cert: str

    @classmethod
    def from_env(cls, prefix: str = "KEYRELAY_") -> "KeyRelayIdentity":
        """Read ``KEYRELAY_CERT``, ``KEYRELAY_KEY`` and ``KEYRELAY_CA_CERT``."""
        try:
            return cls(
                cert=os.environ[f"{prefix}CERT"],
                key=os.environ[f"{prefix}KEY"],
                ca_cert=os.environ[f"{prefix}CA_CERT"],
            )
        except KeyError as exc:
            raise ValueError(f"missing environment variable {exc.args[0]}") from None

    def ssl_context(self) -> ssl.SSLContext:
        """A client SSL context that verifies the relay and presents the
        agent's certificate."""
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=self.ca_cert)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile=self.cert, keyfile=self.key)
        return ctx
