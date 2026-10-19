from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from keyrelay_langchain import KeyRelayIdentity

REPO_ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture(scope="session")
def pki(tmp_path_factory) -> Path:
    """Demo PKI generated with the same script the Docker demo uses."""
    if shutil.which("openssl") is None:
        pytest.skip("openssl not available")
    out = tmp_path_factory.mktemp("pki")
    subprocess.run(
        ["bash", str(REPO_ROOT / "scripts" / "gen-certs.sh"), str(out)],
        check=True,
        capture_output=True,
    )
    return out


@pytest.fixture(scope="session")
def identity_for(pki):
    def _make(name: str) -> KeyRelayIdentity:
        return KeyRelayIdentity(
            cert=str(pki / f"{name}.crt"),
            key=str(pki / f"{name}.key"),
            ca_cert=str(pki / "ca.crt"),
        )

    return _make
