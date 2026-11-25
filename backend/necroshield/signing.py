"""Optional Ed25519 signing of finalized evidence.

The private key comes only from the NECROSHIELD_SIGNING_KEY environment variable (base64 of the 32-byte
seed) or from a key file given to the CLI. It is never written to the repository, never returned by
the API, and never sent to the browser. Signing uses the `cryptography` package (constant-time);
verification, which uses only public data, is done by the standalone verifier in pure Python.

What a signature proves: the holder of the private key attested to this exact content (the payload's
canonical SHA-256, bound to the key id and a claimed time), and that content has not changed since.
What it does NOT prove: that the run was honest (whoever holds the key can sign fabricated evidence),
who holds the key (trust in the public key is established out of band), when it was signed (the time
is the signer's claim, with no timestamp authority), that the key was not stolen or revoked, or that
the payload is fresh rather than an older valid bundle. The payload is still verified in full.
"""

from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .verification import verifier

ENV_KEY = "NECROSHIELD_SIGNING_KEY"


class SigningUnavailable(Exception):
    pass


def _ed25519():
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
    except ImportError as exc:  # pragma: no cover - depends on the environment
        raise SigningUnavailable("the 'cryptography' package is not installed") from exc
    return Ed25519PrivateKey, serialization


def public_bytes(private: Any) -> bytes:
    _, serialization = _ed25519()
    return private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


@dataclass(frozen=True)
class Signer:
    _private: Any

    @property
    def public(self) -> bytes:
        return public_bytes(self._private)

    @property
    def key_id(self) -> str:
        return hashlib.sha256(self.public).hexdigest()[:16]

    def describe(self) -> dict[str, Any]:
        """Everything safe to publish. The private key is not reachable from here."""
        return {"enabled": True, "alg": "ed25519", "key_id": self.key_id, "public_key": self.public.hex()}

    def sign(self, payload: Any) -> dict[str, Any]:
        signed_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        message = verifier().signed_message(self.key_id, signed_at, payload)
        return {"format": verifier().SIGNED_FORMAT, "payload": payload,
                "signature": {"alg": "ed25519", "key_id": self.key_id, "signed_at": signed_at,
                              "sig": base64.b64encode(self._private.sign(message)).decode()}}


def signer_from_seed_b64(text: str) -> Signer:
    Ed25519PrivateKey, _ = _ed25519()
    try:
        seed = base64.b64decode(text.strip(), validate=True)
    except ValueError:
        raise ValueError("signing key must be base64") from None
    if len(seed) != 32:
        raise ValueError("signing key must be a 32-byte Ed25519 seed")
    return Signer(Ed25519PrivateKey.from_private_bytes(seed))


def load_signer(env: dict[str, str] | None = None) -> Signer | None:
    """None when no key is configured (the default, and the public-demo setting)."""
    text = (os.environ if env is None else env).get(ENV_KEY, "").strip()
    return signer_from_seed_b64(text) if text else None


def generate_keypair() -> tuple[str, str]:
    """(seed as base64, public key as hex). The caller decides where the seed goes."""
    Ed25519PrivateKey, serialization = _ed25519()
    private = Ed25519PrivateKey.generate()
    seed = private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    return base64.b64encode(seed).decode(), public_bytes(private).hex()


def write_key_file(path: str | Path, seed_b64: str) -> None:
    """Create a new key file readable only by the owner. Never overwrites."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(seed_b64 + "\n")
