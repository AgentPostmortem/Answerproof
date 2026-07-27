"""Ed25519 keypair generation, signing and verification.

Receipts are signed over their canonical byte serialization. Signatures are
*detached*: the signature and the signer's public key travel alongside the
receipt payload rather than wrapping it, so the payload stays human-readable
and independently hashable.

Keys are exchanged as URL-safe base64 (no padding) of the raw 32-byte Ed25519
values, which keeps them short and copy-pasteable.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


@dataclass(frozen=True)
class SigningKey:
    """An Ed25519 private key used to sign receipts."""

    _private: Ed25519PrivateKey

    @classmethod
    def generate(cls) -> SigningKey:
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_base64(cls, text: str) -> SigningKey:
        raw = _b64d(text)
        return cls(Ed25519PrivateKey.from_private_bytes(raw))

    def to_base64(self) -> str:
        raw = self._private.private_bytes_raw()
        return _b64e(raw)

    @property
    def verify_key(self) -> VerifyKey:
        return VerifyKey(self._private.public_key())

    def sign(self, message: bytes) -> str:
        """Return a detached signature (base64) over ``message``."""
        return _b64e(self._private.sign(message))


@dataclass(frozen=True)
class VerifyKey:
    """An Ed25519 public key used to verify receipts."""

    _public: Ed25519PublicKey

    @classmethod
    def from_base64(cls, text: str) -> VerifyKey:
        raw = _b64d(text)
        return cls(Ed25519PublicKey.from_public_bytes(raw))

    def to_base64(self) -> str:
        raw = self._public.public_bytes_raw()
        return _b64e(raw)

    def verify(self, message: bytes, signature_b64: str) -> bool:
        """True iff ``signature_b64`` is a valid signature of ``message``."""
        try:
            self._public.verify(_b64d(signature_b64), message)
            return True
        except (InvalidSignature, ValueError):
            return False


def generate_keypair() -> tuple[SigningKey, VerifyKey]:
    """Convenience: return a fresh ``(signing_key, verify_key)`` pair."""
    sk = SigningKey.generate()
    return sk, sk.verify_key
