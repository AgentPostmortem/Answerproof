"""Content hashing helpers.

Every source is identified in a receipt by the SHA-256 hash of its exact
content bytes. Hashes are hex-encoded and prefixed with the algorithm so the
format can evolve without ambiguity (e.g. ``sha256:ab12...``).
"""

from __future__ import annotations

import hashlib

HASH_ALGO = "sha256"
_PREFIX = f"{HASH_ALGO}:"


def hash_content(content: str | bytes) -> str:
    """Return a prefixed hex digest of ``content``.

    Strings are encoded as UTF-8 before hashing so the same text always yields
    the same digest regardless of caller encoding.
    """
    data = content.encode("utf-8") if isinstance(content, str) else content
    digest = hashlib.sha256(data).hexdigest()
    return f"{_PREFIX}{digest}"


def is_hash(value: str) -> bool:
    """True if ``value`` looks like a prefixed sha256 digest we produced."""
    if not value.startswith(_PREFIX):
        return False
    hexpart = value[len(_PREFIX) :]
    return len(hexpart) == 64 and all(c in "0123456789abcdef" for c in hexpart)


def verify_content(content: str | bytes, expected_hash: str) -> bool:
    """Constant-shape check that ``content`` hashes to ``expected_hash``."""
    return hash_content(content) == expected_hash
