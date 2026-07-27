"""Deterministic JSON canonicalization.

Signatures and hashes are only stable if two logically-equal objects always
serialize to the exact same bytes. We use a JCS-style canonical form:

* object keys sorted lexicographically (by UTF-16 code unit, matching RFC 8785
  for the ASCII keys we use),
* no insignificant whitespace,
* UTF-8 output, non-ASCII preserved (``ensure_ascii=False``),
* integers and floats rendered without trailing noise.

The goal is not full RFC 8785 float formatting (we avoid raw floats in signed
payloads); it is a reproducible, dependency-free canonical form good enough to
make Ed25519 signatures deterministic across machines and Python versions.
"""

from __future__ import annotations

import json
from typing import Any


def canonicalize(value: Any) -> bytes:
    """Return the canonical UTF-8 byte serialization of ``value``.

    ``value`` must be JSON-serializable (dict, list, str, int, float, bool,
    None). Dict keys must be strings.
    """
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def canonical_str(value: Any) -> str:
    """Return the canonical serialization as a ``str`` (for display/debug)."""
    return canonicalize(value).decode("utf-8")
