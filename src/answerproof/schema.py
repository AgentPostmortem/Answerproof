"""Versioned receipt data model.

A receipt is the tamper-evident record attached to a single generated answer.
It is split into a *payload* (everything that is signed) and a *signature*
envelope. Keeping the signature outside the signed payload is what lets a
verifier recompute the exact bytes that were signed.

Schema versioning: ``schema_version`` lets verifiers reject or migrate future
formats. Bump it on any breaking change to the payload shape.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .canonical import canonicalize

SCHEMA_VERSION = "1.0"


class Source(BaseModel):
    """A single retrieved source and its integrity metadata."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., description="Stable identifier for the source/chunk.")
    content_hash: str = Field(..., description="sha256:<hex> of the exact source content.")
    score: float | None = Field(None, description="Retriever similarity/rank score.")
    metadata: dict[str, Any] = Field(default_factory=dict)


class Citation(BaseModel):
    """Binds a span of the answer to a supporting source."""

    model_config = ConfigDict(extra="forbid")

    source_id: str
    quote: str = Field(..., description="Answer text that is supported by the source.")
    method: str = Field("ngram-overlap", description="How support was determined.")
    score: float = Field(..., description="Support strength in [0, 1].")


class Claim(BaseModel):
    """A sentence-level claim in the answer and whether it is grounded."""

    model_config = ConfigDict(extra="forbid")

    text: str
    supported: bool
    source_ids: list[str] = Field(default_factory=list)
    support_score: float = 0.0


class Grounding(BaseModel):
    """Aggregate grounding assessment of the answer."""

    model_config = ConfigDict(extra="forbid")

    claims: list[Claim] = Field(default_factory=list)
    unsupported_claims: list[str] = Field(default_factory=list)
    grounding_score: float = Field(0.0, description="Fraction of claims supported, in [0, 1].")


class Principal(BaseModel):
    """Who asked, and under which permission scopes the retrieval ran."""

    model_config = ConfigDict(extra="forbid")

    id: str
    permissions: list[str] = Field(default_factory=list)
    tenant: str | None = None


class ModelInfo(BaseModel):
    """The generator model and its decoding parameters."""

    model_config = ConfigDict(extra="forbid")

    name: str
    provider: str | None = None
    params: dict[str, Any] = Field(default_factory=dict)


class ReceiptPayload(BaseModel):
    """The signed portion of a receipt."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = SCHEMA_VERSION
    receipt_id: str
    created_at: str = Field(..., description="RFC 3339 UTC timestamp.")
    query: str
    answer: str
    principal: Principal
    model: ModelInfo
    sources: list[Source] = Field(default_factory=list)
    cited_source_ids: list[str] = Field(default_factory=list)
    merkle_root: str = Field(..., description="Merkle root over source content hashes.")
    citations: list[Citation] = Field(default_factory=list)
    grounding: Grounding = Field(default_factory=Grounding)

    def canonical_bytes(self) -> bytes:
        """Exact bytes that get signed and re-verified."""
        return canonicalize(self.model_dump(mode="json"))


class Signature(BaseModel):
    """Detached signature envelope over a :class:`ReceiptPayload`."""

    model_config = ConfigDict(extra="forbid")

    algorithm: Literal["ed25519"] = "ed25519"
    public_key: str = Field(..., description="Base64 url-safe raw public key.")
    signature: str = Field(..., description="Base64 url-safe detached signature.")


class Receipt(BaseModel):
    """A complete, signed receipt: payload plus signature."""

    model_config = ConfigDict(extra="forbid")

    payload: ReceiptPayload
    signature: Signature

    def to_json(self, *, indent: int | None = 2) -> str:
        return self.model_dump_json(indent=indent)

    @classmethod
    def from_json(cls, text: str) -> Receipt:
        return cls.model_validate_json(text)
