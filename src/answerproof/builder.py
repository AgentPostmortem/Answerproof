"""The :class:`ReceiptBuilder` ergonomic API.

A RAG pipeline drives the builder through the natural order of a request:

    builder = ReceiptBuilder(signing_key=sk)
    builder.set_query("...").set_principal(...).set_model(...)
    builder.add_source("s1", content="...", score=0.82)
    builder.set_answer("...")
    receipt = builder.finalize()

``finalize()`` computes source content hashes, builds the Merkle tree, runs
citation binding, assembles the signed payload and returns a fully signed
:class:`Receipt`. The builder never mutates a receipt after signing.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from .citations import bind_citations
from .crypto import SigningKey
from .hashing import hash_content
from .merkle import MerkleTree
from .schema import (
    ModelInfo,
    Principal,
    Receipt,
    ReceiptPayload,
    Signature,
    Source,
)


class ReceiptBuilder:
    """Collects the facts of one RAG request and produces a signed receipt."""

    def __init__(self, signing_key: SigningKey, *, ngram: int = 3, threshold: float = 0.5):
        self._signing_key = signing_key
        self._ngram = ngram
        self._threshold = threshold
        self._query: str | None = None
        self._answer: str | None = None
        self._principal = Principal(id="anonymous")
        self._model = ModelInfo(name="unspecified")
        # ordered: (source, raw_content)
        self._sources: list[tuple[Source, str]] = []

    def set_query(self, query: str) -> ReceiptBuilder:
        self._query = query
        return self

    def set_answer(self, answer: str) -> ReceiptBuilder:
        self._answer = answer
        return self

    def set_principal(
        self, id: str, *, permissions: list[str] | None = None, tenant: str | None = None
    ) -> ReceiptBuilder:
        self._principal = Principal(id=id, permissions=permissions or [], tenant=tenant)
        return self

    def set_model(
        self, name: str, *, provider: str | None = None, params: dict | None = None
    ) -> ReceiptBuilder:
        self._model = ModelInfo(name=name, provider=provider, params=params or {})
        return self

    def add_source(
        self,
        id: str,
        *,
        content: str,
        score: float | None = None,
        metadata: dict | None = None,
    ) -> ReceiptBuilder:
        """Record a retrieved source. Content is hashed, never stored in the receipt."""
        source = Source(
            id=id,
            content_hash=hash_content(content),
            score=score,
            metadata=metadata or {},
        )
        self._sources.append((source, content))
        return self

    def _validate(self) -> None:
        if self._query is None:
            raise ValueError("query is required; call set_query()")
        if self._answer is None:
            raise ValueError("answer is required; call set_answer()")
        if not self._sources:
            raise ValueError("at least one source is required; call add_source()")
        ids = [s.id for s, _ in self._sources]
        if len(ids) != len(set(ids)):
            raise ValueError("source ids must be unique")

    def finalize(self, *, receipt_id: str | None = None) -> Receipt:
        """Build, sign and return the receipt."""
        self._validate()
        assert self._query is not None and self._answer is not None

        sources = [s for s, _ in self._sources]
        merkle_root = MerkleTree.from_hashes([s.content_hash for s in sources]).root

        citations, grounding = bind_citations(
            self._answer,
            [(s.id, content) for s, content in self._sources],
            n=self._ngram,
            threshold=self._threshold,
        )
        cited_ids = sorted({c.source_id for c in citations})

        payload = ReceiptPayload(
            receipt_id=receipt_id or str(uuid.uuid4()),
            created_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            query=self._query,
            answer=self._answer,
            principal=self._principal,
            model=self._model,
            sources=sources,
            cited_source_ids=cited_ids,
            merkle_root=merkle_root,
            citations=citations,
            grounding=grounding,
        )

        signature = Signature(
            public_key=self._signing_key.verify_key.to_base64(),
            signature=self._signing_key.sign(payload.canonical_bytes()),
        )
        return Receipt(payload=payload, signature=signature)
