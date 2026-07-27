"""Rule-based citation binding and grounding analysis.

This module answers two questions without calling any model:

1. *Which retrieved sources did the answer actually use?* We slide word
   n-grams over the answer and look for the same n-grams in each source. A
   source that shares enough distinctive n-grams with the answer is treated as
   cited.
2. *Is every claim in the answer grounded in some source?* We split the answer
   into sentence-level claims and flag any claim whose overlap with all sources
   falls below a threshold as a potential hallucination.

The method is deliberately transparent and deterministic: it is an evidence
signal a human or downstream policy can audit, not a black box. It will not
catch paraphrased-but-correct claims, and that limitation is documented in the
project's threat model.
"""

from __future__ import annotations

import re

from .schema import Citation, Claim, Grounding

_WORD_RE = re.compile(r"\w+", re.UNICODE)
_SENTENCE_RE = re.compile(r"(?<=[.!?])\s+")


def _tokens(text: str) -> list[str]:
    return [t.lower() for t in _WORD_RE.findall(text)]


def _ngrams(tokens: list[str], n: int) -> set[tuple[str, ...]]:
    if len(tokens) < n:
        return {tuple(tokens)} if tokens else set()
    return {tuple(tokens[i : i + n]) for i in range(len(tokens) - n + 1)}


def split_claims(answer: str) -> list[str]:
    """Split an answer into sentence-level claims."""
    parts = [s.strip() for s in _SENTENCE_RE.split(answer.strip())]
    return [p for p in parts if p]


def overlap_score(claim: str, source_content: str, n: int = 3) -> float:
    """Fraction of the claim's n-grams that also appear in the source.

    Falls back to a smaller n for short claims so single short sentences are
    still comparable.
    """
    claim_tokens = _tokens(claim)
    if not claim_tokens:
        return 0.0
    effective_n = min(n, len(claim_tokens))
    claim_grams = _ngrams(claim_tokens, effective_n)
    if not claim_grams:
        return 0.0
    source_grams = _ngrams(_tokens(source_content), effective_n)
    matches = len(claim_grams & source_grams)
    return matches / len(claim_grams)


def bind_citations(
    answer: str,
    sources: list[tuple[str, str]],
    *,
    n: int = 3,
    threshold: float = 0.5,
) -> tuple[list[Citation], Grounding]:
    """Compute citations and grounding for ``answer`` against ``sources``.

    ``sources`` is a list of ``(source_id, content)`` pairs. Returns the list
    of citations (one best-supporting source per grounded claim) and the
    aggregate grounding assessment.
    """
    claims_out: list[Claim] = []
    citations: list[Citation] = []
    unsupported: list[str] = []

    for claim_text in split_claims(answer):
        best_id: str | None = None
        best_score = 0.0
        for source_id, content in sources:
            s = overlap_score(claim_text, content, n=n)
            if s > best_score:
                best_score = s
                best_id = source_id

        supported = best_id is not None and best_score >= threshold
        source_ids = [best_id] if supported and best_id else []
        claims_out.append(
            Claim(
                text=claim_text,
                supported=supported,
                source_ids=source_ids,
                support_score=round(best_score, 4),
            )
        )
        if supported and best_id:
            citations.append(
                Citation(
                    source_id=best_id,
                    quote=claim_text,
                    method=f"{n}gram-overlap",
                    score=round(best_score, 4),
                )
            )
        else:
            unsupported.append(claim_text)

    grounding_score = (
        sum(1 for c in claims_out if c.supported) / len(claims_out) if claims_out else 0.0
    )
    grounding = Grounding(
        claims=claims_out,
        unsupported_claims=unsupported,
        grounding_score=round(grounding_score, 4),
    )
    return citations, grounding
