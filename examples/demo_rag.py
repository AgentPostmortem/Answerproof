"""End-to-end demo: a mock RAG pipeline that produces and verifies a receipt.

Run it with no external services:

    python examples/demo_rag.py

It will:
  1. build a tiny in-memory knowledge base,
  2. "retrieve" sources for a query,
  3. "generate" an answer (canned, to keep the demo deterministic),
  4. record everything in a signed receipt,
  5. verify the receipt independently,
  6. tamper with the receipt and show verification fail.
"""

from __future__ import annotations

import json

from answerproof import ReceiptBuilder, SigningKey, verify_receipt

KNOWLEDGE_BASE = {
    "doc-eiffel": "The Eiffel Tower is a wrought-iron lattice tower on the Champ de Mars in Paris, France.",
    "doc-height": "The Eiffel Tower is 330 metres tall and was completed in 1889 for the World's Fair.",
    "doc-louvre": "The Louvre in Paris is the world's most-visited art museum.",
    "doc-weather": "Paris has a temperate oceanic climate with mild summers.",
}


def retrieve(query: str, k: int = 3) -> list[tuple[str, str, float]]:
    """A toy retriever: score by shared lowercase words, return top-k."""
    q_words = set(query.lower().split())
    scored = []
    for doc_id, content in KNOWLEDGE_BASE.items():
        overlap = len(q_words & set(content.lower().split()))
        scored.append((doc_id, content, float(overlap)))
    scored.sort(key=lambda x: x[2], reverse=True)
    return scored[:k]


def generate(_query: str) -> str:
    """A canned 'LLM' answer. The last sentence is deliberately unsupported."""
    return (
        "The Eiffel Tower is a wrought-iron lattice tower on the Champ de Mars in Paris, France. "
        "The Eiffel Tower is 330 metres tall and was completed in 1889 for the World's Fair. "
        "It is repainted gold every leap year."
    )


def main() -> None:
    signing_key = SigningKey.generate()
    query = "How tall is the Eiffel Tower in Paris?"

    retrieved = retrieve(query, k=3)
    answer = generate(query)

    builder = ReceiptBuilder(signing_key)
    builder.set_query(query)
    builder.set_answer(answer)
    builder.set_principal("analyst-7", permissions=["kb:paris"], tenant="demo")
    builder.set_model("mock-llm-1", provider="local", params={"temperature": 0.0})
    for doc_id, content, score in retrieved:
        builder.add_source(doc_id, content=content, score=score)

    receipt = builder.finalize()

    print("=== Receipt produced ===")
    print(f"receipt_id      : {receipt.payload.receipt_id}")
    print(f"merkle_root     : {receipt.payload.merkle_root}")
    print(f"cited sources   : {receipt.payload.cited_source_ids}")
    print(f"grounding score : {receipt.payload.grounding.grounding_score}")
    print("unsupported claims:")
    for claim in receipt.payload.grounding.unsupported_claims:
        print(f"  - {claim}")

    # Independent verification against the original source contents.
    source_contents = {doc_id: content for doc_id, content, _ in retrieved}
    verdict = verify_receipt(receipt, source_contents=source_contents)
    print("\n=== Independent verification ===")
    print(f"valid: {verdict.valid}")
    for check in verdict.checks:
        print(f"  [{'ok' if check.passed else 'FAIL'}] {check.name} {check.detail}")

    # Now tamper: change the answer and re-verify.
    tampered = json.loads(receipt.to_json())
    tampered["payload"]["answer"] = "The Eiffel Tower is located in Berlin, Germany."
    from answerproof.schema import Receipt

    tampered_receipt = Receipt.from_json(json.dumps(tampered))
    tampered_verdict = verify_receipt(tampered_receipt, source_contents=source_contents)
    print("\n=== After tampering with the answer ===")
    print(f"valid: {tampered_verdict.valid}")
    for check in tampered_verdict.failures():
        print(f"  [FAIL] {check.name} - {check.detail}")

    if verdict.valid and not tampered_verdict.valid:
        print("\nDemo OK: genuine receipt verified, tampered receipt rejected.")
    else:
        raise SystemExit("Demo failed: unexpected verification outcome.")


if __name__ == "__main__":
    main()
