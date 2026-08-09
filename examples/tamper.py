"""Walk each verification failure mode so newcomers can see what a bad receipt looks like.

Run with no external services:

    python examples/tamper.py

Pairs with ``tests/test_tamper.py``: same mutations, printed as a demo rather
than asserted. Output is also pasted into the README under "what failure looks
like".
"""

from __future__ import annotations

import json

from answerproof import ReceiptBuilder, SigningKey, verify_receipt
from answerproof.schema import Receipt, Signature

SOURCES = {
    "s1": "The Eiffel Tower is a wrought-iron lattice tower in Paris, France.",
    "s2": "It was completed in 1889 and stands 330 metres tall.",
    "s3": "The Louvre is the world's most-visited museum, also in Paris.",
}

ANSWER = (
    "The Eiffel Tower is a wrought-iron lattice tower in Paris, France. "
    "It was completed in 1889 and stands 330 metres tall."
)


def build_receipt(signing_key: SigningKey) -> Receipt:
    builder = ReceiptBuilder(signing_key)
    builder.set_query("Tell me about the Eiffel Tower.")
    builder.set_answer(ANSWER)
    builder.set_principal("user-42", permissions=["kb:paris"], tenant="acme")
    builder.set_model("demo-llm", provider="local", params={"temperature": 0.0})
    for sid, content in SOURCES.items():
        builder.add_source(sid, content=content, score=0.9)
    return builder.finalize()


def _reload(receipt: Receipt) -> dict:
    return json.loads(receipt.to_json())


def _from_dict(d: dict) -> Receipt:
    return Receipt.from_json(json.dumps(d))


def print_verdict(title: str, verdict) -> None:
    print(f"\n=== {title} ===")
    print(f"valid: {verdict.valid}")
    for check in verdict.checks:
        mark = "ok" if check.passed else "FAIL"
        detail = f" — {check.detail}" if check.detail else ""
        print(f"  [{mark}] {check.name}{detail}")
    if verdict.skipped:
        for s in verdict.skipped:
            print(f"  [skip] {s}")


def main() -> None:
    signing_key = SigningKey.generate()
    receipt = build_receipt(signing_key)
    original_pk = receipt.signature.public_key

    # Baseline: genuine receipt with original source contents.
    clean = verify_receipt(receipt, source_contents=SOURCES)
    print_verdict("Genuine receipt", clean)
    if not clean.valid:
        raise SystemExit("baseline receipt failed verification")

    # 1. Source document edited after the fact → fails `sources`.
    edited_sources = dict(SOURCES)
    edited_sources["s1"] = SOURCES["s1"] + " (quietly rewritten)"
    v_sources = verify_receipt(receipt, source_contents=edited_sources)
    print_verdict("1. Source document edited after signing", v_sources)

    # 2. Claim citation swapped to a different (unknown) source id → fails `grounding`.
    d = _reload(receipt)
    if d["payload"]["citations"]:
        d["payload"]["citations"][0]["source_id"] = "not-a-real-source"
    v_grounding = verify_receipt(_from_dict(d), source_contents=SOURCES)
    print_verdict("2. Citation swapped to a different source id", v_grounding)

    # 3. Merkle root edited by hand → fails `merkle` (and usually `signature`).
    d = _reload(receipt)
    d["payload"]["merkle_root"] = "ff" * 32
    v_merkle = verify_receipt(_from_dict(d), source_contents=SOURCES)
    print_verdict("3. Merkle root edited by hand", v_merkle)

    # 4. Payload edited and re-signed with a different key.
    #    Signature alone passes (attacker's key); pinning the real signer catches it.
    attacker = SigningKey.generate()
    d = _reload(receipt)
    d["payload"]["answer"] = "Tampered but re-signed."
    forged = Receipt.from_json(json.dumps(d))
    forged.signature = Signature(
        public_key=attacker.verify_key.to_base64(),
        signature=attacker.sign(forged.payload.canonical_bytes()),
    )
    v_resign = verify_receipt(forged, source_contents=SOURCES)
    print_verdict("4a. Re-signed with attacker's key (no pin)", v_resign)
    v_pinned = verify_receipt(
        forged, source_contents=SOURCES, expected_public_key=original_pk
    )
    print_verdict("4b. Same receipt, signer pinned to the original key", v_pinned)

    ok = (
        not v_sources.valid
        and any(c.name == "sources" and not c.passed for c in v_sources.checks)
        and not v_grounding.valid
        and any(c.name == "grounding" and not c.passed for c in v_grounding.checks)
        and not v_merkle.valid
        and any(c.name == "merkle" and not c.passed for c in v_merkle.checks)
        and v_resign.valid
        and not v_pinned.valid
        and any(c.name == "signer_pin" and not c.passed for c in v_pinned.checks)
    )
    if ok:
        print("\nDemo OK: each failure mode failed the expected check.")
    else:
        raise SystemExit("Demo failed: unexpected verification outcome.")


if __name__ == "__main__":
    main()
