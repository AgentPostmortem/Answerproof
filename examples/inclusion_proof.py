"""Demo: prove a single source was in the retrieval set, without revealing the rest.

A data owner issues a receipt over several sources. Later, an auditor wants to
confirm that one specific document (``doc-height``) was part of that retrieval,
but the owner does not want to disclose the other documents. The Merkle root in
the signed receipt plus a short inclusion proof is enough.

    python examples/inclusion_proof.py
"""

from __future__ import annotations

from answerproof import ReceiptBuilder, SigningKey, hash_content
from answerproof.merkle import verify_proof
from answerproof.verifier import build_inclusion_proof

SOURCES = {
    "doc-eiffel": "The Eiffel Tower is in Paris, France.",
    "doc-height": "The Eiffel Tower is 330 metres tall.",
    "doc-secret": "Internal note: renovation budget is confidential.",
}


def main() -> None:
    sk = SigningKey.generate()
    builder = ReceiptBuilder(sk)
    builder.set_query("How tall is the Eiffel Tower?")
    builder.set_answer("The Eiffel Tower is 330 metres tall.")
    for sid, content in SOURCES.items():
        builder.add_source(sid, content=content)
    receipt = builder.finalize()

    # The owner publishes only: the signed merkle_root, the target's content
    # hash, and the proof path. Not the other sources.
    target_id = "doc-height"
    proof = build_inclusion_proof(receipt, target_id)
    target_hash = hash_content(SOURCES[target_id])
    root = receipt.payload.merkle_root

    print("Disclosed to auditor:")
    print(f"  merkle_root : {root}")
    print(f"  target hash : {target_hash}")
    print(f"  proof steps : {[s.to_dict() for s in proof]}")

    ok = verify_proof(target_hash, proof, root)
    print(f"\nAuditor verifies membership without seeing other sources: {ok}")
    if not ok:
        raise SystemExit("inclusion proof failed")
    print("Proof OK: doc-height was provably part of the retrieval set.")


if __name__ == "__main__":
    main()
