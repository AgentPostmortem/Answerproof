"""Show how each independent receipt check reports tampering.

Run with no external services:

    python examples/tamper.py
"""

from __future__ import annotations

from answerproof import ReceiptBuilder, SigningKey, verify_receipt
from answerproof.schema import Receipt, Signature
from answerproof.verifier import Verdict

SOURCES = {
    "doc-eiffel": "The Eiffel Tower is in Paris, France.",
    "doc-height": "The Eiffel Tower is 330 metres tall.",
}


def clone(receipt: Receipt) -> Receipt:
    """Round-trip through the public JSON format before hostile edits."""
    return Receipt.from_json(receipt.to_json())


def format_verdict(title: str, verdict: Verdict, *, show_passes: tuple[str, ...] = ()) -> str:
    lines = [f"=== {title} ===", f"valid: {verdict.valid}"]
    for check in verdict.failures():
        lines.append(f"  [FAIL] {check.name} - {check.detail}")
    by_name = {check.name: check for check in verdict.checks}
    for name in show_passes:
        check = by_name[name]
        if not check.passed:
            raise RuntimeError(f"expected {name} to pass")
        lines.append(f"  [PASS] {name}")
    return "\n".join(lines)


def build_receipt(signing_key: SigningKey) -> Receipt:
    builder = ReceiptBuilder(signing_key)
    builder.set_query("Where is the Eiffel Tower, and how tall is it?")
    builder.set_answer("The Eiffel Tower is in Paris, France. The Eiffel Tower is 330 metres tall.")
    builder.set_principal("auditor-7", permissions=["kb:paris"], tenant="demo")
    builder.set_model("demo-model", provider="local", params={"temperature": 0.0})
    for source_id, content in SOURCES.items():
        builder.add_source(source_id, content=content)
    return builder.finalize(receipt_id="tamper-demo")


def main() -> None:
    original_key = SigningKey.generate()
    receipt = build_receipt(original_key)
    sections = [
        format_verdict(
            "Genuine receipt",
            verify_receipt(receipt, source_contents=SOURCES),
        )
    ]

    edited_sources = dict(SOURCES)
    edited_sources["doc-eiffel"] = "The Eiffel Tower is in Berlin, Germany."
    sections.append(
        format_verdict(
            "Source document edited after signing",
            verify_receipt(receipt, source_contents=edited_sources),
        )
    )

    citation_tamper = clone(receipt)
    citation_tamper.payload.citations[0].source_id = "doc-unknown"
    sections.append(
        format_verdict(
            "Citation changed to an unknown source",
            verify_receipt(citation_tamper, source_contents=SOURCES),
        )
    )

    merkle_tamper = clone(receipt)
    merkle_tamper.payload.merkle_root = "00" * 32
    sections.append(
        format_verdict(
            "Merkle root edited by hand",
            verify_receipt(merkle_tamper, source_contents=SOURCES),
        )
    )

    attacker_key = SigningKey.generate()
    resigned = clone(receipt)
    resigned.payload.query = "A substituted query"
    resigned.signature = Signature(
        public_key=attacker_key.verify_key.to_base64(),
        signature=attacker_key.sign(resigned.payload.canonical_bytes()),
    )
    sections.append(
        format_verdict(
            "Payload edited and re-signed with another key (unpinned)",
            verify_receipt(resigned, source_contents=SOURCES),
            show_passes=("signature",),
        )
    )
    sections.append(
        format_verdict(
            "Same re-signed receipt with the original signer pinned",
            verify_receipt(
                resigned,
                source_contents=SOURCES,
                expected_public_key=original_key.verify_key.to_base64(),
            ),
            show_passes=("signature",),
        )
    )

    print("\n\n".join(sections))


if __name__ == "__main__":
    main()
