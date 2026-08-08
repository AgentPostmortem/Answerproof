import pytest

from answerproof.merkle import MerkleTree
from answerproof.verifier import build_inclusion_proof, verify_inclusion, verify_receipt


def test_valid_receipt_passes_all_checks(receipt, sources):
    verdict = verify_receipt(receipt, source_contents=sources)
    assert verdict.valid
    names = {c.name for c in verdict.checks}
    assert {"signature", "merkle", "grounding", "sources"} <= names
    assert verdict.failures() == []


def test_verify_without_sources_skips_source_check(receipt):
    verdict = verify_receipt(receipt)
    assert verdict.valid
    assert any("sources" in s for s in verdict.skipped)


def test_signer_pinning_success(receipt, sources):
    pk = receipt.signature.public_key
    verdict = verify_receipt(receipt, source_contents=sources, expected_public_key=pk)
    assert verdict.valid


def test_signer_pinning_failure(receipt, sources):
    verdict = verify_receipt(
        receipt, source_contents=sources, expected_public_key="not-the-real-key"
    )
    assert not verdict.valid
    assert any(c.name == "signer_pin" and not c.passed for c in verdict.checks)


def test_wrong_source_content_fails(receipt):
    bad = {"s1": "This is not the original content."}
    verdict = verify_receipt(receipt, source_contents=bad)
    assert not verdict.valid
    assert any(c.name == "sources" and not c.passed for c in verdict.checks)


def test_inclusion_proof_roundtrip(receipt):
    hashes = [s.content_hash for s in receipt.payload.sources]
    tree = MerkleTree.from_hashes(hashes)
    proof = tree.proof(1)
    result = verify_inclusion(receipt, receipt.payload.sources[1].id, proof)
    assert result.passed


def test_build_inclusion_proof_verifies(receipt):
    for source in receipt.payload.sources:
        proof = build_inclusion_proof(receipt, source.id)
        assert verify_inclusion(receipt, source.id, proof).passed


def test_build_inclusion_proof_unknown_source(receipt):
    with pytest.raises(KeyError):
        build_inclusion_proof(receipt, "nope")


def test_inclusion_proof_unknown_source(receipt):
    result = verify_inclusion(receipt, "does-not-exist", [])
    assert not result.passed


def test_serialized_receipt_roundtrips_and_verifies(receipt, sources):
    from answerproof.schema import Receipt

    restored = Receipt.from_json(receipt.to_json())
    assert verify_receipt(restored, source_contents=sources).valid


def test_unpinned_verify_skips_signer_pin(receipt, sources):
    verdict = verify_receipt(receipt, source_contents=sources)
    assert verdict.valid
    assert any(s.startswith("signer_pin") for s in verdict.skipped)
    assert all(c.name != "signer_pin" for c in verdict.checks)


def test_pinned_verify_does_not_skip_signer_pin(receipt, sources):
    pk = receipt.signature.public_key
    verdict = verify_receipt(receipt, source_contents=sources, expected_public_key=pk)
    assert verdict.valid
    assert not any("signer_pin" in s for s in verdict.skipped)
    assert any(c.name == "signer_pin" and c.passed for c in verdict.checks)


def test_attacker_resign_is_not_presented_as_clean_pass(receipt):
    """Tamper the payload, re-sign with a fresh key; unpinned verify must not
    look like a fully proven receipt (signer_pin skipped)."""
    import json

    from answerproof.crypto import SigningKey
    from answerproof.schema import Receipt, Signature

    attacker = SigningKey.generate()
    d = json.loads(receipt.to_json())
    d["payload"]["answer"] = "Attacker-controlled answer."
    forged = Receipt.from_json(json.dumps(d))
    forged.signature = Signature(
        public_key=attacker.verify_key.to_base64(),
        signature=attacker.sign(forged.payload.canonical_bytes()),
    )
    verdict = verify_receipt(forged)
    # Structural checks pass against the attacker's key...
    assert verdict.valid
    # ...but the verdict records that provenance was not established.
    assert any("signer_pin" in s for s in verdict.skipped)
    as_dict = verdict.to_dict()
    assert as_dict["valid"] is True
    assert any("signer_pin" in s for s in as_dict["skipped"])
