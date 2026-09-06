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


@pytest.mark.parametrize(
    "malformed_key",
    [
        "!!!not-base64!!!",
        "c2hvcnQ",
        "not-ascii-🔑",
    ],
)
def test_malformed_public_key_returns_failed_signature_check(receipt, malformed_key):
    signature = receipt.signature.model_copy(update={"public_key": malformed_key})
    corrupted = receipt.model_copy(update={"signature": signature})

    verdict = verify_receipt(corrupted)

    assert not verdict.valid
    assert len(verdict.failures()) == 1
    failure = verdict.failures()[0]
    assert failure.name == "signature"
    assert failure.detail == "invalid Ed25519 public key"


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
