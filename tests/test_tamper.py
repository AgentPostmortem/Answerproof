"""Tamper-detection tests: any mutation of a signed receipt must be caught."""

import json

from answerproof.schema import Receipt
from answerproof.verifier import verify_receipt


def _reload(receipt) -> dict:
    return json.loads(receipt.to_json())


def _from_dict(d: dict) -> Receipt:
    return Receipt.from_json(json.dumps(d))


def test_tampering_answer_breaks_signature(receipt, sources):
    d = _reload(receipt)
    d["payload"]["answer"] = "The Eiffel Tower is in Berlin."
    verdict = verify_receipt(_from_dict(d), source_contents=sources)
    assert not verdict.valid
    assert any(c.name == "signature" and not c.passed for c in verdict.checks)


def test_tampering_query_breaks_signature(receipt):
    d = _reload(receipt)
    d["payload"]["query"] = "different question"
    assert not verify_receipt(_from_dict(d)).valid


def test_tampering_principal_breaks_signature(receipt):
    d = _reload(receipt)
    d["payload"]["principal"]["permissions"] = ["kb:everything"]
    assert not verify_receipt(_from_dict(d)).valid


def test_swapping_source_hash_breaks_merkle_and_signature(receipt):
    d = _reload(receipt)
    d["payload"]["sources"][0]["content_hash"] = "sha256:" + "00" * 32
    verdict = verify_receipt(_from_dict(d))
    assert not verdict.valid
    failed = {c.name for c in verdict.failures()}
    assert "merkle" in failed or "signature" in failed


def test_forging_merkle_root_breaks_signature(receipt):
    d = _reload(receipt)
    d["payload"]["merkle_root"] = "ff" * 32
    verdict = verify_receipt(_from_dict(d))
    assert not verdict.valid
    failed = {c.name for c in verdict.failures()}
    assert "merkle" in failed and "signature" in failed


def test_tampering_grounding_score_is_detected(receipt):
    d = _reload(receipt)
    d["payload"]["grounding"]["grounding_score"] = 1.0
    d["payload"]["grounding"]["claims"] = [
        {"text": "x", "supported": False, "source_ids": [], "support_score": 0.0}
    ]
    verdict = verify_receipt(_from_dict(d))
    assert not verdict.valid


def test_replacing_signature_fails(receipt):
    d = _reload(receipt)
    d["signature"]["signature"] = d["signature"]["signature"][:-4] + "AAAA"
    assert not verify_receipt(_from_dict(d)).valid


def test_attacker_resigns_with_own_key_is_caught_by_pinning(receipt, sources):
    from answerproof.crypto import SigningKey
    from answerproof.schema import Signature

    original_pk = receipt.signature.public_key
    attacker = SigningKey.generate()
    d = _reload(receipt)
    d["payload"]["answer"] = "Tampered but re-signed."
    forged = Receipt.from_json(json.dumps(d))
    forged.signature = Signature(
        public_key=attacker.verify_key.to_base64(),
        signature=attacker.sign(forged.payload.canonical_bytes()),
    )
    # Signature alone verifies (attacker's key), but pinning to the real signer fails.
    assert verify_receipt(forged).valid
    assert not verify_receipt(forged, expected_public_key=original_pk).valid
