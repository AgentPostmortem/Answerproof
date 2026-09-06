"""Independent verification of a receipt.

Verification is split into independent checks so a caller can see exactly what
holds and what does not:

* **signature** - the detached Ed25519 signature is valid over the canonical
  payload bytes for the embedded public key.
* **merkle** - the Merkle root recomputed from the receipt's source hashes
  matches the signed ``merkle_root``, and (optionally) inclusion proofs verify.
* **sources** - when the original source contents are supplied, each one hashes
  to the ``content_hash`` recorded in the receipt.
* **grounding** - the recorded citations and grounding are internally
  consistent (cited ids exist; grounding score matches the claims).

A receipt is ``valid`` only if every performed check passes. Checks that could
not run (e.g. source contents not supplied) are reported as ``skipped`` and do
not, by themselves, make a receipt invalid.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .crypto import VerifyKey
from .hashing import verify_content
from .merkle import MerkleTree, ProofStep, verify_proof
from .schema import Receipt


@dataclass
class CheckResult:
    name: str
    passed: bool
    detail: str = ""

    def to_dict(self) -> dict:
        return {"name": self.name, "passed": self.passed, "detail": self.detail}


@dataclass
class Verdict:
    """Structured result of verifying a receipt."""

    valid: bool
    checks: list[CheckResult] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "valid": self.valid,
            "checks": [c.to_dict() for c in self.checks],
            "skipped": list(self.skipped),
        }

    def failures(self) -> list[CheckResult]:
        return [c for c in self.checks if not c.passed]


def verify_signature(receipt: Receipt) -> CheckResult:
    try:
        vk = VerifyKey.from_base64(receipt.signature.public_key)
    except ValueError:
        return CheckResult("signature", False, "invalid Ed25519 public key")
    ok = vk.verify(receipt.payload.canonical_bytes(), receipt.signature.signature)
    return CheckResult("signature", ok, "" if ok else "Ed25519 signature does not match payload")


def verify_merkle(receipt: Receipt) -> CheckResult:
    hashes = [s.content_hash for s in receipt.payload.sources]
    if not hashes:
        return CheckResult("merkle", False, "no sources to build a Merkle root")
    recomputed = MerkleTree.from_hashes(hashes).root
    ok = recomputed == receipt.payload.merkle_root
    detail = "" if ok else "recomputed Merkle root does not match signed root"
    return CheckResult("merkle", ok, detail)


def verify_sources(receipt: Receipt, contents: dict[str, str]) -> CheckResult:
    """Check that supplied source contents match their recorded hashes."""
    by_id = {s.id: s for s in receipt.payload.sources}
    mismatched: list[str] = []
    checked = 0
    for sid, content in contents.items():
        source = by_id.get(sid)
        if source is None:
            mismatched.append(f"{sid} (unknown source)")
            continue
        checked += 1
        if not verify_content(content, source.content_hash):
            mismatched.append(sid)
    if mismatched:
        return CheckResult("sources", False, "content hash mismatch: " + ", ".join(mismatched))
    return CheckResult("sources", True, f"{checked} source content(s) matched")


def verify_grounding(receipt: Receipt) -> CheckResult:
    payload = receipt.payload
    source_ids = {s.id for s in payload.sources}
    problems: list[str] = []

    for c in payload.citations:
        if c.source_id not in source_ids:
            problems.append(f"citation references unknown source {c.source_id}")
    for cited in payload.cited_source_ids:
        if cited not in source_ids:
            problems.append(f"cited_source_ids references unknown source {cited}")

    claims = payload.grounding.claims
    if claims:
        supported = sum(1 for c in claims if c.supported)
        expected = round(supported / len(claims), 4)
        if abs(expected - payload.grounding.grounding_score) > 1e-6:
            problems.append(
                f"grounding_score {payload.grounding.grounding_score} != recomputed {expected}"
            )

    if problems:
        return CheckResult("grounding", False, "; ".join(problems))
    return CheckResult("grounding", True, "citations and grounding are self-consistent")


def build_inclusion_proof(receipt: Receipt, source_id: str) -> list[ProofStep]:
    """Produce the Merkle inclusion proof for ``source_id`` in ``receipt``.

    The proof can be handed to a third party (together with the source's content
    hash and the receipt's signed ``merkle_root``) to prove membership without
    disclosing the other sources.
    """
    ids = [s.id for s in receipt.payload.sources]
    if source_id not in ids:
        raise KeyError(f"unknown source {source_id}")
    tree = MerkleTree.from_hashes([s.content_hash for s in receipt.payload.sources])
    return tree.proof(ids.index(source_id))


def verify_inclusion(receipt: Receipt, source_id: str, proof: list[ProofStep]) -> CheckResult:
    by_id = {s.id: s for s in receipt.payload.sources}
    source = by_id.get(source_id)
    if source is None:
        return CheckResult("inclusion", False, f"unknown source {source_id}")
    ok = verify_proof(source.content_hash, proof, receipt.payload.merkle_root)
    detail = "" if ok else f"inclusion proof for {source_id} failed"
    return CheckResult("inclusion", ok, detail)


def verify_receipt(
    receipt: Receipt,
    *,
    source_contents: dict[str, str] | None = None,
    expected_public_key: str | None = None,
) -> Verdict:
    """Run all applicable checks and return a :class:`Verdict`.

    ``source_contents`` maps source id -> original content; when supplied the
    hashes are verified. ``expected_public_key`` pins the signer: if given and
    it does not match the receipt's key, verification fails.
    """
    checks: list[CheckResult] = []
    skipped: list[str] = []

    if expected_public_key is not None:
        pinned = receipt.signature.public_key == expected_public_key
        checks.append(
            CheckResult(
                "signer_pin",
                pinned,
                "" if pinned else "receipt public key does not match expected signer",
            )
        )

    checks.append(verify_signature(receipt))
    checks.append(verify_merkle(receipt))
    checks.append(verify_grounding(receipt))

    if source_contents:
        checks.append(verify_sources(receipt, source_contents))
    else:
        skipped.append("sources (no source contents supplied)")

    valid = all(c.passed for c in checks)
    return Verdict(valid=valid, checks=checks, skipped=skipped)
