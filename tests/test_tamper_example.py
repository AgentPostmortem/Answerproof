"""The documented tamper walkthrough stays runnable and deterministic."""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_tamper_example_prints_each_verification_boundary():
    completed = subprocess.run(
        [sys.executable, "examples/tamper.py"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stderr == ""
    assert (
        completed.stdout
        == """=== Genuine receipt ===
valid: True

=== Source document edited after signing ===
valid: False
  [FAIL] sources - content hash mismatch: doc-eiffel

=== Citation changed to an unknown source ===
valid: False
  [FAIL] signature - Ed25519 signature does not match payload
  [FAIL] grounding - citation references unknown source doc-unknown

=== Merkle root edited by hand ===
valid: False
  [FAIL] signature - Ed25519 signature does not match payload
  [FAIL] merkle - recomputed Merkle root does not match signed root

=== Payload edited and re-signed with another key (unpinned) ===
valid: True
  [PASS] signature

=== Same re-signed receipt with the original signer pinned ===
valid: False
  [FAIL] signer_pin - receipt public key does not match expected signer
  [PASS] signature
"""
    )

    readme = (ROOT / "README.md").read_text()
    section = readme.split("### What failure looks like", 1)[1]
    documented = section.split("```text\n", 1)[1].split("\n```", 1)[0] + "\n"
    assert documented == completed.stdout
