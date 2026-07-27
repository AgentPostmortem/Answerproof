import pytest

from answerproof.hashing import hash_content
from answerproof.merkle import MerkleTree, ProofStep, verify_proof


def _hashes(n: int) -> list[str]:
    return [hash_content(f"source-{i}") for i in range(n)]


@pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 8, 9, 16, 17, 33])
def test_every_leaf_has_a_valid_proof(n):
    hashes = _hashes(n)
    tree = MerkleTree.from_hashes(hashes)
    for i, h in enumerate(hashes):
        proof = tree.proof(i)
        assert verify_proof(h, proof, tree.root)


def test_single_leaf_root_is_leaf_hash():
    hashes = _hashes(1)
    tree = MerkleTree.from_hashes(hashes)
    assert tree.leaf_count == 1
    assert verify_proof(hashes[0], tree.proof(0), tree.root)


def test_root_is_deterministic():
    hashes = _hashes(7)
    assert MerkleTree.from_hashes(hashes).root == MerkleTree.from_hashes(hashes).root


def test_order_changes_root():
    hashes = _hashes(4)
    a = MerkleTree.from_hashes(hashes).root
    b = MerkleTree.from_hashes(list(reversed(hashes))).root
    assert a != b


def test_wrong_leaf_fails_verification():
    hashes = _hashes(5)
    tree = MerkleTree.from_hashes(hashes)
    proof = tree.proof(2)
    other = hash_content("not-in-tree")
    assert not verify_proof(other, proof, tree.root)


def test_tampered_proof_step_fails():
    hashes = _hashes(6)
    tree = MerkleTree.from_hashes(hashes)
    proof = tree.proof(1)
    assert proof, "expected a non-trivial proof"
    forged = list(proof)
    forged[0] = ProofStep(sibling="00" * 32, position=forged[0].position)
    assert not verify_proof(hashes[1], forged, tree.root)


def test_flipped_position_fails():
    hashes = _hashes(4)
    tree = MerkleTree.from_hashes(hashes)
    proof = tree.proof(0)
    flipped = [
        ProofStep(sibling=s.sibling, position="left" if s.position == "right" else "right")
        for s in proof
    ]
    assert not verify_proof(hashes[0], flipped, tree.root)


def test_wrong_root_fails():
    hashes = _hashes(8)
    tree = MerkleTree.from_hashes(hashes)
    assert not verify_proof(hashes[3], tree.proof(3), "ff" * 32)


def test_proof_step_roundtrip():
    step = ProofStep(sibling="ab" * 32, position="left")
    assert ProofStep.from_dict(step.to_dict()) == step


def test_empty_tree_rejected():
    with pytest.raises(ValueError):
        MerkleTree([])


def test_index_out_of_range():
    tree = MerkleTree.from_hashes(_hashes(3))
    with pytest.raises(IndexError):
        tree.proof(3)
