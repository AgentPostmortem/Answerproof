"""A binary Merkle tree with inclusion proofs.

Given the ordered content hashes of the retrieved sources, we build a Merkle
tree and publish only its root in the signed receipt. Anyone can later prove
that a specific source was part of the retrieval set by presenting the leaf
plus a short proof path, without needing every other source.

Design choices that matter for security:

* **Domain separation.** Leaves are hashed with a ``0x00`` prefix and internal
  nodes with a ``0x01`` prefix. This prevents second-preimage attacks where an
  internal node is presented as if it were a leaf.
* **Odd nodes are promoted, not duplicated.** When a level has an odd number of
  nodes the last one is carried up unchanged. Duplicating the last node (the
  classic Bitcoin approach) enables well-known forgery tricks; promotion avoids
  them.
* **Deterministic.** Leaf order is preserved and fixed by the caller, so the
  root is stable and reproducible.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"


def _hash_leaf(data: bytes) -> bytes:
    return hashlib.sha256(_LEAF_PREFIX + data).digest()


def _hash_node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(_NODE_PREFIX + left + right).digest()


@dataclass(frozen=True)
class ProofStep:
    """One sibling on the path from a leaf to the root.

    ``position`` is where the sibling sits relative to the running hash:
    ``"left"`` means the sibling is concatenated before the running hash,
    ``"right"`` means after.
    """

    sibling: str  # hex digest
    position: str  # "left" | "right"

    def to_dict(self) -> dict[str, str]:
        return {"sibling": self.sibling, "position": self.position}

    @classmethod
    def from_dict(cls, d: dict[str, str]) -> ProofStep:
        return cls(sibling=d["sibling"], position=d["position"])


class MerkleTree:
    """Immutable Merkle tree built from a list of leaf byte strings."""

    def __init__(self, leaves: list[bytes]):
        if not leaves:
            raise ValueError("MerkleTree requires at least one leaf")
        self._leaf_count = len(leaves)
        # levels[0] is the leaf hashes, levels[-1] is [root].
        self._levels: list[list[bytes]] = [[_hash_leaf(leaf) for leaf in leaves]]
        while len(self._levels[-1]) > 1:
            self._levels.append(self._build_parent_level(self._levels[-1]))

    @staticmethod
    def _build_parent_level(level: list[bytes]) -> list[bytes]:
        parents: list[bytes] = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                parents.append(_hash_node(level[i], level[i + 1]))
            else:
                # Odd node promoted unchanged.
                parents.append(level[i])
        return parents

    @classmethod
    def from_hashes(cls, hex_hashes: list[str]) -> MerkleTree:
        """Build a tree from hex-encoded leaf digests (e.g. content hashes)."""
        return cls([bytes.fromhex(_strip_prefix(h)) for h in hex_hashes])

    @property
    def root(self) -> str:
        """Hex-encoded Merkle root."""
        return self._levels[-1][0].hex()

    @property
    def leaf_count(self) -> int:
        return self._leaf_count

    def proof(self, index: int) -> list[ProofStep]:
        """Return the inclusion proof for the leaf at ``index``."""
        if not 0 <= index < self._leaf_count:
            raise IndexError(f"leaf index {index} out of range")
        steps: list[ProofStep] = []
        idx = index
        for level in self._levels[:-1]:
            is_right = idx % 2 == 1
            sibling_idx = idx - 1 if is_right else idx + 1
            if sibling_idx < len(level):
                position = "left" if is_right else "right"
                steps.append(ProofStep(sibling=level[sibling_idx].hex(), position=position))
            # else: promoted node, no sibling at this level.
            idx //= 2
        return steps


def _strip_prefix(h: str) -> str:
    return h.split(":", 1)[1] if ":" in h else h


def leaf_hash_hex(content_hash: str) -> str:
    """Hex leaf digest for a (possibly prefixed) content hash."""
    return _hash_leaf(bytes.fromhex(_strip_prefix(content_hash))).hex()


def verify_proof(content_hash: str, proof: list[ProofStep], root: str) -> bool:
    """Verify that ``content_hash`` is included under ``root`` given ``proof``.

    This function is intentionally standalone: a verifier needs only the leaf,
    the proof path, and the root, never the rest of the tree.
    """
    try:
        running = bytes.fromhex(_strip_prefix(leaf_hash_hex(content_hash)))
    except ValueError:
        return False
    for step in proof:
        try:
            sibling = bytes.fromhex(step.sibling)
        except ValueError:
            return False
        if step.position == "left":
            running = _hash_node(sibling, running)
        elif step.position == "right":
            running = _hash_node(running, sibling)
        else:
            return False
    return running.hex() == root
