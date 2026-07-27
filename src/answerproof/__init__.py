"""answerproof: verifiable receipts for RAG and agent answers."""

from .builder import ReceiptBuilder
from .crypto import SigningKey, VerifyKey, generate_keypair
from .hashing import hash_content
from .merkle import MerkleTree, ProofStep, verify_proof
from .schema import Receipt, ReceiptPayload, Signature
from .verifier import Verdict, verify_receipt

__version__ = "0.1.0"

__all__ = [
    "ReceiptBuilder",
    "SigningKey",
    "VerifyKey",
    "generate_keypair",
    "hash_content",
    "MerkleTree",
    "ProofStep",
    "verify_proof",
    "Receipt",
    "ReceiptPayload",
    "Signature",
    "Verdict",
    "verify_receipt",
    "__version__",
]
