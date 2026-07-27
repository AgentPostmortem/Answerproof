import pytest

from answerproof.builder import ReceiptBuilder
from answerproof.crypto import SigningKey
from answerproof.merkle import MerkleTree
from answerproof.verifier import verify_receipt


@pytest.fixture
def sk():
    return SigningKey.generate()


def _base(builder):
    return (
        builder.set_query("q")
        .set_answer("The cat sat on the mat.")
        .add_source("s1", content="The cat sat on the mat.", score=0.5)
    )


def test_requires_query(sk):
    b = ReceiptBuilder(sk).set_answer("a").add_source("s1", content="c")
    with pytest.raises(ValueError, match="query"):
        b.finalize()


def test_requires_answer(sk):
    b = ReceiptBuilder(sk).set_query("q").add_source("s1", content="c")
    with pytest.raises(ValueError, match="answer"):
        b.finalize()


def test_requires_at_least_one_source(sk):
    b = ReceiptBuilder(sk).set_query("q").set_answer("a")
    with pytest.raises(ValueError, match="source"):
        b.finalize()


def test_rejects_duplicate_source_ids(sk):
    b = ReceiptBuilder(sk).set_query("q").set_answer("a")
    b.add_source("dup", content="one").add_source("dup", content="two")
    with pytest.raises(ValueError, match="unique"):
        b.finalize()


def test_fluent_interface_returns_builder(sk):
    b = ReceiptBuilder(sk)
    assert b.set_query("q") is b
    assert b.set_answer("a") is b
    assert b.add_source("s", content="c") is b


def test_finalize_produces_valid_receipt(sk):
    receipt = _base(ReceiptBuilder(sk)).finalize()
    assert verify_receipt(receipt).valid


def test_explicit_receipt_id_is_used(sk):
    receipt = _base(ReceiptBuilder(sk)).finalize(receipt_id="fixed-id")
    assert receipt.payload.receipt_id == "fixed-id"


def test_content_not_stored_only_hash(sk):
    secret = "TOP SECRET CONTENT"
    receipt = (
        ReceiptBuilder(sk)
        .set_query("q")
        .set_answer("a")
        .add_source("s1", content=secret)
        .finalize()
    )
    assert secret not in receipt.to_json()
    assert receipt.payload.sources[0].content_hash.startswith("sha256:")


def test_merkle_root_matches_sources(sk):
    receipt = (
        ReceiptBuilder(sk)
        .set_query("q")
        .set_answer("a")
        .add_source("s1", content="one")
        .add_source("s2", content="two")
        .finalize()
    )
    expected = MerkleTree.from_hashes([s.content_hash for s in receipt.payload.sources]).root
    assert receipt.payload.merkle_root == expected


def test_source_order_is_preserved(sk):
    b = ReceiptBuilder(sk).set_query("q").set_answer("a")
    for i in range(5):
        b.add_source(f"s{i}", content=f"content {i}")
    receipt = b.finalize()
    assert [s.id for s in receipt.payload.sources] == [f"s{i}" for i in range(5)]
