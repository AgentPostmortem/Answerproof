from answerproof.hashing import hash_content, is_hash, verify_content


def test_hash_is_prefixed_and_64_hex():
    h = hash_content("hello")
    assert h.startswith("sha256:")
    assert is_hash(h)


def test_str_and_bytes_agree():
    assert hash_content("héllo") == hash_content("héllo".encode())


def test_different_content_different_hash():
    assert hash_content("a") != hash_content("b")


def test_verify_content_true_and_false():
    h = hash_content("payload")
    assert verify_content("payload", h)
    assert not verify_content("payload!", h)


def test_is_hash_rejects_junk():
    assert not is_hash("sha256:xyz")
    assert not is_hash("nope")
    assert not is_hash("md5:" + "0" * 32)


def test_hash_is_stable():
    assert hash_content("stable input") == hash_content("stable input")
