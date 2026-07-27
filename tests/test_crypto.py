from answerproof.crypto import SigningKey, VerifyKey, generate_keypair


def test_sign_and_verify_roundtrip():
    sk, vk = generate_keypair()
    msg = b"hello answerproof"
    sig = sk.sign(msg)
    assert vk.verify(msg, sig)


def test_verify_rejects_tampered_message():
    sk, vk = generate_keypair()
    sig = sk.sign(b"original")
    assert not vk.verify(b"tampered", sig)


def test_verify_rejects_wrong_key():
    sk, _ = generate_keypair()
    _, other_vk = generate_keypair()
    sig = sk.sign(b"data")
    assert not other_vk.verify(b"data", sig)


def test_signing_key_base64_roundtrip():
    sk = SigningKey.generate()
    restored = SigningKey.from_base64(sk.to_base64())
    msg = b"stable"
    assert restored.verify_key.to_base64() == sk.verify_key.to_base64()
    assert sk.verify_key.verify(msg, restored.sign(msg))


def test_verify_key_base64_roundtrip():
    _, vk = generate_keypair()
    restored = VerifyKey.from_base64(vk.to_base64())
    assert restored.to_base64() == vk.to_base64()


def test_signature_is_deterministic():
    sk = SigningKey.generate()
    # Ed25519 is deterministic: same key + message => same signature.
    assert sk.sign(b"abc") == sk.sign(b"abc")


def test_verify_rejects_garbage_signature():
    _, vk = generate_keypair()
    assert not vk.verify(b"data", "!!!not-base64!!!")
