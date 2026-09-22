"""Unit test cho AES-256-GCM. Bỏ skip khi đã implement."""
import pytest

from hybridcrypto import aes_gcm


@pytest.mark.skip(reason="chưa implement")
def test_encrypt_decrypt_roundtrip():
    key = aes_gcm.generate_key()
    nonce, ct = aes_gcm.encrypt(key, b"hello world")
    assert aes_gcm.decrypt(key, nonce, ct) == b"hello world"


@pytest.mark.skip(reason="chưa implement")
def test_wrong_key_fails():
    key = aes_gcm.generate_key()
    nonce, ct = aes_gcm.encrypt(key, b"secret")
    with pytest.raises(Exception):
        aes_gcm.decrypt(aes_gcm.generate_key(), nonce, ct)


@pytest.mark.skip(reason="chưa implement")
def test_tampered_ciphertext_fails():
    key = aes_gcm.generate_key()
    nonce, ct = aes_gcm.encrypt(key, b"secret")
    tampered = bytes([ct[0] ^ 0x01]) + ct[1:]
    with pytest.raises(Exception):
        aes_gcm.decrypt(key, nonce, tampered)
