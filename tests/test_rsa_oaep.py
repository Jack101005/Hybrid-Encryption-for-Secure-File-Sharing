"""Unit test cho RSA-OAEP key wrapping. Bỏ skip khi đã implement."""
import pytest

from hybridcrypto import aes_gcm, rsa_oaep


@pytest.mark.skip(reason="chưa implement")
def test_wrap_unwrap_roundtrip():
    priv, pub = rsa_oaep.generate_keypair(bits=2048)  # 2048 cho test chạy nhanh
    key = aes_gcm.generate_key()
    wrapped = rsa_oaep.wrap_key(pub, key)
    assert rsa_oaep.unwrap_key(priv, wrapped) == key


@pytest.mark.skip(reason="chưa implement")
def test_wrong_private_key_fails():
    _, pub = rsa_oaep.generate_keypair(bits=2048)
    other_priv, _ = rsa_oaep.generate_keypair(bits=2048)
    key = aes_gcm.generate_key()
    wrapped = rsa_oaep.wrap_key(pub, key)
    with pytest.raises(Exception):
        rsa_oaep.unwrap_key(other_priv, wrapped)
