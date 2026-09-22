"""End-to-end: encrypt file -> decrypt file. Bỏ skip khi đã implement.

[Mảng: Demo + Test]
"""
import pytest

from hybridcrypto import crypto, rsa_oaep


@pytest.mark.skip(reason="chưa implement")
def test_encrypt_then_decrypt(tmp_path):
    # chuẩn bị khoá
    priv, pub = rsa_oaep.generate_keypair(bits=2048)
    priv_path = tmp_path / "private.pem"
    pub_path = tmp_path / "public.pem"
    rsa_oaep.save_private_key(priv, str(priv_path))
    rsa_oaep.save_public_key(pub, str(pub_path))

    # file gốc
    src = tmp_path / "msg.txt"
    src.write_bytes(b"Tai lieu mat 123")
    enc = tmp_path / "msg.hyb"
    dec = tmp_path / "msg.out.txt"

    crypto.encrypt_file(str(src), str(enc), str(pub_path))
    crypto.decrypt_file(str(enc), str(dec), str(priv_path))

    assert dec.read_bytes() == src.read_bytes()


@pytest.mark.skip(reason="chưa implement")
def test_tampered_file_fails(tmp_path):
    priv, pub = rsa_oaep.generate_keypair(bits=2048)
    priv_path = tmp_path / "private.pem"
    pub_path = tmp_path / "public.pem"
    rsa_oaep.save_private_key(priv, str(priv_path))
    rsa_oaep.save_public_key(pub, str(pub_path))

    src = tmp_path / "msg.txt"
    src.write_bytes(b"Tai lieu mat 123")
    enc = tmp_path / "msg.hyb"
    crypto.encrypt_file(str(src), str(enc), str(pub_path))

    # sửa 1 byte gần cuối (vùng ciphertext/tag) -> giải mã phải fail
    blob = bytearray(enc.read_bytes())
    blob[-1] ^= 0x01
    enc.write_bytes(blob)

    with pytest.raises(Exception):
        crypto.decrypt_file(str(enc), str(tmp_path / "out.txt"), str(priv_path))
