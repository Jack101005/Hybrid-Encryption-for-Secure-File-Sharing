"""Tests for digitalSignature.signature (RSA PSS with SHA256).

All files are written in pytest's tmp_path, never in the repo folder.
"""
import pytest

from digitalSignature import signature
from hybridcrypto import rsa_oaep


@pytest.fixture(scope="module")
def keys():
    alice_priv, alice_pub = rsa_oaep.generate_keypair(bits=2048)
    _, trudy_pub = rsa_oaep.generate_keypair(bits=2048)
    return alice_priv, alice_pub, trudy_pub


@pytest.fixture
def signed(tmp_path, keys):
    alice_priv, _, _ = keys
    doc = tmp_path / "doc.txt"
    doc.write_text("Test signature for a file!", encoding="utf-8")
    sig = tmp_path / "doc.txt.sig"
    signature.sign_file(alice_priv, str(doc), str(sig))
    return doc, sig


def test_valid_signature(signed, keys):
    doc, sig = signed
    assert signature.verify_file(keys[1], str(doc), str(sig)) is True


def test_tampered_file(signed, keys):
    doc, sig = signed
    doc.write_text("Tampered file!!!", encoding="utf-8")
    assert signature.verify_file(keys[1], str(doc), str(sig)) is False


def test_tampered_signature(signed, keys):
    doc, sig = signed
    data = bytearray(sig.read_bytes())
    data[10] ^= 0x01
    sig.write_bytes(data)
    assert signature.verify_file(keys[1], str(doc), str(sig)) is False


def test_wrong_signer(signed, keys):
    doc, sig = signed
    trudy_pub = keys[2]
    assert signature.verify_file(trudy_pub, str(doc), str(sig)) is False


def test_two_signatures_differ_but_both_valid(tmp_path, keys):
    alice_priv, alice_pub, _ = keys
    doc = tmp_path / "doc.txt"
    doc.write_text("same file, signed twice", encoding="utf-8")
    sig1, sig2 = tmp_path / "1.sig", tmp_path / "2.sig"
    signature.sign_file(alice_priv, str(doc), str(sig1))
    signature.sign_file(alice_priv, str(doc), str(sig2))
    # PSS uses a random salt, so the bytes are different every time
    assert sig1.read_bytes() != sig2.read_bytes()
    assert signature.verify_file(alice_pub, str(doc), str(sig1)) is True
    assert signature.verify_file(alice_pub, str(doc), str(sig2)) is True


def test_empty_file(tmp_path, keys):
    alice_priv, alice_pub, _ = keys
    doc = tmp_path / "empty.bin"
    doc.write_bytes(b"")
    sig = tmp_path / "empty.sig"
    signature.sign_file(alice_priv, str(doc), str(sig))
    assert signature.verify_file(alice_pub, str(doc), str(sig)) is True


def test_big_file_read_in_chunks(tmp_path, keys):
    alice_priv, alice_pub, _ = keys
    doc = tmp_path / "big.bin"
    doc.write_bytes(b"x" * (3 * 1024 * 1024 + 123))  # bigger than the 1 MB chunk
    sig = tmp_path / "big.sig"
    signature.sign_file(alice_priv, str(doc), str(sig))
    assert signature.verify_file(alice_pub, str(doc), str(sig)) is True
