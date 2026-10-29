"""Tests for hybridcrypto.keyInfo (public key fingerprint).

All files are written in pytest's tmp_path, never in the repo folder.
"""
import hashlib
import re

import pytest
from cryptography.hazmat.primitives import serialization

from hybridcrypto import rsa_oaep
from hybridcrypto.keyInfo import fingerprint, fingerprint_file, keyCompare


@pytest.fixture(scope="module")
def key_files(tmp_path_factory):
    folder = tmp_path_factory.mktemp("keys")
    _, bob_pub = rsa_oaep.generate_keypair(bits=2048)
    _, trudy_pub = rsa_oaep.generate_keypair(bits=2048)
    bob_path, trudy_path = folder / "bob.pem", folder / "trudy.pem"
    rsa_oaep.save_public_key(bob_pub, str(bob_path))
    rsa_oaep.save_public_key(trudy_pub, str(trudy_path))
    return bob_pub, str(bob_path), str(trudy_path)


def raw_hex(public_key):
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def test_key_compare(key_files):
    bob_pub, bob_path, _ = key_files
    assert keyCompare(bob_path, raw_hex(bob_pub)) is True
    assert keyCompare(bob_path, "wrongfingerprint") is False


def test_fingerprint_format(key_files):
    bob_pub, bob_path, _ = key_files
    fp = fingerprint(bob_pub)
    assert re.fullmatch(r"([0-9A-F]{4} ){15}[0-9A-F]{4}", fp)
    assert fp.replace(" ", "").lower() == raw_hex(bob_pub)
    assert fingerprint_file(bob_path) == fp


def test_compare_ignores_spaces_case_and_colons(key_files):
    bob_pub, bob_path, _ = key_files
    fp = fingerprint(bob_pub)
    assert keyCompare(bob_path, fp) is True
    assert keyCompare(bob_path, fp.lower()) is True
    assert keyCompare(bob_path, "  " + fp.replace(" ", "   ") + "\n") is True
    assert keyCompare(bob_path, fp.replace(" ", ":")) is True


def test_swapped_key_is_detected(key_files):
    bob_pub, _, trudy_path = key_files
    # Alice received Trudy's key but Bob read his own fingerprint on the phone
    assert keyCompare(trudy_path, fingerprint(bob_pub)) is False


def test_one_wrong_character_fails(key_files):
    bob_pub, bob_path, _ = key_files
    fp = fingerprint(bob_pub)
    wrong = ("1" if fp[0] != "1" else "2") + fp[1:]
    assert keyCompare(bob_path, wrong) is False
