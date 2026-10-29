"""Tests for the command line interface (hybridcrypto.cli).

Exit codes: 0 means success, 1 means an error or a failed check.
"""
import os
import subprocess
import sys
from pathlib import Path

import pytest

from hybridcrypto import cli

REPO_ROOT = Path(__file__).resolve().parent.parent


def run(*args):
    return cli.main([str(a) for a in args])


@pytest.fixture(scope="module")
def keys(tmp_path_factory):
    folder = tmp_path_factory.mktemp("keys")
    bob, alice = folder / "bob", folder / "alice"
    assert run("keygen", "--out", bob, "--bits", 2048) == 0
    assert run("keygen", "--out", alice, "--bits", 2048) == 0
    return bob, alice


def test_keygen_creates_both_files(keys):
    bob, _ = keys
    assert (bob / "public.pem").exists()
    assert (bob / "private.pem").exists()
    if os.name != "nt":
        assert (bob / "private.pem").stat().st_mode & 0o777 == 0o600


def test_keygen_refuses_to_overwrite(keys):
    bob, _ = keys
    before = (bob / "private.pem").read_bytes()
    assert run("keygen", "--out", bob, "--bits", 2048) == 1
    assert (bob / "private.pem").read_bytes() == before


def test_keygen_rejects_small_keys(tmp_path):
    assert run("keygen", "--out", tmp_path / "k", "--bits", 1024) == 1


def test_encrypt_decrypt_roundtrip(tmp_path, keys):
    bob, _ = keys
    src = tmp_path / "msg.txt"
    src.write_text("Chào Bob, mã két sắt là 2468", encoding="utf-8")
    assert run("encrypt", "--in", src, "--out", tmp_path / "msg.hyb", "--pubkey", bob / "public.pem") == 0
    assert run("decrypt", "--in", tmp_path / "msg.hyb", "--out", tmp_path / "out.txt", "--privkey", bob / "private.pem") == 0
    assert (tmp_path / "out.txt").read_bytes() == src.read_bytes()


def test_decrypt_with_wrong_key_fails(tmp_path, keys, capsys):
    bob, alice = keys
    src = tmp_path / "msg.txt"
    src.write_bytes(b"secret")
    run("encrypt", "--in", src, "--out", tmp_path / "msg.hyb", "--pubkey", bob / "public.pem")
    assert run("decrypt", "--in", tmp_path / "msg.hyb", "--out", tmp_path / "out.txt", "--privkey", alice / "private.pem") == 1
    assert "không mở được khoá AES" in capsys.readouterr().err
    assert not (tmp_path / "out.txt").exists()


def test_decrypt_tampered_file_fails(tmp_path, keys, capsys):
    bob, _ = keys
    src = tmp_path / "msg.txt"
    src.write_bytes(b"secret")
    run("encrypt", "--in", src, "--out", tmp_path / "msg.hyb", "--pubkey", bob / "public.pem")
    data = bytearray((tmp_path / "msg.hyb").read_bytes())
    data[-3] ^= 0x01
    (tmp_path / "msg.hyb").write_bytes(data)
    assert run("decrypt", "--in", tmp_path / "msg.hyb", "--out", tmp_path / "out.txt", "--privkey", bob / "private.pem") == 1
    assert "đã bị sửa" in capsys.readouterr().err
    assert not (tmp_path / "out.txt").exists()


def test_sign_and_verify(tmp_path, keys):
    _, alice = keys
    doc = tmp_path / "doc.hyb"
    doc.write_bytes(b"some encrypted bytes")
    assert run("sign", "--in", doc, "--privkey", alice / "private.pem") == 0
    assert (tmp_path / "doc.hyb.sig").exists()
    assert run("verify", "--in", doc, "--pubkey", alice / "public.pem") == 0


def test_verify_fails_after_tamper_or_wrong_signer(tmp_path, keys):
    bob, alice = keys
    doc = tmp_path / "doc.hyb"
    doc.write_bytes(b"some encrypted bytes")
    run("sign", "--in", doc, "--privkey", alice / "private.pem", "--out", tmp_path / "doc.sig")
    # signed by Alice, checked against Bob's key
    assert run("verify", "--in", doc, "--pubkey", bob / "public.pem", "--sig", tmp_path / "doc.sig") == 1
    # file changed after signing
    doc.write_bytes(b"some encrypted bytes!")
    assert run("verify", "--in", doc, "--pubkey", alice / "public.pem", "--sig", tmp_path / "doc.sig") == 1


def test_fingerprint_print_and_compare(keys, capsys):
    bob, alice = keys
    assert run("fingerprint", "--pubkey", bob / "public.pem") == 0
    fp = capsys.readouterr().out.strip()
    assert len(fp.replace(" ", "")) == 64
    assert run("fingerprint", "--pubkey", bob / "public.pem", "--expect", fp.lower()) == 0
    assert run("fingerprint", "--pubkey", alice / "public.pem", "--expect", fp) == 1


def test_missing_input_file(tmp_path, keys, capsys):
    bob, _ = keys
    assert run("encrypt", "--in", tmp_path / "nope.txt", "--out", tmp_path / "x.hyb", "--pubkey", bob / "public.pem") == 1
    assert "không tìm thấy file" in capsys.readouterr().err


def test_python_m_entry_point_works(keys):
    """Running 'python -m hybridcrypto.cli' must really call main()."""
    bob, _ = keys
    result = subprocess.run(
        [sys.executable, "-m", "hybridcrypto.cli", "fingerprint", "--pubkey", str(bob / "public.pem")],
        cwd=REPO_ROOT, capture_output=True, text=True,
    )
    assert result.returncode == 0
    assert len(result.stdout.strip().replace(" ", "")) == 64
