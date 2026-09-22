"""Unit test cho định dạng file .hyb. Bỏ skip khi đã implement."""
import pytest

from hybridcrypto import container


@pytest.mark.skip(reason="chưa implement")
def test_pack_unpack_roundtrip():
    wrapped, nonce, ct = b"W" * 384, b"N" * 12, b"cipher+tag"
    blob = container.pack(wrapped, nonce, ct)
    c = container.unpack(blob)
    assert (c.wrapped_key, c.nonce, c.ciphertext) == (wrapped, nonce, ct)


@pytest.mark.skip(reason="chưa implement")
def test_bad_magic_raises():
    with pytest.raises(ValueError):
        container.unpack(b"XXXX" + b"\x00" * 20)
