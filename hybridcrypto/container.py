"""``.hyb`` container file format — pack/unpack.

[Array: Key wrapping]

FINALIZE THE FORMAT EARLY so the team can code in parallel without conflicts. Proposed layout
(big-endian, ``struct``):

    MAGIC            4 bytes  = "HYBR"
    VERSION          1 byte   = 1
    wrapped_key_len  2 bytes  (big-endian)
    wrapped_key      N bytes  (RSA-OAEP result)
    nonce            12 bytes (AES-GCM nonce)
    ciphertext       remainder (includes 16-byte tag at the end))

If you change the format, remember to increment the VERSION.
"""
from __future__ import annotations
from dataclasses import dataclass
import struct

MAGIC = b"HYBR"
VERSION = 1
HEADER_FMT = ">4sBH"                     # magic, version, wrapped_key_len
HEADER_LEN = struct.calcsize(HEADER_FMT)  # 7 bytes
NONCE_LEN = 12
TAG_LEN = 16

@dataclass
class Container:
    wrapped_key: bytes
    nonce: bytes
    ciphertext: bytes  # Tags is already included at the end.


def pack(wrapped_key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """Combine the components into a single byte string according to the format above."""
    if len(nonce) != NONCE_LEN:
        raise ValueError(f"nonce must be {NONCE_LEN} bytes, got {len(nonce)}")
    if len(wrapped_key) > 0xFFFF:
        raise ValueError("wrapped_key too long for a 2-byte length field")
    header = struct.pack(HEADER_FMT, MAGIC, VERSION, len(wrapped_key))
    return header + wrapped_key + nonce + ciphertext


def unpack(data: bytes) -> Container:
    """Split a ``.hyb`` file into a ``Container``.
    Raise ``ValueError`` if the MAGIC/VERSION is incorrect or the data is truncated."""
    if len(data) < HEADER_LEN:
        raise ValueError("File too short to be a .hyb file")

    magic, version, key_len = struct.unpack(HEADER_FMT, data[:HEADER_LEN])
    if magic != MAGIC:
        raise ValueError("Not a .hyb file (bad magic)")
    if version != VERSION:
        raise ValueError(f"Unsupported .hyb version: {version}")

    key_end = HEADER_LEN + key_len
    nonce_end = key_end + NONCE_LEN
    # Need at least the nonce plus a full 16-byte tag after the wrapped key
    if len(data) < nonce_end + TAG_LEN:
        raise ValueError("File is truncated or corrupted")

    return Container(
        wrapped_key=data[HEADER_LEN:key_end],
        nonce=data[key_end:nonce_end],
        ciphertext=data[nonce_end:],
    )
