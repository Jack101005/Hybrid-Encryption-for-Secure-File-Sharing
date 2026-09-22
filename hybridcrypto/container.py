"""Định dạng file container ``.hyb`` — pack/unpack.

[Mảng: Key wrapping]

CHỐT FORMAT SỚM để cả nhóm code song song không đụng nhau. Đề xuất layout
(big-endian, ``struct``):

    MAGIC            4 bytes   = b"HYBR"
    VERSION          1 byte    = 1
    wrapped_key_len  2 bytes   (unsigned short)
    wrapped_key      <wrapped_key_len> bytes  (output của RSA-OAEP)
    nonce            12 bytes  (AES-GCM nonce)
    ciphertext       phần còn lại (ĐÃ kèm 16 byte GCM tag ở cuối)

Đổi format thì nhớ tăng VERSION.
"""
from __future__ import annotations

from dataclasses import dataclass

MAGIC = b"HYBR"
VERSION = 1


@dataclass
class Container:
    wrapped_key: bytes
    nonce: bytes
    ciphertext: bytes  # đã kèm tag ở cuối


def pack(wrapped_key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """Gộp các thành phần thành 1 chuỗi bytes theo format ở trên."""
    # TODO: struct.pack(">4sBH", MAGIC, VERSION, len(wrapped_key)) + ...
    raise NotImplementedError


def unpack(data: bytes) -> Container:
    """Tách 1 file ``.hyb`` thành ``Container``.

    Raise ``ValueError`` nếu MAGIC/VERSION sai hoặc dữ liệu bị cắt cụt.
    """
    # TODO: kiểm tra MAGIC + VERSION, đọc wrapped_key_len, cắt các phần
    raise NotImplementedError
