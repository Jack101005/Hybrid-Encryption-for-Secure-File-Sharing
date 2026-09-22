"""AES-256-GCM authenticated encryption.

[Mảng: Crypto core]

Gợi ý implement: dùng ``cryptography.hazmat.primitives.ciphers.aead.AESGCM``.
Lưu ý: với AESGCM của thư viện này, hàm encrypt trả về ciphertext ĐÃ kèm luôn
16 byte tag ở cuối; decrypt sẽ tự tách và verify tag (sai → raise InvalidTag).
"""
from __future__ import annotations

import os

KEY_SIZE = 32    # 256-bit
NONCE_SIZE = 12  # 96-bit — kích thước nonce khuyến nghị cho GCM
TAG_SIZE = 16    # 128-bit tag (đã nằm ở cuối ciphertext)


def generate_key() -> bytes:
    """Sinh AES-256 key ngẫu nhiên (32 bytes)."""
    # TODO: return os.urandom(KEY_SIZE)
    raise NotImplementedError


def generate_nonce() -> bytes:
    """Sinh nonce 12 byte ngẫu nhiên. KHÔNG dùng lại nonce với cùng 1 key."""
    # TODO: return os.urandom(NONCE_SIZE)
    raise NotImplementedError


def encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    """Mã hoá ``plaintext``.

    Trả về ``(nonce, ciphertext)`` — trong đó ``ciphertext`` đã kèm tag ở cuối.
    ``aad`` = associated data (không mã hoá nhưng được xác thực), tuỳ chọn.
    """
    # TODO: nonce = generate_nonce(); ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    raise NotImplementedError


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    """Giải mã + verify tag. Sai key / dữ liệu bị sửa → raise ``InvalidTag``."""
    # TODO: return AESGCM(key).decrypt(nonce, ciphertext, aad)
    raise NotImplementedError
