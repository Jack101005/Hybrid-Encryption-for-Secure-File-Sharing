"""RSA keypair + RSA-OAEP key wrapping.

[Mảng: Key wrapping]

Gợi ý implement: dùng ``cryptography.hazmat.primitives.asymmetric.rsa`` và
padding ``OAEP(mgf=MGF1(SHA256()), algorithm=SHA256(), label=None)``.
RSA-OAEP chỉ dùng để bọc (wrap) AES key — KHÔNG dùng để mã hoá cả file.
"""
from __future__ import annotations

RSA_KEY_BITS = 3072      # match mức bảo mật ~128-bit của AES-256
PUBLIC_EXPONENT = 65537


def generate_keypair(bits: int = RSA_KEY_BITS):
    """Sinh cặp khoá RSA. Trả về ``(private_key, public_key)`` (object)."""
    # TODO: private = rsa.generate_private_key(PUBLIC_EXPONENT, bits)
    #       return private, private.public_key()
    raise NotImplementedError


def save_private_key(private_key, path: str, password: bytes | None = None) -> None:
    """Ghi private key ra file PEM (PKCS8). Cân nhắc đặt password bảo vệ."""
    # TODO: serialize PEM + PKCS8, ghi file (chú ý quyền đọc file khoá)
    raise NotImplementedError


def save_public_key(public_key, path: str) -> None:
    """Ghi public key ra file PEM (SubjectPublicKeyInfo)."""
    # TODO
    raise NotImplementedError


def load_private_key(path: str, password: bytes | None = None):
    """Đọc private key từ file PEM."""
    # TODO
    raise NotImplementedError


def load_public_key(path: str):
    """Đọc public key từ file PEM."""
    # TODO
    raise NotImplementedError


def wrap_key(public_key, aes_key: bytes) -> bytes:
    """Bọc AES key bằng public key (RSA-OAEP). Trả về wrapped key (bytes)."""
    # TODO: return public_key.encrypt(aes_key, OAEP(...))
    raise NotImplementedError


def unwrap_key(private_key, wrapped: bytes) -> bytes:
    """Mở AES key bằng private key (RSA-OAEP). Trả về AES key gốc."""
    # TODO: return private_key.decrypt(wrapped, OAEP(...))
    raise NotImplementedError
