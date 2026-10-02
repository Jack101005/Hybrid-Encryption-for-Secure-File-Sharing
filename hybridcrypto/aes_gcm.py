"""AES-256-GCM authenticated encryption.

Owner: Khoi (crypto core)

Ported from Jack's modules/encryption.py (function aes_ed).
Same primitives as the original: secrets.token_bytes for key and nonce,
AESGCM from the cryptography library. Reshaped so that encryption and
decryption are separate calls that work on raw bytes (files), with the
key passed in from outside.
"""
from __future__ import annotations

import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_SIZE = 32    # 256 bit key
NONCE_SIZE = 12  # 96 bit nonce, the recommended size for GCM
TAG_SIZE = 16    # 128 bit tag, appended to the end of the ciphertext


def generate_key() -> bytes:
    """Return a random 32 byte AES key."""
    return secrets.token_bytes(KEY_SIZE)


def generate_nonce() -> bytes:
    """Return a random 12 byte nonce. Never reuse a nonce with the same key."""
    return secrets.token_bytes(NONCE_SIZE)


def encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    """Encrypt plaintext with AES GCM.

    Returns (nonce, ciphertext). The ciphertext already has the 16 byte
    tag at the end. aad is optional associated data (checked, not encrypted).
    """
    nonce = generate_nonce()
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce, ciphertext


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    """Decrypt and verify the tag. Wrong key or modified data raises InvalidTag."""
    return AESGCM(key).decrypt(nonce, ciphertext, aad)