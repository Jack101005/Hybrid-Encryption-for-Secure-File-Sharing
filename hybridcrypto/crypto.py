"""High level hybrid encryption: AES GCM for the file, RSA OAEP for the key.

Owner: Khoi (integration)

This module does not implement any cryptography itself. It only wires
aes_gcm, rsa_oaep and container together, in the same order as Jack's
original demos in modules/encryption.py:
    aes_ed: make key, make nonce, encrypt, decrypt
    rsa_ed: encrypt with the public key (OAEP), decrypt with the private key
Here the two halves are split: encrypt_file runs on the sender side,
decrypt_file runs on the receiver side, and RSA wraps the AES key
instead of the message itself.
"""
from __future__ import annotations

from pathlib import Path

from . import aes_gcm, container, rsa_oaep


def encrypt_file(input_path: str, output_path: str, public_key_path: str) -> None:
    """Encrypt input_path for the owner of public_key_path and write a .hyb file."""
    data = Path(input_path).read_bytes()

    key = aes_gcm.generate_key()                     # fresh AES key for every file
    nonce, ciphertext = aes_gcm.encrypt(key, data)   # the file, encrypted with AES GCM

    public_key = rsa_oaep.load_public_key(public_key_path)
    wrapped_key = rsa_oaep.wrap_key(public_key, key)  # the AES key, wrapped with RSA OAEP

    Path(output_path).write_bytes(container.pack(wrapped_key, nonce, ciphertext))


def decrypt_file(input_path: str, output_path: str, private_key_path: str,
                 password: bytes | None = None) -> None:
    """Decrypt a .hyb file with private_key_path and write the original file.

    Raises ValueError for a broken file or the wrong private key, and
    InvalidTag if the file was modified. Nothing is written on failure.
    """
    c = container.unpack(Path(input_path).read_bytes())

    private_key = rsa_oaep.load_private_key(private_key_path, password)
    key = rsa_oaep.unwrap_key(private_key, c.wrapped_key)

    data = aes_gcm.decrypt(key, c.nonce, c.ciphertext)
    Path(output_path).write_bytes(data)