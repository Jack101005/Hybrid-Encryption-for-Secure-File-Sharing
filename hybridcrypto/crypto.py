"""Hàm cấp cao: ghép AES-GCM + RSA-OAEP + container.

Đây là chỗ "ráp" các module lại — không tự cài thuật toán, chỉ gọi
``aes_gcm``, ``rsa_oaep``, ``container``.
"""
from __future__ import annotations

from . import aes_gcm, container, rsa_oaep


def encrypt_file(input_path: str, output_path: str, public_key_path: str) -> None:
    """Mã hoá file ``input_path`` cho người sở hữu ``public_key_path``.

    Luồng:
      1. đọc plaintext
      2. aes_key = aes_gcm.generate_key()
      3. nonce, ciphertext = aes_gcm.encrypt(aes_key, plaintext)
      4. wrapped = rsa_oaep.wrap_key(pubkey, aes_key)
      5. ghi container.pack(wrapped, nonce, ciphertext) ra output_path
    """
    raise NotImplementedError


def decrypt_file(input_path: str, output_path: str, private_key_path: str) -> None:
    """Giải mã file ``.hyb`` bằng ``private_key_path``.

    Luồng:
      1. c = container.unpack(đọc input_path)
      2. aes_key = rsa_oaep.unwrap_key(privkey, c.wrapped_key)
      3. plaintext = aes_gcm.decrypt(aes_key, c.nonce, c.ciphertext)  # verify tag
      4. ghi plaintext ra output_path
    """
    raise NotImplementedError
