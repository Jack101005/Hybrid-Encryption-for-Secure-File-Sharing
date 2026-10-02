"""RSA keypair + RSA-OAEP key wrapping.

[Mang: Key wrapping]

Port tu code cua Jack (modules/encryption.py, ham rsa_ed). Doi vai tro cua RSA:
thay vi ma thang message, o day RSA chi dung de boc (wrap) khoa AES 32 byte.
Padding OAEP-SHA256 giu nguyen nhu code goc. Them phan gen / luu / doc khoa PEM.
"""
from __future__ import annotations

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

RSA_KEY_BITS = 3072      # match muc bao mat ~128-bit cua AES-256
PUBLIC_EXPONENT = 65537

# OAEP dung chung cho wrap va unwrap -> phai giong het nhau, khong la mo khong ra
_OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)


def generate_keypair(bits: int = RSA_KEY_BITS):
    """Sinh cap khoa RSA. Tra ve (private_key, public_key)."""
    private_key = rsa.generate_private_key(
        public_exponent=PUBLIC_EXPONENT, key_size=bits
    )
    return private_key, private_key.public_key()


def save_private_key(private_key, path: str, password: bytes | None = None) -> None:
    """Ghi private key ra file PEM (PKCS8). Co password thi ma hoa file khoa."""
    if password:
        enc = serialization.BestAvailableEncryption(password)
    else:
        enc = serialization.NoEncryption()
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc,
    )
    with open(path, "wb") as f:
        f.write(pem)


def save_public_key(public_key, path: str) -> None:
    """Ghi public key ra file PEM (SubjectPublicKeyInfo)."""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(path, "wb") as f:
        f.write(pem)


def load_private_key(path: str, password: bytes | None = None):
    """Doc private key tu file PEM."""
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=password)


def load_public_key(path: str):
    """Doc public key tu file PEM."""
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def wrap_key(public_key, aes_key: bytes) -> bytes:
    """Boc AES key bang public key (RSA-OAEP). Tra ve wrapped key (bytes)."""
    return public_key.encrypt(aes_key, _OAEP)


def unwrap_key(private_key, wrapped: bytes) -> bytes:
    """Mo AES key bang private key (RSA-OAEP). Tra ve AES key goc."""
    return private_key.decrypt(wrapped, _OAEP)