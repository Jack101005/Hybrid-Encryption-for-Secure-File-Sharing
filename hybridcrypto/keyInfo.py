"""Public key fingerprint, to stop someone from swapping the public key.

Owner: An

Problem: if Trudy sits in the middle and replaces Bob's public key with her
own, Alice would encrypt for Trudy without knowing it.
Fix: Bob reads the fingerprint of his public key to Alice over a different
channel (phone call, Zalo). Alice computes the fingerprint of the key she
received and compares. Different fingerprint means the key was swapped.

The fingerprint is SHA256 of the public key in DER (SubjectPublicKeyInfo)
form. It is shown as 16 groups of 4 hex characters so it is easy to read out.
The fingerprint is never stored in the .hyb file.
"""
from __future__ import annotations

import hashlib
import re

from cryptography.hazmat.primitives import serialization

from . import rsa_oaep


def fingerprint(public_key) -> str:
    """Return the fingerprint, for example '3F2A 9C10 ... 77B1'."""
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    hex_digest = hashlib.sha256(der).hexdigest().upper()
    return " ".join(hex_digest[i:i + 4] for i in range(0, len(hex_digest), 4))


def fingerprint_file(public_pem_path: str) -> str:
    """Fingerprint of a public key stored in a .pem file."""
    return fingerprint(rsa_oaep.load_public_key(public_pem_path))


def normalize(fp: str) -> str:
    """Ignore spaces, colons and upper or lower case when comparing."""
    return re.sub(r"[\s:]", "", fp).lower()


def keyCompare(public_pem_path: str, expected_fingerprint: str) -> bool:
    """True if the key in public_pem_path has the expected fingerprint.

    expected_fingerprint is what the key owner read out over the phone.
    Spaces, colons and case do not matter.
    """
    return normalize(fingerprint_file(public_pem_path)) == normalize(expected_fingerprint)
