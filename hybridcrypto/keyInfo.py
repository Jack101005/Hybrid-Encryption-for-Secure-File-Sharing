from cryptography.hazmat.primitives import hashes, serialization
import hashlib

def keyCompare(public_pem_path: str, fingerprint: str):
    with open(public_pem_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )   
    hashed_key = hashlib.sha256(public_der).hexdigest()
    return hashed_key == fingerprint