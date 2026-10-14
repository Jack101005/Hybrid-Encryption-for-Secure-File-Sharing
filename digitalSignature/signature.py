from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.exceptions import InvalidSignature

def hash_file(file_path: str) -> bytes:
    digest = hashes.Hash(hashes.SHA256())

    with open(file_path, "rb") as f:
        while chunk := f.read(1024 * 1024):
            digest.update(chunk)

    return digest.finalize()

def sign_file(private_key, file_path: str, signature_path: str):
    
    digest = hash_file(file_path)

    signature = private_key.sign(
        digest,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        utils.Prehashed(hashes.SHA256())
    )
    with open(signature_path, "wb") as f:
        f.write(signature)


def verify_file(public_key, file_path: str, signature_path: str) -> bool:

    digest = hash_file(file_path)

    with open(signature_path, "rb") as f:
        signature = f.read()

    try:
        public_key.verify(
            signature,
            digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            utils.Prehashed(hashes.SHA256())
        )
        return True
    except InvalidSignature:
        return False


