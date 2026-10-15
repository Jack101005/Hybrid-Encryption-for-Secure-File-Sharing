import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from hybridcrypto.keyInfo import keyCompare
import os
def test_key_compare():
    
    private_key = rsa.generate_private_key(
        public_exponent=65537, 
        key_size=2048,
    )
    public_key = private_key.public_key()

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open("temp_pub.pem", "wb") as f:
        f.write(public_pem)

    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    fingerprint = hashlib.sha256(public_der).hexdigest()

    assert keyCompare("temp_pub.pem", fingerprint) == True
    assert keyCompare("temp_pub.pem", "wrongfingerprint") == False

    os.remove("temp_pub.pem")
