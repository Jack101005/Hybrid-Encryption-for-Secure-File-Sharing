from hybridcrypto import rsa_oaep
from digitalSignature import signature
import os

def test_valid_signature():
    private_key, public_key = rsa_oaep.generate_keypair(bits=2048)
    with open("file_tmp.txt", "w", encoding="utf-8") as f:
        f.write("Test signature for a file!")

    signature.sign_file(private_key, "file_tmp.txt", "document.sig")

    assert(signature.verify_file(public_key, "file_tmp.txt", "document.sig") == True)

    os.remove("file_tmp.txt")
    os.remove("document.sig")

def test_invalid_signature():
    private_key, public_key = rsa_oaep.generate_keypair(bits=2048)
    with open("file_tmp.txt", "w", encoding="utf-8") as f:
        f.write("Test signature for a file!")

    signature.sign_file(private_key, "file_tmp.txt", "document.sig")

    with open("file_tmp.txt", "w", encoding="utf-8") as f:
                f.write("Tampered file!!!")

    assert(signature.verify_file(public_key, "file_tmp.txt", "document.sig") == False)

    os.remove("file_tmp.txt")
    os.remove("document.sig")

def test_wrong_signer():
    private_key_bob, _ = rsa_oaep.generate_keypair(bits=2048)
    _, public_key_trudy = rsa_oaep.generate_keypair(bits=2048)
    with open("file_tmp.txt", "w", encoding="utf-8") as f:
        f.write("Test signature for a file!")

    signature.sign_file(private_key_bob, "file_tmp.txt", "document.sig")

    assert(signature.verify_file(public_key_trudy, "file_tmp.txt", "document.sig") == False)

    os.remove("file_tmp.txt")
    os.remove("document.sig")