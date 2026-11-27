import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from digitalSignature import signature
from hybridcrypto import aes_gcm, container, keyInfo, rsa_oaep

WORK = REPO / "demo" / "out_3_4"

def setup():
    WORK.mkdir(parents=True, exist_ok=True)
    (WORK / ".gitignore").write_text("*\n")

    for name in ("alice", "bob", "trudy"):
        (WORK / name).mkdir(exist_ok=True)
        priv,pub= rsa_oaep.generate_keypair(3072)
        rsa_oaep.save_private_key(priv, WORK / name / "private.pem")
        rsa_oaep.save_public_key(pub, WORK / name / "public.pem")   
    print("[SETUP] Generated keypair for Alice, Bob and Trudy.")
            
def attack3():
    print("[ATTACK3]: MAN-IN-THE-MIDDLE ATTACK")
    msg= b"Hello Bob, this is Alice. I am sending you a secret message 2711."
    swapped_pub_path = WORK / "trudy" / "public.pem"


    aes_key= aes_gcm.generate_key()
    nonce, ciphertext= aes_gcm.encrypt(aes_key, msg)
    pub= rsa_oaep.load_public_key(swapped_pub_path)
    wrapped_key= rsa_oaep.wrap_key(pub, aes_key)
    hyb_path= WORK / "alice" / "mitm.hyb"
    hyb_path.write_bytes(container.pack(wrapped_key, nonce, ciphertext))

    c= container.unpack(hyb_path.read_bytes())
    trudy_priv= rsa_oaep.load_private_key(str(WORK / "trudy" / "private.pem"))
    stolen_aes= rsa_oaep.unwrap_key(trudy_priv, c.wrapped_key)
    stolen_msg= aes_gcm.decrypt(stolen_aes, c.nonce, c.ciphertext)
    print(f"[ATTACK3 without defense]: Trudy stole the message: {stolen_msg.decode()}")
    print("[ATTACK3 without defense]: Alice and Bob are unaware of the attack.")

    bob_fp= keyInfo.fingerprint_file(str(WORK / "bob" / "public.pem"))
    ok= keyInfo.keyCompare(str(swapped_pub_path), bob_fp)
    if not ok:
        print("[ATTACK3 with defense]: Bob's public key fingerprint does not match the expected value.")
        print("[ATTACK3 with defense]: Alice and Bob are alerted to the attack.")

def attack4():
    print("[ATTACK4]: fake sender attack")
    fake_msg= b"Hello Bob, this is Alice. I am sending you a secret message 2711 share it with trudy."

    aes_key= aes_gcm.generate_key()
    nonce, ciphertext= aes_gcm.encrypt(aes_key, fake_msg)
    bob_pub= rsa_oaep.load_public_key(str(WORK / "bob" / "public.pem"))
    wrapped_key= rsa_oaep.wrap_key(bob_pub, aes_key)
    fake_hyb= WORK / "trudy" / "fake.hyb"
    fake_hyb.write_bytes(container.pack(wrapped_key, nonce, ciphertext))

    c= container.unpack(fake_hyb.read_bytes())
    bob_priv= rsa_oaep.load_private_key(str(WORK / "bob" / "private.pem"))
    aes_back= rsa_oaep.unwrap_key(bob_priv, c.wrapped_key)
    bob_read= aes_gcm.decrypt(aes_back, c.nonce, c.ciphertext)
    print(f"[ATTACK4 without defense]: Bob received a message from Trudy: {bob_read.decode()}")
    print("[ATTACK4 without defense]: Bob is unaware of the attack.")

    fake_sig= WORK / "trudy" / "fake.hyb.sig"
    trudy_priv= rsa_oaep.load_private_key(str(WORK / "trudy" / "private.pem"))
    signature.sign_file(trudy_priv,str(fake_hyb),str(fake_sig))

    alice_pub= rsa_oaep.load_public_key(str(WORK / "alice" / "public.pem"))
    valid= signature.verify_file(alice_pub,str(fake_hyb),str(fake_sig))
    if not valid:
        print("[ATTACK4 with defense]: Signature verification failed. Bob is alerted to the attack.")
    else:
        print("[ATTACK4 with defense]: Signature verification succeeded. Bob is unaware of the attack.")

if __name__ == "__main__":
    setup()
    attack3()
    attack4()