import crypto_operations as rfcrypt
import rftests

def do_demo():
    demo = rfcrypt.Demo()
    demo.start_demo()

def do_regular():
    crypt = rfcrypt.rfc()
    public_key, private_key = crypt.keygen()
 
    """
    encrypted = crypt.encrypt(public_key=public_key, message=1)
    print(encrypted)

    decrypted = crypt.decrypt(private_key=private_key, ciphertext=encrypted)
    print(decrypted)

    """
    encrypted = crypt.encrypt_message(public_key=public_key, message_str="testicles")
    #print(encrypted)

    decrypted = crypt.decrypt_message(private_key=private_key, ciphertexts=encrypted)
    print(decrypted)
    
def production():
    cipher = rfcrypt.rfc_q(n=4098, q=999983, std_dev=0.25)

    pub, priv = cipher.keygen()

    """
    for bit in [0, 1]:
        ct = cipher.encrypt(pub, bit)
        recovered_bit = cipher.decrypt(priv, ct)
        print(f"Original: {bit}, Recovered: {recovered_bit}")"""

    encrypted = cipher.encrypt_message(pub, "test")

    decrypted = cipher.decrypt_message(priv, encrypted)
    print(decrypted)

def tests():
    test = rftests.Testing(rounds=10)

    test.start_tests()

if __name__ == "__main__":
    tests()