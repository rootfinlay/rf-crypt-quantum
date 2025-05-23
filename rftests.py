import random, string, time
import crypto_operations as rfcrypt

class Testing:
    def __init__(self, rounds=5):
        self.rounds = rounds

    def start_tests(self):
        pt = ""
        for _ in range(128):
            pt += random.choice(string.ascii_letters)

        count = 0

        for i in range(self.rounds):
            start = time.time()
            cipher = rfcrypt.rfc_q(n=4098, q=999983, std_dev=0.2)

            pub, priv = cipher.keygen()

            encrypted = cipher.encrypt_message(pub, pt)

            decrypted = cipher.decrypt_message(priv, encrypted)
            end = time.time()
            
            if decrypted == pt:
                count += 1
                print(f"test {i+1} passed in {end - start}")
            else:
                print(f"test {i+1} failed in {end - start}")

        print(f"{count} out of {self.rounds} passed..")