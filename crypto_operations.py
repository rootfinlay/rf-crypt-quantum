import numpy as np
from errors import CouldntDecrypt

class Demo():
    """Demo of the encryption with a small key size"""

    def __init__(self):
        # Parameters
        self.n = 4
        self.q = 3301
        self.std_dev = 1.0

    def sample_error(self):
        """Sample small error term from discrete Gaussian (approx)."""
        return int(np.random.normal(0, self.std_dev)) % self.q

    def keygen(self):
        """Generate a public and private key."""
        A = np.random.randint(0, self.q, size=(self.n, self.n))
        s = np.random.randint(0, self.q, size=(self.n, 1))  # secret key
        e = np.array([[self.sample_error()] for _ in range(self.n)])
        
        b = (A @ s + e) % self.q
        public_key = (A, b)
        private_key = s
        return public_key, private_key

    def encrypt(self, public_key, message):
        """Encrypt a single bit message (0 or 1)."""
        A, b = public_key
        r = np.random.randint(0, 2, size=(self.n, 1))  # random bits
        e1 = np.array([[self.sample_error()] for _ in range(self.n)])
        e2 = self.sample_error()
        
        u = (A.T @ r + e1) % self.q
        v = (b.T @ r + e2 + (self.q // 2) * message) % self.q
        return (u, v)

    def decrypt(self, private_key, ciphertext):
        """Decrypt the ciphertext."""
        u, v = ciphertext
        approx = (v - (private_key.T @ u)) % self.q
        # Decide if closer to 0 or q/2
        return int(np.abs(approx - self.q//2) < self.q//4)

    # Example Usage
    def start_demo(self):
        print("Generating keys...")
        public_key, private_key = self.keygen()
        
        message = 1  # Encrypt bit 1
        print(f"Encrypting message: {message}")
        ciphertext = self.encrypt(public_key, message)
        
        print(f"Ciphertext: {ciphertext}")
        
        recovered = self.decrypt(private_key, ciphertext)
        print(f"Decrypted message: {recovered}")

import base64
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

class rfc():
    """(hopefully) a secure implementation of a quantum resistant algorithm utilizing the LWE problem..."""

    def __init__(self):
        self.n = 256
        self.q = 3001
        self.std_dev = 0.1

    def sample_error(self):
        """Sample small error term from discrete Gaussian (approx)."""
        return int(np.random.normal(0, self.std_dev)) % self.q

    def keygen(self):
        """Generate a public and private key."""
        A = np.random.randint(0, self.q, size=(self.n, self.n))
        s = np.random.randint(0, self.q, size=(self.n, 1))  # secret key
        e = np.array([[self.sample_error()] for _ in range(self.n)])
        
        b = (A @ s + e) % self.q
        public_key = (A, b)
        private_key = s
        return public_key, private_key

    def encrypt(self, public_key, message):
        """Encrypt a single bit message (0 or 1)."""
        A, b = public_key
        r = np.random.randint(0, 2, size=(self.n, 1))  # random bits
        e1 = np.array([[self.sample_error()] for _ in range(self.n)])
        e2 = self.sample_error()
        
        u = (A.T @ r + e1) % self.q
        v = (b.T @ r + e2 + (self.q // 2) * message) % self.q
        return (u, v)

    def decrypt(self, private_key, ciphertext):
        """Decrypt the ciphertext."""
        u, v = ciphertext
        approx = (v - (private_key.T @ u)) % self.q
        # Decide if closer to 0 or q/2
        return int(np.abs(approx - self.q//2) < self.q//4)

    def encrypt_message(self, public_key, message_str):
        """Encrypt a full string message into a list of ciphertexts."""
        # Convert string to bytes
        message_bytes = message_str.encode()

        # Convert bytes to bits
        bits = ''.join(f'{byte:08b}' for byte in message_bytes)

        ciphertexts = []
        for bit in bits:
            ct = self.encrypt(public_key, int(bit))
            ciphertexts.append(ct)

        return ciphertexts

    def decrypt_message(self, private_key, ciphertexts):
        """Decrypt a list of ciphertexts back into the original string."""
        bits = ''
        for ct in ciphertexts:
            bit = self.decrypt(private_key, ct)
            bits += str(bit)

        # Make sure bits length is multiple of 8
        if len(bits) % 8 != 0:
            raise ValueError("Bit string length is not a multiple of 8!")

        # Convert bits to bytes
        message_bytes = int(bits, 2).to_bytes(len(bits) // 8, byteorder='big')

        print(message_bytes)

        try:
            return message_bytes.decode('utf-8')
        except UnicodeDecodeError:
            raise Exception("Decryption succeeded but output is not valid UTF-8 text. Maybe wrong key?")

    def export_public(self, public_key):
        comp = f"{base64.b64encode(public_key[0])}:{base64.b64encode(public_key[1])}"

        b64_public_key = base64.b64encode(comp.encode())

        output = "-----BEGIN RF-CRYPT PUBLIC KEY-----\n\n"
        
        count = 0
        for char in b64_public_key.decode():
            output += char
            if count == 64:
                output += "\n"
                count = 0

            count+=1

        output += "\n-----END RF-CRYPT PUBLIC KEY-----"

        with open("public.key", "w") as f:
            f.write(output)

        f.close()

        return output

    def export_private(self, private_key):
        passphrase = input("Choose a passphrase to encrypt the private key with:\n> ")
        aes_key = PBKDF2(passphrase, 1, 32)

        aes_cipher = AES.new(aes_key, AES.MODE_EAX)
        ciphertext, tag = aes_cipher.encrypt_and_digest(private_key.tobytes())
        nonce = aes_cipher.nonce

        b64_ciphertext = base64.b64encode(ciphertext)
        b64_tag = base64.b64encode(tag)
        b64_nonce = base64.b64encode(nonce)

        composition = f"{b64_ciphertext.decode()}:{b64_tag.decode()}:{b64_nonce.decode()}"

        b64_private_key = base64.b64encode(composition.encode())

        output = "-----BEGIN RF-CRYPT PRIVATE KEY-----\n\n"
        
        count = 0
        for char in b64_private_key.decode():
            output += char
            if count == 64:
                output += "\n"
                count = 0

            count+=1

        output += "\n-----END RF-CRYPT PRIVATE KEY-----"

        with open("private.key", "w") as f:
            f.write(output)

        f.close()

        return output

    def import_public(self, public_key):
        lines = public_key.splitlines()
        del lines[0]
        del lines[-1]

        out = ""
        for line in lines:
            out += lines[line]

        comps = base64.b64decode(out.encode()).split(":")
        public_key = (base64.b64decode(comps[0].encode()), base64.b64decode(comps[1].encode()))

        return public_key

    def import_private(self, private_key):
        passphrase = input("Please input the passphrase for the private key:\n> ")

        lines = private_key.splitlines()
        del lines[0]
        del lines[-1]

        out = ""
        for line in lines:
            out += line

        priv_key_comp = base64.b64decode(out.encode())
        
        multi = priv_key_comp.split(b":")

        ciphertext = base64.b64decode(multi[0])
        tag = base64.b64decode(multi[1])
        nonce = base64.b64decode(multi[2])

        aes_key = PBKDF2(passphrase, b"1", 32)  # Correct salt type (must be bytes)

        cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce)
        try:
            data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        except Exception as e:
            raise Exception("Could not decrypt private key: " + str(e))

        # Now reconstruct private key array from bytes
        private_key_array = np.frombuffer(data, dtype=np.int32).reshape((self.n, 1))

        return private_key_array

class rfc_q():
    def __init__(self, n=512, q=8189, std_dev=3.0):
        self.n = n
        self.q = q
        self.std_dev = std_dev

    def sample_error(self):
        """Sample small error term from a discrete Gaussian distribution."""
        return int(np.random.normal(0, self.std_dev)) % self.q
        #return np.random.choice([-1, 0, 1], p=[0.25, 0.5, 0.25])

    def keygen(self):
        """Generate a public and private key."""
        A = np.random.randint(0, self.q, size=(self.n, self.n))  # Public matrix A
        s = np.random.randint(0, self.q, size=(self.n, 1))  # Secret key
        e = np.array([[self.sample_error()] for _ in range(self.n)])  # Error vector

        b = (A @ s + e) % self.q  # Public key (A, b)
        public_key = (A, b)
        private_key = s
        return public_key, private_key

    def encrypt(self, public_key, message_bit):
        """Encrypt a single bit message (0 or 1), with error correction."""
        A, b = public_key
        ct_list = []
        for _ in range(7):  # Encrypt the bit 7 times (majority voting)
            r = np.random.randint(0, 2, size=(self.n, 1))  # Random binary vector
            e1 = np.array([[self.sample_error()] for _ in range(self.n)])
            e2 = self.sample_error()

            u = (A.T @ r + e1) % self.q
            v = (b.T @ r + e2 + (self.q // 2) * message_bit) % self.q
            ct_list.append((u, v))
        return ct_list

    def decrypt(self, private_key, ciphertext_list):
        """Decrypt the ciphertext (with error correction and adaptive thresholding)."""
        votes = []
        for ciphertext in ciphertext_list:
            u, v = ciphertext
            approx = (v - (private_key.T @ u)) % self.q
            
            # Smooth the result further
            if approx < self.q // 4:
                votes.append(0)  # Closer to 0
            elif approx > 3 * (self.q // 4):
                votes.append(1)  # Closer to 1
            else:
                # If the result is near q//2, apply an adaptive thresholding
                if approx < self.q // 2:
                    votes.append(0)
                else:
                    votes.append(1)
        
        # Return the majority vote (0 or 1)
        return int(np.mean(votes) > 0.5)

    def encrypt_message(self, public_key, message_str):
        """Encrypt a full string message into a list of ciphertexts."""
        # Convert string to bytes
        message_bytes = message_str.encode()

        # Convert bytes to bits
        bits = ''.join(f'{byte:08b}' for byte in message_bytes)

        ciphertexts = []
        for bit in bits:
            ct = self.encrypt(public_key, int(bit))
            ciphertexts.append(ct)

        return ciphertexts

    def decrypt_message(self, private_key, ciphertexts):
        """Decrypt a list of ciphertexts back into the original string."""
        bits = ''
        for ct in ciphertexts:
            bit = self.decrypt(private_key, ct)
            bits += str(bit)

        # Make sure bits length is multiple of 8
        if len(bits) % 8 != 0:
            raise ValueError("Bit string length is not a multiple of 8!")

        # Convert bits to bytes
        message_bytes = int(bits, 2).to_bytes(len(bits) // 8, byteorder='big')

        print(message_bytes)

        try:
            return message_bytes.decode('utf-8')
        except UnicodeDecodeError:
            raise Exception("Decryption succeeded but output is not valid UTF-8 text. Maybe wrong key?")

    def export_public(self, public_key):
        """Export the public key to a file in a custom format."""
        comp = f"{base64.b64encode(public_key[0].tobytes())}:{base64.b64encode(public_key[1].tobytes())}"
        b64_public_key = base64.b64encode(comp.encode())

        output = "-----BEGIN RF-CRYPT PUBLIC KEY-----\n\n"
        count = 0
        for char in b64_public_key.decode():
            output += char
            if count == 64:
                output += "\n"
                count = 0
            count += 1

        output += "\n-----END RF-CRYPT PUBLIC KEY-----"

        with open("public.key", "w") as f:
            f.write(output)

        return output

    def export_private(self, private_key):
        passphrase = input("Choose a passphrase to encrypt the private key with:\n> ")
        aes_key = PBKDF2(passphrase, 1, 32)

        aes_cipher = AES.new(aes_key, AES.MODE_EAX)
        ciphertext, tag = aes_cipher.encrypt_and_digest(private_key.tobytes())
        nonce = aes_cipher.nonce

        b64_ciphertext = base64.b64encode(ciphertext)
        b64_tag = base64.b64encode(tag)
        b64_nonce = base64.b64encode(nonce)

        composition = f"{b64_ciphertext.decode()}:{b64_tag.decode()}:{b64_nonce.decode()}"
        b64_private_key = base64.b64encode(composition.encode())

        output = "-----BEGIN RF-CRYPT PRIVATE KEY-----\n\n"
        count = 0
        for char in b64_private_key.decode():
            output += char
            if count == 64:
                output += "\n"
                count = 0
            count += 1

        output += "\n-----END RF-CRYPT PRIVATE KEY-----"

        with open("private.key", "w") as f:
            f.write(output)

        return output

    def import_public(self, public_key):
        lines = public_key.splitlines()
        del lines[0]
        del lines[-1]

        out = ""
        for line in lines:
            out += line

        comps = base64.b64decode(out.encode()).split(":")
        public_key = (base64.b64decode(comps[0].encode()), base64.b64decode(comps[1].encode()))
        return public_key

    def import_private(self, private_key):
        passphrase = input("Please input the passphrase for the private key:\n> ")
        lines = private_key.splitlines()
        del lines[0]
        del lines[-1]

        out = ""
        for line in lines:
            out += line

        priv_key_comp = base64.b64decode(out.encode())
        multi = priv_key_comp.split(":")

        ciphertext = multi[0]
        tag = multi[1]
        nonce = multi[2]

        cipher_aes = AES.new(passphrase.encode(), AES.MODE_EAX, nonce)
        try:
            data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        except:
            raise Exception("Couldn't decrypt.")
        return data.decode()