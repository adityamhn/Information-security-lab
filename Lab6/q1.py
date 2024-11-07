# from Crypto.PublicKey import ElGamal
# from Crypto.Random import get_random_bytes
# from Crypto.Random.random import randint
# from Crypto.Util.number import GCD, inverse
# import hashlib

# # ElGamal Key Generation
# def generate_elgamal_key(bits=256):
#     key = ElGamal.generate(bits, get_random_bytes)
#     public_key = (key.p, key.g, key.y)  # Public key (p, g, y)
#     private_key = key.x  # Private key (x)
#     return public_key, private_key

# # Schnorr Signature Generation
# def schnorr_sign(message, p, g, x):
#     p = int(p)  # Ensure p is an integer
#     q = (p - 1) // 2  # Schnorr subgroup
#     k = randint(1, int(q) - 1)  # Random nonce; ensure q is converted to an integer
#     r = pow(g, k, p)  # Commitment
#     h = int(hashlib.sha256((str(r) + str(message)).encode()).hexdigest(), 16) % q  # Hash of commitment and message
#     s = (k + h * int(x)) % q  # Convert x to an integer before multiplication
#     return r, s

# # Schnorr Signature Verification
# def schnorr_verify(message, r, s, p, g, y):
#     p = int(p)  # Ensure p is an integer
#     q = (p - 1) // 2  # Schnorr subgroup
#     h = int(hashlib.sha256((str(r) + str(message)).encode()).hexdigest(), 16) % q  # Hash of commitment and message
#     v1 = pow(g, s, p)
#     v2 = (r * pow(y, h, p)) % p
#     return v1 == v2

# # ElGamal Encryption
# def elgamal_encrypt(message, public_key):
#     p, g, y = public_key
#     p = int(p)  # Convert p to a Python integer
#     g = int(g)  # Convert g to a Python integer
#     y = int(y)  # Convert y to a Python integer
#     k = randint(1, p - 2)
#     while GCD(k, p - 1) != 1:
#         k = randint(1, p - 2)
#     c1 = pow(g, k, p)
#     c2 = (message * pow(y, k, p)) % p
#     return (c1, c2)

# # ElGamal Decryption
# def elgamal_decrypt(cipher_text, private_key, public_key):
#     c1, c2 = cipher_text
#     p, g, y = public_key
#     p = int(p)  # Convert p to a Python integer
#     s = pow(c1, int(private_key), p)
#     s_inv = inverse(s, p)  # Multiplicative inverse of s mod p
#     return (c2 * s_inv) % p

# # Example usage
# public_key, private_key = generate_elgamal_key(bits=256)
# message = 4441

# # Schnorr Signing
# r, s = schnorr_sign(message, public_key[0], public_key[1], private_key)
# print("Schnorr Signature (r, s):", (r, s))

# # Verify Schnorr Signature
# is_valid = schnorr_verify(message, r, s, public_key[0], public_key[1], public_key[2])
# print("Schnorr Signature Valid:", is_valid)

# # ElGamal Encryption
# cipher_text = elgamal_encrypt(message, public_key)
# print("Encrypted message:", cipher_text)

# # ElGamal Decryption
# decrypted_message = elgamal_decrypt(cipher_text, private_key, public_key)
# print("Decrypted message:", decrypted_message)


from Crypto.Util import number
import hashlib
import random

# -------------------- ElGamal Encryption --------------------

class ElGamal:
    def __init__(self, key_size=256):
        self.p = number.getPrime(key_size)  # Large prime
        self.g = random.randint(2, self.p - 1)  # Generator
        self.x = random.randint(1, self.p - 2)  # Private key
        self.h = pow(self.g, self.x, self.p)  # Public key h = g^x mod p

    def encrypt(self, message):
        """Encrypt the given message using ElGamal encryption."""
        # Convert message to an integer
        M = int.from_bytes(message.encode('utf-8'), byteorder='big')

        # Check if message is too large for the modulus
        if M >= self.p:
            raise ValueError("Message is too large to encrypt with current prime size. Choose a larger key size.")

        y = random.randint(1, self.p - 2)  # Random ephemeral key
        c1 = pow(self.g, y, self.p)  # c1 = g^y mod p
        s = pow(self.h, y, self.p)  # s = h^y mod p (shared secret)
        c2 = (M * s) % self.p  # c2 = M * s mod p
        return c1, c2

    def decrypt(self, c1, c2):
        """Decrypt the ciphertext using ElGamal decryption."""
        s = pow(c1, self.x, self.p)  # s = c1^x mod p (shared secret)
        s_inv = pow(s, -1, self.p)  # Inverse of s mod p
        M = (c2 * s_inv) % self.p  # M = c2 * s_inv mod p

        try:
            # Try decoding the message back to a string
            return M.to_bytes((M.bit_length() + 7) // 8, byteorder='big').decode('utf-8')
        except UnicodeDecodeError as e:
            print(f"Decryption error: {e}")
            return "Decryption failed: Unable to decode message."


# -------------------- Schnorr Signature --------------------

class Schnorr:
    def __init__(self, key_size=256):
        self.p = number.getPrime(key_size)  # Large prime
        self.g = random.randint(2, self.p - 1)  # Generator
        self.x = random.randint(1, self.p - 2)  # Private key
        self.h = pow(self.g, self.x, self.p)  # Public key h = g^x mod p

    def sign(self, message):
        """Generate a Schnorr signature for the given message."""
        k = random.randint(1, self.p - 2)  # Random nonce
        r = pow(self.g, k, self.p)  # r = g^k mod p
        e = int(hashlib.sha256((str(r) + message).encode('utf-8')).hexdigest(), 16) % self.p  # e = H(r, m)
        s = (k - self.x * e) % (self.p - 1)  # s = k - xe mod (p - 1)
        return (r, s)

    def verify(self, message, r, s):
        """Verify a Schnorr signature."""
        e = int(hashlib.sha256((str(r) + message).encode('utf-8')).hexdigest(), 16) % self.p  # e = H(r, m)
        v1 = pow(self.g, s, self.p) * pow(self.h, e, self.p) % self.p  # g^s * h^e mod p
        return v1 == r  # Signature is valid if v1 == r

# -------------------- Main Functionality --------------------

def main():
    # ElGamal encryption
    elgamal = ElGamal(key_size=256)
    message = "ElGamal encryption!"
    print(f"Original Message: {message}")

    # Encrypt the message
    c1, c2 = elgamal.encrypt(message)
    print(f"Ciphertext: (c1={c1}, c2={c2})")

    # Decrypt the message
    decrypted_message = elgamal.decrypt(c1, c2)
    print(f"Decrypted Message: {decrypted_message}")

    # Schnorr signature
    schnorr = Schnorr(key_size=256)
    message = "This is a test message for Schnorr signature!"
    print(f"\nMessage to be signed: {message}")

    # Sign the message
    r, s = schnorr.sign(message)
    print(f"Signature: (r={r}, s={s})")

    # Verify the signature
    if schnorr.verify(message, r, s):
        print("Schnorr signature verification successful!")
    else:
        print("Schnorr signature verification failed!")

if __name__ == "__main__":
    main()
