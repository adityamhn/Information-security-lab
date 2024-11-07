from Crypto.Util.number import getPrime, inverse
from Crypto.Random import get_random_bytes
import random

def generate_keys():
    # Generate a large prime p
    p = getPrime(512)
    # Select a generator g (e.g., 2)
    g = 2
    # Choose a private key x
    x = random.randint(1, p - 2)
    # Compute the public key h
    h = pow(g, x, p)
    return p, g, h, x

def encrypt(msg, p, g, h):
    k = random.randint(1, p - 2)
    C1 = pow(g, k, p)
    s = pow(h, k, p)
    ciphertext = []
    for char in msg:
        ciphertext.append((ord(char) * s) % p)
    return C1, ciphertext

def decrypt(C1, ciphertext, p, x):
    s = pow(C1, x, p)
    plaintext = []
    for c in ciphertext:
        plaintext.append(chr((c * inverse(s, p)) % p))
    return ''.join(plaintext)

msg = "Confidential Data"
p, g, h, x = generate_keys()
C1, ciphertext = encrypt(msg, p, g, h)
decrypted_msg = decrypt(C1, ciphertext, p, x)

print("Original Message:", msg)
print("Decrypted Message:", decrypted_msg)

