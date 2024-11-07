# multiplicatively homomorphic encryption scheme


from Crypto.Util.number import getPrime, inverse
import random

# Key generation
def generate_rsa_keys(bits=512):
    p = getPrime(bits // 2)
    q = getPrime(bits // 2)
    n = p * q
    e = 65537  # Common choice for e
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)
    return (n, e, d)

# RSA encryption
def rsa_encrypt(m, n, e):
    return pow(m, e, n)

# RSA decryption
def rsa_decrypt(c, n, d):
    return pow(c, d, n)

# Generate RSA keys
n, e, d = generate_rsa_keys(bits=512)

# Sample messages
m1 = 5
m2 = 7

# Encrypt messages
c1 = rsa_encrypt(m1, n, e)
c2 = rsa_encrypt(m2, n, e)

# Homomorphic property: Multiplying ciphertexts
c_product = (c1 * c2) % n

# Decrypt the product
decrypted_product = rsa_decrypt(c_product, n, d)

# Expected result
expected_product = (m1 * m2) % n

# Output the results
print("Message 1 (m1):", m1)
print("Message 2 (m2):", m2)
print("Ciphertext 1 (c1):", c1)
print("Ciphertext 2 (c2):", c2)
print("Ciphertext Product (c1 * c2) mod n:", c_product)
print("Decrypted Product:", decrypted_product)
print("Expected Product (m1 * m2) mod n:", expected_product)
print("Homomorphic property holds:", decrypted_product == expected_product)
