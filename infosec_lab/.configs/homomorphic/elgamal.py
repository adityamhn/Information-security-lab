import random
from Crypto.Util.number import getPrime, inverse

# Key generation for ElGamal
def generate_elgamal_keys(bits=512):
    p = getPrime(bits)
    g = random.randint(2, p - 2)  # Choose a generator g
    x = random.randint(1, p - 2)  # Private key
    h = pow(g, x, p)  # Public key h = g^x mod p
    return (p, g, h, x)

# ElGamal encryption
def elgamal_encrypt(m, p, g, h):
    k = random.randint(1, p - 2)  # Random ephemeral key
    c1 = pow(g, k, p)
    c2 = (m * pow(h, k, p)) % p
    return (c1, c2)

# ElGamal decryption
def elgamal_decrypt(c1, c2, p, x):
    # Calculate m = c2 * (c1^x)^(-1) mod p
    s = pow(c1, x, p)
    s_inv = inverse(s, p)
    m = (c2 * s_inv) % p
    return m

# Generate keys
p, g, h, x = generate_elgamal_keys(bits=512)

# Sample messages
m1 = 5
m2 = 7

# Encrypt messages
c1_1, c1_2 = elgamal_encrypt(m1, p, g, h)
c2_1, c2_2 = elgamal_encrypt(m2, p, g, h)

# Homomorphic property: Multiplying ciphertexts component-wise
c_product_1 = (c1_1 * c2_1) % p
c_product_2 = (c1_2 * c2_2) % p

# Decrypt the product ciphertext
decrypted_product = elgamal_decrypt(c_product_1, c_product_2, p, x)

# Expected result
expected_product = (m1 * m2) % p

# Output the results
print("Message 1 (m1):", m1)
print("Message 2 (m2):", m2)
print("Ciphertext 1 (c1_1, c1_2):", (c1_1, c1_2))
print("Ciphertext 2 (c2_1, c2_2):", (c2_1, c2_2))
print("Ciphertext Product ((c1_1 * c2_1) % p, (c1_2 * c2_2) % p):", (c_product_1, c_product_2))
print("Decrypted Product:", decrypted_product)
print("Expected Product (m1 * m2) % p:", expected_product)
print("Homomorphic property holds:", decrypted_product == expected_product)
