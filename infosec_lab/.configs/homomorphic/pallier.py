from Crypto.Util.number import getPrime, inverse, GCD
import random

# Paillier Key Generation
def generate_paillier_keys(bits=512):
    p = getPrime(bits // 2)
    q = getPrime(bits // 2)
    n = p * q
    n_square = n * n
    g = n + 1  # Common choice for g in Paillier
    lambda_val = (p - 1) * (q - 1) // GCD(p - 1, q - 1)  # λ = lcm(p-1, q-1)
    mu = inverse(lambda_val, n)  # μ = (L(g^λ mod n^2))^-1 mod n
    return (n, g, n_square, lambda_val, mu)

# Paillier Encryption
def paillier_encrypt(m, n, g, n_square):
    r = random.randint(1, n - 1)
    while GCD(r, n) != 1:  # Ensure r is coprime with n
        r = random.randint(1, n - 1)
    c = (pow(g, m, n_square) * pow(r, n, n_square)) % n_square
    return c

# Paillier Decryption
def paillier_decrypt(c, n, n_square, lambda_val, mu):
    # L(u) = (u - 1) // n
    def L(u, n):
        return (u - 1) // n

    # Compute m = L(c^λ mod n^2) * μ mod n
    u = pow(c, lambda_val, n_square)
    l_u = L(u, n)
    m = (l_u * mu) % n
    return m

# Generate Paillier keys
n, g, n_square, lambda_val, mu = generate_paillier_keys(bits=512)

# Sample messages
m1 = 5
m2 = 5

# Encrypt messages
c1 = paillier_encrypt(m1, n, g, n_square)
c2 = paillier_encrypt(m2, n, g, n_square)

# Homomorphic property: Adding ciphertexts by multiplying them
c_sum = (c1 * c2) % n_square

# Decrypt the sum ciphertext
decrypted_sum = paillier_decrypt(c_sum, n, n_square, lambda_val, mu)

# Expected result
expected_sum = (m1 + m2) % n

# Output the results
print("Message 1 (m1):", m1)
print("Message 2 (m2):", m2)
print("Ciphertext 1 (c1):", c1)
print("Ciphertext 2 (c2):", c2)
print("Ciphertext Sum (c1 * c2) mod n^2:", c_sum)
print("Decrypted Sum:", decrypted_sum)
print("Expected Sum (m1 + m2) mod n:", expected_sum)
print("Homomorphic property holds:", decrypted_sum == expected_sum)
