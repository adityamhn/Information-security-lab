import random
from math import gcd

def generate_keypair(p, q):
    n = p * q
    phi = (p - 1) * (q - 1)
    
    e = random.randrange(1, phi)
    while gcd(e, phi) != 1:
        e = random.randrange(1, phi)
    
    d = mod_inverse(e, phi)
    
    return ((e, n), (d, n))

def mod_inverse(a, m):
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % m

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        gcd, x, y = extended_gcd(b % a, a)
        return gcd, y - (b // a) * x, x

def encrypt(public_key, plaintext):
    e, n = public_key
    return pow(plaintext, e, n)

def decrypt(private_key, ciphertext):
    d, n = private_key
    return pow(ciphertext, d, n)

def homomorphic_multiplication(c1, c2, n):
    return (c1 * c2) % n

# Main execution
# For simplicity, we'll use small prime numbers. In practice, use large primes.
p, q = 61, 53
public_key, private_key = generate_keypair(p, q)
n = public_key[1]  # n is the same for both public and private keys

# Encrypt two integers
m1, m2 = 7, 3
c1 = encrypt(public_key, m1)
c2 = encrypt(public_key, m2)

print(f"Ciphertext of {m1}: {c1}")
print(f"Ciphertext of {m2}: {c2}")

# Perform homomorphic multiplication
c_product = homomorphic_multiplication(c1, c2, n)
print(f"Encrypted product: {c_product}")

# Decrypt the result
decrypted_product = decrypt(private_key, c_product)
print(f"Decrypted product: {decrypted_product}")
print(f"Actual product: {m1 * m2}")
print(f"Verification: {'Successful' if decrypted_product == m1 * m2 else 'Failed'}")


# Output
# Ciphertext of 7: 1385
# Ciphertext of 3: 845
# Encrypted product: 3212
# Decrypted product: 21
# Actual product: 21
# Verification: Successful