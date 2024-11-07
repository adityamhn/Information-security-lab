import random
import sympy

# Key generation for Rabin cryptosystem
def generate_rabin_keys(bits=512):
    # Generate two large primes p and q congruent to 3 mod 4
    while True:
        p = sympy.nextprime(random.getrandbits(bits // 2))
        if p % 4 == 3:
            break
    while True:
        q = sympy.nextprime(random.getrandbits(bits // 2))
        if q % 4 == 3:
            break
    n = p * q
    return (n, p, q)

# Rabin encryption
def rabin_encrypt(message, n):
    # Convert the message to an integer
    m = int.from_bytes(message.encode(), 'big')
    # Calculate the ciphertext: C = M^2 mod n
    c = pow(m, 2, n)
    return c

# Rabin decryption
def rabin_decrypt(ciphertext, p, q):
    # Use the Chinese Remainder Theorem (CRT) to find the four possible plaintexts
    # Solve m1 = ±√c mod p and m2 = ±√c mod q
    m1 = pow(ciphertext, (p + 1) // 4, p)
    m2 = pow(ciphertext, (q + 1) // 4, q)
    n = p * q

    # Using CRT to calculate the four solutions
    def crt(a, b, p, q):
        # Combine results using CRT: x ≡ a (mod p) and x ≡ b (mod q)
        _, yp, yq = sympy.gcdex(p, q)
        return (a * yq * q + b * yp * p) % (p * q)

    # Calculate the four possible messages
    r1 = crt(m1, m2, p, q)
    r2 = crt(m1, -m2 % q, p, q)
    r3 = crt(-m1 % p, m2, p, q)
    r4 = crt(-m1 % p, -m2 % q, p, q)

    # Convert the integer results back to bytes and decode
    possible_messages = []
    for r in [r1, r2, r3, r4]:
        try:
            # Convert sympy.Integer to Python int
            message_int = int(r)
            possible_messages.append(message_int.to_bytes((message_int.bit_length() + 7) // 8, 'big').decode())
        except UnicodeDecodeError:
            # Skip non-decodable solutions
            pass

    return possible_messages

# Example Usage
# Generate keys
n, p, q = generate_rabin_keys(bits=512)
message = "Hello, Rabin!"

# Encrypt the message
ciphertext = rabin_encrypt(message, n)
print("Encrypted Ciphertext:", ciphertext)

# Decrypt the message
decrypted_messages = rabin_decrypt(ciphertext, p, q)
print("Possible Decrypted Messages:", decrypted_messages)
