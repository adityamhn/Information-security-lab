import hashlib
import sympy
import random

# Step 1: Key generation
def generate_rabin_keys(bits=512):
    # Generate two large primes p and q
    p = sympy.nextprime(random.getrandbits(bits // 2))
    q = sympy.nextprime(random.getrandbits(bits // 2))
    n = p * q
    return (n, p, q)

# Step 2: Hash the message and create the signature
def hash_message(message):
    # Hash the message using SHA-256
    return int(hashlib.sha256(message.encode()).hexdigest(), 16)

def sign_rabin(message, n, p, q):
    H = hash_message(message)
    # Calculate the signature S: S^2 ≡ H(M) mod n
    # We need to find a square root modulo n (solve S^2 ≡ H mod n)
    # Randomly selecting a candidate S that matches, if there’s ambiguity.
    # This may need extra handling to disambiguate in a full implementation.
    S = pow(H, (p + 1) // 4, p) * pow(H, (q + 1) // 4, q) % n
    return S

# Step 3: Verification
def verify_rabin_signature(signature, message, n):
    H = hash_message(message)
    # Verify: S^2 ≡ H(M) mod n
    return (signature * signature) % n == H % n

# Example Usage
# Generate keys
n, p, q = generate_rabin_keys(bits=512)
message = "Cryptographic Protocols"

# Sign the message
signature = sign_rabin(message, n, p, q)
print("Signature:", signature)

# Verify the signature
is_valid = verify_rabin_signature(signature, message, n)
print("Signature valid:", is_valid)
