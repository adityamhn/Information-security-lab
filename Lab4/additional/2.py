import math
from Crypto.Util import number

# -------------------- Weak RSA Key Generation --------------------

def generate_weak_rsa_key(key_size):
    """Generate RSA keys with small primes."""
    p = number.getPrime(key_size // 2)  # First prime
    q = number.getPrime(key_size // 2)  # Second prime
    n = p * q  # RSA modulus
    e = 65537  # Public exponent (common choice)

    # Compute Euler's totient function φ(n)
    phi = (p - 1) * (q - 1)

    # Compute the private exponent d
    d = pow(e, -1, phi)

    # Return public and private keys
    public_key = (n, e)
    private_key = (n, d)
    
    return public_key, private_key, p, q

# -------------------- Eve's Attack to Recover Private Key --------------------

def factorize_n(n):
    """Use trial division to factorize n and recover p and q."""
    # Brute-force factorization by checking divisibility with small numbers
    for i in range(2, math.isqrt(n) + 1):  # math.isqrt(n) is the integer square root of n
        if n % i == 0:  # If i divides n, then it's a factor
            p = i
            q = n // i
            return p, q
    return None

def recover_private_key(p, q, e, n):
    """Recover the private key d using p, q, and the public exponent e."""
    phi = (p - 1) * (q - 1)  # Euler's totient function φ(n)
    d = pow(e, -1, phi)  # Calculate private exponent d
    return d

# -------------------- Attack Demonstration --------------------

def rsa_attack_demo():
    # Generate a weak RSA keypair
    print("Generating weak RSA keypair with small primes...")
    key_size = 512  # Small key size for demonstration (insecure)
    public_key, private_key, p, q = generate_weak_rsa_key(key_size)
    n, e = public_key

    print(f"Public Key (n, e): ({n}, {e})")
    print(f"Private Key (n, d): ({private_key[0]}, {private_key[1]})")

    # Simulate Eve's attack by factorizing n to recover p and q
    print("\nEve is attempting to factorize n to recover p and q...")
    recovered_p, recovered_q = factorize_n(n)
    if recovered_p and recovered_q:
        print(f"Successfully factorized n: p = {recovered_p}, q = {recovered_q}")
    else:
        print("Failed to factorize n. (In practice, this would be infeasible for large primes.)")
        return

    # Recover the private key using p, q, and e
    recovered_d = recover_private_key(recovered_p, recovered_q, e, n)
    print(f"\nEve has successfully recovered the private key: d = {recovered_d}")

    # Check if Eve's private key matches the original private key
    if recovered_d == private_key[1]:
        print("Eve has successfully recovered the full private key!")
    else:
        print("Eve failed to recover the private key.")

# -------------------- Mitigation Strategies --------------------

def mitigation_strategies():
    print("\nMitigation strategies to prevent this type of attack:")
    print("1. Use sufficiently large prime numbers (e.g., at least 2048 bits for modern security).")
    print("2. Ensure that prime numbers used in RSA key generation are truly random.")
    print("3. Avoid using predictable or low-entropy random number generators for prime generation.")
    print("4. Periodically rotate keys and monitor for any potential key compromise.")
    print("5. Employ stronger encryption schemes if necessary (e.g., elliptic curve cryptography).")

# -------------------- Main --------------------

if __name__ == "__main__":
    rsa_attack_demo()
    mitigation_strategies()
