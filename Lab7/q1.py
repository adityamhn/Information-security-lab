import random
import math

# Paillier Key Generation
def lcm(x, y):
    # Calculates the Least Common Multiple (LCM) of two integers x and y
    return x * y // math.gcd(x, y)

def modinv(a, m):
    # Computes the modular inverse of a modulo m using the Extended Euclidean Algorithm
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        # If the GCD of a and m is not 1, there is no modular inverse
        raise Exception('Modular inverse does not exist')
    else:
        # Returns the modular inverse (x) mod m
        return x % m

def extended_gcd(a, b):
    # Recursive implementation of the Extended Euclidean Algorithm
    if a == 0:
        # Base case: if a is 0, return b as the GCD and coefficients
        return b, 0, 1
    # Recursive case: compute the GCD, x1, and y1
    g, x1, y1 = extended_gcd(b % a, a)
    # Update x and y based on the recursive result
    x = y1 - (b // a) * x1
    y = x1
    # Return the GCD, x, and y
    return g, x, y

class Paillier:
    def __init__(self, bit_length=512):
        # Initializes Paillier encryption system with key generation
        
        self.bit_length = bit_length
        # Generate two large primes p and q
        self.p, self.q = self.generate_large_primes()
        # Compute n = p * q
        self.n = self.p * self.q
        # Compute lambda (λ), the LCM of p-1 and q-1
        self.lambda_ = lcm(self.p - 1, self.q - 1)
        # g is set to n + 1 (simplifies encryption process)
        self.g = self.n + 1
        # Compute the modular inverse mu using the L function and g^λ mod n^2
        self.mu = modinv(self.L(pow(self.g, self.lambda_, self.n ** 2)), self.n)

    def generate_large_primes(self):
        # Generate two large random prime numbers p and q
        p = self.generate_prime(self.bit_length // 2)
        q = self.generate_prime(self.bit_length // 2)
        return p, q

    def generate_prime(self, bits):
        # Generate a random prime number of the specified bit length
        while True:
            prime = random.getrandbits(bits)  # Generate a random number with the given bit length
            if self.is_prime(prime):  # Check if the number is prime
                return prime  # Return the prime if the check passes

    def is_prime(self, n, k=10):
        # Miller-Rabin primality test to check if n is prime (k iterations)
        if n == 2 or n == 3:
            return True  # 2 and 3 are prime numbers
        if n % 2 == 0 or n == 1:
            return False  # Even numbers (other than 2) and 1 are not prime
        
        # Write n - 1 as d * 2^r where d is odd
        d, r = n - 1, 0
        while d % 2 == 0:
            d //= 2
            r += 1
        
        # Perform k iterations of the Miller-Rabin test
        for _ in range(k):
            a = random.randint(2, n - 2)  # Random integer a in range [2, n-2]
            x = pow(a, d, n)  # Compute a^d mod n
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)  # Compute x^2 mod n
                if x == n - 1:
                    break
            else:
                return False  # Composite number found
        return True  # Probably prime

    def L(self, u):
        # The L function used in decryption, defined as (u - 1) // n
        return (u - 1) // self.n

    def encrypt(self, m):
        # Encrypts the message m
        r = random.randint(1, self.n - 1)  # Choose a random r in the range [1, n-1]
        # Compute ciphertext using the Paillier encryption formula
        return (pow(self.g, m, self.n ** 2) * pow(r, self.n, self.n ** 2)) % (self.n ** 2)

    def decrypt(self, c):
        # Decrypts the ciphertext c
        u = pow(c, self.lambda_, self.n ** 2)  # Compute u = c^λ mod n^2
        # Compute the original message m using the L function and mu
        return (self.L(u) * self.mu) % self.n

# Main Paillier Encryption and Homomorphic Addition
if __name__ == "__main__":
    # Create an instance of the Paillier encryption system
    paillier = Paillier()

    # Encrypt two integers
    m1 = 15  # First plaintext message
    m2 = 25  # Second plaintext message
    # Encrypt the plaintext integers
    c1 = paillier.encrypt(m1)
    c2 = paillier.encrypt(m2)

    # Print the ciphertexts for m1 and m2
    print(f"Ciphertext of {m1}: {c1}")
    print(f"Ciphertext of {m2}: {c2}")

    # Perform addition of encrypted values using homomorphic property of Paillier
    # Multiply the two ciphertexts to get the encryption of (m1 + m2)
    encrypted_sum = (c1 * c2) % (paillier.n ** 2)

    # Print the encrypted sum (ciphertext of m1 + m2)
    print(f"Encrypted sum: {encrypted_sum}")

    # Decrypt the sum to retrieve the original result (m1 + m2)
    decrypted_sum = paillier.decrypt(encrypted_sum)
    print(f"Decrypted sum: {decrypted_sum}")

    # Verify the decryption matches the expected result (m1 + m2)
    assert decrypted_sum == m1 + m2, "Decryption failed, incorrect sum."
    print(f"Sum of {m1} and {m2} matches the decrypted result.")
