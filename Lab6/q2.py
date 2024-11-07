import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import hashlib

# -------------------- Diffie-Hellman Key Exchange --------------------

class DiffieHellman:
    def __init__(self, key_size=256):
        # Prime number and generator (p and g) for Diffie-Hellman
        self.p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1
        self.g = 2
        self.private_key = random.randint(1, self.p - 1)  # Private key (a random number)
    
    def generate_public_key(self):
        """Generate the public key to share with the other party."""
        return pow(self.g, self.private_key, self.p)  # g^private_key mod p

    def compute_shared_secret(self, other_public_key):
        """Compute the shared secret using the other party's public key."""
        shared_secret = pow(other_public_key, self.private_key, self.p)
        return hashlib.sha256(str(shared_secret).encode()).digest()  # Hash the shared secret for AES key

# -------------------- Symmetric Encryption (AES) --------------------

def aes_encrypt(key, plaintext):
    """Encrypt the plaintext using AES with the shared key."""
    cipher = AES.new(key, AES.MODE_CBC)  # Create AES cipher in CBC mode
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return cipher.iv, ciphertext  # Return the initialization vector and the ciphertext

def aes_decrypt(key, iv, ciphertext):
    """Decrypt the ciphertext using AES with the shared key."""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode()

# -------------------- Main Diffie-Hellman Key Exchange and Verification --------------------

def main():
    # Create two parties: Alice and Bob
    alice = DiffieHellman()
    bob = DiffieHellman()

    # Generate public keys
    alice_public_key = alice.generate_public_key()
    bob_public_key = bob.generate_public_key()

    print(f"Alice's public key: {alice_public_key}")
    print(f"Bob's public key: {bob_public_key}")

    # Both parties compute the shared secret
    alice_shared_key = alice.compute_shared_secret(bob_public_key)
    bob_shared_key = bob.compute_shared_secret(alice_public_key)

    print(f"Alice's shared key (SHA-256): {alice_shared_key.hex()}")
    print(f"Bob's shared key (SHA-256): {bob_shared_key.hex()}")

    # Verify that both parties have derived the same shared secret
    assert alice_shared_key == bob_shared_key, "Shared keys do not match!"
    print("Shared keys match! Secure communication can proceed.")

    # Use the shared key to encrypt and decrypt a message with AES
    message = "This is a confidential message!"
    print(f"\nOriginal Message: {message}")

    # Alice encrypts the message
    iv, ciphertext = aes_encrypt(alice_shared_key, message)
    print(f"Ciphertext (AES Encrypted): {ciphertext.hex()}")

    # Bob decrypts the message
    decrypted_message = aes_decrypt(bob_shared_key, iv, ciphertext)
    print(f"Decrypted Message: {decrypted_message}")

if __name__ == "__main__":
    main()


# Output:
# Alice's public key: 3046238479754092551546788423430164471583104029604108696438
# Bob's public key: 6218796018271298899956959472877389071298740584399128947438
# Alice's shared key (SHA-256): ebaa57506a614231f6afd6316da248cdb52858a04ecc99f9da7bf6ee101ef870
# Bob's shared key (SHA-256): ebaa57506a614231f6afd6316da248cdb52858a04ecc99f9da7bf6ee101ef870
# Shared keys match! Secure communication can proceed.

# Original Message: This is a confidential message!
# Ciphertext (AES Encrypted): 24bdaa9bfac3fdec1a770e6491dfd95e94e2a1ce278a349eb9ab9c761cab4a7a
# Decrypted Message: This is a confidential message!