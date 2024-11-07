from Crypto.Random import get_random_bytes
from Crypto.Util.number import getPrime, inverse
import time

# ---------------- DIFFIE-HELLMAN KEY EXCHANGE ----------------

class DiffieHellman:
    def __init__(self, p=None, g=None):
        # If not provided, we will generate large prime p and generator g
        if not p or not g:
            self.p = getPrime(2048)  # 2048-bit prime
            self.g = 2  # 2 is commonly used as the generator
        else:
            self.p = p
            self.g = g

        # Generate private key (random large number)
        self.private_key = self._generate_private_key()

        # Generate public key
        self.public_key = self._generate_public_key()

    def _generate_private_key(self):
        """
        Generates a random private key for the Diffie-Hellman exchange.
        """
        return int.from_bytes(get_random_bytes(256), byteorder="big")  # 256 bytes

    def _generate_public_key(self):
        """
        Generates the public key using the formula: g^private_key mod p
        """
        return pow(self.g, self.private_key, self.p)

    def compute_shared_secret(self, peer_public_key):
        """
        Compute the shared secret using the peer's public key.
        Shared secret formula: peer_public_key^private_key mod p
        """
        return pow(peer_public_key, self.private_key, self.p)


# ---------------- TIME MEASUREMENT FUNCTION ----------------

def measure_diffie_hellman_key_exchange():
    """
    Measure the time taken for key generation and key exchange between two peers.
    """
    # Measure key generation time for Peer A
    start_time = time.time()
    peer_a = DiffieHellman()
    key_gen_time_a = time.time() - start_time
    print(f"Peer A Key Generation Time: {key_gen_time_a:.6f} seconds")

    # Measure key generation time for Peer B
    start_time = time.time()
    peer_b = DiffieHellman(p=peer_a.p, g=peer_a.g)  # Use the same p and g for both peers
    key_gen_time_b = time.time() - start_time
    print(f"Peer B Key Generation Time: {key_gen_time_b:.6f} seconds")

    # Measure key exchange time (computing shared secret for both peers)
    start_time = time.time()
    shared_secret_a = peer_a.compute_shared_secret(peer_b.public_key)
    shared_secret_b = peer_b.compute_shared_secret(peer_a.public_key)
    key_exchange_time = time.time() - start_time
    print(f"Key Exchange Time: {key_exchange_time:.6f} seconds")

    # Verify that both peers computed the same shared secret
    if shared_secret_a == shared_secret_b:
        print("Shared secret computed successfully!")
    else:
        print("Error: Shared secrets do not match!")

    print(f"Shared Secret (hex): {shared_secret_a.to_bytes(256, byteorder='big').hex()}")

# ---------------- MAIN PROGRAM ----------------

if __name__ == "__main__":
    # Measure the Diffie-Hellman key exchange process
    measure_diffie_hellman_key_exchange()


# OUTPUT:
# Peer A Key Generation Time: 1.594317 seconds
# Peer B Key Generation Time: 0.030667 seconds
# Key Exchange Time: 0.103445 seconds
# Shared secret computed successfully!
# Shared Secret (hex): 4f051c1b1ef13a1d417e17a45be269161f4ccca16c44cf8f15836f49e2db874890fc85a9590e62d5b11cd263e4b0417d85763810231604332c86a8bdb1b6f2efce8418aeb382a6e73e52c01c24eaa5fac9baa23c7d31ae932645e1dbdb1eb0fff1446c47f3c717162e6b6ff326f22de9f151aaa501b71916fda6e21802a5169bc572acb5b124ab14881f65d6ea8bf9d394e7496291b05568c188233596f5819e4c0cac064767ae12708183016a17fc5d28ef5f621eaa8198d323e28afa38b26a2c8622bafa00cad9a08286debd66993c9ba7aae080d1e6dba55c8762d9010e091972a5a850abadbd00d13c4f06d891e5c988145d74caa6f57fd024e4db28ac98