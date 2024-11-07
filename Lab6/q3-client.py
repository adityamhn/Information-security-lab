import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import hashlib
import random

# -------------------- Diffie-Hellman Key Exchange (Client) --------------------

class DiffieHellmanClient:
    def __init__(self, key_size=256):
        # Prime number and generator (p and g) for Diffie-Hellman
        self.p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1
        self.g = 2
        self.private_key = random.randint(1, self.p - 1)  # Client private key

    def generate_public_key(self):
        """Generate the public key to send to the server."""
        return pow(self.g, self.private_key, self.p)  # g^private_key mod p

    def compute_shared_secret(self, server_public_key):
        """Compute the shared secret using the server's public key."""
        shared_secret = pow(server_public_key, self.private_key, self.p)
        return hashlib.sha256(str(shared_secret).encode()).digest()  # SHA-256 of shared secret

def aes_encrypt(key, plaintext):
    """Encrypt the plaintext using AES."""
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return cipher.iv, ciphertext

def client_program():
    client = DiffieHellmanClient()
    client_public_key = client.generate_public_key()

    # Setting up socket connection
    host = '127.0.0.1'
    port = 65432

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))

        # Step 1: Receive server public key
        server_public_key = int(s.recv(1024).decode())
        print(f"Received Server's Public Key: {server_public_key}")

        # Step 2: Send client public key to server
        s.sendall(str(client_public_key).encode())
        print(f"Sent Client's Public Key: {client_public_key}")

        # Step 3: Compute shared secret
        shared_secret = client.compute_shared_secret(server_public_key)
        print(f"Client's Shared Secret (SHA-256): {shared_secret.hex()}")

        # Step 4: Encrypt and send a message using the shared secret
        message = "Hello Server! This message is confidential."
        iv, ciphertext = aes_encrypt(shared_secret, message)
        print(f"Sending Ciphertext: {ciphertext.hex()}")

        # Send IV and ciphertext
        s.sendall(iv)  # IV is sent separately
        s.sendall(ciphertext)

if __name__ == "__main__":
    client_program()



# Server listening on 127.0.0.1:65432...
# Connected by ('127.0.0.1', 57385)
# Received Client's Public Key: 2994285816226243502364570731856903376361415227832058412664
# Server's Shared Secret (SHA-256): 113958fd81ee61d4b7d417ad03ad9c742830469341cf7180a0eeeb9dafe07213
# Received Ciphertext: 4dd237935aa2a01f9085eca9b36a991b34c5b54527ce681090f3514fc1c0b176eabb2b8d5e3bff5cd28f2b3809b7ee3d
# Decrypted Message: Hello Server! This message is confidential.