import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import random

# -------------------- Diffie-Hellman Key Exchange (Server) --------------------

class DiffieHellmanServer:
    def __init__(self, key_size=256):
        # Prime number and generator (p and g) for Diffie-Hellman
        self.p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1
        self.g = 2
        self.private_key = random.randint(1, self.p - 1)  # Server private key

    def generate_public_key(self):
        """Generate the public key to send to the client."""
        return pow(self.g, self.private_key, self.p)  # g^private_key mod p

    def compute_shared_secret(self, client_public_key):
        """Compute the shared secret using the client's public key."""
        shared_secret = pow(client_public_key, self.private_key, self.p)
        return hashlib.sha256(str(shared_secret).encode()).digest()  # SHA-256 of shared secret

def aes_decrypt(key, iv, ciphertext):
    """Decrypt the AES ciphertext."""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode()

def server_program():
    server = DiffieHellmanServer()
    server_public_key = server.generate_public_key()

    # Setting up socket connection
    host = '127.0.0.1'
    port = 65432

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print(f"Server listening on {host}:{port}...")

        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")

            # Step 1: Send server public key to client
            conn.sendall(str(server_public_key).encode())

            # Step 2: Receive client's public key
            client_public_key = int(conn.recv(1024).decode())
            print(f"Received Client's Public Key: {client_public_key}")

            # Step 3: Compute shared secret
            shared_secret = server.compute_shared_secret(client_public_key)
            print(f"Server's Shared Secret (SHA-256): {shared_secret.hex()}")

            # Step 4: Receive AES-encrypted message
            iv = conn.recv(16)  # AES IV is always 16 bytes
            ciphertext = conn.recv(1024)
            print(f"Received Ciphertext: {ciphertext.hex()}")

            # Step 5: Decrypt the message using the shared secret
            decrypted_message = aes_decrypt(shared_secret, iv, ciphertext)
            print(f"Decrypted Message: {decrypted_message}")

if __name__ == "__main__":
    server_program()


# Received Server's Public Key: 5499505891735835615176679433906551302964266023861169629593
# Sent Client's Public Key: 2994285816226243502364570731856903376361415227832058412664
# Client's Shared Secret (SHA-256): 113958fd81ee61d4b7d417ad03ad9c742830469341cf7180a0eeeb9dafe07213
# Sending Ciphertext: 4dd237935aa2a01f9085eca9b36a991b34c5b54527ce681090f3514fc1c0b176eabb2b8d5e3bff5cd28f2b3809b7ee3d