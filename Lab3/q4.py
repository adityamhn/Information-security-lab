from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from ecies.utils import generate_key
from ecies import encrypt, decrypt
import os
import time


# ---------------- RSA FUNCTIONS ----------------

# RSA Key Generation (2048-bit)
def generate_rsa_keys():
    """
    Generate RSA key pair (public and private keys).
    Returns:
        private_key (bytes): The private key in bytes format.
        public_key (bytes): The public key in bytes format.
    """
    start_time = time.time()
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    key_gen_time = time.time() - start_time
    print(f"RSA Key Generation Time: {key_gen_time:.6f} seconds")
    return private_key, public_key


# RSA Encryption (Hybrid with AES for large files)
def rsa_encrypt_file(file_path, public_key):
    """
    Encrypt a file using RSA (to encrypt AES key) and AES (to encrypt the file).
    Args:
        file_path (str): The path to the file to encrypt.
        public_key (bytes): The RSA public key to use for encryption.
    Returns:
        encrypted_aes_key (bytes): The AES key encrypted with RSA.
        iv (bytes): Initialization vector used for AES encryption.
        ciphertext (bytes): The encrypted file content.
    """
    # Load the RSA public key
    rsa_key = RSA.import_key(public_key)
    rsa_cipher = PKCS1_OAEP.new(rsa_key)

    # Generate AES key for file encryption
    aes_key = get_random_bytes(32)
    aes_cipher = AES.new(aes_key, AES.MODE_CBC)

    # Encrypt AES key with RSA
    encrypted_aes_key = rsa_cipher.encrypt(aes_key)

    # Read and encrypt file
    with open(file_path, 'rb') as f:
        plaintext = f.read()
        ciphertext = aes_cipher.encrypt(pad(plaintext, AES.block_size))

    return encrypted_aes_key, aes_cipher.iv, ciphertext


# RSA Decryption (Hybrid with AES for large files)
def rsa_decrypt_file(encrypted_aes_key, iv, ciphertext, private_key):
    """
    Decrypt a file using RSA (to decrypt AES key) and AES (to decrypt the file).
    Args:
        encrypted_aes_key (bytes): The AES key encrypted with RSA.
        iv (bytes): Initialization vector used for AES encryption.
        ciphertext (bytes): The encrypted file content.
        private_key (bytes): The RSA private key to use for decryption.
    Returns:
        plaintext (bytes): The decrypted file content.
    """
    # Load the RSA private key
    rsa_key = RSA.import_key(private_key)
    rsa_cipher = PKCS1_OAEP.new(rsa_key)

    # Decrypt AES key
    aes_key = rsa_cipher.decrypt(encrypted_aes_key)

    # Decrypt the file using AES
    aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    plaintext = unpad(aes_cipher.decrypt(ciphertext), AES.block_size)

    return plaintext


# ---------------- ECC FUNCTIONS ----------------

# ECC Key Generation (secp256r1 curve)
def generate_ecc_keys():
    """
    Generate ECC key pair (private and public keys) using secp256r1 curve.
    Returns:
        private_key (str): The ECC private key in hex format.
        public_key (bytes): The ECC public key in bytes format.
    """
    start_time = time.time()
    private_key = generate_key()
    public_key = private_key.public_key
    key_gen_time = time.time() - start_time
    print(f"ECC Key Generation Time: {key_gen_time:.6f} seconds")
    return private_key.to_hex(), public_key.format(True)


# ECC Encryption
def ecc_encrypt_file(file_path, public_key):
    """
    Encrypt a file using ECC (ECIES).
    Args:
        file_path (str): The path to the file to encrypt.
        public_key (bytes): The ECC public key to use for encryption.
    Returns:
        ciphertext (bytes): The encrypted file content.
    """
    with open(file_path, 'rb') as f:
        plaintext = f.read()
        ciphertext = encrypt(public_key, plaintext)
    return ciphertext


# ECC Decryption
def ecc_decrypt_file(ciphertext, private_key):
    """
    Decrypt a file using ECC (ECIES).
    Args:
        ciphertext (bytes): The encrypted file content.
        private_key (str): The ECC private key to use for decryption (in hex format).
    Returns:
        plaintext (bytes): The decrypted file content.
    """
    plaintext = decrypt(private_key, ciphertext)
    return plaintext


# ---------------- PERFORMANCE TESTING FUNCTIONS ----------------

# Create a test file with random content of a given size
def create_test_file(file_path, size_in_mb):
    """
    Create a random file of the given size.
    Args:
        file_path (str): The path to the file to create.
        size_in_mb (int): The size of the file to create, in megabytes.
    """
    with open(file_path, 'wb') as f:
        f.write(os.urandom(size_in_mb * 1024 * 1024))  # Generate random bytes for file


# Measure RSA and ECC performance
def measure_performance():
    """
    Measure and compare the performance of RSA and ECC encryption and decryption.
    """
    # Create test files (1MB and 10MB)
    file_1mb = "test_1mb.bin"
    file_10mb = "test_10mb.bin"
    create_test_file(file_1mb, 1)
    create_test_file(file_10mb, 10)

    # ---------------- RSA Performance ----------------
    private_key_rsa, public_key_rsa = generate_rsa_keys()

    # Encrypt and Decrypt 1MB file with RSA
    start_time = time.time()
    encrypted_aes_key, iv, ciphertext_rsa_1mb = rsa_encrypt_file(file_1mb, public_key_rsa)
    rsa_encryption_time_1mb = time.time() - start_time
    print(f"RSA Encryption Time (1MB): {rsa_encryption_time_1mb:.6f} seconds")

    start_time = time.time()
    decrypted_text_rsa = rsa_decrypt_file(encrypted_aes_key, iv, ciphertext_rsa_1mb, private_key_rsa)
    rsa_decryption_time_1mb = time.time() - start_time
    print(f"RSA Decryption Time (1MB): {rsa_decryption_time_1mb:.6f} seconds")

    # ---------------- ECC Performance ----------------
    private_key_ecc, public_key_ecc = generate_ecc_keys()

    # Encrypt and Decrypt 1MB file with ECC
    start_time = time.time()
    ciphertext_ecc_1mb = ecc_encrypt_file(file_1mb, public_key_ecc)
    ecc_encryption_time_1mb = time.time() - start_time
    print(f"ECC Encryption Time (1MB): {ecc_encryption_time_1mb:.6f} seconds")

    start_time = time.time()
    decrypted_text_ecc = ecc_decrypt_file(ciphertext_ecc_1mb, private_key_ecc)
    ecc_decryption_time_1mb = time.time() - start_time
    print(f"ECC Decryption Time (1MB): {ecc_decryption_time_1mb:.6f} seconds")


# ---------------- MAIN PROGRAM ----------------

if __name__ == "__main__":
    # Measure the performance of RSA and ECC
    measure_performance()


# OUTPUT:
# RSA Key Generation Time: 0.287670 seconds
# RSA Encryption Time (1MB): 0.009329 seconds
# RSA Decryption Time (1MB): 0.030310 seconds
# ECC Key Generation Time: 0.000431 seconds
# ECC Encryption Time (1MB): 0.010126 seconds
# ECC Decryption Time (1MB): 0.012148 seconds