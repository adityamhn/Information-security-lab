from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from ecies import encrypt, decrypt
from ecies.utils import generate_key
import time
import os

# Generate RSA keys (2048-bit)
def generate_rsa_keys():
    start_time = time.time()
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    key_gen_time = time.time() - start_time
    return private_key, public_key, key_gen_time

# RSA encryption of AES key and AES encryption of the message
def rsa_aes_encrypt_decrypt(public_key, private_key, message):
    rsa_key = RSA.import_key(public_key)
    rsa_cipher = PKCS1_OAEP.new(rsa_key)

    # Step 1: Generate AES key
    aes_key = get_random_bytes(32)  # AES-256 key

    # Encrypt AES key using RSA
    start_time = time.time()
    encrypted_aes_key = rsa_cipher.encrypt(aes_key)
    encryption_time_rsa = time.time() - start_time

    # Step 2: Encrypt the message using AES
    aes_cipher = AES.new(aes_key, AES.MODE_CBC)
    ciphertext_aes = aes_cipher.encrypt(pad(message, AES.block_size))
    
    # Step 3: Decrypt the AES key using RSA
    rsa_private_key = RSA.import_key(private_key)
    rsa_cipher_decrypt = PKCS1_OAEP.new(rsa_private_key)

    start_time = time.time()
    decrypted_aes_key = rsa_cipher_decrypt.decrypt(encrypted_aes_key)  # FIXED: decrypt method used here
    decryption_time_rsa = time.time() - start_time

    # Step 4: Decrypt the message using AES
    aes_cipher_decrypt = AES.new(decrypted_aes_key, AES.MODE_CBC, aes_cipher.iv)
    decrypted_message_aes = unpad(aes_cipher_decrypt.decrypt(ciphertext_aes), AES.block_size)

    return ciphertext_aes, decrypted_message_aes, encryption_time_rsa, decryption_time_rsa

# Generate ECC keys for ElGamal (secp256r1)
def generate_ecc_keys():
    start_time = time.time()
    private_key = generate_key()
    public_key = private_key.public_key
    key_gen_time = time.time() - start_time
    return private_key, public_key, key_gen_time

# ElGamal encryption and decryption using secp256r1 curve
def ecc_encrypt_decrypt(public_key, private_key, message):
    # Encrypt
    start_time = time.time()
    ciphertext = encrypt(public_key.format(True), message)
    encryption_time = time.time() - start_time

    # Decrypt
    start_time = time.time()
    decrypted_message = decrypt(private_key.to_hex(), ciphertext)
    decryption_time = time.time() - start_time

    return ciphertext, decrypted_message, encryption_time, decryption_time

# Generate random message data of specified size
def generate_message_data(size_in_kb):
    return os.urandom(size_in_kb * 1024)  # Random bytes

# Run tests for both RSA and ElGamal for different message sizes
def run_tests(message_sizes):
    print(f"{'Algorithm':<15} | {'Message Size (KB)':<15} | {'Key Gen Time (s)':<15} | {'Enc Time (s)':<15} | {'Dec Time (s)':<15}")
    print("-" * 70)

    # Test RSA + AES (Hybrid)
    private_key_rsa, public_key_rsa, key_gen_time_rsa = generate_rsa_keys()

    for size in message_sizes:
        message = generate_message_data(size)

        # RSA + AES encryption and decryption
        _, decrypted_message_rsa, encryption_time_rsa, decryption_time_rsa = rsa_aes_encrypt_decrypt(public_key_rsa, private_key_rsa, message)
        if message == decrypted_message_rsa:
            print(f"RSA+AES         | {size:<15} | {key_gen_time_rsa:<15.6f} | {encryption_time_rsa:<15.6f} | {decryption_time_rsa:<15.6f}")
        else:
            print(f"RSA+AES encryption/decryption failed for {size} KB message")

    # Test ElGamal with ECC
    private_key_ecc, public_key_ecc, key_gen_time_ecc = generate_ecc_keys()

    for size in message_sizes:
        message = generate_message_data(size)

        # ECC encryption and decryption
        _, decrypted_message_ecc, encryption_time_ecc, decryption_time_ecc = ecc_encrypt_decrypt(public_key_ecc, private_key_ecc, message)
        if message == decrypted_message_ecc:
            print(f"ECC ElGamal      | {size:<15} | {key_gen_time_ecc:<15.6f} | {encryption_time_ecc:<15.6f} | {decryption_time_ecc:<15.6f}")
        else:
            print(f"ECC ElGamal encryption/decryption failed for {size} KB message")

# Run the performance tests
message_sizes = [1, 10, 100, 1024]  # Sizes in KB
run_tests(message_sizes)


# Algorithm       | Message Size (KB) | Key Gen Time (s) | Enc Time (s)    | Dec Time (s)   
# ----------------------------------------------------------------------
# RSA+AES         | 1               | 0.423840        | 0.001563        | 0.001321       
# RSA+AES         | 10              | 0.423840        | 0.000308        | 0.000917       
# RSA+AES         | 100             | 0.423840        | 0.000271        | 0.001777       
# RSA+AES         | 1024            | 0.423840        | 0.000282        | 0.000912       
# ECC ElGamal      | 1               | 0.000465        | 0.002070        | 0.005374       
# ECC ElGamal      | 10              | 0.000465        | 0.000303        | 0.000252       
# ECC ElGamal      | 100             | 0.000465        | 0.001118        | 0.001531       
# ECC ElGamal      | 1024            | 0.000465        | 0.012825        | 0.009142  