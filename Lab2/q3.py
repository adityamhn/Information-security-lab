import time
from Crypto.Cipher import DES, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# Message to be encrypted
plaintext = b"Performance Testing of Encryption Algorithms"

# DES Setup (DES key is 8 bytes long)
des_key = b"01234567"  # 8-byte key for DES
des_iv = get_random_bytes(8)  # DES requires an 8-byte IV
des_cipher = DES.new(des_key, DES.MODE_CBC, des_iv)

# AES-256 Setup (AES-256 key is 32 bytes long)
aes_key = b"0123456789ABCDEF0123456789ABCDEF"  # 32-byte key for AES-256
aes_iv = get_random_bytes(16)  # AES requires a 16-byte IV
aes_cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)

# Perform DES encryption and decryption timing
start_time = time.time()
des_ciphertext = des_cipher.encrypt(pad(plaintext, DES.block_size))
des_encryption_time = time.time() - start_time

des_cipher_decrypt = DES.new(des_key, DES.MODE_CBC, des_iv)
start_time = time.time()
des_decrypted_text = unpad(des_cipher_decrypt.decrypt(des_ciphertext), DES.block_size)
des_decryption_time = time.time() - start_time

# Perform AES-256 encryption and decryption timing
start_time = time.time()
aes_ciphertext = aes_cipher.encrypt(pad(plaintext, AES.block_size))
aes_encryption_time = time.time() - start_time

aes_cipher_decrypt = AES.new(aes_key, AES.MODE_CBC, aes_iv)
start_time = time.time()
aes_decrypted_text = unpad(aes_cipher_decrypt.decrypt(aes_ciphertext), AES.block_size)
aes_decryption_time = time.time() - start_time

# Display results
print(f"DES Encryption Time: {des_encryption_time} seconds")
print(f"DES Decryption Time: {des_decryption_time} seconds")
print(f"AES-256 Encryption Time: {aes_encryption_time} seconds")
print(f"AES-256 Decryption Time: {aes_decryption_time} seconds")


# OUTPUT:
# DES Encryption Time: 0.00011587142944335938 seconds
# DES Decryption Time: 2.384185791015625e-05 seconds
# AES-256 Encryption Time: 1.0967254638671875e-05 seconds
# AES-256 Decryption Time: 1.0967254638671875e-05 seconds