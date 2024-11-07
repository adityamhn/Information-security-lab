from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

# List of messages to encrypt
messages = [
    b"Message 1: Secret",
    b"Message 2: Top Secret",
    b"Message 3: Classified",
    b"Message 4: Confidential",
    b"Message 5: Highly Confidential"
]

# DES Key (must be exactly 8 bytes)
des_key = b"12345678"
# AES-128, AES-192, AES-256 Keys (16, 24, and 32 bytes respectively)
aes_key_128 = b"1234567890ABCDEF"           # 128-bit key
aes_key_192 = b"1234567890ABCDEF12345678"    # 192-bit key
aes_key_256 = b"1234567890ABCDEF1234567890ABCDEF"  # 256-bit key

# DES Encryption
def encrypt_des(message, key):
    iv = get_random_bytes(8)  # DES requires an 8-byte IV
    cipher = DES.new(key, DES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(message, DES.block_size))
    return iv + ciphertext  # Prepend IV to ciphertext

# AES Encryption (takes key and message as input)
def encrypt_aes(message, key):
    iv = get_random_bytes(16)  # AES requires a 16-byte IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(message, AES.block_size))
    return iv + ciphertext  # Prepend IV to ciphertext

# Encrypt messages using DES
print("DES Encryption:")
for message in messages:
    ciphertext = encrypt_des(message, des_key)
    print(f"Ciphertext (hex) for '{message.decode('utf-8')}': {ciphertext.hex()}")

# Encrypt messages using AES-128
print("\nAES-128 Encryption:")
for message in messages:
    ciphertext = encrypt_aes(message, aes_key_128)
    print(f"Ciphertext (hex) for '{message.decode('utf-8')}': {ciphertext.hex()}")

# Encrypt messages using AES-192
print("\nAES-192 Encryption:")
for message in messages:
    ciphertext = encrypt_aes(message, aes_key_192)
    print(f"Ciphertext (hex) for '{message.decode('utf-8')}': {ciphertext.hex()}")

# Encrypt messages using AES-256
print("\nAES-256 Encryption:")
for message in messages:
    ciphertext = encrypt_aes(message, aes_key_256)
    print(f"Ciphertext (hex) for '{message.decode('utf-8')}': {ciphertext.hex()}")
