from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Message to encrypt
plaintext = b"Encryption Strength"

# AES-256 key (must be 32 bytes for AES-256)
key = b"0123456789ABCDEF0123456789ABCDEF"  # 32-byte key

# AES requires a 16-byte IV (Initialization Vector) for CBC mode
iv = get_random_bytes(16)

# Create AES cipher object in CBC mode
cipher = AES.new(key, AES.MODE_CBC, iv)

# Encrypt the plaintext (note: padding is necessary to ensure block size)
ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

# Display ciphertext in hexadecimal format
print("Ciphertext (hex):", ciphertext.hex())

# To decrypt, recreate the cipher object with the same key and IV
cipher_decrypt = AES.new(key, AES.MODE_CBC, iv)

# Decrypt and unpad the ciphertext
decrypted_text = unpad(cipher_decrypt.decrypt(ciphertext), AES.block_size)

# Display the decrypted text
print("Decrypted text:", decrypted_text.decode('utf-8'))


# OUTPUT:
# Ciphertext (hex): 6abfc60d7cd8f7fc13e51104c3464fadb26b2f52d265529f6c879aa5ebf471a1
# Decrypted text: Encryption Strength