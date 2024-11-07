from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# Message to encrypt
plaintext = b"Sensitive Information"

# AES-128 key (16 bytes = 128 bits)
key = b"0123456789ABCDEF"  # AES-128 requires the key to be exactly 16 bytes

# Generate a random IV (initialization vector)
iv = get_random_bytes(16)

# Create AES cipher object in CBC mode
cipher = AES.new(key, AES.MODE_CBC, iv)

# Encrypt the plaintext (note: AES block size is 16 bytes, so we must pad the plaintext)
ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

# Print the ciphertext in hexadecimal format
print("Ciphertext (hex):", ciphertext.hex())

# To decrypt the message, create a new cipher object with the same key and IV
cipher_decrypt = AES.new(key, AES.MODE_CBC, iv)

# Decrypt and unpad the ciphertext
decrypted_text = unpad(cipher_decrypt.decrypt(ciphertext), AES.block_size)

# Print the decrypted text
print("Decrypted text:", decrypted_text.decode("utf-8"))


# OUTPUT:
# Ciphertext (hex): ece418a211fac3ddd861b05d6a08bbd0c11c612ce01bf7ed8cf1db6e25bdc487
# Decrypted text: Sensitive Information