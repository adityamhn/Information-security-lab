from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Message to encrypt
plaintext = b"Classified Text"

# Triple DES requires a key of 24 bytes (192 bits)
key = b"1234567890ABCDEF1234567890ABCDEF"[:24]  # Use the first 24 bytes of the given key

# Generate a random IV (initialization vector) for CBC mode
iv = get_random_bytes(8)

# Create a Triple DES cipher object in CBC mode
cipher = DES3.new(key, DES3.MODE_CBC, iv)

# Encrypt the plaintext (note: padding is necessary to ensure block size)
ciphertext = cipher.encrypt(pad(plaintext, DES3.block_size))

# To decrypt, recreate the cipher object with the same key and IV
cipher_decrypt = DES3.new(key, DES3.MODE_CBC, iv)
decrypted_text = unpad(cipher_decrypt.decrypt(ciphertext), DES3.block_size)

# Display the results
print("Ciphertext (hex):", ciphertext.hex())
print("Decrypted text:", decrypted_text.decode("utf-8"))


# OUTPUT:
# Ciphertext (hex): ebc8cb480d781a6cd64ec4c03356d62a
# Decrypted text: Classified Text