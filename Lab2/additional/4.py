from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

# Message to encrypt
plaintext = b"Secure Communication"

# DES key (must be 8 bytes for DES)
key = b"A1B2C3D4"

# Initialization Vector (IV) must be 8 bytes for DES
iv = b"12345678"

# Create a DES cipher object in CBC mode
cipher = DES.new(key, DES.MODE_CBC, iv)

# Encrypt the plaintext (note: padding is necessary to ensure block size)
ciphertext = cipher.encrypt(pad(plaintext, DES.block_size))

# Display ciphertext in hexadecimal format
print("Ciphertext (hex):", ciphertext.hex())

# Decrypt the ciphertext to retrieve the original message
cipher_decrypt = DES.new(key, DES.MODE_CBC, iv)
decrypted_text = unpad(cipher_decrypt.decrypt(ciphertext), DES.block_size)

# Display the decrypted text
print("Decrypted text:", decrypted_text.decode('utf-8'))


# OUTPUT:
# Ciphertext (hex): 248a096ffffb6459dc76a423b1b22f15f642b95a4bc1c307
# Decrypted text: Secure Communication