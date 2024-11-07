from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from binascii import unhexlify

# DES key (must be 8 bytes for DES)
key = b"A1B2C3D4"  # Shortened to 8 bytes (64 bits)

# Block 1 and Block 2 data (in hexadecimal form)
block1_hex = "54686973206973206120636f6e666964656e7469616c206d657373616765"
block2_hex = "416e64207468697320697320746865207365636f6e6420626c6f636b"

# Convert hex to bytes
block1 = unhexlify(block1_hex)
block2 = unhexlify(block2_hex)

# Generate a random IV (Initialization Vector) for CBC mode
iv = b'\x00\x00\x00\x00\x00\x00\x00\x00'  # Using a fixed IV for reproducibility

# Create DES cipher object in CBC mode
cipher = DES.new(key, DES.MODE_CBC, iv)

# Encrypt both blocks after padding them to be a multiple of the block size (8 bytes)
ciphertext1 = cipher.encrypt(pad(block1, DES.block_size))
ciphertext2 = cipher.encrypt(pad(block2, DES.block_size))

# Display ciphertext in hexadecimal format
print("Ciphertext for Block 1 (hex):", ciphertext1.hex())
print("Ciphertext for Block 2 (hex):", ciphertext2.hex())

# Decryption to verify
cipher_decrypt = DES.new(key, DES.MODE_CBC, iv)

# Decrypt both ciphertext blocks
decrypted_block1 = unpad(cipher_decrypt.decrypt(ciphertext1), DES.block_size)
decrypted_block2 = unpad(cipher_decrypt.decrypt(ciphertext2), DES.block_size)

# Display decrypted plaintext
print("\nDecrypted Block 1 (plaintext):", decrypted_block1.decode('utf-8'))
print("Decrypted Block 2 (plaintext):", decrypted_block2.decode('utf-8'))


# OUTPUT:
# Ciphertext for Block 1 (hex): 13777717f79fbdb375d58b71f10b0053d1cdab58b4620016e685c47b1d46acaf
# Ciphertext for Block 2 (hex): ab3c384afefe2f921fff1530c45753ac822c9833e715bde2929da21a83ab454b

# Decrypted Block 1 (plaintext): This is a confidential message
# Decrypted Block 2 (plaintext): And this is the second block