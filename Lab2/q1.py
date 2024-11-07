# Import necessary modules from the pycryptodome library
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


plaintext = b"Confidential Data"
key = b"A1B2C3D4"

cipher = DES.new(key, DES.MODE_ECB)


ciphertext = cipher.encrypt(pad(plaintext, 8))

decrypted_text = unpad(cipher.decrypt(ciphertext), 8)

print("Ciphertext:", ciphertext.hex())
print("Decrypted text:", decrypted_text.decode("utf-8"))


# OUTPUT:
# Ciphertext: 20089c56693b4b0a685304930baf3ed459a54a2e4ada7187
# Decrypted text: Confidential Data



# from Crypto.Cipher import DES
# from Crypto.Random import get_random_bytes
# from Crypto.Util.Padding import pad, unpad

# # Define the plaintext and key
# plaintext = b"Confidential Data"
# key = b"A1B2C3D4"  # DES key must be exactly 8 bytes long

# # DES Encryption and Decryption using ECB mode (Electronic Codebook)
# def des_ecb(plaintext, key):
#     cipher = DES.new(key, DES.MODE_ECB)
#     ciphertext = cipher.encrypt(pad(plaintext, 8))
#     decrypted_text = unpad(cipher.decrypt(ciphertext), 8)
#     print("ECB Mode - Ciphertext:", ciphertext.hex())
#     print("ECB Mode - Decrypted text:", decrypted_text.decode("utf-8"))

# # DES Encryption and Decryption using CBC mode (Cipher Block Chaining)
# def des_cbc(plaintext, key):
#     iv = get_random_bytes(8)  # Initialization vector for CBC
#     cipher = DES.new(key, DES.MODE_CBC, iv)
#     ciphertext = cipher.encrypt(pad(plaintext, 8))
#     decrypted_text = unpad(cipher.decrypt(ciphertext), 8)
#     print("CBC Mode - Ciphertext:", ciphertext.hex())
#     print("CBC Mode - Decrypted text:", decrypted_text.decode("utf-8"))
#     print("CBC Mode - IV:", iv.hex())

# # DES Encryption and Decryption using CFB mode (Cipher Feedback)
# def des_cfb(plaintext, key):
#     iv = get_random_bytes(8)  # Initialization vector for CFB
#     cipher = DES.new(key, DES.MODE_CFB, iv)
#     ciphertext = cipher.encrypt(plaintext)  # No padding required in CFB mode
#     decrypted_text = cipher.decrypt(ciphertext)
#     print("CFB Mode - Ciphertext:", ciphertext.hex())
#     print("CFB Mode - Decrypted text:", decrypted_text.decode("utf-8"))
#     print("CFB Mode - IV:", iv.hex())

# # DES Encryption and Decryption using OFB mode (Output Feedback)
# def des_ofb(plaintext, key):
#     iv = get_random_bytes(8)  # Initialization vector for OFB
#     cipher = DES.new(key, DES.MODE_OFB, iv)
#     ciphertext = cipher.encrypt(plaintext)  # No padding required in OFB mode
#     decrypted_text = cipher.decrypt(ciphertext)
#     print("OFB Mode - Ciphertext:", ciphertext.hex())
#     print("OFB Mode - Decrypted text:", decrypted_text.decode("utf-8"))
#     print("OFB Mode - IV:", iv.hex())

# # DES Encryption and Decryption using CTR mode (Counter Mode)
# def des_ctr(plaintext, key):
#     cipher = DES.new(key, DES.MODE_CTR)
#     ciphertext = cipher.encrypt(plaintext)  # No padding required in CTR mode
#     decrypted_text = cipher.decrypt(ciphertext)
#     print("CTR Mode - Ciphertext:", ciphertext.hex())
#     print("CTR Mode - Decrypted text:", decrypted_text.decode("utf-8"))
#     print("CTR Mode - Nonce:", cipher.nonce.hex())

# # Execute the encryption and decryption for all modes
# print("----- ECB Mode -----")
# des_ecb(plaintext, key)

# print("\n----- CBC Mode -----")
# des_cbc(plaintext, key)

# print("\n----- CFB Mode -----")
# des_cfb(plaintext, key)

# print("\n----- OFB Mode -----")
# des_ofb(plaintext, key)

# print("\n----- CTR Mode -----")
# des_ctr(plaintext, key)
