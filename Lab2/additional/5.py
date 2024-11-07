from Crypto.Cipher import AES
from Crypto.Util import Counter

# Message to encrypt
plaintext = b"Cryptography Lab Exercise"

# AES-256 key (must be 32 bytes for AES-256)
key = b"0123456789ABCDEF0123456789ABCDEF"

# Nonce (for CTR mode) - it should be 8 bytes for AES, prefixing with 0 for simplicity
nonce = b"0000000000000000"

# Create a counter object with the nonce
ctr = Counter.new(128, initial_value=int.from_bytes(nonce, byteorder='big'))

# Create AES cipher object in CTR mode
cipher = AES.new(key, AES.MODE_CTR, counter=ctr)

# Encrypt the plaintext
ciphertext = cipher.encrypt(plaintext)

# Display ciphertext in hexadecimal format
print("Ciphertext (hex):", ciphertext.hex())

# To decrypt, recreate the cipher object with the same key and nonce
ctr_decrypt = Counter.new(128, initial_value=int.from_bytes(nonce, byteorder='big'))
cipher_decrypt = AES.new(key, AES.MODE_CTR, counter=ctr_decrypt)

# Decrypt the ciphertext
decrypted_text = cipher_decrypt.decrypt(ciphertext)

# Display the decrypted text
print("Decrypted text:", decrypted_text.decode('utf-8'))


# OUTPUT:
# Ciphertext (hex): 2d09b47c798a4e704713dcbfcc230ca24a32d6ca1e7d57ef60
# Decrypted text: Cryptography Lab Exercise