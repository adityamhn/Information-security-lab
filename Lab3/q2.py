from ecies import encrypt, decrypt
from ecies.utils import generate_key

# Generate ECC private key
private_key = generate_key()
public_key = private_key.public_key

# Message to encrypt
plaintext = b"Secure Transactions"

# Encrypt the message using the public key
ciphertext = encrypt(public_key.format(True), plaintext)

# Display the ciphertext in hexadecimal format
print("Ciphertext (hex):", ciphertext.hex())

# Decrypt the ciphertext using the private key
decrypted_text = decrypt(private_key.to_hex(), ciphertext)

# Display the decrypted text
print("\nDecrypted text:", decrypted_text.decode('utf-8'))
