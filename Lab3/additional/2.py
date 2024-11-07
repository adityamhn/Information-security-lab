from ecies import encrypt, decrypt
from ecies.utils import generate_key

# Generate ECC private and public keys
private_key = generate_key()  # Generate private key
public_key = private_key.public_key  # Derive public key from private key

# Message to encrypt
message = b"Secure Transactions"

# Encrypt the message using the public key
ciphertext = encrypt(public_key.format(True), message)
print(f"Ciphertext (hex): {ciphertext.hex()}")

# Decrypt the ciphertext using the private key
decrypted_message = decrypt(private_key.to_hex(), ciphertext)
print(f"Decrypted message: {decrypted_message.decode('utf-8')}")
