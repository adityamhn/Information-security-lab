from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import base64

def aes_192_encryption(plaintext, key):
    # Ensure the key length is 24 bytes (192 bits)
    if len(key) != 24:
        raise ValueError("AES-192 key must be 24 bytes long")

    # Create an AES cipher object
    cipher = AES.new(key, AES.MODE_ECB)

    # Pad the plaintext to a multiple of 16 bytes
    plaintext = pad(plaintext.encode("utf-8"), 16)

    # Encrypt the plaintext
    ciphertext = cipher.encrypt(plaintext)

    # Convert ciphertext to base64 for readability
    encrypted_base64 = base64.b64encode(ciphertext).decode("utf-8")
    return encrypted_base64

if __name__ == "__main__":
    plaintext = "Top Secret Data"
    key = b"FEDCBA9876543210FEDCBA98"

    encrypted_text = aes_192_encryption(plaintext, key)
    print("Encrypted (Base64):", encrypted_text)
