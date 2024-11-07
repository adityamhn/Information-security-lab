def text_to_int(char):
    """Convert a single character to an integer (ASCII)."""
    return ord(char)

def int_to_text(integer):
    """Convert an integer back to a single character."""
    return chr(integer)

def rsa_encrypt(char, n, e):
    """Encrypt a single character using RSA public key (n, e)."""
    m = text_to_int(char)
    # Encrypt: C = M^e mod n
    c = pow(m, e, n)
    return c

def rsa_decrypt(ciphertext, n, d):
    """Decrypt a single integer ciphertext using RSA private key (n, d)."""
    # Decrypt: M = C^d mod n
    m = pow(ciphertext, d, n)
    return int_to_text(m)

# Given RSA parameters
n = 323
e = 5
d = 173
message = "Cryptographic Protocols"

# Encrypt each character and store in a list
ciphertext = [rsa_encrypt(char, n, e) for char in message]
print("Encrypted Ciphertext:", ciphertext)

# Decrypt each character and join them to form the original message
decrypted_message = ''.join(rsa_decrypt(c, n, d) for c in ciphertext)
print("Decrypted Message:", decrypted_message)
