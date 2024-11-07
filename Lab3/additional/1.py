from Crypto.Util.number import inverse, getPrime
import random

# ElGamal encryption function
def elgamal_encrypt(p, g, h, message):
    # Convert the message to an integer
    m = int.from_bytes(message.encode('utf-8'), byteorder='big')
    
    if m >= p:
        raise ValueError("The message is too large for the chosen prime 'p'. Choose a larger 'p'.")

    # Generate random k
    k = random.randint(1, p - 2)
    
    # c1 = g^k mod p
    c1 = pow(g, k, p)
    
    # c2 = m * h^k mod p
    c2 = (m * pow(h, k, p)) % p
    
    return c1, c2

# ElGamal decryption function
def elgamal_decrypt(p, x, c1, c2):
    # Compute s = c1^x mod p
    s = pow(c1, x, p)
    
    # Compute the modular inverse of s
    s_inv = inverse(s, p)
    
    # Recover the message: m = c2 * s_inv mod p
    m = (c2 * s_inv) % p
    
    # Convert the integer back to a message
    message_length = (m.bit_length() + 7) // 8
    decrypted_message = m.to_bytes(message_length, byteorder='big').decode('utf-8')
    
    return decrypted_message

# Generate a larger prime 'p' (at least 160 bits)
p = getPrime(256)  # 256-bit prime
g = 2

# Generate a private key 'x' where 1 < x < p - 1
x = random.randint(2, p - 2)

# Compute public key component 'h'
h = pow(g, x, p)

# Message to encrypt
message = "Asymmetric Algorithms"

# Ensure the message integer is less than 'p'
m = int.from_bytes(message.encode('utf-8'), byteorder='big')
if m >= p:
    raise ValueError("The message is too large for the chosen prime 'p'. Choose a larger 'p'.")

# Encryption
c1, c2 = elgamal_encrypt(p, g, h, message)
print(f"Ciphertext: (c1={c1}, c2={c2})")

# Decryption
decrypted_message = elgamal_decrypt(p, x, c1, c2)
print(f"Decrypted message: {decrypted_message}")
