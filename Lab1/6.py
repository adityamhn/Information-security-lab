import math

# Function to check if a number is coprime with 26 (GCD must be 1)
def is_coprime(a, m=26):
    return math.gcd(a, m) == 1

# Function to decrypt using the affine cipher: D(y) = a_inv * (y - b) % 26
def affine_decrypt(ciphertext, a, b):
    plaintext = ""
    a_inv = pow(a, -1, 26)  # Find modular inverse of a mod 26
    for char in ciphertext:
        if char.isalpha():
            y = ord(char.lower()) - ord('a')
            x = (a_inv * (y - b)) % 26
            plaintext += chr(x + ord('a'))
        else:
            plaintext += char  # Keep non-alphabetic characters unchanged
    return plaintext

# Known mappings: 'a' -> 'G' (6) and 'b' -> 'L' (11)
plaintext_pairs = [(0, 6), (1, 11)]  # (plaintext, ciphertext) pairs

# Ciphertext to decrypt
ciphertext = "XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS"

# Brute-force search over possible values of 'a' and 'b'
for a in range(1, 26):  # 'a' must be coprime with 26
    if is_coprime(a):
        for b in range(0, 26):  # 'b' can be any value from 0 to 25
            # Check if the affine function satisfies the known plaintext-ciphertext pairs
            if (a * plaintext_pairs[0][0] + b) % 26 == plaintext_pairs[0][1] and \
               (a * plaintext_pairs[1][0] + b) % 26 == plaintext_pairs[1][1]:
                print(f"Found possible keys: a = {a}, b = {b}")
                
                # Decrypt the full ciphertext using the discovered keys
                decrypted_message = affine_decrypt(ciphertext, a, b)
                print(f"Decrypted message using a={a}, b={b}: {decrypted_message}")

# OUTPUT:
# Found possible keys: a = 5, b = 6
# Decrypted message using a=5, b=6: thebestofafightismakingupakterwards