# Function to calculate the Caesar cipher shift
def calculate_shift(plain_char, cipher_char):
    return (ord(cipher_char.lower()) - ord(plain_char.lower())) % 26

# Function to decrypt using a Caesar cipher with a given shift
def decrypt_caesar(ciphertext, shift):
    plaintext = ""
    for char in ciphertext:
        if char.isalpha():  # Only decrypt alphabetic characters
            decrypted_char = chr((ord(char.lower()) - ord('a') - shift) % 26 + ord('a'))
            plaintext += decrypted_char
        else:
            plaintext += char  # Non-alphabetic characters remain unchanged
    return plaintext

# Known plaintext and ciphertext
known_plaintext = "yes"
known_ciphertext = "CIW"

# Calculate the shift by comparing the known plaintext and ciphertext
shift = calculate_shift(known_plaintext[0], known_ciphertext[0])

# Ciphertext from the tablet found by the hero
tablet_ciphertext = "XVIEWYWI"

# Decrypt the tablet ciphertext using the discovered shift
decrypted_message = decrypt_caesar(tablet_ciphertext, shift)

print("The shift used in the cipher is:", shift)
print("The decrypted message is:", decrypted_message)


# OUTPUT:
# The shift used in the cipher is: 4
# The decrypted message is: treasuse