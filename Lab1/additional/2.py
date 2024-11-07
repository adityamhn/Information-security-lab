import string

def vigenere_encrypt(plaintext, keyword):
    alphabet = string.ascii_uppercase
    keyword = keyword.upper()
    plaintext = plaintext.upper()
    
    ciphertext = ""
    keyword_repeated = ""
    keyword_index = 0

    # Loop through each character in the plaintext
    for char in plaintext:
        if char in alphabet:
            # Repeat keyword to match the length of the plaintext
            keyword_repeated += keyword[keyword_index % len(keyword)]
            # Get the position of the plaintext letter and keyword letter
            plain_pos = alphabet.index(char)
            key_pos = alphabet.index(keyword_repeated[keyword_index % len(keyword)])
            # Perform the Vigenere shift
            cipher_pos = (plain_pos + key_pos) % 26
            ciphertext += alphabet[cipher_pos]
            keyword_index += 1
        else:
            # Keep non-alphabet characters unchanged
            ciphertext += char

    return ciphertext

# Message to encrypt
plaintext = "Life is full of surprises"
# Keyword for the Vigenere cipher
keyword = "HEALTH"

# Encrypt the message using the Vigenere cipher
ciphertext = vigenere_encrypt(plaintext, keyword)
print(f"Ciphertext: {ciphertext}")


# Ouput:
# Ciphertext: SMFP BZ MYLW HM ZYRAKPZIS