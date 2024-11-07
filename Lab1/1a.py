# Additive cipher

def encrypt(plain_text, key):
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    encrypted_text = ""
    plain_text = list(plain_text)

    for x in range(len(plain_text)):
            char_index = alphabet.index(plain_text[x].lower())
            encrypted_index = (char_index + key) % 26
            encrypted_char = alphabet[encrypted_index]
            encrypted_text += encrypted_char

    return encrypted_text

def decrypt(cipher_text, key):
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    decrypted_text = ""

    for char in cipher_text:
        if char.isalpha():
            char_index = alphabet.index(char.lower())
            shifted_index = (char_index - key) % 26
            decrypted_char = alphabet[shifted_index]
            decrypted_text += decrypted_char
        else:
            decrypted_text += char

    return decrypted_text



text = input("Enter the message you want to encrypt: ")
key = int(input("Enter your cipher key: "))

encrypted_message = encrypt(text, key)

print(f"Your Encrpyted Message is: {encrypted_message}")

plain_text = decrypt(encrypted_message, key)

print(f"Your Decrypted Message is: {plain_text}")