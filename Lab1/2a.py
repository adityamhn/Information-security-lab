def vigenere_encrypt(plain_text, key):
    key = key.upper()  # Convert the key to uppercase
    cipher_text = ""
    for i, char in enumerate(plain_text):
        if char.isalpha():
            char = char.upper()  # Convert the plaintext character to uppercase
            key_char = key[i % len(key)]  # Repeating key characters
            shift = ord(key_char) - ord('A')
            encrypted_char = chr(((ord(char) - ord('A') + shift) % 26) + ord('A'))
            cipher_text += encrypted_char
        else:
            cipher_text += char
    return cipher_text



def vigenere_decrypt(cipher_text, key):
    key = key.upper()  # Convert the key to uppercase
    plain_text = ""
    for i, char in enumerate(cipher_text):
        if char.isalpha():
            char = char.upper()  # Convert the ciphertext character to uppercase
            key_char = key[i % len(key)]  # Repeating key characters
            shift = ord(key_char) - ord('A')
            decrypted_char = chr(((ord(char) - ord('A') - shift) % 26) + ord('A'))
            plain_text += decrypted_char
        else:
            plain_text += char
    return plain_text

plain_text = input("Enter the message you want to encrypt: ")
key = "dollars"

cipher_text = vigenere_encrypt(plain_text, key)
print("Encrypted text:", cipher_text)
decrypted_text = vigenere_decrypt(cipher_text, key)
print("Decrypted text:", decrypted_text)
