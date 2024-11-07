def autokey_encrypt(plain_text, key):
    key = key.upper()  # Convert the key to uppercase
    cipher_text = ""
    key_index = 0

    for char in plain_text:
        if char.isalpha():
            char = char.upper()  # Convert the plaintext character to uppercase
            key_char = key[key_index % len(key)]  # Repeating key characters
            shift = ord(key_char) - ord('A')
            encrypted_char = chr(((ord(char) - ord('A') + shift) % 26) + ord('A'))
            cipher_text += encrypted_char
            key_index += 1
        else:
            cipher_text += char

    return cipher_text

def autokey_decrypt(cipher_text, key):
    key = key.upper()  # Convert the key to uppercase
    plain_text = ""
    key_index = 0

    for char in cipher_text:
        if char.isalpha():
            char = char.upper()  # Convert the ciphertext character to uppercase
            key_char = key[key_index % len(key)]  # Repeating key characters
            shift = ord(key_char) - ord('A')
            decrypted_char = chr(((ord(char) - ord('A') - shift) % 26) + ord('A'))
            plain_text += decrypted_char
            key_index += 1
        else:
            plain_text += char

    return plain_text

# Example usage
plain_text = input("Enter the message you want to encrypt: ")
key = "7"  # Use any key you like
cipher_text = autokey_encrypt(plain_text, key)
print("Encrypted text:", cipher_text)

decrypted_text = autokey_decrypt(cipher_text, key)
print("Decrypted text:", decrypted_text)
