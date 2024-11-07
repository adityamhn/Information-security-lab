def affine_encrypt(plain_text, a, b):
    cipher_text = ""
    for char in plain_text:
        if char.isalpha():
            char = char.upper()  # Convert to uppercase for consistent range
            encrypted_char = chr(((a * (ord(char) - ord('A')) + b) % 26) + ord('A'))
            cipher_text += encrypted_char
        else:
            cipher_text += char
    return cipher_text



def affine_decrypt(cipher_text, a, b):
    plain_text = ""
    m = 26  # Size of the alphabet
    a_inverse = pow(a, -1, m)  # Modular multiplicative inverse of 'a'
    for char in cipher_text:
        if char.isalpha():
            char = char.upper()
            decrypted_char = chr(((a_inverse * (ord(char) - ord('A') - b)) % m) + ord('A'))
            plain_text += decrypted_char
        else:
            plain_text += char
    return plain_text


plain_text = input("Enter the message you want to encrypt: ")
a = int(input("Enter your first cipher key: "))
b = int(input("Enter your second cipher key: "))

cipher_text = affine_encrypt(plain_text, a, b)
print("Encrypted text:", cipher_text)
decrypted_text = affine_decrypt(cipher_text, a, b)
print("Decrypted text:", decrypted_text)
