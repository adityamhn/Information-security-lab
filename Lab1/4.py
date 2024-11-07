import numpy as np


# Convert a letter to its corresponding number (A=0, B=1, ..., Z=25)
def letter_to_num(letter):
    return ord(letter.lower()) - ord('a')


# Convert a number (0-25) to its corresponding letter
def num_to_letter(num):
    return chr(num + ord('a'))


# Function to prepare the message by removing spaces and padding if necessary
def prepare_message(message):
    message = message.replace(" ", "").lower()
    if len(message) % 2 != 0:  # If the length of the message is odd, pad with 'x'
        message += 'x'
    return message


# Hill cipher encryption function
def hill_cipher_encrypt(message, key_matrix):
    message = prepare_message(message)
    ciphertext = ""

    # Process the message in 2-letter chunks
    for i in range(0, len(message), 2):
        pair = message[i:i + 2]
        vector = np.array([[letter_to_num(pair[0])], [letter_to_num(pair[1])]])  # 2x1 column vector

        # Multiply the vector by the key matrix and take mod 26
        encrypted_vector = np.dot(key_matrix, vector) % 26

        # Convert numbers back to letters
        ciphertext += num_to_letter(encrypted_vector[0, 0])
        ciphertext += num_to_letter(encrypted_vector[1, 0])

    return ciphertext


# Key matrix for the Hill cipher (2x2 matrix)
key_matrix = np.array([[3, 3], [2, 7]])

# Input message
message = "We live in an insecure world"

# Encrypt the message
ciphertext = hill_cipher_encrypt(message, key_matrix)
print("Encrypted message:", ciphertext)


# OUTPUT:
# Encrypted message: aufaxsldnnldomoolkemghal