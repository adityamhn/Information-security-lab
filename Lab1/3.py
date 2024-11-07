# Helper function to create the Playfair cipher matrix
def create_playfair_matrix(key):
    # Remove duplicates and join the remaining letters to form the key matrix
    key = "".join(sorted(set(key), key=lambda x: key.index(x)))
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # Combine I and J
    matrix = []

    # Add the key letters to the matrix
    for char in key:
        if char not in matrix:
            matrix.append(char)

    # Add the rest of the letters in the alphabet to the matrix
    for char in alphabet:
        if char not in matrix:
            matrix.append(char)

    # Convert the matrix list to a 5x5 grid
    matrix_5x5 = [matrix[i:i + 5] for i in range(0, 25, 5)]
    return matrix_5x5


# Function to prepare the message (removing spaces, padding, etc.)
def prepare_message(message):
    message = message.replace(" ", "").upper().replace("J", "I")
    prepared = ""
    i = 0
    while i < len(message):
        char1 = message[i]
        if i + 1 < len(message):
            char2 = message[i + 1]
            if char1 == char2:  # Insert 'X' between repeated letters
                prepared += char1 + 'X'
                i += 1
            else:
                prepared += char1 + char2
                i += 2
        else:
            prepared += char1 + 'X'  # If odd length, add 'X'
            i += 1
    return prepared


# Helper function to find positions of characters in the matrix
def find_position(char, matrix):
    for row in range(5):
        for col in range(5):
            if matrix[row][col] == char:
                return row, col
    return None


# Playfair cipher encryption function
def playfair_encrypt(message, matrix):
    cipher_text = ""
    for i in range(0, len(message), 2):
        char1, char2 = message[i], message[i + 1]
        row1, col1 = find_position(char1, matrix)
        row2, col2 = find_position(char2, matrix)

        # Same row
        if row1 == row2:
            cipher_text += matrix[row1][(col1 + 1) % 5]
            cipher_text += matrix[row2][(col2 + 1) % 5]
        # Same column
        elif col1 == col2:
            cipher_text += matrix[(row1 + 1) % 5][col1]
            cipher_text += matrix[(row2 + 1) % 5][col2]
        # Rectangle case
        else:
            cipher_text += matrix[row1][col2]
            cipher_text += matrix[row2][col1]

    return cipher_text


# Playfair cipher decryption function (for completeness)
def playfair_decrypt(ciphertext, matrix):
    plain_text = ""
    for i in range(0, len(ciphertext), 2):
        char1, char2 = ciphertext[i], ciphertext[i + 1]
        row1, col1 = find_position(char1, matrix)
        row2, col2 = find_position(char2, matrix)

        # Same row
        if row1 == row2:
            plain_text += matrix[row1][(col1 - 1) % 5]
            plain_text += matrix[row2][(col2 - 1) % 5]
        # Same column
        elif col1 == col2:
            plain_text += matrix[(row1 - 1) % 5][col1]
            plain_text += matrix[(row2 - 1) % 5][col2]
        # Rectangle case
        else:
            plain_text += matrix[row1][col2]
            plain_text += matrix[row2][col1]

    return plain_text


# Input message and key
key = "GUIDANCE"
message = "The key is hidden under the door pad"

# Step 1: Create the Playfair matrix
matrix = create_playfair_matrix(key.upper())

# Step 2: Prepare the message for encryption
prepared_message = prepare_message(message)

# Step 3: Encrypt the message
ciphertext = playfair_encrypt(prepared_message, matrix)
print("Encrypted message:", ciphertext)

# Step 4: Decrypt the message (for verification)
decrypted_message = playfair_decrypt(ciphertext, matrix)
print("Decrypted message:", decrypted_message)


# OUTPUT:
# Encrypted message: POCLBXDRLGIYIBCGBGLXPOBILZLTTGIY
# Decrypted message: THEKEYISHIDXDENUNDERTHEDOXORPADX