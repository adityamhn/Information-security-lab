def custom_hash(input_string):
    # Initial hash value
    hash_value = 5381

    # Process each character in the input string
    for char in input_string:
        # Multiply current hash by 33 and add the ASCII value of the character
        hash_value = ((hash_value << 5) + hash_value) + ord(char)  # Equivalent to hash_value * 33 + ord(char)
        
        # Ensure the hash stays within the 32-bit range using a mask
        hash_value = hash_value & 0xFFFFFFFF  # Apply 32-bit mask

    return hash_value

input_str = "TestPassword"
hash_result = custom_hash(input_str)
print(f"The hash value for '{input_str}' is: {hash_result}")

# Output:
# The hash value for 'TestPassword' is: 3007072088