from ecies import encrypt, decrypt
from ecies.utils import generate_key
import time
import os

# Function to generate ECC keys (secp256r1)
def generate_ecc_keys():
    private_key = generate_key()  # Generate private key
    public_key = private_key.public_key  # Derive public key
    return private_key, public_key

# Function to encrypt patient data using recipient's public key
def encrypt_patient_data(public_key, patient_data):
    start_time = time.time()  # Start timer
    ciphertext = encrypt(public_key.format(True), patient_data)  # Encrypt using public key
    encryption_time = time.time() - start_time  # End timer
    return ciphertext, encryption_time

# Function to decrypt patient data using recipient's private key
def decrypt_patient_data(private_key, ciphertext):
    start_time = time.time()  # Start timer
    plaintext = decrypt(private_key.to_hex(), ciphertext)  # Decrypt using private key
    decryption_time = time.time() - start_time  # End timer
    return plaintext, decryption_time

# Function to simulate patient data of varying sizes (KB, MB)
def generate_patient_data(size_in_kb):
    return os.urandom(size_in_kb * 1024)  # Generate random binary data of specified size

# Main function to execute the encryption and decryption process
def run_encryption_decryption_test(patient_data_size_kb):
    # Step 1: Generate ECC keys for encryption (public key) and decryption (private key)
    private_key, public_key = generate_ecc_keys()

    # Step 2: Generate patient data of specified size
    patient_data = generate_patient_data(patient_data_size_kb)
    print(f"\nPatient data size: {patient_data_size_kb} KB")

    # Step 3: Encrypt the patient data
    ciphertext, encryption_time = encrypt_patient_data(public_key, patient_data)
    print(f"Encryption time: {encryption_time:.6f} seconds")

    # Step 4: Decrypt the ciphertext back to the original data
    decrypted_data, decryption_time = decrypt_patient_data(private_key, ciphertext)
    print(f"Decryption time: {decryption_time:.6f} seconds")

    # Step 5: Verify that the original data matches the decrypted data
    if patient_data == decrypted_data:
        print("Decryption successful! The original data matches the decrypted data.")
    else:
        print("Error: Decrypted data does not match the original data!")

# Run the tests for different sizes of patient data (1KB, 10KB, 100KB, 1MB)
data_sizes = [1, 10, 100, 1024]  # Sizes in KB
for size in data_sizes:
    run_encryption_decryption_test(size)



# Patient data size: 1 KB
# Encryption time: 0.001655 seconds
# Decryption time: 0.000673 seconds
# Decryption successful! The original data matches the decrypted data.

# Patient data size: 10 KB
# Encryption time: 0.000239 seconds
# Decryption time: 0.000229 seconds
# Decryption successful! The original data matches the decrypted data.

# Patient data size: 100 KB
# Encryption time: 0.000942 seconds
# Decryption time: 0.000945 seconds
# Decryption successful! The original data matches the decrypted data.

# Patient data size: 1024 KB
# Encryption time: 0.008578 seconds
# Decryption time: 0.010829 seconds
# Decryption successful! The original data matches the decrypted data.