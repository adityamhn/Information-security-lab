# import os
# import json
# from Crypto.PublicKey import RSA
# from Crypto.Random import get_random_bytes
# from Crypto.Cipher import AES
# from Crypto.Util.Padding import pad, unpad
# import hashlib

# class Subsystem:
#     def __init__(self, name):
#         self.name = name
#         self.employees = {}
#         self.documents = []

#     def add_employee(self, employee):
#         self.employees[employee.id] = employee

#     def remove_employee(self, employee_id):
#         if employee_id in self.employees:
#             del self.employees[employee_id]

#     def add_document(self, document):
#         self.documents.append(document)

# class Employee:
#     def __init__(self, emp_id, name, role):
#         self.id = emp_id
#         self.name = name
#         self.role = role
#         self.private_key = RSA.generate(2048)
#         self.public_key = self.private_key.publickey()

#     def revoke_keys(self):
#         self.private_key = None
#         self.public_key = None

# class Document:
#     def __init__(self, content, owner, allowed_roles):
#         self.content = content
#         self.owner = owner
#         self.allowed_roles = allowed_roles  # List of roles that can access this document

# class SecureCommunication:
#     def __init__(self):
#         self.subsystems = {}

#     def add_subsystem(self, subsystem_name):
#         self.subsystems[subsystem_name] = Subsystem(subsystem_name)

#     def remove_subsystem(self, subsystem_name):
#         if subsystem_name in self.subsystems:
#             del self.subsystems[subsystem_name]

#     def encrypt_document(self, document_content, employee):
#         if employee.role not in ['Finance', 'HR', 'Supply Chain']:
#             raise PermissionError("Employee does not have permission to encrypt documents.")

#         session_key = get_random_bytes(16)  # Generate a new session key
#         cipher = AES.new(session_key, AES.MODE_CBC)
#         ct_bytes = cipher.encrypt(pad(document_content.encode(), AES.block_size))
#         iv = cipher.iv
#         # Create a Document object with the content, owner, and allowed roles
#         allowed_roles = ['Finance', 'HR']  # Only Finance and HR can access this document
#         document = Document(iv + ct_bytes + session_key, employee.role, allowed_roles)
#         return document

#     def decrypt_document(self, document, employee):
#         if employee.role not in document.allowed_roles:
#             raise PermissionError("Employee does not have permission to access this document.")

#         iv = document.content[:AES.block_size]  # Extract the IV
#         ct = document.content[AES.block_size:-16]  # Extract the ciphertext
#         session_key = document.content[-16:]  # Extract the session key
#         cipher = AES.new(session_key, AES.MODE_CBC, iv)
#         return unpad(cipher.decrypt(ct), AES.block_size).decode()

# def main():
#     secure_comm = SecureCommunication()

#     # Adding subsystems
#     secure_comm.add_subsystem("Finance System (System A)")
#     secure_comm.add_subsystem("HR System (System B)")
#     secure_comm.add_subsystem("Supply Chain Management (System C)")

#     # Adding employees
#     finance_emp = Employee("E001", "Alice", "Finance")
#     hr_emp = Employee("E002", "Bob", "HR")
#     supply_chain_emp = Employee("E003", "Charlie", "Supply Chain")

#     secure_comm.subsystems["Finance System (System A)"].add_employee(finance_emp)
#     secure_comm.subsystems["HR System (System B)"].add_employee(hr_emp)
#     secure_comm.subsystems["Supply Chain Management (System C)"].add_employee(supply_chain_emp)

#     # Finance subsystem sends a document
#     document_content = "Financial Report Q3"
#     document = secure_comm.encrypt_document(document_content, finance_emp)
#     print(f"Document encrypted and created by {finance_emp.name} in {finance_emp.role} subsystem.")

#     # HR subsystem accesses the document
#     try:
#         decrypted_doc_hr = secure_comm.decrypt_document(document, hr_emp)
#         print(f"HR Access - Decrypted Document: {decrypted_doc_hr}")
#     except PermissionError as e:
#         print(e)

#     # Supply Chain subsystem attempts to access the document
#     try:
#         decrypted_doc_sc = secure_comm.decrypt_document(document, supply_chain_emp)
#         print(f"Supply Chain Access - Decrypted Document: {decrypted_doc_sc}")
#     except PermissionError as e:
#         print(f"Supply Chain Access - {e}")

#     # Revoking an employee's keys
#     finance_emp.revoke_keys()
#     print(f"Employee {finance_emp.name}'s keys revoked.")

# if __name__ == "__main__":
#     main()

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Random.random import randint
import hashlib
import time
import os

# -------------------- Key Management System (KMS) --------------------

class KeyManagementSystem:
    def __init__(self):
        self.keys = {}
    
    def generate_rsa_keys(self, subsystem):
        # Generate RSA keys for a subsystem
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        self.keys[subsystem] = {'private_key': private_key, 'public_key': public_key}
        print(f"Generated RSA keys for {subsystem}")
        return private_key, public_key
    
    def get_public_key(self, subsystem):
        return self.keys[subsystem]['public_key']
    
    def get_private_key(self, subsystem):
        return self.keys[subsystem]['private_key']
    
    def revoke_key(self, subsystem):
        # Revoke and regenerate keys for a subsystem
        print(f"Revoking RSA keys for {subsystem}...")
        self.generate_rsa_keys(subsystem)
        print(f"New RSA keys generated for {subsystem}")

# -------------------- Diffie-Hellman Key Exchange --------------------

class DiffieHellman:
    def __init__(self):
        self.p = 23  # A small prime for demonstration purposes
        self.g = 5   # A primitive root modulo p
        self.private_key = randint(1, self.p-1)  # Private key (a random number)
        self.public_key = pow(self.g, self.private_key, self.p)  # Public key
    
    def generate_shared_secret(self, other_public_key):
        # Generate shared secret using the other subsystem's public key
        shared_secret = pow(other_public_key, self.private_key, self.p)
        return hashlib.sha256(str(shared_secret).encode()).digest()  # Hash the shared secret for AES key

# -------------------- Subsystem (Entity) Class --------------------

class Subsystem:
    def __init__(self, name, kms):
        self.name = name
        self.kms = kms
        self.private_key, self.public_key = self.kms.generate_rsa_keys(name)
        self.diffie_hellman = DiffieHellman()
    
    def encrypt_document(self, recipient_subsystem, document):
        print(f"Encrypting document for {recipient_subsystem.name}...")
        # Use recipient's RSA public key to encrypt the AES key
        rsa_public_key = RSA.import_key(self.kms.get_public_key(recipient_subsystem.name))
        rsa_cipher = PKCS1_OAEP.new(rsa_public_key)

        # Diffie-Hellman key exchange to establish shared AES key
        shared_secret = self.diffie_hellman.generate_shared_secret(recipient_subsystem.diffie_hellman.public_key)

        # AES encryption
        aes_cipher = AES.new(shared_secret, AES.MODE_CBC)
        ciphertext = aes_cipher.encrypt(pad(document.encode('utf-8'), AES.block_size))

        # Encrypt the AES key using RSA (for added security)
        encrypted_aes_key = rsa_cipher.encrypt(shared_secret)

        return encrypted_aes_key, aes_cipher.iv, ciphertext

    def decrypt_document(self, sender_subsystem, encrypted_aes_key, iv, ciphertext):
        print(f"Decrypting document from {sender_subsystem.name}...")
        # Decrypt the AES key using this subsystem's private RSA key
        rsa_private_key = RSA.import_key(self.kms.get_private_key(self.name))
        rsa_cipher = PKCS1_OAEP.new(rsa_private_key)
        shared_secret = rsa_cipher.decrypt(encrypted_aes_key)

        # AES decryption
        aes_cipher = AES.new(shared_secret, AES.MODE_CBC, iv)
        decrypted_document = unpad(aes_cipher.decrypt(ciphertext), AES.block_size)

        return decrypted_document.decode('utf-8')

# -------------------- Main Communication System --------------------

def main():
    # Initialize Key Management System (KMS)
    kms = KeyManagementSystem()

    # Create subsystems: Finance, HR, Supply Chain
    finance_system = Subsystem("Finance System (A)", kms)
    hr_system = Subsystem("HR System (B)", kms)
    supply_chain_system = Subsystem("Supply Chain Management (C)", kms)

    # Example 1: Finance System sends a document to HR System
    document = "Financial Report Q3 2023"
    print(f"\nOriginal Document: {document}")

    encrypted_aes_key, iv, ciphertext = finance_system.encrypt_document(hr_system, document)
    decrypted_document = hr_system.decrypt_document(finance_system, encrypted_aes_key, iv, ciphertext)

    print(f"Decrypted Document: {decrypted_document}")

    # Example 2: HR System sends a document to Supply Chain Management System
    document_hr = "Employee Contracts 2023"
    print(f"\nOriginal Document: {document_hr}")

    encrypted_aes_key, iv, ciphertext = hr_system.encrypt_document(supply_chain_system, document_hr)
    decrypted_document = supply_chain_system.decrypt_document(hr_system, encrypted_aes_key, iv, ciphertext)

    print(f"Decrypted Document: {decrypted_document}")

    # Key revocation example
    print("\nRevoking keys for HR System (B)...")
    kms.revoke_key("HR System (B)")

if __name__ == "__main__":
    main()
