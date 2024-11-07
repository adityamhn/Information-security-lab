# from Crypto.Util import number
# from Crypto.Random import get_random_bytes
# import os
# import json
# import hashlib


# class RabinKeyManagementService:
#     def __init__(self, key_size=1024):
#         self.key_size = key_size
#         self.key_storage = "keys/"
#         self.log_file = "key_management.log"
#         os.makedirs(self.key_storage, exist_ok=True)

#     def generate_rabin_keys(self):
#         while True:
#             p = number.getPrime(self.key_size // 2)
#             q = number.getPrime(self.key_size // 2)
#             if p % 4 == 3 and q % 4 == 3:
#                 break
#         n = p * q
#         public_key = n
#         private_key = (p, q)
#         return public_key, private_key

#     def store_keys(self, hospital_id, public_key, private_key):
#         file_path = os.path.join(self.key_storage, f"{hospital_id}.json")
#         with open(file_path, 'w') as f:
#             json.dump({
#                 "public_key": public_key,
#                 "private_key": private_key
#             }, f)
#         self.log_action(f"Keys stored for {hospital_id}")

#     def log_action(self, message):
#         with open(self.log_file, 'a') as f:
#             f.write(f"{message}\n")

#     def key_revocation(self, hospital_id):
#         file_path = os.path.join(self.key_storage, f"{hospital_id}.json")
#         if os.path.exists(file_path):
#             os.remove(file_path)
#             self.log_action(f"Keys revoked for {hospital_id}")

#     def key_renewal(self, hospital_id):
#         public_key, private_key = self.generate_rabin_keys()
#         self.store_keys(hospital_id, public_key, private_key)
#         self.log_action(f"Keys renewed for {hospital_id}")

#     def generate_and_distribute_keys(self, hospital_id):
#         public_key, private_key = self.generate_rabin_keys()
#         self.store_keys(hospital_id, public_key, private_key)
#         return public_key, private_key

#     def get_key(self, hospital_id):
#         file_path = os.path.join(self.key_storage, f"{hospital_id}.json")
#         if os.path.exists(file_path):
#             with open(file_path, 'r') as f:
#                 return json.load(f)
#         else:
#             return None


# # Example usage
# def healthcare_key_management():
#     kms = RabinKeyManagementService()

#     # Generate and distribute keys to Hospital A
#     public_key_a, private_key_a = kms.generate_and_distribute_keys("HospitalA")

#     print(public_key_a)

#     # Renew keys for Hospital A
#     kms.key_renewal("HospitalA")

#     print(kms.get_key("HospitalA"))

#     # Revoke keys for Hospital A
#     # kms.key_revocation("HospitalA")

#     # Audit logs
#     # with open(kms.log_file, 'r') as log:
#     #     print(log.read())


# healthcare_key_management()


from Crypto.Util import number
import time
import json
import os
import logging

# Set up logging
logging.basicConfig(filename='kms.log', level=logging.INFO)

# -------------------- Rabin Cryptosystem Implementation --------------------

class RabinCryptosystem:
    def generate_keypair(self, key_size=1024):
        """Generate public and private keys for Rabin cryptosystem."""
        while True:
            p = number.getPrime(key_size // 2)
            q = number.getPrime(key_size // 2)
            if p % 4 == 3 and q % 4 == 3:
                break
        n = p * q
        return (n, (p, q))  # Public key (n), Private key (p, q)

    def encrypt(self, public_key, message):
        """Encrypt a message using the Rabin cryptosystem."""
        n = public_key
        m = int.from_bytes(message.encode('utf-8'), byteorder='big')
        ciphertext = pow(m, 2, n)  # c = m^2 mod n
        return ciphertext

    def decrypt(self, private_key, ciphertext):
        """Decrypt a message using the Rabin cryptosystem."""
        p, q = private_key
        n = p * q

        # Using the Chinese Remainder Theorem to compute the square roots mod p and q
        mp = pow(ciphertext, (p + 1) // 4, p)
        mq = pow(ciphertext, (q + 1) // 4, q)

        # Combine results using CRT
        yp = number.inverse(q, p)
        yq = number.inverse(p, q)

        root1 = (yp * p * mq + yq * q * mp) % n
        root2 = (yp * p * mq - yq * q * mp) % n

        # Convert roots back to message and decode
        for root in [root1, root2]:
            try:
                message = root.to_bytes((root.bit_length() + 7) // 8, byteorder='big').decode('utf-8')
                return message
            except:
                continue

        return None

# -------------------- Key Management System --------------------

class KeyManagementSystem:
    def __init__(self):
        self.keys = {}
        self.audits = []

    def generate_keys(self, hospital_name, key_size=1024):
        """Generate Rabin keys for a hospital/clinic."""
        rabin = RabinCryptosystem()
        public_key, private_key = rabin.generate_keypair(key_size)
        
        self.keys[hospital_name] = {
            "public_key": public_key,
            "private_key": private_key,
            "timestamp": time.time()
        }

        logging.info(f"{hospital_name} - Keys generated.")
        self.audits.append(f"Generated keys for {hospital_name}")
        self._store_keys()

        return public_key, private_key

    def revoke_keys(self, hospital_name):
        """Revoke keys for a hospital/clinic."""
        if hospital_name in self.keys:
            del self.keys[hospital_name]
            logging.info(f"{hospital_name} - Keys revoked.")
            self.audits.append(f"Revoked keys for {hospital_name}")
            self._store_keys()

    def renew_keys(self):
        """Automatically renew keys for hospitals and clinics every 12 months."""
        current_time = time.time()
        for hospital_name, key_data in self.keys.items():
            if current_time - key_data["timestamp"] > 12 * 30 * 24 * 3600:  # 12 months
                logging.info(f"{hospital_name} - Keys expired, renewing...")
                self.generate_keys(hospital_name)

    def request_public_key(self, hospital_name):
        """Return the public key of a hospital/clinic."""
        return self.keys[hospital_name]['public_key']

    def _store_keys(self):
        """Store keys securely."""
        with open('keys.json', 'w') as f:
            json.dump(self.keys, f)
        logging.info("Keys stored securely.")

    def _load_keys(self):
        """Load keys from secure storage."""
        if os.path.exists('keys.json'):
            with open('keys.json', 'r') as f:
                self.keys = json.load(f)
            logging.info("Keys loaded from secure storage.")

# -------------------- Centralized Key Management Service --------------------

def main():
    # Create the KMS
    kms = KeyManagementSystem()
    
    # Key generation for hospitals
    print("\n--- Key Generation ---")
    public_key_A, private_key_A = kms.generate_keys("Hospital A", key_size=1024)
    public_key_B, private_key_B = kms.generate_keys("Hospital B", key_size=1024)

    print(f"Public Key (Hospital A): {public_key_A}")
    print(f"Public Key (Hospital B): {public_key_B}")

    # Encrypting and decrypting messages
    print("\n--- Secure Communication ---")
    rabin = RabinCryptosystem()
    message = "Patient medical records"
    print(f"Original Message: {message}")

    # Hospital A encrypts data
    ciphertext = rabin.encrypt(public_key_B, message)
    print(f"Encrypted Message (Hospital A -> B): {ciphertext}")

    # Hospital B decrypts data
    decrypted_message = rabin.decrypt(private_key_B, ciphertext)
    print(f"Decrypted Message (Hospital B): {decrypted_message}")

    # Key revocation
    print("\n--- Key Revocation ---")
    kms.revoke_keys("Hospital B")

    # Automatically renew keys (this would be scheduled in a real system)
    print("\n--- Key Renewal ---")
    kms.renew_keys()

    # Auditing
    print("\n--- Audit Logs ---")
    for log in kms.audits:
        print(log)

if __name__ == "__main__":
    main()
