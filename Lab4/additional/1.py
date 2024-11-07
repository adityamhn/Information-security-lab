from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random.random import randint
import json
import time
import os
import logging

# Set up logging
logging.basicConfig(filename='drm_system.log', level=logging.INFO)

# -------------------- ElGamal Key Management and Content Encryption --------------------

class DRMSystem:
    def __init__(self, key_size=2048):
        self.master_keypair = None
        self.key_size = key_size
        self.customers = {}  # Store customer data and access rights
        self.content_metadata = {}  # Store encrypted content metadata
        self.load_state()

    def generate_master_keypair(self):
        """Generate the master ElGamal public-private key pair."""
        self.master_keypair = ElGamal.generate(self.key_size, get_random_bytes)
        logging.info("Generated master ElGamal keypair.")
        self.store_state()

    def encrypt_content(self, content_id, content_data):
        """Encrypt digital content using the master public key."""
        if self.master_keypair is None:
            raise ValueError("Master keypair not generated. Please generate it first.")
        
        public_key = self.master_keypair.publickey()

        # Generate a random AES key for content encryption
        aes_key = get_random_bytes(32)  # AES-256 key
        cipher_aes = AES.new(aes_key, AES.MODE_CBC)
        ciphertext = cipher_aes.encrypt(pad(content_data.encode('utf-8'), AES.block_size))

        # Encrypt the AES key with ElGamal public key
        k = randint(1, public_key.p - 2)
        shared_secret = pow(public_key.g, k, public_key.p)
        aes_encrypted_key = (pow(public_key.y, k, public_key.p) * aes_key[0]) % public_key.p
        
        self.content_metadata[content_id] = {
            "content_id": content_id,
            "ciphertext": ciphertext,
            "iv": cipher_aes.iv,
            "aes_encrypted_key": aes_encrypted_key,
            "shared_secret": shared_secret
        }
        
        logging.info(f"Encrypted content: {content_id}")
        self.store_state()

    def grant_access(self, customer_id, content_id):
        """Grant access to a customer for specific content."""
        if customer_id not in self.customers:
            raise ValueError(f"Customer {customer_id} not registered.")
        if content_id not in self.content_metadata:
            raise ValueError(f"Content {content_id} not found.")
        
        self.customers[customer_id]['access'][content_id] = {
            "granted_at": time.time(),
            "expires_at": None  # Set to None for indefinite access
        }

        logging.info(f"Granted access to customer {customer_id} for content {content_id}.")
        self.store_state()

    def revoke_access(self, customer_id, content_id):
        """Revoke access to a customer for specific content."""
        if customer_id in self.customers and content_id in self.customers[customer_id]['access']:
            del self.customers[customer_id]['access'][content_id]
            logging.info(f"Revoked access to customer {customer_id} for content {content_id}.")
            self.store_state()

    def revoke_master_key(self):
        """Revoke the master private key (e.g., in case of a breach)."""
        logging.warning("Master private key revoked due to security reasons.")
        self.master_keypair = None
        self.store_state()

    def renew_master_keypair(self):
        """Renew the master keypair every 24 months."""
        current_time = time.time()
        if self.master_keypair is not None and current_time - os.path.getctime('master_keypair.json') > 24 * 30 * 24 * 3600:
            self.generate_master_keypair()
            logging.info("Master keypair renewed.")
            self.store_state()

    def decrypt_content(self, customer_id, content_id):
        """Allow authorized customers to decrypt content."""
        if customer_id not in self.customers:
            raise ValueError(f"Customer {customer_id} not registered.")
        if content_id not in self.customers[customer_id]['access']:
            raise ValueError(f"Access not granted to customer {customer_id} for content {content_id}.")

        content_meta = self.content_metadata[content_id]
        aes_encrypted_key = content_meta['aes_encrypted_key']
        shared_secret = content_meta['shared_secret']

        # Decrypt the AES key
        private_key = self.master_keypair.x
        decrypted_aes_key = (aes_encrypted_key * pow(shared_secret, private_key, self.master_keypair.p)) % self.master_keypair.p
        
        # Decrypt the content
        cipher_aes = AES.new(decrypted_aes_key, AES.MODE_CBC, iv=content_meta['iv'])
        decrypted_content = unpad(cipher_aes.decrypt(content_meta['ciphertext']), AES.block_size)

        logging.info(f"Customer {customer_id} decrypted content {content_id}.")
        return decrypted_content.decode('utf-8')

    def register_customer(self, customer_id):
        """Register a new customer."""
        if customer_id not in self.customers:
            self.customers[customer_id] = {"access": {}}
            logging.info(f"Registered new customer: {customer_id}")
            self.store_state()

    def store_state(self):
        """Save current state to a JSON file."""
        state = {
            "customers": self.customers,
            "content_metadata": self.content_metadata
        }
        with open('drm_state.json', 'w') as f:
            json.dump(state, f)
        if self.master_keypair:
            with open('master_keypair.json', 'w') as f:
                json.dump({
                    "p": self.master_keypair.p,
                    "g": self.master_keypair.g,
                    "y": self.master_keypair.y,
                    "x": self.master_keypair.x
                }, f)

    def load_state(self):
        """Load state from a JSON file."""
        if os.path.exists('drm_state.json'):
            with open('drm_state.json', 'r') as f:
                state = json.load(f)
                self.customers = state["customers"]
                self.content_metadata = state["content_metadata"]
        
        if os.path.exists('master_keypair.json'):
            with open('master_keypair.json', 'r') as f:
                key_data = json.load(f)
                self.master_keypair = ElGamal.construct((key_data['p'], key_data['g'], key_data['y'], key_data['x']))

# -------------------- Main Functionality for DigiRights DRM System --------------------

def main():
    # Initialize DRM system
    drm = DRMSystem(key_size=2048)

    # Generate master keypair
    print("\n--- Generating Master Keypair ---")
    drm.generate_master_keypair()

    # Register customers
    print("\n--- Registering Customers ---")
    drm.register_customer("customer1")
    drm.register_customer("customer2")

    # Encrypt content
    print("\n--- Encrypting Content ---")
    drm.encrypt_content("content1", "Digital content: E-book - Learning Python")
    drm.encrypt_content("content2", "Digital content: Movie - The Matrix")

    # Grant access to customers
    print("\n--- Granting Access ---")
    drm.grant_access("customer1", "content1")
    drm.grant_access("customer2", "content2")

    # Decrypt content for customers
    print("\n--- Decrypting Content for Customer1 ---")
    decrypted_content = drm.decrypt_content("customer1", "content1")
    print(f"Decrypted Content (Customer1): {decrypted_content}")

    print("\n--- Decrypting Content for Customer2 ---")
    decrypted_content = drm.decrypt_content("customer2", "content2")
    print(f"Decrypted Content (Customer2): {decrypted_content}")

    # Revoke access
    print("\n--- Revoking Access for Customer1 ---")
    drm.revoke_access("customer1", "content1")

    # Revoke master key (emergency)
    print("\n--- Revoking Master Key ---")
    drm.revoke_master_key()

if __name__ == "__main__":
    main()
