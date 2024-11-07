import json
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
from base64 import b64encode, b64decode
from datetime import datetime

class SecureBankingSystem:
    def __init__(self):
        # Generate RSA keys for different roles
        self.manager_keys = self._generate_rsa_keys()
        self.accountant_keys = self._generate_rsa_keys()
        
        # Generate symmetric key for Fernet (used for file encryption)
        self.symmetric_key = Fernet.generate_key()
        self.fernet = Fernet(self.symmetric_key)
        
        # Initialize storage files
        self.records_file = "records.json"
        self.transactions_file = "transactions.json"
        self._initialize_storage()

    def _generate_rsa_keys(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        return {
            'private': private_key,
            'public': public_key
        }

    def _initialize_storage(self):
        # Create empty files if they don't exist
        if not os.path.exists(self.records_file):
            with open(self.records_file, 'w') as f:
                json.dump({}, f)
        
        if not os.path.exists(self.transactions_file):
            with open(self.transactions_file, 'w') as f:
                json.dump([], f)

    def _encrypt_data(self, data):
        """Encrypt data using symmetric encryption"""
        return self.fernet.encrypt(json.dumps(data).encode())

    def _decrypt_data(self, encrypted_data):
        """Decrypt data using symmetric encryption"""
        return json.loads(self.fernet.decrypt(encrypted_data))

    def _create_signature(self, data, private_key):
        """Create digital signature for data"""
        signature = private_key.sign(
            json.dumps(data).encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return b64encode(signature).decode()

    def _verify_signature(self, data, signature, public_key):
        """Verify digital signature"""
        try:
            public_key.verify(
                b64decode(signature),
                json.dumps(data).encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except:
            return False

    def _create_searchable_index(self, data, keywords):
        """Create searchable encryption index"""
        index = {}
        for keyword in keywords:
            # Create a deterministic encryption of the keyword
            keyword_hash = hashlib.sha256(keyword.encode()).hexdigest()
            index[keyword_hash] = []
            
            # Find all records containing this keyword
            for record_id, record in data.items():
                if keyword.lower() in str(record).lower():
                    index[keyword_hash].append(record_id)
        return index

class Manager:
    def __init__(self, system, private_key, public_key):
        self.system = system
        self.private_key = private_key
        self.public_key = public_key

    def approve_transaction(self, transaction_id, approval_status):
        """Approve a transaction with digital signature"""
        with open(self.system.transactions_file, 'r') as f:
            transactions = json.load(f)
        
        for transaction in transactions:
            if transaction['id'] == transaction_id:
                approval_data = {
                    'transaction_id': transaction_id,
                    'status': approval_status,
                    'timestamp': str(datetime.now())
                }
                
                # Sign the approval
                signature = self.system._create_signature(approval_data, self.private_key)
                
                transaction['approval'] = approval_data
                transaction['signature'] = signature
                break
        
        with open(self.system.transactions_file, 'w') as f:
            json.dump(transactions, f)

class Clerk:
    def __init__(self, system):
        self.system = system

    def search_transactions(self, keyword):
        """Search encrypted transactions using searchable encryption"""
        with open(self.system.transactions_file, 'r') as f:
            transactions = json.load(f)
        
        # Create searchable index
        index = self.system._create_searchable_index(
            {str(i): t for i, t in enumerate(transactions)},
            [keyword]
        )
        
        # Get matching transaction IDs
        keyword_hash = hashlib.sha256(keyword.encode()).hexdigest()
        matching_ids = index.get(keyword_hash, [])
        
        # Return matching transactions
        return [transactions[int(id)] for id in matching_ids]

    def create_transaction(self, customer_id, amount, transaction_type):
        """Create a new transaction"""
        transaction = {
            'id': hashlib.sha256(str(datetime.now().timestamp()).encode()).hexdigest()[:8],
            'customer_id': customer_id,
            'amount': amount,
            'type': transaction_type,
            'timestamp': str(datetime.now()),
            'status': 'pending'
        }
        
        with open(self.system.transactions_file, 'r') as f:
            transactions = json.load(f)
        
        transactions.append(transaction)
        
        with open(self.system.transactions_file, 'w') as f:
            json.dump(transactions, f)
        
        return transaction['id']

class Accountant:
    def __init__(self, system, private_key, public_key):
        self.system = system
        self.private_key = private_key
        self.public_key = public_key

    def generate_financial_summary(self, start_date, end_date):
        """Generate and sign financial summary"""
        with open(self.system.transactions_file, 'r') as f:
            transactions = json.load(f)
        
        # Filter transactions by date and calculate summary
        summary = {
            'total_transactions': 0,
            'total_amount': 0,
            'period': f"{start_date} to {end_date}"
        }
        
        for transaction in transactions:
            transaction_date = datetime.strptime(transaction['timestamp'], '%Y-%m-%d %H:%M:%S.%f')
            if start_date <= transaction_date <= end_date:
                summary['total_transactions'] += 1
                summary['total_amount'] += transaction['amount']
        
        # Sign the summary
        signature = self.system._create_signature(summary, self.private_key)
        
        return {
            'summary': summary,
            'signature': signature
        }

# Example usage
def main():
    # Initialize the system
    system = SecureBankingSystem()
    
    # Create role instances
    manager = Manager(system, system.manager_keys['private'], system.manager_keys['public'])
    clerk = Clerk(system)
    accountant = Accountant(system, system.accountant_keys['private'], system.accountant_keys['public'])
    
    # Example operations
    # 1. Clerk creates a transaction
    transaction_id = clerk.create_transaction("CUST001", 1000.00, "deposit")
    print(f"Created transaction: {transaction_id}")
    
    # 2. Manager approves transaction
    manager.approve_transaction(transaction_id, "approved")
    print("Transaction approved by manager")
    
    # 3. Clerk searches for transactions
    matching_transactions = clerk.search_transactions("CUST001")
    print(f"Found transactions: {matching_transactions}")
    
    # 4. Accountant generates summary
    start_date = datetime.now()
    end_date = datetime.now()
    summary = accountant.generate_financial_summary(start_date, end_date)
    print(f"Financial summary: {summary}")

if __name__ == "__main__":
    main()