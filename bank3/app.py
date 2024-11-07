import json
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import os
from base64 import b64encode, b64decode
from datetime import datetime
from enum import Enum
from functools import wraps

# Define roles and permissions
class Role(Enum):
    MANAGER = "manager"
    CLERK = "clerk"
    ACCOUNTANT = "accountant"

class Permission(Enum):
    CREATE_TRANSACTION = "create_transaction"
    APPROVE_TRANSACTION = "approve_transaction"
    SEARCH_TRANSACTIONS = "search_transactions"
    GENERATE_SUMMARY = "generate_summary"
    VIEW_TRANSACTION_DETAILS = "view_transaction_details"

# Define role-permission mappings
ROLE_PERMISSIONS = {
    Role.MANAGER: [
        Permission.APPROVE_TRANSACTION,
        Permission.SEARCH_TRANSACTIONS,
        Permission.VIEW_TRANSACTION_DETAILS
    ],
    Role.CLERK: [
        Permission.CREATE_TRANSACTION,
        Permission.SEARCH_TRANSACTIONS
    ],
    Role.ACCOUNTANT: [
        Permission.GENERATE_SUMMARY
    ]
}

# Decorator for permission checking
def require_permission(permission):
    def decorator(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            if not self.user.has_permission(permission):
                raise PermissionError(f"User {self.user.username} does not have permission: {permission.value}")
            return func(self, *args, **kwargs)
        return wrapper
    return decorator

class User:
    def __init__(self, username, role):
        self.username = username
        self.role = role
        self.rsa_keys = self._generate_rsa_keys()

    def _generate_rsa_keys(self):
        key = RSA.generate(2048)
        return {
            'private': key,
            'public': key.publickey()
        }

    def has_permission(self, permission):
        return permission in ROLE_PERMISSIONS[self.role]

class SecureBankingSystem:
    def __init__(self):
        # Generate AES key for symmetric encryption
        self.symmetric_key = get_random_bytes(32)  # AES-256 key
        
        # Initialize storage files
        self.records_file = "records.json"
        self.transactions_file = "transactions.json"
        self.users = {}  # Store user instances
        self._initialize_storage()

    def _initialize_storage(self):
        for file_path in [self.records_file, self.transactions_file]:
            if not os.path.exists(file_path):
                with open(file_path, 'w') as f:
                    json.dump([], f)

    def create_user(self, username, role):
        """Create a new user with specified role"""
        if username in self.users:
            raise ValueError(f"User {username} already exists")
        user = User(username, role)
        self.users[username] = user
        return user

    def get_user(self, username):
        """Get user by username"""
        return self.users.get(username)

    def _encrypt_data(self, data):
        """Encrypt data using AES"""
        cipher = AES.new(self.symmetric_key, AES.MODE_GCM)
        json_str = json.dumps(data)
        ciphertext, tag = cipher.encrypt_and_digest(json_str.encode())
        
        encrypted_data = {
            'nonce': b64encode(cipher.nonce).decode('utf-8'),
            'ciphertext': b64encode(ciphertext).decode('utf-8'),
            'tag': b64encode(tag).decode('utf-8')
        }
        return encrypted_data

    def _decrypt_data(self, encrypted_data):
        """Decrypt data using AES"""
        nonce = b64decode(encrypted_data['nonce'])
        ciphertext = b64decode(encrypted_data['ciphertext'])
        tag = b64decode(encrypted_data['tag'])
        
        cipher = AES.new(self.symmetric_key, AES.MODE_GCM, nonce=nonce)
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
        return json.loads(decrypted_data)

    def _create_signature(self, data, private_key):
        """Create digital signature for data"""
        hash_obj = SHA256.new(json.dumps(data).encode())
        signature = pkcs1_15.new(private_key).sign(hash_obj)
        return b64encode(signature).decode()

    def _verify_signature(self, data, signature, public_key):
        """Verify digital signature"""
        try:
            hash_obj = SHA256.new(json.dumps(data).encode())
            pkcs1_15.new(public_key).verify(hash_obj, b64decode(signature))
            return True
        except (ValueError, TypeError):
            return False

    def _create_searchable_index(self, data, keywords):
        """Create searchable encryption index using deterministic encryption"""
        index = {}
        for keyword in keywords:
            # Create a deterministic hash of the keyword
            keyword_hash = SHA256.new(keyword.encode()).hexdigest()
            index[keyword_hash] = []
            
            # Find all records containing this keyword
            for record_id, record in data.items():
                if keyword.lower() in str(record).lower():
                    index[keyword_hash].append(record_id)
        return index

class BankingOperation:
    def __init__(self, system, user):
        self.system = system
        self.user = user

    @require_permission(Permission.CREATE_TRANSACTION)
    def create_transaction(self, customer_id, amount, transaction_type):
        """Create a new transaction"""
        transaction = {
            'id': SHA256.new(str(datetime.now().timestamp()).encode()).hexdigest()[:8],
            'customer_id': customer_id,
            'amount': amount,
            'type': transaction_type,
            'timestamp': str(datetime.now()),
            'status': 'pending',
            'created_by': self.user.username
        }
        
        # Encrypt transaction data
        encrypted_transaction = self.system._encrypt_data(transaction)
        
        with open(self.system.transactions_file, 'r') as f:
            transactions = json.load(f)
        
        transactions.append({
            'id': transaction['id'],
            'data': encrypted_transaction
        })
        
        with open(self.system.transactions_file, 'w') as f:
            json.dump(transactions, f)
        
        return transaction['id']

    @require_permission(Permission.APPROVE_TRANSACTION)
    def approve_transaction(self, transaction_id, approval_status):
        """Approve a transaction with digital signature"""
        with open(self.system.transactions_file, 'r') as f:
            transactions = json.load(f)
        
        for transaction in transactions:
            if transaction['id'] == transaction_id:
                # Decrypt transaction data
                decrypted_data = self.system._decrypt_data(transaction['data'])
                
                approval_data = {
                    'transaction_id': transaction_id,
                    'status': approval_status,
                    'timestamp': str(datetime.now()),
                    'approved_by': self.user.username
                }
                
                # Sign the approval
                signature = self.system._create_signature(
                    approval_data, 
                    self.user.rsa_keys['private']
                )
                
                decrypted_data['approval'] = approval_data
                decrypted_data['signature'] = signature
                
                # Re-encrypt the updated transaction data
                transaction['data'] = self.system._encrypt_data(decrypted_data)
                break
        
        with open(self.system.transactions_file, 'w') as f:
            json.dump(transactions, f)

    @require_permission(Permission.SEARCH_TRANSACTIONS)
    def search_transactions(self, keyword):
        """Search encrypted transactions using searchable encryption"""
        with open(self.system.transactions_file, 'r') as f:
            encrypted_transactions = json.load(f)
        
        # Decrypt all transactions for searching
        transactions = {}
        for i, t in enumerate(encrypted_transactions):
            decrypted_data = self.system._decrypt_data(t['data'])
            transactions[str(i)] = decrypted_data
        
        # Create searchable index
        index = self.system._create_searchable_index(transactions, [keyword])
        
        # Get matching transaction IDs
        keyword_hash = SHA256.new(keyword.encode()).hexdigest()
        matching_ids = index.get(keyword_hash, [])
        
        # Return matching transactions
        return [transactions[id] for id in matching_ids]

    @require_permission(Permission.GENERATE_SUMMARY)
    def generate_financial_summary(self, start_date, end_date):
        """Generate and sign financial summary"""
        with open(self.system.transactions_file, 'r') as f:
            encrypted_transactions = json.load(f)
        
        summary = {
            'total_transactions': 0,
            'total_amount': 0,
            'period': f"{start_date} to {end_date}",
            'generated_by': self.user.username,
            'timestamp': str(datetime.now())
        }
        
        for transaction in encrypted_transactions:
            decrypted_data = self.system._decrypt_data(transaction['data'])
            transaction_date = datetime.strptime(
                decrypted_data['timestamp'], 
                '%Y-%m-%d %H:%M:%S.%f'
            )
            if start_date <= transaction_date <= end_date:
                summary['total_transactions'] += 1
                summary['total_amount'] += decrypted_data['amount']
        
        # Sign the summary
        signature = self.system._create_signature(
            summary, 
            self.user.rsa_keys['private']
        )
        
        return {
            'summary': summary,
            'signature': signature
        }

def main():
    # Initialize the system
    system = SecureBankingSystem()
    
    # Create users with different roles
    manager = system.create_user("john_manager", Role.MANAGER)
    clerk = system.create_user("jane_clerk", Role.CLERK)
    accountant = system.create_user("bob_accountant", Role.ACCOUNTANT)
    
    # Create banking operations for each user
    manager_ops = BankingOperation(system, manager)
    clerk_ops = BankingOperation(system, clerk)
    accountant_ops = BankingOperation(system, accountant)
    
    try:
        # 1. Clerk creates a transaction
        transaction_id = clerk_ops.create_transaction("CUST001", 1000.00, "deposit")
        print(f"Created transaction: {transaction_id}")
        
        # 2. Manager approves transaction
        manager_ops.approve_transaction(transaction_id, "approved")
        print("Transaction approved by manager")
        
        # 3. Clerk searches for transactions
        matching_transactions = clerk_ops.search_transactions("CUST001")
        print(f"Found transactions: {matching_transactions}")
        
        # 4. Accountant generates summary
        start_date = datetime.now()
        end_date = datetime.now()
        summary = accountant_ops.generate_financial_summary(start_date, end_date)
        print(f"Financial summary: {summary}")
        
        # 5. Test permission error
        try:
            # Clerk trying to approve transaction (should fail)
            clerk_ops.approve_transaction(transaction_id, "approved")
        except PermissionError as e:
            print(f"Permission check working: {e}")
            
    except Exception as e:
        print(f"Error occurred: {e}")

if __name__ == "__main__":
    main()