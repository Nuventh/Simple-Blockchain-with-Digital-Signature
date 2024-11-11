import hashlib
import secrets
import time
import rsa

# Generates an 8-character transaction ID.
def generate_transaction_id():
    return secrets.token_hex(8)

# Hashes the input data and returns it in hexadecimal format.
def hash_data(data): 
    return hashlib.sha256(data.encode()).hexdigest()

class User:
    # Initializes a user with an RSA key pair.
    def __init__(self, name):
        self.name = name
        self.public_key, self.private_key = rsa.newkeys(2048)
    
    # Signs a transaction with the user's private key.
    def sign_transaction(self, data):
        return rsa.sign(data.encode(), self.private_key, 'SHA-256')
        
class MerkleTree:
    # Initializes the Merkle tree with transactions and determines the root hash.
    def __init__(self, transactions):
        self.transactions = transactions
        self.root = self.build_merkle_root(transactions)

    # Creates the Merkle root based on a list of transactions.
    def build_merkle_root(self, transactions):
        # Base case: if no transactions, return hash of an empty string
        if len(transactions) == 0:
            return hash_data("")
        
        # If we have only one transaction, that's our root (single transaction tree)
        if len(transactions) == 1:
            return hash_data(transactions[0])
        
        # If there's an odd number of transactions, append an empty hash
        if len(transactions) % 2 != 0:
            transactions.append("")

        # Create the next level by pairing up transactions and hashing them
        next_level = []
        for i in range(0, len(transactions), 2):
            combined_hash = hash_data(transactions[i] + transactions[i + 1])
            next_level.append(combined_hash)
        
        # Recursively build the tree until the root is found
        return self.build_merkle_root(next_level)

class Block:
    # Initializes a block with an index, transactions, previous hash, and timestamp.
    def __init__(self, index, transactions, previous_hash):
        self.index = index
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.timestamp = time.time()
        self.merkle_tree = MerkleTree(transactions)
        self.merkle_root = self.merkle_tree.root
        self.nonce = 0
        self.hash = None
        self.proof_of_work()

    # Calculates the block hash based on all block attributes.
    def calculate_hash(self):
        block_data = f"{self.index}{self.previous_hash}{self.timestamp}{self.merkle_root}{self.nonce}"
        return hash_data(block_data)

    # Proof of Work, ensures the block hash meets the specified difficulty level.
    def proof_of_work(self, difficulty=4):
        prefix_str = '0' * difficulty
        while True:
            self.hash = self.calculate_hash()
            if self.hash.startswith(prefix_str):
                break
            self.nonce += 1

class Blockchain:
    # Initializes the blockchain with a genesis block.
    def __init__(self):
        self.chain = [self.create_genesis_block()]

    # Creates the genesis block.
    def create_genesis_block(self):
        return Block(0, ["Genesis Block"], "0")

    # Returns the latest block in the chain.
    def get_latest_block(self):
        return self.chain[-1]

    # Sets the new block's previous hash, recalculates its hash, then adds it to the chain.
    def add_block(self, new_block):
        new_block.previous_hash = self.get_latest_block().hash
        new_block.proof_of_work()  # Runs PoW on the new block
        self.chain.append(new_block)

    # Checks if every block in the chain is valid.
    def is_chain_valid(self, difficulty=4):
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            
            # Validates the block hash integrity.
            if current_block.hash != current_block.calculate_hash():
                print("The current block hash is invalid.")
                return False
            
            # Validates the previous block hash integrity.
            if current_block.previous_hash != previous_block.hash:
                print("The previous block hash is invalid.")
                return False

            # Proof of Work requirement validation.
            if not current_block.hash.startswith('0' * difficulty):
                print("Proof of Work does not match the required difficulty.")
                return False

        return True

class DigitalSignature:
    # Verifies the given signature with the public key and data.
    def verify_signature(public_key, signature, data):
        try:
            rsa.verify(data.encode(), signature, public_key)
            return True
        except rsa.VerificationError:
            return False

# Blockchain initialization and user creation.
blockchain = Blockchain()
alice = User("Alice")
bob = User("Bob")
users = [alice, bob]
num_transactions = 3

# Generates and adds 3 blocks to the blockchain.
for i in range(1, 4):
    transactions = []
    signatures = []
    
    # Creates and signs each transaction by Alice.
    for j in range(num_transactions):
        tx_description = f"Transaction #{generate_transaction_id()} - Payer: {alice.name}, Recipient: {bob.name}, Amount: 10 BTC"
        signature = alice.sign_transaction(tx_description)
        transactions.append(tx_description)
        signatures.append((alice.public_key, signature, tx_description))
    
    # Verifies each transaction's signature before adding the block.
    all_verified = all(DigitalSignature.verify_signature(pub_key, sig, tx) for pub_key, sig, tx in signatures)

    if all_verified:
        print(f"All transactions verified, adding Block {i} to the blockchain...")
        block = Block(i, transactions, blockchain.get_latest_block().hash)
        blockchain.add_block(block)
    else:
        print(f"Invalid transactions detected in Block {i}!")

# Checks the validity of the blockchain.
print("Blockchain is valid:", blockchain.is_chain_valid())

# Prints the blockchain.
for block in blockchain.chain:
    print(f"Block {block.index}:")
    print(f"  Hash: {block.hash}")
    print(f"  Previous Hash: {block.previous_hash}")
    print(f"  Merkle Root: {block.merkle_root}")
    print(f"  Transactions: {block.transactions}")
    print(f"  Nonce: {block.nonce}\n")
