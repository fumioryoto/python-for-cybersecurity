#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Blockchain Technology in Python for Cybersecurity
This script implements blockchain concepts and applications:
- Blockchain data structure
- Proof of Work algorithm
- Transactions and blocks
- Smart contracts
- Decentralized applications
- Cryptocurrency basics
Perfect for beginners!
"""

import os
import sys
import time
import hashlib
import json
import base64
import random
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass
from enum import Enum
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization

@dataclass
class Transaction:
    """Transaction structure"""
    sender: str
    receiver: str
    amount: float
    timestamp: float
    signature: str
    metadata: Dict[str, Any] = None

@dataclass
class Block:
    """Block structure"""
    index: int
    timestamp: float
    transactions: List[Transaction]
    previous_hash: str
    hash: str
    nonce: int
    difficulty: int
    merkle_root: str

class ConsensusAlgorithm(Enum):
    """Consensus algorithm enumeration"""
    PROOF_OF_WORK = 0
    PROOF_OF_STAKE = 1
    PROOF_OF_AUTHORITY = 2
    DIRECTED_ACYCLIC_GRAPH = 3

class Blockchain:
    """Blockchain implementation"""
    
    def __init__(self, difficulty: int = 4, consensus: ConsensusAlgorithm = ConsensusAlgorithm.PROOF_OF_WORK):
        """
        Initialize blockchain
        
        Args:
            difficulty: Mining difficulty (number of leading zeros)
            consensus: Consensus algorithm to use
        """
        self.chain: List[Block] = []
        self.pending_transactions: List[Transaction] = []
        self.difficulty = difficulty
        self.consensus = consensus
        self.wallets: Dict[str, Dict[str, str]] = {}
        self.balances: Dict[str, float] = {}
        
        # Create genesis block
        self._create_genesis_block()
        
    def _create_genesis_block(self):
        """Create genesis block"""
        genesis_transaction = Transaction(
            sender="system",
            receiver="genesis",
            amount=0,
            timestamp=time.time(),
            signature="genesis_signature",
            metadata={"description": "Genesis block"}
        )
        
        self.pending_transactions.append(genesis_transaction)
        
        genesis_block = Block(
            index=0,
            timestamp=time.time(),
            transactions=[genesis_transaction],
            previous_hash="genesis",
            hash="",
            nonce=0,
            difficulty=self.difficulty,
            merkle_root=self._calculate_merkle_root([genesis_transaction])
        )
        
        genesis_block.hash = self._calculate_block_hash(genesis_block)
        self.chain.append(genesis_block)
        
        # Initialize balances
        self.balances["genesis"] = 1000000
        
    def _calculate_hash(self, data: str) -> str:
        """Calculate SHA-256 hash of data"""
        return hashlib.sha256(data.encode('utf-8')).hexdigest()
        
    def _calculate_block_hash(self, block: Block) -> str:
        """Calculate block hash"""
        block_data = {
            'index': block.index,
            'timestamp': block.timestamp,
            'transactions': [
                {
                    'sender': tx.sender,
                    'receiver': tx.receiver,
                    'amount': tx.amount,
                    'timestamp': tx.timestamp,
                    'signature': tx.signature,
                    'metadata': tx.metadata
                }
                for tx in block.transactions
            ],
            'previous_hash': block.previous_hash,
            'nonce': block.nonce,
            'difficulty': block.difficulty,
            'merkle_root': block.merkle_root
        }
        
        return self._calculate_hash(json.dumps(block_data, sort_keys=True))
        
    def _calculate_merkle_root(self, transactions: List[Transaction]) -> str:
        """Calculate Merkle root of transactions"""
        if not transactions:
            return ''
            
        transaction_hashes = []
        
        for tx in transactions:
            tx_hash = self._calculate_hash(json.dumps({
                'sender': tx.sender,
                'receiver': tx.receiver,
                'amount': tx.amount,
                'timestamp': tx.timestamp,
                'signature': tx.signature,
                'metadata': tx.metadata
            }, sort_keys=True))
            
            transaction_hashes.append(tx_hash)
            
        # Build Merkle tree
        while len(transaction_hashes) > 1:
            next_level = []
            
            for i in range(0, len(transaction_hashes), 2):
                left = transaction_hashes[i]
                right = transaction_hashes[i+1] if i+1 < len(transaction_hashes) else left
                combined = self._calculate_hash(left + right)
                next_level.append(combined)
                
            transaction_hashes = next_level
            
        return transaction_hashes[0]
        
    def create_wallet(self) -> Tuple[str, str]:
        """
        Create new blockchain wallet
        
        Returns:
            Tuple of (address, private_key)
        """
        try:
            # Generate keys
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            
            public_key = private_key.public_key()
            
            # Serialize keys
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Create address
            address = self._calculate_hash(public_pem.decode('utf-8'))[:32]
            
            # Store keys
            self.wallets[address] = {
                'private_key': private_pem.decode('utf-8'),
                'public_key': public_pem.decode('utf-8')
            }
            
            # Initialize balance
            self.balances[address] = 0
            
            return address, private_pem.decode('utf-8')
            
        except Exception as e:
            print(f"Error creating wallet: {e}")
            return None, None
            
    def get_balance(self, address: str) -> float:
        """
        Get wallet balance
        
        Args:
            address: Wallet address
            
        Returns:
            Current balance
        """
        return self.balances.get(address, 0)
        
    def add_transaction(self, sender: str, receiver: str, amount: float,
                      signature: str, metadata: Dict[str, Any] = None) -> bool:
        """
        Add transaction to pending list
        
        Args:
            sender: Sender address
            receiver: Receiver address
            amount: Transaction amount
            signature: Digital signature
            metadata: Additional metadata
            
        Returns:
            True if transaction valid, False otherwise
        """
        try:
            # Validate sender and receiver
            if sender not in self.wallets or receiver not in self.wallets:
                print("Sender or receiver does not exist")
                return False
                
            # Validate balance
            if self.get_balance(sender) < amount:
                print("Insufficient balance")
                return False
                
            transaction = Transaction(
                sender=sender,
                receiver=receiver,
                amount=amount,
                timestamp=time.time(),
                signature=signature,
                metadata=metadata or {}
            )
            
            # Verify signature
            if not self._verify_transaction_signature(transaction):
                print("Invalid signature")
                return False
                
            self.pending_transactions.append(transaction)
            
            return True
            
        except Exception as e:
            print(f"Error adding transaction: {e}")
            return False
            
    def _verify_transaction_signature(self, transaction: Transaction) -> bool:
        """Verify transaction signature"""
        try:
            if transaction.sender not in self.wallets:
                return False
                
            # Create signature data string
            data_to_sign = f"{transaction.sender}:{transaction.receiver}:{transaction.amount}:{transaction.timestamp}"
            
            # Load public key
            public_pem = self.wallets[transaction.sender]['public_key']
            public_key = serialization.load_pem_public_key(public_pem.encode('utf-8'))
            
            # Verify signature
            public_key.verify(
                base64.b64decode(transaction.signature),
                data_to_sign.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            return True
            
        except Exception as e:
            print(f"Signature verification failed: {e}")
            return False
            
    def mine_block(self, miner_address: str) -> Block:
        """
        Mine new block
        
        Args:
            miner_address: Miner's wallet address
            
        Returns:
            New Block object
        """
        if not self.pending_transactions:
            print("No transactions to mine")
            return None
            
        try:
            last_block = self.chain[-1]
            
            # Create new block
            new_block = Block(
                index=last_block.index + 1,
                timestamp=time.time(),
                transactions=self.pending_transactions.copy(),
                previous_hash=last_block.hash,
                hash='',
                nonce=0,
                difficulty=self.difficulty,
                merkle_root=self._calculate_merkle_root(self.pending_transactions)
            )
            
            # Mine block
            if self.consensus == ConsensusAlgorithm.PROOF_OF_WORK:
                new_block = self._proof_of_work(new_block)
            elif self.consensus == ConsensusAlgorithm.PROOF_OF_STAKE:
                new_block = self._proof_of_stake(new_block)
                
            # Add mining reward
            reward_transaction = Transaction(
                sender="system",
                receiver=miner_address,
                amount=10,  # Block reward
                timestamp=time.time(),
                signature="system_reward",
                metadata={"description": "Block reward"}
            )
            
            new_block.transactions.append(reward_transaction)
            
            # Calculate final block hash
            new_block.merkle_root = self._calculate_merkle_root(new_block.transactions)
            new_block.hash = self._calculate_block_hash(new_block)
            
            self.chain.append(new_block)
            
            # Clear pending transactions and update balances
            self._update_balances(new_block)
            self.pending_transactions.clear()
            
            print(f"Block mined successfully! Index: {new_block.index}")
            
            return new_block
            
        except Exception as e:
            print(f"Error mining block: {e}")
            return None
            
    def _proof_of_work(self, block: Block) -> Block:
        """Proof of Work algorithm"""
        prefix = '0' * self.difficulty
        
        print(f"Mining block {block.index} with difficulty {self.difficulty}...")
        
        while True:
            block.nonce += 1
            block_hash = self._calculate_block_hash(block)
            
            if block_hash.startswith(prefix):
                block.hash = block_hash
                print(f"Found nonce: {block.nonce}")
                print(f"Hash: {block_hash}")
                break
                
            if block.nonce % 10000 == 0:
                print(f"Tried {block.nonce} nonces...")
                
        return block
        
    def _proof_of_stake(self, block: Block) -> Block:
        """Proof of Stake algorithm (simplified)"""
        # Calculate stakeholder weights
        stakeholders = {}
        total_stake = 0
        
        for address, balance in self.balances.items():
            if balance > 0:
                stakeholders[address] = balance
                total_stake += balance
                
        # Select miner based on stake
        if not stakeholders:
            raise Exception("No valid stakeholders")
            
        stake_weights = [balance / total_stake for address, balance in stakeholders.items()]
        selected_address = random.choices(list(stakeholders.keys()), weights=stake_weights)[0]
        
        print(f"Selected validator: {selected_address}")
        
        block.nonce = random.randint(0, 1000)
        block.hash = self._calculate_block_hash(block)
        
        return block
        
    def _update_balances(self, block: Block):
        """Update balances after block creation"""
        for transaction in block.transactions:
            if transaction.sender != "system":
                self.balances[transaction.sender] -= transaction.amount
                
            if transaction.receiver != "genesis":
                if transaction.receiver not in self.balances:
                    self.balances[transaction.receiver] = 0
                    
                self.balances[transaction.receiver] += transaction.amount
                
    def validate_chain(self) -> bool:
        """
        Validate blockchain integrity
        
        Returns:
            True if chain valid, False otherwise
        """
        if len(self.chain) == 0:
            return True
            
        previous_block = self.chain[0]
        
        for i in range(1, len(self.chain)):
            block = self.chain[i]
            
            print(f"Checking block {i}...")
            
            if block.previous_hash != previous_block.hash:
                print(f"Block {i} previous hash mismatch")
                return False
                
            current_hash = self._calculate_block_hash(block)
            
            if block.hash != current_hash:
                print(f"Block {i} hash mismatch")
                return False
                
            previous_block = block
            
        return True
        
    def get_block_by_index(self, index: int) -> Block:
        """
        Get block by index
        
        Args:
            index: Block index
            
        Returns:
            Block or None
        """
        if index < 0 or index >= len(self.chain):
            return None
            
        return self.chain[index]
        
    def get_block_by_hash(self, block_hash: str) -> Block:
        """
        Get block by hash
        
        Args:
            block_hash: Block hash
            
        Returns:
            Block or None
        """
        for block in self.chain:
            if block.hash == block_hash:
                return block
                
        return None
        
    def get_transactions_by_address(self, address: str) -> List[Transaction]:
        """
        Get transactions by address
        
        Args:
            address: Wallet address
            
        Returns:
            List of transactions involving the address
        """
        transactions = []
        
        for block in self.chain:
            for tx in block.transactions:
                if tx.sender == address or tx.receiver == address:
                    transactions.append(tx)
                    
        return transactions
        
    def save_blockchain(self, file_path: str):
        """
        Save blockchain to file
        
        Args:
            file_path: Output file path
        """
        try:
            blockchain_data = {
                'chain': [],
                'pending_transactions': [],
                'difficulty': self.difficulty,
                'consensus': self.consensus.value,
                'wallets': self.wallets,
                'balances': self.balances
            }
            
            for block in self.chain:
                block_data = {
                    'index': block.index,
                    'timestamp': block.timestamp,
                    'transactions': [
                        {
                            'sender': tx.sender,
                            'receiver': tx.receiver,
                            'amount': tx.amount,
                            'timestamp': tx.timestamp,
                            'signature': tx.signature,
                            'metadata': tx.metadata
                        }
                        for tx in block.transactions
                    ],
                    'previous_hash': block.previous_hash,
                    'hash': block.hash,
                    'nonce': block.nonce,
                    'difficulty': block.difficulty,
                    'merkle_root': block.merkle_root
                }
                
                blockchain_data['chain'].append(block_data)
                
            for tx in self.pending_transactions:
                tx_data = {
                    'sender': tx.sender,
                    'receiver': tx.receiver,
                    'amount': tx.amount,
                    'timestamp': tx.timestamp,
                    'signature': tx.signature,
                    'metadata': tx.metadata
                }
                
                blockchain_data['pending_transactions'].append(tx_data)
                
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(blockchain_data, f, indent=2, default=str)
                
            print(f"Blockchain saved to: {file_path}")
            
        except Exception as e:
            print(f"Error saving blockchain: {e}")
            
    def load_blockchain(self, file_path: str):
        """
        Load blockchain from file
        
        Args:
            file_path: File to load from
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                blockchain_data = json.load(f)
                
            # Load chain
            self.chain = []
            
            for block_data in blockchain_data['chain']:
                block = Block(
                    index=block_data['index'],
                    timestamp=float(block_data['timestamp']),
                    transactions=[
                        Transaction(
                            sender=tx['sender'],
                            receiver=tx['receiver'],
                            amount=tx['amount'],
                            timestamp=float(tx['timestamp']),
                            signature=tx['signature'],
                            metadata=tx.get('metadata')
                        )
                        for tx in block_data['transactions']
                    ],
                    previous_hash=block_data['previous_hash'],
                    hash=block_data['hash'],
                    nonce=block_data['nonce'],
                    difficulty=block_data['difficulty'],
                    merkle_root=block_data['merkle_root']
                )
                
                self.chain.append(block)
                
            # Load pending transactions
            self.pending_transactions = [
                Transaction(
                    sender=tx['sender'],
                    receiver=tx['receiver'],
                    amount=tx['amount'],
                    timestamp=float(tx['timestamp']),
                    signature=tx['signature'],
                    metadata=tx.get('metadata')
                )
                for tx in blockchain_data['pending_transactions']
            ]
            
            # Load other data
            self.difficulty = blockchain_data['difficulty']
            self.consensus = ConsensusAlgorithm(blockchain_data['consensus'])
            self.wallets = blockchain_data['wallets']
            self.balances = {k: float(v) for k, v in blockchain_data['balances'].items()}
            
            print(f"Blockchain loaded from: {file_path}")
            
        except Exception as e:
            print(f"Error loading blockchain: {e}")

def main():
    """Main function to demonstrate blockchain functionality"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Blockchain Technology - Demonstration of blockchain concepts"
    )
    
    parser.add_argument(
        "-c", "--create-wallet",
        action="store_true",
        help="Create new blockchain wallet"
    )
    
    parser.add_argument(
        "-b", "--balance",
        help="Get balance for specific address"
    )
    
    parser.add_argument(
        "-t", "--transaction",
        nargs=3,
        metavar=("SENDER", "RECEIVER", "AMOUNT"),
        help="Create new transaction"
    )
    
    parser.add_argument(
        "-m", "--mine",
        help="Mine new block with specified miner address"
    )
    
    parser.add_argument(
        "-v", "--validate",
        action="store_true",
        help="Validate blockchain integrity"
    )
    
    parser.add_argument(
        "-s", "--save",
        help="Save blockchain to file"
    )
    
    parser.add_argument(
        "-l", "--load",
        help="Load blockchain from file"
    )
    
    parser.add_argument(
        "-p", "--print-chain",
        action="store_true",
        help="Print entire blockchain"
    )
    
    parser.add_argument(
        "-d", "--difficulty",
        type=int,
        default=4,
        help="Mining difficulty"
    )
    
    args = parser.parse_args()
    
    bc = Blockchain(difficulty=args.difficulty)
    
    try:
        if args.create_wallet:
            address, private_key = bc.create_wallet()
            
            if address:
                print(f"{'='*60}")
                print(f"  NEW WALLET CREATED")
                print(f"{'='*60}")
                print(f"Address: {address}")
                print(f"Private Key:")
                print(private_key)
                
        elif args.balance:
            balance = bc.get_balance(args.balance)
            
            print(f"{'='*60}")
            print(f"  WALLET BALANCE")
            print(f"{'='*60}")
            print(f"Address: {args.balance}")
            print(f"Balance: {balance:.2f} coins")
            
        elif args.transaction:
            sender = args.transaction[0]
            receiver = args.transaction[1]
            amount = float(args.transaction[2])
            
            if sender not in bc.wallets:
                print(f"Sender {sender} does not exist")
                return
                
            if receiver not in bc.wallets:
                print(f"Receiver {receiver} does not exist")
                return
                
            if bc.get_balance(sender) < amount:
                print("Insufficient balance")
                return
                
            # Create transaction signature
            import base64
            
            data_to_sign = f"{sender}:{receiver}:{amount}:{time.time()}"
            
            private_key = serialization.load_pem_private_key(
                bc.wallets[sender]['private_key'].encode('utf-8'),
                password=None
            )
            
            signature = private_key.sign(
                data_to_sign.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            signature_base64 = base64.b64encode(signature).decode('utf-8')
            
            if bc.add_transaction(sender, receiver, amount, signature_base64):
                print(f"{'='*60}")
                print(f"  TRANSACTION ADDED")
                print(f"{'='*60}")
                print(f"Sender: {sender}")
                print(f"Receiver: {receiver}")
                print(f"Amount: {amount:.2f} coins")
                print(f"Signature: {signature_base64}")
                
        elif args.mine:
            if args.mine not in bc.wallets:
                print(f"Miner address {args.mine} does not exist")
                return
                
            block = bc.mine_block(args.mine)
            
            if block:
                print(f"{'='*60}")
                print(f"  BLOCK MINED")
                print(f"{'='*60}")
                print(f"Block Index: {block.index}")
                print(f"Hash: {block.hash}")
                print(f"Previous Hash: {block.previous_hash}")
                print(f"Nonce: {block.nonce}")
                print(f"Transactions: {len(block.transactions)}")
                print(f"Difficulty: {block.difficulty}")
                
        elif args.validate:
            if bc.validate_chain():
                print("Blockchain is valid")
            else:
                print("Blockchain validation failed")
                
        elif args.save:
            bc.save_blockchain(args.save)
            
        elif args.load:
            bc.load_blockchain(args.load)
            
        elif args.print_chain:
            for i, block in enumerate(bc.chain):
                print(f"{'='*60}")
                print(f"  BLOCK {i}")
                print(f"{'='*60}")
                print(f"Index: {block.index}")
                print(f"Timestamp: {time.ctime(block.timestamp)}")
                print(f"Hash: {block.hash}")
                print(f"Previous Hash: {block.previous_hash}")
                print(f"Nonce: {block.nonce}")
                print(f"Difficulty: {block.difficulty}")
                print(f"Merkle Root: {block.merkle_root}")
                print(f"Transactions: {len(block.transactions)}")
                
                if block.transactions:
                    print(f"{'='*60}")
                    print(f"  TRANSACTIONS")
                    print(f"{'='*60}")
                    
                    for j, tx in enumerate(block.transactions):
                        print(f"Transaction {j+1}:")
                        print(f"  Sender: {tx.sender}")
                        print(f"  Receiver: {tx.receiver}")
                        print(f"  Amount: {tx.amount:.2f}")
                        print(f"  Time: {time.ctime(tx.timestamp)}")
                        
                        if tx.metadata:
                            print(f"  Metadata: {json.dumps(tx.metadata, indent=2)}")
                            
                        print()
                
        else:
            parser.print_help()
            
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        print(traceback.format_exc())

if __name__ == "__main__":
    main()
