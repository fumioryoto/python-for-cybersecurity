# Cryptography Projects

This file contains project ideas to enhance your Python cryptography skills with practical, hands-on experience. Each project includes learning objectives, key technologies, and implementation guidance.

## Project 1: Cryptographic File Encryption Tool

**Learning Objectives:**

- Understand symmetric and asymmetric encryption concepts
- Implement file encryption/decryption functionality
- Manage cryptographic keys and passwords
- Handle file operations and data persistence

**Key Technologies:**

- Fernet (symmetric encryption)
- RSA (asymmetric encryption)
- OS module for file operations
- Tkinter for GUI (optional)
- Argparse for command-line interface

**Implementation Steps:**

1. **Core Encryption Engine:**
   - Implement symmetric encryption using Fernet
   - Implement asymmetric encryption using RSA
   - Handle password-based key derivation
   - Provide both encryption and decryption methods

2. **File Operations:**
   - Read and write encrypted files
   - Handle large file streaming
   - Validate file integrity
   - Implement secure file deletion

3. **Key Management:**
   - Generate and store cryptographic keys
   - Implement key rotation
   - Handle password protection
   - Support key export/import

4. **User Interface:**
   - Command-line interface with argparse
   - Optional GUI using Tkinter
   - File selection dialogs
   - Progress indicators for large files

5. **Security Features:**
   - Verify file integrity with checksums
   - Implement secure random number generation
   - Add password strength validation
   - Handle error conditions gracefully

**Example Code Snippet:**

```python
from cryptography.fernet import Fernet
import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class FileEncryptor:
    def __init__(self):
        self.key = None

    def generate_key(self, password: str, salt: bytes = None) -> bytes:
        """Generate encryption key from password"""
        if salt is None:
            salt = os.urandom(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000
        )

        key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))

        return key

    def encrypt_file(self, file_path: str, output_path: str, password: str):
        """Encrypt file using password-based encryption"""
        salt = os.urandom(16)
        key = self.generate_key(password, salt)

        with open(file_path, 'rb') as f:
            data = f.read()

        fernet = Fernet(key)
        encrypted_data = fernet.encrypt(data)

        with open(output_path, 'wb') as f:
            f.write(salt)
            f.write(encrypted_data)

        print(f"File encrypted successfully: {output_path}")

    def decrypt_file(self, file_path: str, output_path: str, password: str):
        """Decrypt file using password-based encryption"""
        with open(file_path, 'rb') as f:
            salt = f.read(16)
            encrypted_data = f.read()

        key = self.generate_key(password, salt)

        fernet = Fernet(key)
        decrypted_data = fernet.decrypt(encrypted_data)

        with open(output_path, 'wb') as f:
            f.write(decrypted_data)

        print(f"File decrypted successfully: {output_path}")
```

## Project 2: Secure Password Manager

**Learning Objectives:**

- Implement password storage and management
- Use secure cryptographic practices
- Create user authentication system
- Develop password generation and strength checking

**Key Technologies:**

- AES encryption for data storage
- PBKDF2 for key derivation
- SQLite3 for database operations
- Tkinter or PyQt for GUI
- Clipboard operations

**Implementation Steps:**

1. **Password Storage:**
   - Create secure password database
   - Encrypt passwords using AES
   - Implement password retrieval and updating
   - Handle duplicate entries

2. **User Authentication:**
   - Implement master password authentication
   - Add biometric authentication support (optional)
   - Handle login attempts and lockout
   - Implement password reset functionality

3. **Password Generation:**
   - Create random password generator
   - Allow customization of password complexity
   - Generate pronounceable passwords (optional)
   - Test password strength

4. **Password Strength Checker:**
   - Implement zxcvbn library for strength estimation
   - Provide real-time feedback on password strength
   - Check for common passwords and patterns
   - Suggest improvements for weak passwords

5. **Additional Features:**
   - Auto-fill and clipboard management
   - Browser extension integration (optional)
   - Password sharing functionality
   - Backup and sync capabilities

**Example Code Snippet:**

```python
import sqlite3
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import random
import string

class PasswordManager:
    def __init__(self, db_path: str = 'passwords.db'):
        self.db_path = db_path
        self.conn = None
        self.cursor = None
        self.key = None

    def connect(self):
        """Connect to password database"""
        self.conn = sqlite3.connect(self.db_path)
        self.cursor = self.conn.cursor()

        # Create passwords table if it doesn't exist
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                website TEXT NOT NULL,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

    def generate_password(self, length: int = 12, include_symbols: bool = True) -> str:
        """Generate random secure password"""
        charset = string.ascii_letters + string.digits

        if include_symbols:
            charset += '!@#$%^&*()_+-=[]{}|;:,.<>?'

        password = ''.join(random.choice(charset) for _ in range(length))

        return password

    def add_password(self, website: str, username: str, password: str, notes: str = ''):
        """Add password to database (encrypted)"""
        encrypted_password = self._encrypt(password)

        self.cursor.execute('''
            INSERT INTO passwords (website, username, password, notes)
            VALUES (?, ?, ?, ?)
        ''', (website, username, encrypted_password, notes))

        self.conn.commit()

    def get_passwords(self):
        """Get all passwords from database (decrypted)"""
        self.cursor.execute('SELECT id, website, username, password, notes FROM passwords')

        passwords = []

        for row in self.cursor.fetchall():
            id_, website, username, encrypted_password, notes = row

            try:
                password = self._decrypt(encrypted_password)
            except Exception as e:
                print(f"Decryption failed: {e}")
                continue

            passwords.append({
                'id': id_,
                'website': website,
                'username': username,
                'password': password,
                'notes': notes
            })

        return passwords

    def _encrypt(self, text: str) -> bytes:
        """Encrypt text using Fernet"""
        fernet = Fernet(self.key)
        return fernet.encrypt(text.encode('utf-8'))

    def _decrypt(self, encrypted_text: bytes) -> str:
        """Decrypt text using Fernet"""
        fernet = Fernet(self.key)
        return fernet.decrypt(encrypted_text).decode('utf-8')
```

## Project 3: Digital Signature Verification Tool

**Learning Objectives:**

- Understand digital signature concepts
- Implement signature verification algorithms
- Validate certificate chains
- Handle different signature formats

**Key Technologies:**

- OpenSSL libraries for signatures
- Cryptography module for X.509 certificates
- Hash functions (SHA-256, SHA-512)
- File formats (PDF, XML, etc.)
- GUI framework (optional)

**Implementation Steps:**

1. **Signature Validation:**
   - Implement RSA and DSA signature verification
   - Handle PKCS#7 and CMS signature formats
   - Verify signature against public key
   - Validate hash algorithms

2. **Certificate Management:**
   - Parse X.509 certificates
   - Validate certificate chains
   - Check certificate revocation status (CRL/OCSP)
   - Extract certificate information

3. **Document Signing:**
   - Support common document formats
   - Embed signatures in files
   - Verify signed documents
   - Extract signature information

4. **User Interface:**
   - File selection and validation
   - Display signature details
   - Certificate chain visualization
   - Export validation reports

**Example Code Snippet:**

```python
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import base64
import hashlib

class DigitalSignature:
    def __init__(self):
        self.backend = default_backend()

    def generate_rsa_key_pair(self, key_size: int = 2048):
        """Generate RSA key pair for signing"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=self.backend
        )

        public_key = private_key.public_key()

        return private_key, public_key

    def sign_data(self, data: bytes, private_key):
        """Sign data using RSA private key"""
        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return signature

    def verify_signature(self, data: bytes, signature: bytes, public_key):
        """Verify signature against public key"""
        try:
            public_key.verify(
                signature,
                data,
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

    def sign_file(self, file_path: str, private_key, output_path: str = None):
        """Sign file and save signed version"""
        with open(file_path, 'rb') as f:
            data = f.read()

        signature = self.sign_data(data, private_key)

        if output_path is None:
            output_path = file_path + '.signed'

        with open(output_path, 'wb') as f:
            f.write(base64.b64encode(signature) + b'\n')
            f.write(data)

        return output_path

    def verify_file(self, signed_file_path: str, public_key):
        """Verify signed file"""
        with open(signed_file_path, 'rb') as f:
            signature_line = f.readline().strip()
            data = f.read()

        try:
            signature = base64.b64decode(signature_line)
        except Exception as e:
            print(f"Invalid signature format: {e}")
            return False

        return self.verify_signature(data, signature, public_key)
```

## Project 4: Network Protocol Analyzer with Encryption Support

**Learning Objectives:**

- Capture and analyze network traffic
- Decrypt encrypted network protocols
- Implement packet sniffing
- Handle various network protocols

**Key Technologies:**

- Scapy for packet sniffing and analysis
- Cryptography module for encryption/decryption
- Wireshark integration
- Socket programming
- Protocol parsing

**Implementation Steps:**

1. **Packet Capture:**
   - Implement packet sniffing with Scapy
   - Filter traffic based on protocols and hosts
   - Capture and save packets to PCAP files
   - Real-time packet analysis

2. **Protocol Decryption:**
   - Support for TLS/SSL decryption
   - Handle HTTP, HTTPS, FTP, and other protocols
   - Decrypt encrypted payloads
   - Extract and decode data

3. **Traffic Analysis:**
   - Parse and display packet information
   - Identify network anomalies
   - Detect common attacks
   - Generate traffic statistics

4. **User Interface:**
   - Real-time packet display
   - Packet filtering and search
   - Protocol-specific views
   - Export analysis reports

**Example Code Snippet:**

```python
from scapy.all import sniff, IP, TCP, UDP, Raw
import scapy.all as scapy
import base64
from cryptography.fernet import Fernet

class NetworkAnalyzer:
    def __init__(self, interface: str = 'eth0', filter_str: str = ''):
        self.interface = interface
        self.filter_str = filter_str
        self.packets = []

    def start_sniffing(self, packet_count: int = 100):
        """Start packet sniffing"""
        print(f"Sniffing packets on {self.interface}...")

        self.packets = sniff(
            iface=self.interface,
            count=packet_count,
            filter=self.filter_str,
            prn=self._process_packet
        )

        return self.packets

    def _process_packet(self, packet):
        """Process captured packet"""
        print(f"Captured packet from {packet[IP].src} to {packet[IP].dst}")

        # Check for encrypted payload
        if Raw in packet:
            payload = packet[Raw].load

            # Try to detect encrypted data
            if self._is_encrypted(payload):
                print("Encrypted payload detected")

                # Try to decrypt with known keys
                decrypted = self._try_decryption(payload)

                if decrypted:
                    print(f"Decrypted payload: {decrypted}")

    def _is_encrypted(self, data: bytes) -> bool:
        """Check if data is likely encrypted"""
        # Simple heuristic: encrypted data has high entropy and no readable text
        try:
            decoded = data.decode('utf-8')
            return len(decoded) < len(data) or any(ord(c) > 127 for c in decoded)
        except:
            return True

    def _try_decryption(self, data: bytes) -> str:
        """Try common decryption methods"""
        # Check if data is base64 encoded
        try:
            decoded = base64.b64decode(data)
            return decoded.decode('utf-8')
        except:
            pass

        return None

    def analyze_protocol_distribution(self):
        """Analyze protocol distribution in captured packets"""
        protocols = {}

        for packet in self.packets:
            protocol = self._get_protocol(packet)

            if protocol not in protocols:
                protocols[protocol] = 0

            protocols[protocol] += 1

        return protocols

    def _get_protocol(self, packet):
        """Determine protocol from packet"""
        if TCP in packet:
            return 'TCP'
        elif UDP in packet:
            return 'UDP'
        elif packet.haslayer('ICMP'):
            return 'ICMP'
        else:
            return 'Other'
```

## Project 5: Blockchain Implementation with Cryptography

**Learning Objectives:**

- Implement blockchain data structure
- Use cryptographic hashes
- Create proof-of-work algorithm
- Handle transaction signing

**Key Technologies:**

- SHA-256 hash function
- ECDSA for digital signatures
- JSON for data serialization
- HTTP for network communication
- Flask for API endpoints

**Implementation Steps:**

1. **Blockchain Structure:**
   - Create block class with transactions and hash
   - Implement block chaining and validation
   - Add block timestamp and previous hash
   - Handle genesis block creation

2. **Transaction System:**
   - Implement transaction structure
   - Add digital signature verification
   - Handle transaction mining
   - Implement UTXO (unspent transaction outputs)

3. **Consensus Mechanism:**
   - Implement proof-of-work algorithm
   - Create mining process
   - Handle difficulty adjustment
   - Implement peer-to-peer network

4. **Network Integration:**
   - Create API endpoints for interaction
   - Implement peer discovery and communication
   - Handle blockchain synchronization
   - Support wallet operations

**Example Code Snippet:**

```python
import hashlib
import json
from time import time
from urllib.parse import urlparse
from uuid import uuid4
import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

class Blockchain:
    def __init__(self):
        self.chain = []
        self.current_transactions = []
        self.nodes = set()

        # Create genesis block
        self.new_block(previous_hash='1', proof=100)

    def new_transaction(self, sender: str, recipient: str, amount: float, signature: str) -> int:
        """Add new transaction to list of pending transactions"""
        self.current_transactions.append({
            'sender': sender,
            'recipient': recipient,
            'amount': amount,
            'signature': signature,
            'timestamp': time()
        })

        return self.last_block['index'] + 1

    def new_block(self, proof: int, previous_hash: str = None) -> dict:
        """Create new Block in Blockchain"""
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }

        # Reset the current list of transactions
        self.current_transactions = []

        self.chain.append(block)
        return block

    @property
    def last_block(self) -> dict:
        """Return last block in chain"""
        return self.chain[-1]

    @staticmethod
    def hash(block: dict) -> str:
        """Create SHA-256 hash of a Block"""
        block_string = json.dumps(block, sort_keys=True).encode()

        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self, last_block: dict, last_proof: int) -> int:
        """Simple Proof-of-Work Algorithm:
         - Find a number p' such that hash(pp') contains 4 leading zeros, where p is the previous p'
         - p is the previous proof, and p' is the new proof
        """
        proof = 0

        while self.valid_proof(last_proof, proof) is False:
            proof += 1

        return proof

    @staticmethod
    def valid_proof(last_proof: int, proof: int) -> bool:
        """Validates the Proof"""
        guess = f"{last_proof}{proof}".encode()
        guess_hash = hashlib.sha256(guess).hexdigest()

        return guess_hash[:4] == "0000"

    def register_node(self, address: str):
        """Add a new node to the list of nodes"""
        parsed_url = urlparse(address)
        self.nodes.add(parsed_url.netloc)

    def valid_chain(self, chain: list) -> bool:
        """Determine if a given blockchain is valid"""
        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]

            if block['previous_hash'] != self.hash(last_block):
                return False

            if not self.valid_proof(last_block['proof'], block['proof']):
                return False

            last_block = block
            current_index += 1

        return True

    def resolve_conflicts(self) -> bool:
        """Consensus Algorithm to resolve conflicts"""
        neighbors = self.nodes
        new_chain = None
        max_length = len(self.chain)

        for node in neighbors:
            response = requests.get(f"http://{node}/chain")

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain

        if new_chain:
            self.chain = new_chain
            return True

        return False
```

## Learning Resources

**Books:**

- "Cryptography and Network Security: Principles and Practice" by William Stallings
- "Practical Cryptography" by Niels Ferguson and Bruce Schneier
- "Real-World Cryptography" by David Wong

**Online Courses:**

- Coursera: Cryptography I and Cryptography II (Stanford)
- edX: Applied Cryptography (University of Maryland)
- Khan Academy: Cryptography

**Documentation:**

- Python Cryptography Library: https://cryptography.io/en/latest/
- OpenSSL Documentation: https://www.openssl.org/docs/
- PyCryptodome Documentation: https://www.pycryptodome.org/

**Practice Platforms:**

- CryptoPals: https://cryptopals.com/
- Hack The Box: https://www.hackthebox.com/
- TryHackMe: https://tryhackme.com/

Remember, the best way to learn cryptography is by doing. Start with simple projects and gradually build complexity as you gain experience.
