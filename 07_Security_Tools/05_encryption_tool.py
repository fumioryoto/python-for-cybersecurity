#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Encryption Tool in Python for Cybersecurity
This script implements various encryption and decryption methods
including AES, RSA, hashing, and digital signatures.
Perfect for beginners!
"""

import hashlib
import base64
import os
import json
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization

class EncryptionTool:
    """Comprehensive encryption tool with multiple algorithms"""
    
    def __init__(self):
        """Initialize encryption tool"""
        self.backend = default_backend()
        
    # ==========================================
    # Hash Functions
    # ==========================================
    def calculate_hash(self, data, algorithm='sha256'):
        """
        Calculate hash of data
        
        Args:
            data: Data to hash (string or bytes)
            algorithm: Hash algorithm (md5, sha1, sha256, sha512)
            
        Returns:
            Hexadecimal hash string
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        if algorithm == 'md5':
            return hashlib.md5(data).hexdigest()
        elif algorithm == 'sha1':
            return hashlib.sha1(data).hexdigest()
        elif algorithm == 'sha256':
            return hashlib.sha256(data).hexdigest()
        elif algorithm == 'sha512':
            return hashlib.sha512(data).hexdigest()
        else:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")
            
    def verify_hash(self, data, expected_hash, algorithm='sha256'):
        """
        Verify that data matches expected hash
        
        Args:
            data: Data to verify
            expected_hash: Expected hash value
            algorithm: Hash algorithm
            
        Returns:
            Boolean indicating if hash matches
        """
        return self.calculate_hash(data, algorithm) == expected_hash
            
    # ==========================================
    # Symmetric Encryption (AES)
    # ==========================================
    def generate_aes_key(self, key_size=256):
        """
        Generate random AES key
        
        Args:
            key_size: Key size in bits (128, 192, or 256)
            
        Returns:
            Base64 encoded key string
        """
        key_bytes = os.urandom(key_size // 8)
        return base64.b64encode(key_bytes).decode('utf-8')
        
    def aes_encrypt(self, data, key):
        """
        Encrypt data using AES
        
        Args:
            data: Data to encrypt (string or bytes)
            key: AES key (base64 encoded string)
            
        Returns:
            Encrypted data as base64 encoded string
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        key_bytes = base64.b64decode(key)
        
        # Generate random IV (Initialization Vector)
        iv = os.urandom(16)
        
        # Pad data to multiple of block size
        padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        
        # Create cipher object
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        
        # Encrypt data
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Combine IV and encrypted data and base64 encode
        return base64.b64encode(iv + encrypted_data).decode('utf-8')
        
    def aes_decrypt(self, encrypted_data, key):
        """
        Decrypt AES encrypted data
        
        Args:
            encrypted_data: Encrypted data as base64 encoded string
            key: AES key (base64 encoded string)
            
        Returns:
            Decrypted data as string
        """
        encrypted_bytes = base64.b64decode(encrypted_data)
        
        # Extract IV (first 16 bytes)
        iv = encrypted_bytes[:16]
        ciphertext = encrypted_bytes[16:]
        
        key_bytes = base64.b64decode(key)
        
        # Create cipher object
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        
        try:
            # Decrypt data
            decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Unpad data
            unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
            unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
            
            return unpadded_data.decode('utf-8')
            
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")
            
    # ==========================================
    # Asymmetric Encryption (RSA)
    # ==========================================
    def generate_rsa_keys(self, key_size=2048):
        """
        Generate RSA key pair
        
        Args:
            key_size: Key size in bits (minimum 2048 recommended)
            
        Returns:
            Tuple (private_key, public_key) as PEM encoded strings
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=self.backend
        )
        
        # Serialize private key
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Serialize public key
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem.decode('utf-8'), public_pem.decode('utf-8')
        
    def rsa_encrypt(self, data, public_key):
        """
        Encrypt data using RSA public key
        
        Args:
            data: Data to encrypt (string or bytes)
            public_key: RSA public key (PEM encoded string)
            
        Returns:
            Encrypted data as base64 encoded string
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        # Load public key
        try:
            public_key_obj = serialization.load_pem_public_key(
                public_key.encode('utf-8'),
                backend=self.backend
            )
        except Exception as e:
            raise ValueError(f"Invalid public key: {e}")
            
        # Encrypt data
        encrypted_data = public_key_obj.encrypt(
            data,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return base64.b64encode(encrypted_data).decode('utf-8')
        
    def rsa_decrypt(self, encrypted_data, private_key):
        """
        Decrypt RSA encrypted data
        
        Args:
            encrypted_data: Encrypted data as base64 encoded string
            private_key: RSA private key (PEM encoded string)
            
        Returns:
            Decrypted data as string
        """
        encrypted_bytes = base64.b64decode(encrypted_data)
        
        # Load private key
        try:
            private_key_obj = serialization.load_pem_private_key(
                private_key.encode('utf-8'),
                password=None,
                backend=self.backend
            )
        except Exception as e:
            raise ValueError(f"Invalid private key: {e}")
            
        # Decrypt data
        try:
            decrypted_data = private_key_obj.decrypt(
                encrypted_bytes,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            return decrypted_data.decode('utf-8')
            
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")
            
    # ==========================================
    # Digital Signatures (RSA)
    # ==========================================
    def rsa_sign(self, data, private_key):
        """
        Sign data using RSA private key
        
        Args:
            data: Data to sign (string or bytes)
            private_key: RSA private key (PEM encoded string)
            
        Returns:
            Digital signature as base64 encoded string
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        # Load private key
        try:
            private_key_obj = serialization.load_pem_private_key(
                private_key.encode('utf-8'),
                password=None,
                backend=self.backend
            )
        except Exception as e:
            raise ValueError(f"Invalid private key: {e}")
            
        # Sign data
        signature = private_key_obj.sign(
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return base64.b64encode(signature).decode('utf-8')
        
    def rsa_verify(self, data, signature, public_key):
        """
        Verify digital signature using RSA public key
        
        Args:
            data: Data to verify (string or bytes)
            signature: Digital signature (base64 encoded string)
            public_key: RSA public key (PEM encoded string)
            
        Returns:
            Boolean indicating if signature is valid
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        try:
            # Load public key
            public_key_obj = serialization.load_pem_public_key(
                public_key.encode('utf-8'),
                backend=self.backend
            )
            
            # Verify signature
            public_key_obj.verify(
                base64.b64decode(signature),
                data,
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            return True
            
        except Exception as e:
            print(f"Signature verification failed: {e}")
            return False
            
    # ==========================================
    # File Operations
    # ==========================================
    def encrypt_file(self, file_path, key, output_path=None):
        """
        Encrypt file using AES
        
        Args:
            file_path: Path to input file
            key: AES key (base64 encoded string)
            output_path: Path to output encrypted file
            
        Returns:
            Path to encrypted file
        """
        if not output_path:
            output_path = file_path + '.encrypted'
            
        try:
            # Read file content
            with open(file_path, 'rb') as f:
                data = f.read()
                
            # Encrypt data
            encrypted_data = self.aes_encrypt(data, key)
            
            # Write encrypted data
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(encrypted_data)
                
            return output_path
            
        except Exception as e:
            raise ValueError(f"File encryption failed: {e}")
            
    def decrypt_file(self, file_path, key, output_path=None):
        """
        Decrypt file using AES
        
        Args:
            file_path: Path to encrypted file
            key: AES key (base64 encoded string)
            output_path: Path to output decrypted file
            
        Returns:
            Path to decrypted file
        """
        if not output_path:
            if file_path.endswith('.encrypted'):
                output_path = file_path[:-len('.encrypted')]
            else:
                output_path = file_path + '.decrypted'
                
        try:
            # Read encrypted data
            with open(file_path, 'r', encoding='utf-8') as f:
                encrypted_data = f.read()
                
            # Decrypt data
            decrypted_data = self.aes_decrypt(encrypted_data, key)
            
            # Write decrypted data
            with open(output_path, 'wb') as f:
                f.write(decrypted_data.encode('utf-8'))
                
            return output_path
            
        except Exception as e:
            raise ValueError(f"File decryption failed: {e}")
            
    def calculate_file_hash(self, file_path, algorithm='sha256'):
        """
        Calculate hash of file content
        
        Args:
            file_path: Path to file
            algorithm: Hash algorithm
            
        Returns:
            Hexadecimal hash string
        """
        hash_obj = None
        
        if algorithm == 'md5':
            hash_obj = hashlib.md5()
        elif algorithm == 'sha1':
            hash_obj = hashlib.sha1()
        elif algorithm == 'sha256':
            hash_obj = hashlib.sha256()
        elif algorithm == 'sha512':
            hash_obj = hashlib.sha512()
        else:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")
            
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hash_obj.update(chunk)
                    
            return hash_obj.hexdigest()
            
        except Exception as e:
            raise ValueError(f"File hash calculation failed: {e}")

def demo_encryption_tool():
    """Demonstrate encryption tool functionality"""
    print(f"{'='*60}")
    print(f"  ENCRYPTION TOOL DEMONSTRATION")
    print(f"{'='*60}")
    
    tool = EncryptionTool()
    
    # Test hash functions
    print(f"\n{'='*40}")
    print(f"  HASH FUNCTIONS")
    print(f"{'='*40}")
    
    test_data = "Hello, Cybersecurity!"
    print(f"Original data: {test_data}")
    
    for algorithm in ['md5', 'sha1', 'sha256', 'sha512']:
        hash_value = tool.calculate_hash(test_data, algorithm)
        print(f"{algorithm.upper()}: {hash_value}")
        
    # Test AES encryption
    print(f"\n{'='*40}")
    print(f"  AES ENCRYPTION")
    print(f"{'='*40}")
    
    aes_key = tool.generate_aes_key(256)
    print(f"Generated AES key: {aes_key}")
    
    encrypted_data = tool.aes_encrypt(test_data, aes_key)
    print(f"Encrypted data: {encrypted_data}")
    
    decrypted_data = tool.aes_decrypt(encrypted_data, aes_key)
    print(f"Decrypted data: {decrypted_data}")
    
    print(f"Decrypted matches original: {decrypted_data == test_data}")
    
    # Test RSA encryption
    print(f"\n{'='*40}")
    print(f"  RSA ENCRYPTION")
    print(f"{'='*40}")
    
    private_key, public_key = tool.generate_rsa_keys(2048)
    print(f"Generated RSA keys (2048 bits)")
    
    encrypted_rsa = tool.rsa_encrypt(test_data, public_key)
    print(f"Encrypted with public key: {encrypted_rsa}")
    
    decrypted_rsa = tool.rsa_decrypt(encrypted_rsa, private_key)
    print(f"Decrypted with private key: {decrypted_rsa}")
    
    print(f"Decrypted matches original: {decrypted_rsa == test_data}")
    
    # Test digital signatures
    print(f"\n{'='*40}")
    print(f"  DIGITAL SIGNATURES")
    print(f"{'='*40}")
    
    signature = tool.rsa_sign(test_data, private_key)
    print(f"Generated signature: {signature}")
    
    is_valid = tool.rsa_verify(test_data, signature, public_key)
    print(f"Signature is valid: {is_valid}")
    
    # Test invalid signature
    invalid_signature = signature[:-1] + '0'
    is_valid = tool.rsa_verify(test_data, invalid_signature, public_key)
    print(f"Invalid signature is valid: {is_valid}")
    
    return True

def main():
    """Main function to run encryption tool"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Encryption Tool - Comprehensive encryption utility"
    )
    
    parser.add_argument(
        "-d", "--demo",
        action="store_true",
        help="Run encryption tool demonstration"
    )
    
    parser.add_argument(
        "-a", "--action",
        choices=['hash', 'encrypt', 'decrypt', 'sign', 'verify'],
        help="Action to perform"
    )
    
    parser.add_argument(
        "-i", "--input",
        help="Input data or file"
    )
    
    parser.add_argument(
        "-o", "--output",
        help="Output file"
    )
    
    parser.add_argument(
        "-k", "--key",
        help="Encryption key"
    )
    
    parser.add_argument(
        "-A", "--algorithm",
        choices=['aes', 'rsa', 'md5', 'sha1', 'sha256', 'sha512'],
        default='sha256',
        help="Algorithm to use (default: sha256)"
    )
    
    args = parser.parse_args()
    
    try:
        if args.demo:
            demo_encryption_tool()
        else:
            tool = EncryptionTool()
            
            if args.action == 'hash':
                if os.path.exists(args.input):
                    hash_value = tool.calculate_file_hash(args.input, args.algorithm)
                    print(f"{args.algorithm.upper()} hash of {args.input}: {hash_value}")
                else:
                    hash_value = tool.calculate_hash(args.input, args.algorithm)
                    print(f"{args.algorithm.upper()} hash: {hash_value}")
                    
            elif args.action == 'encrypt':
                if args.algorithm == 'aes':
                    if not args.key:
                        args.key = tool.generate_aes_key(256)
                        print(f"Generated AES key (save this!): {args.key}")
                        
                    if os.path.exists(args.input):
                        output = tool.encrypt_file(args.input, args.key, args.output)
                        print(f"Encrypted file saved to: {output}")
                    else:
                        encrypted = tool.aes_encrypt(args.input, args.key)
                        if args.output:
                            with open(args.output, 'w', encoding='utf-8') as f:
                                f.write(encrypted)
                            print(f"Encrypted data saved to: {args.output}")
                        else:
                            print(f"Encrypted data: {encrypted}")
                            
                elif args.algorithm == 'rsa':
                    if not args.key:
                        private_key, public_key = tool.generate_rsa_keys()
                        print(f"Generated RSA keys (save these!):")
                        print(f"Public key:\n{public_key}")
                        print(f"Private key:\n{private_key}")
                        
                        with open('public_key.pem', 'w', encoding='utf-8') as f:
                            f.write(public_key)
                        with open('private_key.pem', 'w', encoding='utf-8') as f:
                            f.write(private_key)
                            
                        print("\nKeys saved to public_key.pem and private_key.pem")
                        
                    if os.path.exists(args.input):
                        with open(args.input, 'rb') as f:
                            data = f.read()
                    else:
                        data = args.input
                        
                    encrypted = tool.rsa_encrypt(data, args.key)
                    if args.output:
                        with open(args.output, 'w', encoding='utf-8') as f:
                            f.write(encrypted)
                        print(f"Encrypted data saved to: {args.output}")
                    else:
                        print(f"Encrypted data: {encrypted}")
                        
            elif args.action == 'decrypt':
                if args.algorithm == 'aes':
                    if not args.key:
                        raise ValueError("AES key required for decryption")
                        
                    if os.path.exists(args.input):
                        output = tool.decrypt_file(args.input, args.key, args.output)
                        print(f"Decrypted file saved to: {output}")
                    else:
                        decrypted = tool.aes_decrypt(args.input, args.key)
                        if args.output:
                            with open(args.output, 'w', encoding='utf-8') as f:
                                f.write(decrypted)
                            print(f"Decrypted data saved to: {args.output}")
                        else:
                            print(f"Decrypted data: {decrypted}")
                            
                elif args.algorithm == 'rsa':
                    if not args.key:
                        raise ValueError("RSA private key required for decryption")
                        
                    if os.path.exists(args.input):
                        with open(args.input, 'r', encoding='utf-8') as f:
                            encrypted = f.read()
                    else:
                        encrypted = args.input
                        
                    decrypted = tool.rsa_decrypt(encrypted, args.key)
                    if args.output:
                        with open(args.output, 'w', encoding='utf-8') as f:
                            f.write(decrypted)
                        print(f"Decrypted data saved to: {args.output}")
                    else:
                        print(f"Decrypted data: {decrypted}")
                        
            elif args.action == 'sign':
                if os.path.exists(args.input):
                    with open(args.input, 'rb') as f:
                        data = f.read()
                else:
                    data = args.input
                    
                signature = tool.rsa_sign(data, args.key)
                
                if args.output:
                    with open(args.output, 'w', encoding='utf-8') as f:
                        f.write(signature)
                    print(f"Signature saved to: {args.output}")
                else:
                    print(f"Signature: {signature}")
                    
            elif args.action == 'verify':
                if os.path.exists(args.input):
                    with open(args.input, 'rb') as f:
                        data = f.read()
                else:
                    data = args.input
                    
                valid = tool.rsa_verify(data, args.key, args.algorithm)
                print(f"Signature is valid: {valid}")
                
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        print(traceback.format_exc())

if __name__ == "__main__":
    main()
