#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Symmetric Encryption in Python for Cybersecurity - BEGINNER FRIENDLY
This script implements various symmetric encryption algorithms explained in simple terms.
Symmetric encryption uses the SAME secret key for both encryption and decryption - 
like a lock that uses the same key to lock and unlock it!

What's included:
- AES (Advanced Encryption Standard) - THE GOLD STANDARD for secure encryption
- DES (Data Encryption Standard) - OLD and weak, not recommended
- 3DES (Triple DES) - Also old, but more secure than DES
- ChaCha20-Poly1305 - MODERN authenticated encryption (used by Google and Apple)
- Modes of operation (ECB, CBC, CFB, OFB, CTR) - How encryption works with data blocks

Perfect for cybersecurity beginners learning about encrypted communication!
"""

# ========================================================================
# Import necessary modules - THE TOOLS WE NEED!
# ========================================================================
import os                   # For generating random numbers and files
import binascii             # For working with hexadecimal data
import base64               # For encoding binary data as text
import hashlib              # For secure hashing functions
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class SymmetricEncryption:
    """Class for symmetric encryption operations - BEGINNER FRIENDLY!"""
    
    def __init__(self):
        """Initialize symmetric encryption class"""
        self.backend = default_backend()
        
    # ========================================================================
    # Key Management - THE SECRET KEY!
    # ========================================================================
    def generate_key(self, algorithm='AES', key_size=256):
        """
        Generate symmetric encryption key - LIKE MAKING A NEW KEY FOR YOUR LOCK!
        
        Args:
            algorithm: Encryption algorithm to use (AES is recommended)
            key_size: Key size in bits (bigger is stronger!)
            
        Returns:
            Generated key as random bytes - the actual secret key
        """
        if algorithm == 'AES':
            # AES can have 128, 192, or 256-bit keys
            if key_size not in [128, 192, 256]:
                raise ValueError("AES key size must be 128, 192, or 256 bits")
                
            # Generate random key of specified size (bytes = bits / 8)
            return os.urandom(key_size // 8)
            
        elif algorithm == 'DES':
            # DES is old and weak - only 56-bit effective key length
            if key_size != 64:
                raise ValueError("DES key size must be 64 bits")
            return os.urandom(8)
            
        elif algorithm == '3DES':
            if key_size not in [128, 192]:
                raise ValueError("3DES key size must be 128 or 192 bits")
            return os.urandom(key_size // 8)
            
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
            
    def derive_key(self, password, salt=None, iterations=100000, key_length=32):
        """
        Derive encryption key from password using PBKDF2
        
        Args:
            password: Password string
            salt: Salt value (if None, generate new salt)
            iterations: Number of PBKDF2 iterations
            key_length: Derived key length in bytes
            
        Returns:
            (derived_key, salt) tuple
        """
        if salt is None:
            salt = os.urandom(16)
            
        kdf = PBKDF2HMAC(
            algorithm=hashlib.sha256(),
            length=key_length,
            salt=salt,
            iterations=iterations,
            backend=self.backend
        )
        
        if isinstance(password, str):
            password = password.encode('utf-8')
            
        derived_key = kdf.derive(password)
        
        return derived_key, salt
        
    # ==========================================
    # AES Encryption
    # ==========================================
    def aes_encrypt(self, plaintext, key, mode='CBC'):
        """
        Encrypt data using AES algorithm
        
        Args:
            plaintext: Data to encrypt (string or bytes)
            key: Encryption key (bytes)
            mode: Block cipher mode (ECB, CBC, CFB, OFB, CTR)
            
        Returns:
            Tuple containing (ciphertext, iv, salt)
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
            
        salt = os.urandom(16)
        iv = os.urandom(16)
        
        # Pad plaintext to block size
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_text = padder.update(plaintext) + padder.finalize()
        
        # Choose encryption mode
        if mode == 'ECB':
            cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=self.backend)
        elif mode == 'CBC':
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        elif mode == 'CFB':
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=self.backend)
        elif mode == 'OFB':
            cipher = Cipher(algorithms.AES(key), modes.OFB(iv), backend=self.backend)
        elif mode == 'CTR':
            cipher = Cipher(algorithms.AES(key), modes.CTR(iv[:16]), backend=self.backend)
        else:
            raise ValueError(f"Unsupported mode: {mode}")
            
        # Encrypt data
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_text) + encryptor.finalize()
        
        return ciphertext, iv, salt
        
    def aes_decrypt(self, ciphertext, key, iv, salt, mode='CBC'):
        """
        Decrypt data using AES algorithm
        
        Args:
            ciphertext: Encrypted data (bytes)
            key: Encryption key (bytes)
            iv: Initialization vector (bytes)
            salt: Salt value (bytes)
            mode: Block cipher mode (ECB, CBC, CFB, OFB, CTR)
            
        Returns:
            Decrypted plaintext (bytes)
        """
        # Choose encryption mode
        if mode == 'ECB':
            cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=self.backend)
        elif mode == 'CBC':
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        elif mode == 'CFB':
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=self.backend)
        elif mode == 'OFB':
            cipher = Cipher(algorithms.AES(key), modes.OFB(iv), backend=self.backend)
        elif mode == 'CTR':
            cipher = Cipher(algorithms.AES(key), modes.CTR(iv[:16]), backend=self.backend)
        else:
            raise ValueError(f"Unsupported mode: {mode}")
            
        # Decrypt data
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(decrypted_data) + unpadder.finalize()
        
        return plaintext
        
    # ==========================================
    # DES Encryption
    # ==========================================
    def des_encrypt(self, plaintext, key, mode='CBC'):
        """
        Encrypt data using DES algorithm (legacy)
        
        Args:
            plaintext: Data to encrypt (string or bytes)
            key: Encryption key (bytes)
            mode: Block cipher mode (ECB, CBC, CFB, OFB, CTR)
            
        Returns:
            Tuple containing (ciphertext, iv, salt)
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
            
        salt = os.urandom(8)
        iv = os.urandom(8)
        
        # Pad plaintext to block size
        padder = padding.PKCS7(algorithms.DES.block_size).padder()
        padded_text = padder.update(plaintext) + padder.finalize()
        
        # Choose encryption mode
        if mode == 'ECB':
            cipher = Cipher(algorithms.DES(key), modes.ECB(), backend=self.backend)
        elif mode == 'CBC':
            cipher = Cipher(algorithms.DES(key), modes.CBC(iv), backend=self.backend)
        elif mode == 'CFB':
            cipher = Cipher(algorithms.DES(key), modes.CFB(iv), backend=self.backend)
        elif mode == 'OFB':
            cipher = Cipher(algorithms.DES(key), modes.OFB(iv), backend=self.backend)
        elif mode == 'CTR':
            cipher = Cipher(algorithms.DES(key), modes.CTR(iv[:8]), backend=self.backend)
        else:
            raise ValueError(f"Unsupported mode: {mode}")
            
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_text) + encryptor.finalize()
        
        return ciphertext, iv, salt
        
    def des_decrypt(self, ciphertext, key, iv, salt, mode='CBC'):
        """
        Decrypt data using DES algorithm (legacy)
        
        Args:
            ciphertext: Encrypted data (bytes)
            key: Encryption key (bytes)
            iv: Initialization vector (bytes)
            salt: Salt value (bytes)
            mode: Block cipher mode (ECB, CBC, CFB, OFB, CTR)
            
        Returns:
            Decrypted plaintext (bytes)
        """
        if mode == 'ECB':
            cipher = Cipher(algorithms.DES(key), modes.ECB(), backend=self.backend)
        elif mode == 'CBC':
            cipher = Cipher(algorithms.DES(key), modes.CBC(iv), backend=self.backend)
        elif mode == 'CFB':
            cipher = Cipher(algorithms.DES(key), modes.CFB(iv), backend=self.backend)
        elif mode == 'OFB':
            cipher = Cipher(algorithms.DES(key), modes.OFB(iv), backend=self.backend)
        elif mode == 'CTR':
            cipher = Cipher(algorithms.DES(key), modes.CTR(iv[:8]), backend=self.backend)
        else:
            raise ValueError(f"Unsupported mode: {mode}")
            
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        unpadder = padding.PKCS7(algorithms.DES.block_size).unpadder()
        plaintext = unpadder.update(decrypted_data) + unpadder.finalize()
        
        return plaintext
        
    # ==========================================
    # 3DES Encryption
    # ==========================================
    def triple_des_encrypt(self, plaintext, key, mode='CBC'):
        """
        Encrypt data using 3DES algorithm (legacy)
        
        Args:
            plaintext: Data to encrypt (string or bytes)
            key: Encryption key (bytes)
            mode: Block cipher mode (ECB, CBC, CFB, OFB, CTR)
            
        Returns:
            Tuple containing (ciphertext, iv, salt)
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
            
        salt = os.urandom(8)
        iv = os.urandom(8)
        
        padder = padding.PKCS7(algorithms.TripleDES.block_size).padder()
        padded_text = padder.update(plaintext) + padder.finalize()
        
        if mode == 'ECB':
            cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), backend=self.backend)
        elif mode == 'CBC':
            cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=self.backend)
        elif mode == 'CFB':
            cipher = Cipher(algorithms.TripleDES(key), modes.CFB(iv), backend=self.backend)
        elif mode == 'OFB':
            cipher = Cipher(algorithms.TripleDES(key), modes.OFB(iv), backend=self.backend)
        elif mode == 'CTR':
            cipher = Cipher(algorithms.TripleDES(key), modes.CTR(iv[:8]), backend=self.backend)
        else:
            raise ValueError(f"Unsupported mode: {mode}")
            
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_text) + encryptor.finalize()
        
        return ciphertext, iv, salt
        
    def triple_des_decrypt(self, ciphertext, key, iv, salt, mode='CBC'):
        """
        Decrypt data using 3DES algorithm (legacy)
        
        Args:
            ciphertext: Encrypted data (bytes)
            key: Encryption key (bytes)
            iv: Initialization vector (bytes)
            salt: Salt value (bytes)
            mode: Block cipher mode (ECB, CBC, CFB, OFB, CTR)
            
        Returns:
            Decrypted plaintext (bytes)
        """
        if mode == 'ECB':
            cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), backend=self.backend)
        elif mode == 'CBC':
            cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=self.backend)
        elif mode == 'CFB':
            cipher = Cipher(algorithms.TripleDES(key), modes.CFB(iv), backend=self.backend)
        elif mode == 'OFB':
            cipher = Cipher(algorithms.TripleDES(key), modes.OFB(iv), backend=self.backend)
        elif mode == 'CTR':
            cipher = Cipher(algorithms.TripleDES(key), modes.CTR(iv[:8]), backend=self.backend)
        else:
            raise ValueError(f"Unsupported mode: {mode}")
            
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        unpadder = padding.PKCS7(algorithms.TripleDES.block_size).unpadder()
        plaintext = unpadder.update(decrypted_data) + unpadder.finalize()
        
        return plaintext
        
    # ==========================================
    # ChaCha20-Poly1305 (Modern Authenticated Encryption)
    # ==========================================
    def chacha20_poly1305_encrypt(self, plaintext, key, associated_data=b''):
        """
        Encrypt data using ChaCha20-Poly1305 authenticated encryption
        
        Args:
            plaintext: Data to encrypt (string or bytes)
            key: Encryption key (bytes)
            associated_data: Additional authenticated data (bytes)
            
        Returns:
            Tuple containing (ciphertext, nonce, tag)
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
            
        nonce = os.urandom(12)
        
        cipher = Cipher(algorithms.ChaCha20Poly1305(key), mode=None, backend=self.backend)
        encryptor = cipher.encryptor()
        encryptor.authenticate_additional_data(associated_data)
        
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        return ciphertext, nonce, encryptor.tag
        
    def chacha20_poly1305_decrypt(self, ciphertext, key, nonce, tag, associated_data=b''):
        """
        Decrypt data using ChaCha20-Poly1305 authenticated encryption
        
        Args:
            ciphertext: Encrypted data (bytes)
            key: Encryption key (bytes)
            nonce: Nonce value (bytes)
            tag: Authentication tag (bytes)
            associated_data: Additional authenticated data (bytes)
            
        Returns:
            Decrypted plaintext (bytes)
        """
        cipher = Cipher(algorithms.ChaCha20Poly1305(key), mode=None, backend=self.backend)
        decryptor = cipher.decryptor()
        decryptor.authenticate_additional_data(associated_data)
        
        try:
            plaintext = decryptor.update(ciphertext) + decryptor.finalize_with_tag(tag)
            return plaintext
        except Exception as e:
            raise ValueError(f"Authentication failed: {e}")
            
    # ==========================================
    # Helper Methods
    # ==========================================
    def encrypt_file(self, input_file, output_file, key, algorithm='AES', mode='CBC'):
        """
        Encrypt file using specified algorithm
        
        Args:
            input_file: Path to input file
            output_file: Path to output encrypted file
            key: Encryption key (bytes)
            algorithm: Encryption algorithm
            mode: Block cipher mode
        """
        with open(input_file, 'rb') as f:
            plaintext = f.read()
            
        if algorithm == 'AES':
            ciphertext, iv, salt = self.aes_encrypt(plaintext, key, mode)
        elif algorithm == 'DES':
            ciphertext, iv, salt = self.des_encrypt(plaintext, key, mode)
        elif algorithm == '3DES':
            ciphertext, iv, salt = self.triple_des_encrypt(plaintext, key, mode)
        elif algorithm == 'ChaCha20Poly1305':
            ciphertext, iv, salt = self.chacha20_poly1305_encrypt(plaintext, key)
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
            
        with open(output_file, 'wb') as f:
            f.write(salt)
            f.write(iv)
            f.write(ciphertext)
            
    def decrypt_file(self, input_file, output_file, key, algorithm='AES', mode='CBC'):
        """
        Decrypt file using specified algorithm
        
        Args:
            input_file: Path to encrypted file
            output_file: Path to output decrypted file
            key: Decryption key (bytes)
            algorithm: Encryption algorithm
            mode: Block cipher mode
        """
        with open(input_file, 'rb') as f:
            salt = f.read(16 if algorithm == 'AES' else 8)
            iv = f.read(16 if algorithm == 'AES' else 8)
            ciphertext = f.read()
            
        if algorithm == 'AES':
            plaintext = self.aes_decrypt(ciphertext, key, iv, salt, mode)
        elif algorithm == 'DES':
            plaintext = self.des_decrypt(ciphertext, key, iv, salt, mode)
        elif algorithm == '3DES':
            plaintext = self.triple_des_decrypt(ciphertext, key, iv, salt, mode)
        elif algorithm == 'ChaCha20Poly1305':
            # ChaCha20-Poly1305 has different file format
            plaintext = self.chacha20_poly1305_decrypt(ciphertext, key, iv, salt)
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
            
        with open(output_file, 'wb') as f:
            f.write(plaintext)
            
    def key_to_hex(self, key):
        """Convert key to hexadecimal string"""
        return binascii.hexlify(key).decode('utf-8')
        
    def key_from_hex(self, hex_str):
        """Convert hexadecimal string to key"""
        return binascii.unhexlify(hex_str)
        
    def key_to_base64(self, key):
        """Convert key to Base64 string"""
        return base64.b64encode(key).decode('utf-8')
        
    def key_from_base64(self, base64_str):
        """Convert Base64 string to key"""
        return base64.b64decode(base64_str)
        
    def compare_keys(self, key1, key2):
        """Compare keys using constant time algorithm to prevent timing attacks"""
        if len(key1) != len(key2):
            return False
            
        result = 0
        for a, b in zip(key1, key2):
            result |= a ^ b
            
        return result == 0

def demo_symmetric_encryption():
    """Demonstrate symmetric encryption functionality"""
    print(f"{'='*60}")
    print(f"  SYMMETRIC ENCRYPTION DEMONSTRATION")
    print(f"{'='*60}")
    
    crypto = SymmetricEncryption()
    
    # Test 1: AES Encryption
    print(f"\n1. AES Encryption (CBC mode):")
    plaintext = "This is a secret message that needs to be encrypted!"
    key = crypto.generate_key('AES', 256)
    
    ciphertext, iv, salt = crypto.aes_encrypt(plaintext, key, 'CBC')
    decrypted = crypto.aes_decrypt(ciphertext, key, iv, salt, 'CBC').decode('utf-8')
    
    print(f"   Plaintext: {plaintext}")
    print(f"   Ciphertext (hex): {binascii.hexlify(ciphertext).decode('utf-8')}")
    print(f"   Decrypted: {decrypted}")
    print(f"   Success: {plaintext == decrypted}")
    
    # Test 2: AES Encryption with password
    print(f"\n2. AES Encryption with Password:")
    password = "StrongPassword123!"
    derived_key, salt = crypto.derive_key(password, key_length=32)
    
    ciphertext, iv, salt = crypto.aes_encrypt(plaintext, derived_key, 'CBC')
    decrypted = crypto.aes_decrypt(ciphertext, derived_key, iv, salt, 'CBC').decode('utf-8')
    
    print(f"   Plaintext: {plaintext}")
    print(f"   Decrypted: {decrypted}")
    print(f"   Success: {plaintext == decrypted}")
    
    # Test 3: ChaCha20-Poly1305 (Authenticated Encryption)
    print(f"\n3. ChaCha20-Poly1305 (Authenticated Encryption):")
    key = crypto.generate_key('AES', 256)  # ChaCha20-Poly1305 uses 256-bit keys
    
    ciphertext, nonce, tag = crypto.chacha20_poly1305_encrypt(plaintext, key)
    decrypted = crypto.chacha20_poly1305_decrypt(ciphertext, key, nonce, tag).decode('utf-8')
    
    print(f"   Plaintext: {plaintext}")
    print(f"   Decrypted: {decrypted}")
    print(f"   Success: {plaintext == decrypted}")
    
    # Test 4: Key comparison (constant time)
    print(f"\n4. Key Comparison:")
    key1 = crypto.generate_key('AES', 128)
    key2 = key1.copy()
    key3 = crypto.generate_key('AES', 128)
    
    print(f"   Key1 == Key2: {crypto.compare_keys(key1, key2)}")
    print(f"   Key1 == Key3: {crypto.compare_keys(key1, key3)}")
    
    return True

def main():
    """Main function to demonstrate symmetric encryption"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Symmetric Encryption - Demonstration and file encryption"
    )
    
    parser.add_argument(
        "-d", "--demo",
        action="store_true",
        help="Run symmetric encryption demonstration"
    )
    
    parser.add_argument(
        "-e", "--encrypt",
        action="store_true",
        help="Encrypt file"
    )
    
    parser.add_argument(
        "-D", "--decrypt",
        action="store_true",
        help="Decrypt file"
    )
    
    parser.add_argument(
        "-i", "--input",
        help="Input file path"
    )
    
    parser.add_argument(
        "-o", "--output",
        help="Output file path"
    )
    
    parser.add_argument(
        "-a", "--algorithm",
        choices=['AES', 'DES', '3DES', 'ChaCha20Poly1305'],
        default='AES',
        help="Encryption algorithm (default: AES)"
    )
    
    parser.add_argument(
        "-m", "--mode",
        choices=['ECB', 'CBC', 'CFB', 'OFB', 'CTR'],
        default='CBC',
        help="Block cipher mode (default: CBC)"
    )
    
    parser.add_argument(
        "-k", "--key",
        help="Encryption key (hex or Base64)"
    )
    
    parser.add_argument(
        "-p", "--password",
        help="Password for key derivation"
    )
    
    args = parser.parse_args()
    
    try:
        crypto = SymmetricEncryption()
        
        if args.demo:
            demo_symmetric_encryption()
        elif args.encrypt and args.input and args.output:
            # Generate or load key
            if args.key:
                if len(args.key) % 2 == 0:  # Hexadecimal
                    key = crypto.key_from_hex(args.key)
                else:  # Base64
                    key = crypto.key_from_base64(args.key)
            elif args.password:
                key, salt = crypto.derive_key(args.password, key_length=32)
            else:
                key = crypto.generate_key(args.algorithm, 256)
                
            # Encrypt file
            crypto.encrypt_file(args.input, args.output, key, args.algorithm, args.mode)
            
            if not args.key and not args.password:
                print(f"Generated key: {crypto.key_to_hex(key)}")
                print(f"Key (Base64): {crypto.key_to_base64(key)}")
                
            print(f"File encrypted successfully: {args.input} -> {args.output}")
            
        elif args.decrypt and args.input and args.output:
            if not args.key and not args.password:
                print("Error: Key or password required for decryption")
                return
                
            if args.key:
                if len(args.key) % 2 == 0:
                    key = crypto.key_from_hex(args.key)
                else:
                    key = crypto.key_from_base64(args.key)
            else:
                # This would need salt from encrypted file for password-based decryption
                raise NotImplementedError("Password-based decryption not implemented for files")
                
            crypto.decrypt_file(args.input, args.output, key, args.algorithm, args.mode)
            print(f"File decrypted successfully: {args.input} -> {args.output}")
            
        else:
            parser.print_help()
            
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        print(traceback.format_exc())

if __name__ == "__main__":
    main()
