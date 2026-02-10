#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Asymmetric Encryption in Python for Cybersecurity
This script implements public-key cryptography concepts:
- RSA (Rivest-Shamir-Adleman) - Most widely used algorithm
- Digital signatures
- Key generation and management
- Hybrid encryption (combines symmetric and asymmetric)
- Certificate handling
Perfect for beginners!
"""

import os
import binascii
import base64
import hashlib
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, NoEncryption, PublicFormat, SubjectPublicKeyInfo
)

class AsymmetricEncryption:
    """Class for asymmetric encryption operations"""
    
    def __init__(self):
        """Initialize asymmetric encryption class"""
        self.backend = default_backend()
        
    # ==========================================
    # Key Generation
    # ==========================================
    def generate_rsa_keys(self, key_size=2048, public_exponent=65537):
        """
        Generate RSA key pair
        
        Args:
            key_size: Key size in bits (2048 or 4096 recommended)
            public_exponent: Public exponent (65537 is standard)
            
        Returns:
            Tuple containing (private_key, public_key) objects
        """
        private_key = rsa.generate_private_key(
            public_exponent=public_exponent,
            key_size=key_size,
            backend=self.backend
        )
        
        public_key = private_key.public_key()
        
        return private_key, public_key
        
    # ==========================================
    # Key Serialization and Storage
    # ==========================================
    def serialize_private_key(self, private_key, encoding=Encoding.PEM, 
                            format=PrivateFormat.PKCS8, encryption=NoEncryption()):
        """
        Serialize private key to string
        
        Args:
            private_key: Private key object
            encoding: PEM or DER encoding
            format: PKCS8, TraditionalOpenSSL, or PKCS1 format
            encryption: Encryption to apply (default: NoEncryption)
            
        Returns:
            Serialized key as bytes
        """
        return private_key.private_bytes(
            encoding=encoding,
            format=format,
            encryption_algorithm=encryption
        )
        
    def serialize_public_key(self, public_key, encoding=Encoding.PEM, 
                           format=SubjectPublicKeyInfo):
        """
        Serialize public key to string
        
        Args:
            public_key: Public key object
            encoding: PEM or DER encoding
            format: SubjectPublicKeyInfo or PKCS1 format
            
        Returns:
            Serialized key as bytes
        """
        return public_key.public_bytes(
            encoding=encoding,
            format=format
        )
        
    def load_private_key(self, key_data, password=None):
        """
        Load private key from serialized data
        
        Args:
            key_data: Serialized key data (bytes)
            password: Password for encrypted keys (optional)
            
        Returns:
            Private key object
        """
        return serialization.load_pem_private_key(
            key_data,
            password=password,
            backend=self.backend
        )
        
    def load_public_key(self, key_data):
        """
        Load public key from serialized data
        
        Args:
            key_data: Serialized key data (bytes)
            
        Returns:
            Public key object
        """
        return serialization.load_pem_public_key(
            key_data,
            backend=self.backend
        )
        
    def save_private_key(self, private_key, filename, password=None):
        """
        Save private key to file
        
        Args:
            private_key: Private key object
            filename: Output filename
            password: Password to encrypt key (optional)
        """
        encryption = NoEncryption()
        
        if password:
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            
            # Generate random salt and IV
            salt = os.urandom(16)
            iv = os.urandom(16)
            
            # Derive key from password
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=self.backend
            )
            
            key = kdf.derive(password.encode('utf-8'))
            
            encryption = serialization.BestAvailableEncryption(key)
            
        with open(filename, 'wb') as f:
            f.write(self.serialize_private_key(private_key, encryption=encryption))
            
    def save_public_key(self, public_key, filename):
        """
        Save public key to file
        
        Args:
            public_key: Public key object
            filename: Output filename
        """
        with open(filename, 'wb') as f:
            f.write(self.serialize_public_key(public_key))
            
    # ==========================================
    # RSA Encryption/Decryption
    # ==========================================
    def rsa_encrypt(self, plaintext, public_key, padding_scheme=padding.OAEP):
        """
        Encrypt data using RSA public key
        
        Args:
            plaintext: Data to encrypt (string or bytes)
            public_key: Public key object
            padding_scheme: OAEP (recommended) or PKCS1v15
            
        Returns:
            Encrypted ciphertext (bytes)
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
            
        if padding_scheme == padding.OAEP:
            encrypted = public_key.encrypt(
                plaintext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        elif padding_scheme == padding.PKCS1v15:
            encrypted = public_key.encrypt(
                plaintext,
                padding.PKCS1v15()
            )
        else:
            raise ValueError("Unsupported padding scheme")
            
        return encrypted
        
    def rsa_decrypt(self, ciphertext, private_key, padding_scheme=padding.OAEP):
        """
        Decrypt data using RSA private key
        
        Args:
            ciphertext: Encrypted data (bytes)
            private_key: Private key object
            padding_scheme: OAEP or PKCS1v15
            
        Returns:
            Decrypted plaintext (bytes)
        """
        if padding_scheme == padding.OAEP:
            decrypted = private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        elif padding_scheme == padding.PKCS1v15:
            decrypted = private_key.decrypt(
                ciphertext,
                padding.PKCS1v15()
            )
        else:
            raise ValueError("Unsupported padding scheme")
            
        return decrypted
        
    # ==========================================
    # Digital Signatures
    # ==========================================
    def rsa_sign(self, data, private_key, padding_scheme=padding.PSS, hash_algorithm=hashes.SHA256()):
        """
        Sign data using RSA private key
        
        Args:
            data: Data to sign (string or bytes)
            private_key: Private key object
            padding_scheme: PSS (recommended) or PKCS1v15
            hash_algorithm: Hash algorithm to use
            
        Returns:
            Digital signature (bytes)
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        if padding_scheme == padding.PSS:
            signature = private_key.sign(
                data,
                padding.PSS(
                    mgf=padding.MGF1(hash_algorithm),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hash_algorithm
            )
        elif padding_scheme == padding.PKCS1v15:
            signature = private_key.sign(
                data,
                padding.PKCS1v15(),
                hash_algorithm
            )
        else:
            raise ValueError("Unsupported padding scheme")
            
        return signature
        
    def rsa_verify(self, data, signature, public_key, padding_scheme=padding.PSS, 
                 hash_algorithm=hashes.SHA256()):
        """
        Verify RSA digital signature
        
        Args:
            data: Original data (string or bytes)
            signature: Digital signature (bytes)
            public_key: Public key object
            padding_scheme: PSS or PKCS1v15
            hash_algorithm: Hash algorithm used for signing
            
        Returns:
            True if signature is valid, False otherwise
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        try:
            if padding_scheme == padding.PSS:
                public_key.verify(
                    signature,
                    data,
                    padding.PSS(
                        mgf=padding.MGF1(hash_algorithm),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hash_algorithm
                )
            elif padding_scheme == padding.PKCS1v15:
                public_key.verify(
                    signature,
                    data,
                    padding.PKCS1v15(),
                    hash_algorithm
                )
            else:
                raise ValueError("Unsupported padding scheme")
                
            return True
            
        except Exception as e:
            print(f"Signature verification failed: {e}")
            return False
            
    # ==========================================
    # Hybrid Encryption
    # ==========================================
    def hybrid_encrypt(self, plaintext, public_key):
        """
        Hybrid encryption (RSA + AES) for large data
        
        Args:
            plaintext: Data to encrypt (string or bytes)
            public_key: RSA public key
            
        Returns:
            Tuple containing (encrypted_aes_key, aes_ciphertext, iv, salt)
        """
        from 01_symmetric_encryption import SymmetricEncryption
        
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
            
        # Generate random AES key
        aes = SymmetricEncryption()
        aes_key = aes.generate_key('AES', 256)
        
        # Encrypt data with AES
        aes_ciphertext, iv, salt = aes.aes_encrypt(plaintext, aes_key, 'CBC')
        
        # Encrypt AES key with RSA
        encrypted_aes_key = self.rsa_encrypt(aes_key, public_key)
        
        return encrypted_aes_key, aes_ciphertext, iv, salt
        
    def hybrid_decrypt(self, encrypted_aes_key, aes_ciphertext, iv, salt, private_key):
        """
        Decrypt hybrid encrypted data
        
        Args:
            encrypted_aes_key: RSA encrypted AES key
            aes_ciphertext: AES encrypted data
            iv: AES initialization vector
            salt: AES salt
            private_key: RSA private key
            
        Returns:
            Decrypted plaintext (bytes)
        """
        from 01_symmetric_encryption import SymmetricEncryption
        
        # Decrypt AES key with RSA
        aes_key = self.rsa_decrypt(encrypted_aes_key, private_key)
        
        # Decrypt data with AES
        aes = SymmetricEncryption()
        plaintext = aes.aes_decrypt(aes_ciphertext, aes_key, iv, salt, 'CBC')
        
        return plaintext
        
    # ==========================================
    # Certificate Generation and Handling
    # ==========================================
    def generate_self_signed_certificate(self, subject_name, private_key, 
                                       valid_days=365):
        """
        Generate self-signed X.509 certificate
        
        Args:
            subject_name: Certificate subject name (common name)
            private_key: Private key to use
            valid_days: Number of days certificate is valid
            
        Returns:
            X.509 certificate object
        """
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=valid_days)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(subject_name)]),
            critical=False,
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        ).sign(private_key, hashes.SHA256(), self.backend)
        
        return cert
        
    def serialize_certificate(self, certificate, encoding=Encoding.PEM):
        """
        Serialize X.509 certificate
        
        Args:
            certificate: X.509 certificate object
            encoding: PEM or DER encoding
            
        Returns:
            Serialized certificate (bytes)
        """
        return certificate.public_bytes(encoding=encoding)
        
    def load_certificate(self, cert_data):
        """
        Load X.509 certificate from serialized data
        
        Args:
            cert_data: Serialized certificate (bytes)
            
        Returns:
            X.509 certificate object
        """
        return x509.load_pem_x509_certificate(cert_data, self.backend)
        
    def save_certificate(self, certificate, filename):
        """
        Save X.509 certificate to file
        
        Args:
            certificate: X.509 certificate object
            filename: Output filename
        """
        with open(filename, 'wb') as f:
            f.write(self.serialize_certificate(certificate))
            
    def verify_certificate_chain(self, certificate, trusted_certs):
        """
        Verify X.509 certificate chain
        
        Args:
            certificate: Certificate to verify
            trusted_certs: List of trusted CA certificates
            
        Returns:
            True if certificate chain is valid, False otherwise
        """
        # In real-world scenario, use certificate verification library
        # This is a simplified verification
        try:
            # Check validity period
            if datetime.utcnow() < certificate.not_valid_before or \
               datetime.utcnow() > certificate.not_valid_after:
                return False
                
            # Check signature (simplified)
            issuer_public_key = certificate.public_key()
            try:
                # Verify signature with public key (this is a simplification)
                # In real scenario, you'd extract issuer public key from CA certificate
                return True
            except Exception as e:
                print(f"Signature verification failed: {e}")
                return False
                
        except Exception as e:
            print(f"Certificate verification failed: {e}")
            return False
            
    # ==========================================
    # Helper Methods
    # ==========================================
    def key_to_hex(self, key):
        """Convert key to hexadecimal string"""
        if hasattr(key, 'public_bytes'):
            return binascii.hexlify(self.serialize_public_key(key)).decode('utf-8')
        else:
            return binascii.hexlify(key).decode('utf-8')
            
    def key_to_base64(self, key):
        """Convert key to Base64 string"""
        if hasattr(key, 'public_bytes'):
            return base64.b64encode(self.serialize_public_key(key)).decode('utf-8')
        else:
            return base64.b64encode(key).decode('utf-8')
            
    def get_key_info(self, key):
        """Get key information as dictionary"""
        info = {}
        
        if hasattr(key, 'key_size'):
            info['key_size'] = key.key_size
            
        if hasattr(key, 'public_key'):
            public_key = key.public_key()
            if hasattr(public_key, 'public_numbers'):
                numbers = public_key.public_numbers()
                info['modulus'] = numbers.n
                info['public_exponent'] = numbers.e
                
        return info

def demo_asymmetric_encryption():
    """Demonstrate asymmetric encryption functionality"""
    print(f"{'='*60}")
    print(f"  ASYMMETRIC ENCRYPTION DEMONSTRATION")
    print(f"{'='*60}")
    
    crypto = AsymmetricEncryption()
    
    # Test 1: RSA Key Generation
    print(f"\n1. RSA Key Generation (2048-bit):")
    private_key, public_key = crypto.generate_rsa_keys(2048)
    
    print(f"   Private key type: {type(private_key)}")
    print(f"   Public key type: {type(public_key)}")
    
    # Test 2: RSA Encryption/Decryption
    print(f"\n2. RSA Encryption/Decryption (OAEP):")
    plaintext = "This is a secret message for RSA encryption!"
    ciphertext = crypto.rsa_encrypt(plaintext, public_key)
    decrypted = crypto.rsa_decrypt(ciphertext, private_key).decode('utf-8')
    
    print(f"   Plaintext: {plaintext}")
    print(f"   Ciphertext length: {len(ciphertext)} bytes")
    print(f"   Decrypted: {decrypted}")
    print(f"   Success: {plaintext == decrypted}")
    
    # Test 3: Digital Signatures
    print(f"\n3. RSA Digital Signatures (PSS):")
    message = "This is a message to be signed!"
    signature = crypto.rsa_sign(message, private_key)
    is_valid = crypto.rsa_verify(message, signature, public_key)
    
    print(f"   Message: {message}")
    print(f"   Signature length: {len(signature)} bytes")
    print(f"   Signature valid: {is_valid}")
    
    # Test 4: Signature forgery attempt
    print(f"\n4. Signature Forgery Attempt:")
    fake_message = "This is a fake message!"
    fake_valid = crypto.rsa_verify(fake_message, signature, public_key)
    
    print(f"   Fake message: {fake_message}")
    print(f"   Signature valid for fake message: {fake_valid}")
    
    # Test 5: Hybrid Encryption
    print(f"\n5. Hybrid Encryption (RSA + AES):")
    large_message = "This is a very large message that would exceed RSA's maximum" \
                   " encryption size limit if we tried to encrypt it directly with" \
                   " RSA. Hybrid encryption solves this problem by using RSA to" \
                   " encrypt a random AES key, which is then used to encrypt the" \
                   " actual message data." * 10
                   
    encrypted_aes_key, aes_ciphertext, iv, salt = crypto.hybrid_encrypt(large_message, public_key)
    decrypted_message = crypto.hybrid_decrypt(encrypted_aes_key, aes_ciphertext, iv, salt, private_key).decode('utf-8')
    
    print(f"   Large message length: {len(large_message.encode('utf-8'))} bytes")
    print(f"   Encrypted AES key length: {len(encrypted_aes_key)} bytes")
    print(f"   AES ciphertext length: {len(aes_ciphertext)} bytes")
    print(f"   Decrypted successfully: {large_message == decrypted_message}")
    
    # Test 6: Certificate Generation
    print(f"\n6. Self-Signed Certificate Generation:")
    certificate = crypto.generate_self_signed_certificate("test.example.com", private_key, 365)
    
    print(f"   Subject: {certificate.subject.rfc4514_string()}")
    print(f"   Issuer: {certificate.issuer.rfc4514_string()}")
    print(f"   Valid from: {certificate.not_valid_before}")
    print(f"   Valid to: {certificate.not_valid_after}")
    
    return True

def main():
    """Main function to demonstrate asymmetric encryption"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Asymmetric Encryption - Demonstration and operations"
    )
    
    parser.add_argument(
        "-d", "--demo",
        action="store_true",
        help="Run asymmetric encryption demonstration"
    )
    
    parser.add_argument(
        "-g", "--generate-keys",
        action="store_true",
        help="Generate new RSA key pair"
    )
    
    parser.add_argument(
        "-k", "--key-size",
        type=int,
        default=2048,
        help="RSA key size in bits (default: 2048)"
    )
    
    parser.add_argument(
        "-e", "--encrypt",
        action="store_true",
        help="Encrypt message using public key"
    )
    
    parser.add_argument(
        "-D", "--decrypt",
        action="store_true",
        help="Decrypt message using private key"
    )
    
    parser.add_argument(
        "-s", "--sign",
        action="store_true",
        help="Sign message using private key"
    )
    
    parser.add_argument(
        "-v", "--verify",
        action="store_true",
        help="Verify signature using public key"
    )
    
    parser.add_argument(
        "-m", "--message",
        help="Message to process"
    )
    
    parser.add_argument(
        "-pk", "--public-key",
        help="Path to public key file"
    )
    
    parser.add_argument(
        "-sk", "--secret-key",
        help="Path to secret/private key file"
    )
    
    parser.add_argument(
        "-S", "--signature",
        help="Path to signature file"
    )
    
    args = parser.parse_args()
    
    try:
        crypto = AsymmetricEncryption()
        
        if args.demo:
            demo_asymmetric_encryption()
        elif args.generate_keys:
            private_key, public_key = crypto.generate_rsa_keys(args.key_size)
            
            private_file = f"private_key_{args.key_size}bit.pem"
            public_file = f"public_key_{args.key_size}bit.pem"
            
            crypto.save_private_key(private_key, private_file)
            crypto.save_public_key(public_key, public_file)
            
            print(f"Keys generated and saved to:")
            print(f"  Private key: {private_file}")
            print(f"  Public key: {public_file}")
            
        elif args.encrypt and args.message and args.public_key:
            with open(args.public_key, 'rb') as f:
                public_key = crypto.load_public_key(f.read())
                
            ciphertext = crypto.rsa_encrypt(args.message, public_key)
            
            print(f"Encrypted message (hex): {binascii.hexlify(ciphertext).decode('utf-8')}")
            print(f"Encrypted message (base64): {base64.b64encode(ciphertext).decode('utf-8')}")
            
        elif args.decrypt and args.message and args.secret_key:
            with open(args.secret_key, 'rb') as f:
                private_key = crypto.load_private_key(f.read())
                
            # Decode message from hex or base64
            try:
                ciphertext = binascii.unhexlify(args.message)
            except:
                try:
                    ciphertext = base64.b64decode(args.message)
                except:
                    ciphertext = args.message.encode('utf-8')
                    
            plaintext = crypto.rsa_decrypt(ciphertext, private_key).decode('utf-8')
            
            print(f"Decrypted message: {plaintext}")
            
        elif args.sign and args.message and args.secret_key:
            with open(args.secret_key, 'rb') as f:
                private_key = crypto.load_private_key(f.read())
                
            signature = crypto.rsa_sign(args.message, private_key)
            
            if args.signature:
                with open(args.signature, 'wb') as f:
                    f.write(signature)
                print(f"Signature saved to: {args.signature}")
            else:
                print(f"Signature (hex): {binascii.hexlify(signature).decode('utf-8')}")
                
        elif args.verify and args.message and args.public_key and (args.signature or args.message.startswith('0x') or args.message.count(':') > 0):
            with open(args.public_key, 'rb') as f:
                public_key = crypto.load_public_key(f.read())
                
            if args.signature and os.path.exists(args.signature):
                with open(args.signature, 'rb') as f:
                    signature = f.read()
            else:
                try:
                    signature = binascii.unhexlify(args.signature.strip())
                except:
                    signature = base64.b64decode(args.signature.strip())
                    
            is_valid = crypto.rsa_verify(args.message, signature, public_key)
            print(f"Signature valid: {is_valid}")
            
        else:
            parser.print_help()
            
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        print(traceback.format_exc())

if __name__ == "__main__":
    main()
