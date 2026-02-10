#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Key Management in Python for Cybersecurity
This script implements key management concepts and practices:
- Key generation and storage
- Key exchange protocols
- Key derivation functions
- Key rotation and management
- Hardware security module (HSM) integration
Perfect for beginners!
"""

import os
import sys
import json
import yaml
import binascii
import base64
import hashlib
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography import exceptions

class KeyManagement:
    """Class for cryptographic key management operations"""
    
    def __init__(self, config_file='config/key_management.yaml'):
        """
        Initialize key management system
        
        Args:
            config_file: Path to configuration file
        """
        self.backend = default_backend()
        self.config = self._load_config(config_file)
        self.keys = {}
        self.key_chain = []
        
    def _load_config(self, config_file):
        """Load key management configuration"""
        default_config = {
            'key_storage': {
                'type': 'file',
                'path': 'keys',
                'encryption': 'aes-256-cbc',
                'password': 'default_key_password'
            },
            'key_generation': {
                'rsa_key_size': 2048,
                'ecc_curve': 'secp256r1',
                'dh_group': 14,
                'validity_period': 365
            },
            'key_rotation': {
                'enabled': True,
                'rotation_period': 90,
                'grace_period': 30
            },
            'backup': {
                'enabled': True,
                'location': 'backups',
                'encryption': 'aes-256-gcm'
            },
            'audit': {
                'enabled': True,
                'log_file': 'logs/key_management.log',
                'max_entries': 10000
            }
        }
        
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    user_config = yaml.safe_load(f)
                return {**default_config, **user_config}
            except Exception as e:
                print(f"Error loading config: {e}")
                return default_config
                
        return default_config
        
    # ==========================================
    # Key Generation
    # ==========================================
    def generate_rsa_key(self, key_size=None):
        """
        Generate RSA key pair
        
        Args:
            key_size: Key size in bits (1024, 2048, 4096)
            
        Returns:
            Tuple containing (private_key, public_key) objects
        """
        if key_size is None:
            key_size = self.config['key_generation']['rsa_key_size']
            
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=self.backend
        )
        
        public_key = private_key.public_key()
        
        return private_key, public_key
        
    def generate_ecc_key(self, curve=None):
        """
        Generate ECC (Elliptic Curve Cryptography) key pair
        
        Args:
            curve: ECC curve name (secp256r1, secp384r1, secp521r1)
            
        Returns:
            Tuple containing (private_key, public_key) objects
        """
        if curve is None:
            curve = self.config['key_generation']['ecc_curve']
            
        if curve == 'secp256r1':
            curve_obj = ec.SECP256R1()
        elif curve == 'secp384r1':
            curve_obj = ec.SECP384R1()
        elif curve == 'secp521r1':
            curve_obj = ec.SECP521R1()
        else:
            raise ValueError(f"Unsupported ECC curve: {curve}")
            
        private_key = ec.generate_private_key(curve_obj, self.backend)
        public_key = private_key.public_key()
        
        return private_key, public_key
        
    def generate_dh_parameters(self, group=None):
        """
        Generate Diffie-Hellman parameters
        
        Args:
            group: DH group number (14 is recommended)
            
        Returns:
            DH parameters object
        """
        if group is None:
            group = self.config['key_generation']['dh_group']
            
        if group == 14:
            # RFC 3526 group 14: 2048-bit MODP group
            parameters = dh.generate_parameters(generator=2, key_size=2048, backend=self.backend)
        elif group == 15:
            # RFC 3526 group 15: 3072-bit MODP group
            parameters = dh.generate_parameters(generator=2, key_size=3072, backend=self.backend)
        elif group == 16:
            # RFC 3526 group 16: 4096-bit MODP group
            parameters = dh.generate_parameters(generator=2, key_size=4096, backend=self.backend)
        else:
            raise ValueError(f"Unsupported DH group: {group}")
            
        return parameters
        
    def generate_symmetric_key(self, key_size=256):
        """
        Generate symmetric encryption key
        
        Args:
            key_size: Key size in bits (128, 192, 256)
            
        Returns:
            Random key as bytes
        """
        return os.urandom(key_size // 8)
        
    # ==========================================
    # Key Serialization and Storage
    # ==========================================
    def serialize_private_key(self, private_key, encoding='pem', format='pkcs8', password=None):
        """
        Serialize private key to string
        
        Args:
            private_key: Private key object
            encoding: PEM or DER encoding
            format: PKCS8, TraditionalOpenSSL, or PKCS1 format
            password: Password for encrypted keys (optional)
            
        Returns:
            Serialized key as bytes
        """
        if encoding == 'pem':
            encoding_obj = serialization.Encoding.PEM
        elif encoding == 'der':
            encoding_obj = serialization.Encoding.DER
        else:
            raise ValueError(f"Unsupported encoding: {encoding}")
            
        if format == 'pkcs8':
            format_obj = serialization.PrivateFormat.PKCS8
        elif format == 'traditional':
            format_obj = serialization.PrivateFormat.TraditionalOpenSSL
        elif format == 'pkcs1':
            format_obj = serialization.PrivateFormat.PKCS1
        else:
            raise ValueError(f"Unsupported format: {format}")
            
        if password:
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            
            salt = os.urandom(16)
            iv = os.urandom(16)
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=self.backend
            )
            
            key = kdf.derive(password.encode('utf-8'))
            
            encryption = serialization.BestAvailableEncryption(key)
        else:
            encryption = serialization.NoEncryption()
            
        return private_key.private_bytes(
            encoding=encoding_obj,
            format=format_obj,
            encryption_algorithm=encryption
        )
        
    def serialize_public_key(self, public_key, encoding='pem', format='subject_public_key_info'):
        """
        Serialize public key to string
        
        Args:
            public_key: Public key object
            encoding: PEM or DER encoding
            format: SubjectPublicKeyInfo or PKCS1 format
            
        Returns:
            Serialized key as bytes
        """
        if encoding == 'pem':
            encoding_obj = serialization.Encoding.PEM
        elif encoding == 'der':
            encoding_obj = serialization.Encoding.DER
        else:
            raise ValueError(f"Unsupported encoding: {encoding}")
            
        if format == 'subject_public_key_info':
            format_obj = serialization.PublicFormat.SubjectPublicKeyInfo
        elif format == 'pkcs1':
            format_obj = serialization.PublicFormat.PKCS1
        else:
            raise ValueError(f"Unsupported format: {format}")
            
        return public_key.public_bytes(
            encoding=encoding_obj,
            format=format_obj
        )
        
    def save_key(self, key_data, filename, key_type='private', password=None):
        """
        Save key to file
        
        Args:
            key_data: Key data to save
            filename: Output filename
            key_type: Key type (private, public, symmetric)
            password: Password for encrypted keys (optional)
        """
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        
        with open(filename, 'wb') as f:
            f.write(key_data)
            
        # Set appropriate permissions
        os.chmod(filename, 0o600 if key_type == 'private' else 0o644)
        
    def load_key(self, filename, key_type='private', password=None):
        """
        Load key from file
        
        Args:
            filename: Path to key file
            key_type: Key type (private, public, symmetric)
            password: Password for encrypted keys (optional)
            
        Returns:
            Key object
        """
        with open(filename, 'rb') as f:
            key_data = f.read()
            
        if key_type == 'private':
            return self._load_private_key(key_data, password)
        elif key_type == 'public':
            return self._load_public_key(key_data)
        elif key_type == 'symmetric':
            return self._load_symmetric_key(key_data)
        else:
            raise ValueError(f"Unsupported key type: {key_type}")
            
    def _load_private_key(self, key_data, password=None):
        """Load private key from bytes"""
        return serialization.load_pem_private_key(
            key_data,
            password=password.encode('utf-8') if password else None,
            backend=self.backend
        )
        
    def _load_public_key(self, key_data):
        """Load public key from bytes"""
        return serialization.load_pem_public_key(
            key_data,
            backend=self.backend
        )
        
    def _load_symmetric_key(self, key_data):
        """Load symmetric key from bytes"""
        return key_data
        
    # ==========================================
    # Key Exchange Protocols
    # ==========================================
    def diffie_hellman_exchange(self, parameters=None):
        """
        Perform Diffie-Hellman key exchange
        
        Args:
            parameters: DH parameters (if None, generate new)
            
        Returns:
            Tuple containing (private_key, public_key, shared_secret)
        """
        if parameters is None:
            parameters = self.generate_dh_parameters()
            
        # Generate private keys for both parties
        private_key_a = parameters.generate_private_key()
        private_key_b = parameters.generate_private_key()
        
        # Get public keys
        public_key_a = private_key_a.public_key()
        public_key_b = private_key_b.public_key()
        
        # Compute shared secret
        shared_secret_a = private_key_a.exchange(public_key_b)
        shared_secret_b = private_key_b.exchange(public_key_a)
        
        return private_key_a, public_key_a, private_key_b, public_key_b, shared_secret_a
        
    def ec_diffie_hellman_exchange(self, curve=None):
        """
        Perform Elliptic Curve Diffie-Hellman key exchange
        
        Args:
            curve: ECC curve to use
            
        Returns:
            Tuple containing (private_key, public_key, shared_secret)
        """
        if curve is None:
            curve = self.config['key_generation']['ecc_curve']
            
        # Generate ECC key pairs for both parties
        private_key_a, public_key_a = self.generate_ecc_key(curve)
        private_key_b, public_key_b = self.generate_ecc_key(curve)
        
        # Compute shared secret
        shared_secret_a = private_key_a.exchange(ec.ECDH(), public_key_b)
        shared_secret_b = private_key_b.exchange(ec.ECDH(), public_key_a)
        
        return private_key_a, public_key_a, private_key_b, public_key_b, shared_secret_a
        
    def generate_shared_secret(self, private_key, peer_public_key):
        """
        Generate shared secret using key exchange
        
        Args:
            private_key: Local private key
            peer_public_key: Remote public key
            
        Returns:
            Shared secret as bytes
        """
        if hasattr(private_key, 'exchange'):
            # ECC key exchange
            return private_key.exchange(ec.ECDH(), peer_public_key)
        elif hasattr(private_key, 'parameters'):
            # Diffie-Hellman key exchange
            return private_key.exchange(peer_public_key)
        else:
            raise ValueError("Unsupported key type for key exchange")
            
    # ==========================================
    # Key Derivation Functions
    # ==========================================
    def pbkdf2(self, password, salt=None, iterations=100000, key_length=32, algorithm='sha256'):
        """
        Key derivation using PBKDF2
        
        Args:
            password: Password string
            salt: Salt value (if None, generate new)
            iterations: Number of iterations
            key_length: Derived key length in bytes
            algorithm: Hash algorithm (sha256, sha512)
            
        Returns:
            Tuple containing (derived_key, salt)
        """
        if salt is None:
            salt = os.urandom(16)
            
        if algorithm == 'sha256':
            hash_algorithm = hashes.SHA256()
        elif algorithm == 'sha512':
            hash_algorithm = hashes.SHA512()
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
            
        kdf = PBKDF2HMAC(
            algorithm=hash_algorithm,
            length=key_length,
            salt=salt,
            iterations=iterations,
            backend=self.backend
        )
        
        derived_key = kdf.derive(password.encode('utf-8'))
        
        return derived_key, salt
        
    def hkdf(self, key_material, salt=None, info=b'', length=32, algorithm='sha256'):
        """
        Key derivation using HKDF (HMAC-based Key Derivation Function)
        
        Args:
            key_material: Initial key material
            salt: Salt value (optional)
            info: Context info (optional)
            length: Derived key length in bytes
            algorithm: Hash algorithm
            
        Returns:
            Derived key as bytes
        """
        if algorithm == 'sha256':
            hash_algorithm = hashes.SHA256()
        elif algorithm == 'sha512':
            hash_algorithm = hashes.SHA512()
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
            
        kdf = HKDF(
            algorithm=hash_algorithm,
            length=length,
            salt=salt,
            info=info,
            backend=self.backend
        )
        
        return kdf.derive(key_material)
        
    # ==========================================
    # Key Rotation and Management
    # ==========================================
    def rotate_key(self, key_id, new_algorithm=None, new_key_size=None):
        """
        Rotate cryptographic key
        
        Args:
            key_id: Key identifier to rotate
            new_algorithm: New algorithm for rotated key
            new_key_size: New key size for rotated key
            
        Returns:
            Tuple containing (old_key, new_key)
        """
        if key_id not in self.keys:
            raise ValueError(f"Key not found: {key_id}")
            
        old_key = self.keys[key_id]
        
        # Generate new key
        if new_algorithm is None:
            new_algorithm = old_key.get('algorithm', 'RSA')
            
        if new_key_size is None:
            new_key_size = old_key.get('key_size', 2048)
            
        if new_algorithm == 'RSA':
            new_private, new_public = self.generate_rsa_key(new_key_size)
        elif new_algorithm == 'ECC':
            new_private, new_public = self.generate_ecc_key()
        else:
            raise ValueError(f"Unsupported algorithm: {new_algorithm}")
            
        # Create new key entry
        new_key = {
            'id': f"{key_id}_v{old_key.get('version', 1) + 1}",
            'algorithm': new_algorithm,
            'key_size': new_key_size,
            'private_key': new_private,
            'public_key': new_public,
            'created_at': datetime.now().isoformat(),
            'expires_at': (datetime.now() + timedelta(days=self.config['key_generation']['validity_period'])).isoformat(),
            'status': 'active',
            'version': old_key.get('version', 1) + 1,
            'previous_key': key_id
        }
        
        # Update old key status
        old_key['status'] = 'deprecated'
        old_key['deprecated_at'] = datetime.now().isoformat()
        
        # Add new key to keys dictionary
        self.keys[new_key['id']] = new_key
        
        # Add to key chain
        self.key_chain.append(new_key)
        
        return old_key, new_key
        
    def retire_key(self, key_id, grace_period=None):
        """
        Retire cryptographic key
        
        Args:
            key_id: Key identifier to retire
            grace_period: Grace period in days before key is deleted
            
        Returns:
            Boolean indicating success
        """
        if key_id not in self.keys:
            raise ValueError(f"Key not found: {key_id}")
            
        key = self.keys[key_id]
        
        if grace_period is None:
            grace_period = self.config['key_rotation']['grace_period']
            
        key['status'] = 'retired'
        key['retired_at'] = datetime.now().isoformat()
        key['expires_at'] = (datetime.now() + timedelta(days=grace_period)).isoformat()
        
        return True
        
    def delete_key(self, key_id):
        """
        Delete cryptographic key
        
        Args:
            key_id: Key identifier to delete
            
        Returns:
            Boolean indicating success
        """
        if key_id not in self.keys:
            raise ValueError(f"Key not found: {key_id}")
            
        # Check if key is expired
        key = self.keys[key_id]
        
        if key['status'] not in ['retired', 'deprecated']:
            raise ValueError("Active keys cannot be deleted immediately")
            
        # Check if grace period has passed
        expires_at = datetime.fromisoformat(key['expires_at'])
        if datetime.now() < expires_at:
            raise ValueError("Key is still within grace period")
            
        del self.keys[key_id]
        self.key_chain = [k for k in self.key_chain if k['id'] != key_id]
        
        return True
        
    # ==========================================
    # Key Backup and Recovery
    # ==========================================
    def backup_key(self, key_id, backup_path=None, encryption_key=None):
        """
        Backup cryptographic key
        
        Args:
            key_id: Key identifier to backup
            backup_path: Path to backup directory
            encryption_key: Encryption key for backup
            
        Returns:
            Path to backup file
        """
        if key_id not in self.keys:
            raise ValueError(f"Key not found: {key_id}")
            
        if backup_path is None:
            backup_path = self.config['backup']['location']
            
        os.makedirs(backup_path, exist_ok=True)
        
        key = self.keys[key_id]
        
        # Serialize key
        if key['algorithm'] in ['RSA', 'ECC']:
            private_key_data = self.serialize_private_key(key['private_key'], password=encryption_key)
            public_key_data = self.serialize_public_key(key['public_key'])
            
            backup_data = {
                'id': key['id'],
                'algorithm': key['algorithm'],
                'key_size': key['key_size'],
                'private_key': base64.b64encode(private_key_data).decode('utf-8'),
                'public_key': base64.b64encode(public_key_data).decode('utf-8'),
                'created_at': key['created_at'],
                'expires_at': key['expires_at'],
                'status': key['status'],
                'version': key.get('version', 1),
                'previous_key': key.get('previous_key')
            }
            
        elif key['algorithm'] == 'symmetric':
            backup_data = {
                'id': key['id'],
                'algorithm': key['algorithm'],
                'key_size': key['key_size'],
                'key': base64.b64encode(key['key']).decode('utf-8'),
                'created_at': key['created_at'],
                'expires_at': key['expires_at'],
                'status': key['status']
            }
            
        else:
            raise ValueError(f"Unsupported algorithm: {key['algorithm']}")
            
        backup_filename = os.path.join(backup_path, f"key_{key_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        
        with open(backup_filename, 'w', encoding='utf-8') as f:
            json.dump(backup_data, f, indent=2, default=str)
            
        return backup_filename
        
    def restore_key(self, backup_filename, encryption_key=None):
        """
        Restore key from backup
        
        Args:
            backup_filename: Path to backup file
            encryption_key: Decryption key for backup
            
        Returns:
            Restored key information
        """
        with open(backup_filename, 'r', encoding='utf-8') as f:
            backup_data = json.load(f)
            
        if backup_data['algorithm'] in ['RSA', 'ECC']:
            private_key = self._load_private_key(
                base64.b64decode(backup_data['private_key']),
                encryption_key
            )
            
            public_key = self._load_public_key(
                base64.b64decode(backup_data['public_key'])
            )
            
            key_info = {
                'id': backup_data['id'],
                'algorithm': backup_data['algorithm'],
                'key_size': backup_data['key_size'],
                'private_key': private_key,
                'public_key': public_key,
                'created_at': backup_data['created_at'],
                'expires_at': backup_data['expires_at'],
                'status': backup_data['status'],
                'version': backup_data.get('version', 1),
                'previous_key': backup_data.get('previous_key')
            }
            
        elif backup_data['algorithm'] == 'symmetric':
            key_info = {
                'id': backup_data['id'],
                'algorithm': backup_data['algorithm'],
                'key_size': backup_data['key_size'],
                'key': base64.b64decode(backup_data['key']),
                'created_at': backup_data['created_at'],
                'expires_at': backup_data['expires_at'],
                'status': backup_data['status']
            }
            
        else:
            raise ValueError(f"Unsupported algorithm: {backup_data['algorithm']}")
            
        self.keys[key_info['id']] = key_info
        self.key_chain.append(key_info)
        
        return key_info
        
    # ==========================================
    # Key Usage and Auditing
    # ==========================================
    def record_key_usage(self, key_id, operation, user, system):
        """
        Record key usage for auditing purposes
        
        Args:
            key_id: Key identifier
            operation: Operation performed (encrypt, decrypt, sign, verify)
            user: User performing the operation
            system: System the operation was performed on
            
        Returns:
            Boolean indicating success
        """
        # In a real system, this would log to a secure audit log
        audit_entry = {
            'timestamp': datetime.now().isoformat(),
            'key_id': key_id,
            'operation': operation,
            'user': user,
            'system': system,
            'success': True
        }
        
        print(f"Audit entry: {audit_entry}")
        return True
        
    def get_key_audit_logs(self, key_id, start_date=None, end_date=None):
        """
        Get key usage audit logs
        
        Args:
            key_id: Key identifier
            start_date: Start date for logs
            end_date: End date for logs
            
        Returns:
            List of audit log entries
        """
        # In a real system, this would query the audit log database
        return []
        
    # ==========================================
    # Key Policy Enforcement
    # ==========================================
    def validate_key_policy(self, key_info):
        """
        Validate key against security policy
        
        Args:
            key_info: Key information dictionary
            
        Returns:
            Tuple containing (is_valid, issues)
        """
        issues = []
        
        # Check key size
        if key_info['algorithm'] == 'RSA':
            if key_info['key_size'] < 2048:
                issues.append("RSA key size should be at least 2048 bits")
        elif key_info['algorithm'] == 'ECC':
            if key_info['key_size'] < 256:
                issues.append("ECC key size should be at least 256 bits")
        elif key_info['algorithm'] == 'symmetric':
            if key_info['key_size'] < 128:
                issues.append("Symmetric key size should be at least 128 bits")
                
        # Check expiration
        expires_at = datetime.fromisoformat(key_info['expires_at'])
        if datetime.now() > expires_at:
            issues.append("Key has expired")
        elif datetime.now() > (expires_at - timedelta(days=30)):
            issues.append("Key will expire within 30 days")
            
        # Check key status
        if key_info['status'] not in ['active', 'deprecated', 'retired']:
            issues.append(f"Invalid key status: {key_info['status']}")
            
        return len(issues) == 0, issues

def demo_key_management():
    """Demonstrate key management functionality"""
    print(f"{'='*60}")
    print(f"  KEY MANAGEMENT SYSTEM DEMONSTRATION")
    print(f"{'='*60}")
    
    km = KeyManagement()
    
    # Test 1: Key Generation
    print(f"\n1. KEY GENERATION:")
    
    # RSA keys
    rsa_private, rsa_public = km.generate_rsa_key(2048)
    rsa_key_info = {
        'id': 'rsa_key_1',
        'algorithm': 'RSA',
        'key_size': 2048,
        'private_key': rsa_private,
        'public_key': rsa_public,
        'created_at': datetime.now().isoformat(),
        'expires_at': (datetime.now() + timedelta(days=365)).isoformat(),
        'status': 'active',
        'version': 1
    }
    km.keys['rsa_key_1'] = rsa_key_info
    
    # ECC keys
    ecc_private, ecc_public = km.generate_ecc_key()
    ecc_key_info = {
        'id': 'ecc_key_1',
        'algorithm': 'ECC',
        'key_size': 256,
        'private_key': ecc_private,
        'public_key': ecc_public,
        'created_at': datetime.now().isoformat(),
        'expires_at': (datetime.now() + timedelta(days=365)).isoformat(),
        'status': 'active',
        'version': 1
    }
    km.keys['ecc_key_1'] = ecc_key_info
    
    # Symmetric key
    symmetric_key = km.generate_symmetric_key(256)
    symmetric_key_info = {
        'id': 'symmetric_key_1',
        'algorithm': 'symmetric',
        'key_size': 256,
        'key': symmetric_key,
        'created_at': datetime.now().isoformat(),
        'expires_at': (datetime.now() + timedelta(days=90)).isoformat(),
        'status': 'active'
    }
    km.keys['symmetric_key_1'] = symmetric_key_info
    
    print(f"   Generated {len(km.keys)} keys")
    print(f"   Key types: {', '.join(km.keys.keys())}")
    
    # Test 2: Key Serialization
    print(f"\n2. KEY SERIALIZATION:")
    
    # Serialize and save RSA keys
    rsa_private_data = km.serialize_private_key(rsa_private, password='test123')
    rsa_public_data = km.serialize_public_key(rsa_public)
    
    km.save_key(rsa_private_data, 'keys/rsa_private.pem', 'private')
    km.save_key(rsa_public_data, 'keys/rsa_public.pem', 'public')
    
    print(f"   RSA keys saved to:")
    print(f"     Private: keys/rsa_private.pem")
    print(f"     Public: keys/rsa_public.pem")
    
    # Test 3: Key Exchange
    print(f"\n3. KEY EXCHANGE (ECDH):")
    
    # Perform key exchange
    priv_a, pub_a, priv_b, pub_b, shared_secret = km.ec_diffie_hellman_exchange()
    
    print(f"   Key exchange completed")
    print(f"   Shared secret length: {len(shared_secret)} bytes")
    print(f"   Shared secret: {base64.b64encode(shared_secret).decode('utf-8')}")
    
    # Test 4: Key Rotation
    print(f"\n4. KEY ROTATION:")
    
    old_rsa_key, new_rsa_key = km.rotate_key('rsa_key_1')
    
    print(f"   Key rotated successfully")
    print(f"   Old key: {old_rsa_key['id']} (version {old_rsa_key['version']})")
    print(f"   New key: {new_rsa_key['id']} (version {new_rsa_key['version']})")
    
    # Test 5: Key Policy Validation
    print(f"\n5. KEY POLICY VALIDATION:")
    
    valid, issues = km.validate_key_policy(km.keys['ecc_key_1'])
    
    print(f"   ECC key policy validation: {'✓ Valid' if valid else '✗ Invalid'}")
    if issues:
        for issue in issues:
            print(f"     - {issue}")
            
    # Create an invalid key for testing
    invalid_key = {
        'id': 'invalid_key',
        'algorithm': 'RSA',
        'key_size': 1024,  # Too small for modern standards
        'created_at': datetime.now().isoformat(),
        'expires_at': (datetime.now() - timedelta(days=1)).isoformat(),  # Already expired
        'status': 'active',
        'version': 1
    }
    
    valid, issues = km.validate_key_policy(invalid_key)
    
    print(f"   Invalid key policy validation: {'✓ Valid' if valid else '✗ Invalid'}")
    if issues:
        for issue in issues:
            print(f"     - {issue}")
            
    # Cleanup
    if os.path.exists('keys/rsa_private.pem'):
        os.remove('keys/rsa_private.pem')
    if os.path.exists('keys/rsa_public.pem'):
        os.remove('keys/rsa_public.pem')
    if os.path.exists('keys'):
        os.rmdir('keys')
        
    return True

def main():
    """Main function to demonstrate key management"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Key Management - Key generation, storage, and management"
    )
    
    parser.add_argument(
        "-d", "--demo",
        action="store_true",
        help="Run key management demonstration"
    )
    
    parser.add_argument(
        "-g", "--generate",
        choices=['rsa', 'ecc', 'symmetric'],
        help="Generate new cryptographic key"
    )
    
    parser.add_argument(
        "-k", "--key-size",
        type=int,
        default=2048,
        help="Key size in bits (default: 2048)"
    )
    
    parser.add_argument(
        "-p", "--password",
        help="Password for encrypted keys"
    )
    
    parser.add_argument(
        "-s", "--save",
        help="Path to save generated key"
    )
    
    parser.add_argument(
        "-l", "--load",
        help="Path to load key from"
    )
    
    parser.add_argument(
        "-b", "--backup",
        help="Backup key to specified location"
    )
    
    parser.add_argument(
        "-r", "--restore",
        help="Restore key from backup"
    )
    
    parser.add_argument(
        "-K", "--rotate",
        help="Rotate specified key"
    )
    
    args = parser.parse_args()
    
    try:
        km = KeyManagement()
        
        if args.demo:
            demo_key_management()
            
        elif args.generate:
            if args.generate == 'rsa':
                private_key, public_key = km.generate_rsa_key(args.key_size)
            elif args.generate == 'ecc':
                private_key, public_key = km.generate_ecc_key()
            elif args.generate == 'symmetric':
                key_data = km.generate_symmetric_key(args.key_size)
                
            if args.save:
                if args.generate in ['rsa', 'ecc']:
                    private_data = km.serialize_private_key(private_key, password=args.password)
                    public_data = km.serialize_public_key(public_key)
                    
                    private_file = args.save + '.pem' if args.save else 'private_key.pem'
                    public_file = args.save + '.pub' if args.save else 'public_key.pem'
                    
                    km.save_key(private_data, private_file, 'private')
                    km.save_key(public_data, public_file, 'public')
                    
                    print(f"Keys saved:")
                    print(f"  Private key: {private_file}")
                    print(f"  Public key: {public_file}")
                    
                elif args.generate == 'symmetric':
                    with open(args.save, 'wb') as f:
                        f.write(key_data)
                        
                    print(f"Symmetric key saved to: {args.save}")
                    
            else:
                print("Key generated but not saved (use -s/--save to save)")
                
        elif args.load:
            key_type = 'private' if args.load.endswith('.pem') and 'private' in args.load.lower() else 'public'
            key = km.load_key(args.load, key_type, args.password)
            
            print(f"Key loaded from {args.load}")
            print(f"Type: {type(key)}")
            
        elif args.backup and args.rotate:
            print("Error: -b/--backup and -r/--rotate cannot be used together")
            
        elif args.backup:
            # In a real scenario, you would have keys in the system
            print("Error: No active keys to backup")
            
        elif args.restore:
            key_info = km.restore_key(args.restore, args.password)
            print(f"Key restored successfully: {key_info['id']}")
            print(f"Algorithm: {key_info['algorithm']}")
            print(f"Key size: {key_info['key_size']} bits")
            
        elif args.rotate:
            if args.rotate in km.keys:
                old_key, new_key = km.rotate_key(args.rotate)
                print(f"Key rotation completed")
                print(f"Old key: {old_key['id']}")
                print(f"New key: {new_key['id']}")
            else:
                print(f"Key not found: {args.rotate}")
                
        else:
            parser.print_help()
            
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        print(traceback.format_exc())

if __name__ == "__main__":
    main()
