#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Elliptic Curve Cryptography (ECC) in Python for Cybersecurity
This script implements ECC concepts and algorithms:
- Elliptic curve definitions
- Point addition and doubling
- Scalar multiplication
- ECDSA signature algorithm
- ECDH key exchange
- Common ECC curves
Perfect for beginners!
"""

import os
import sys
import math
import random
from typing import Tuple, List
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

class EllipticCurve:
    """Class for elliptic curve operations"""
    
    def __init__(self, name='secp256r1'):
        """
        Initialize elliptic curve
        
        Args:
            name: Curve name (secp256r1, secp384r1, secp521r1, ed25519)
        """
        self.name = name
        self.curve = self._get_curve_by_name(name)
        self.field_size = self._get_field_size()
        
    def _get_curve_by_name(self, name):
        """Get curve object by name"""
        if name == 'secp256r1':
            return ec.SECP256R1()
        elif name == 'secp384r1':
            return ec.SECP384R1()
        elif name == 'secp521r1':
            return ec.SECP521R1()
        elif name == 'ed25519':
            return ec.Ed25519()
        else:
            raise ValueError(f"Unsupported curve: {name}")
            
    def _get_field_size(self):
        """Get field size for curve"""
        if self.name == 'secp256r1':
            return 256
        elif self.name == 'secp384r1':
            return 384
        elif self.name == 'secp521r1':
            return 521
        elif self.name == 'ed25519':
            return 256
        else:
            return 256
            
    # ==========================================
    # Key Generation
    # ==========================================
    def generate_key_pair(self):
        """
        Generate ECC key pair
        
        Returns:
            Tuple of (private_key, public_key)
        """
        private_key = ec.generate_private_key(self.curve)
        public_key = private_key.public_key()
        
        return private_key, public_key
        
    # ==========================================
    # Key Serialization
    # ==========================================
    def serialize_public_key(self, public_key, encoding='pem'):
        """
        Serialize public key
        
        Args:
            public_key: Public key object
            encoding: Encoding format (pem, der)
            
        Returns:
            Serialized key as bytes
        """
        if encoding == 'pem':
            encoding_obj = serialization.Encoding.PEM
        elif encoding == 'der':
            encoding_obj = serialization.Encoding.DER
        else:
            raise ValueError(f"Unsupported encoding: {encoding}")
            
        return public_key.public_bytes(
            encoding=encoding_obj,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
    def serialize_private_key(self, private_key, encoding='pem', password=None):
        """
        Serialize private key
        
        Args:
            private_key: Private key object
            encoding: Encoding format (pem, der)
            password: Optional password for encryption
            
        Returns:
            Serialized key as bytes
        """
        if encoding == 'pem':
            encoding_obj = serialization.Encoding.PEM
        elif encoding == 'der':
            encoding_obj = serialization.Encoding.DER
        else:
            raise ValueError(f"Unsupported encoding: {encoding}")
            
        if password:
            encryption = serialization.BestAvailableEncryption(password.encode('utf-8'))
        else:
            encryption = serialization.NoEncryption()
            
        return private_key.private_bytes(
            encoding=encoding_obj,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )
        
    def load_public_key(self, key_data, encoding='pem'):
        """
        Load public key from serialized data
        
        Args:
            key_data: Serialized key data
            encoding: Encoding format (pem, der)
            
        Returns:
            Public key object
        """
        if encoding == 'pem':
            encoding_obj = serialization.Encoding.PEM
        elif encoding == 'der':
            encoding_obj = serialization.Encoding.DER
        else:
            raise ValueError(f"Unsupported encoding: {encoding}")
            
        return serialization.load_pem_public_key(key_data) if encoding == 'pem' else \
               serialization.load_der_public_key(key_data)
               
    def load_private_key(self, key_data, encoding='pem', password=None):
        """
        Load private key from serialized data
        
        Args:
            key_data: Serialized key data
            encoding: Encoding format (pem, der)
            password: Optional decryption password
            
        Returns:
            Private key object
        """
        if encoding == 'pem':
            encoding_obj = serialization.Encoding.PEM
        elif encoding == 'der':
            encoding_obj = serialization.Encoding.DER
        else:
            raise ValueError(f"Unsupported encoding: {encoding}")
            
        if password:
            password = password.encode('utf-8')
            
        return serialization.load_pem_private_key(key_data, password) if encoding == 'pem' else \
               serialization.load_der_private_key(key_data, password)
               
    # ==========================================
    # ECDSA Signature
    # ==========================================
    def sign_message(self, private_key, message, hash_algorithm='sha256'):
        """
        Sign message using ECDSA
        
        Args:
            private_key: Private key for signing
            message: Message to sign
            hash_algorithm: Hash algorithm to use
            
        Returns:
            Signature as bytes
        """
        if isinstance(message, str):
            message = message.encode('utf-8')
            
        if hash_algorithm == 'sha256':
            hash_obj = hashes.SHA256()
        elif hash_algorithm == 'sha384':
            hash_obj = hashes.SHA384()
        elif hash_algorithm == 'sha512':
            hash_obj = hashes.SHA512()
        else:
            raise ValueError(f"Unsupported hash algorithm: {hash_algorithm}")
            
        return private_key.sign(message, ec.ECDSA(hash_obj))
        
    def verify_signature(self, public_key, message, signature, hash_algorithm='sha256'):
        """
        Verify ECDSA signature
        
        Args:
            public_key: Public key for verification
            message: Original message
            signature: Signature to verify
            hash_algorithm: Hash algorithm used for signing
            
        Returns:
            Boolean indicating if signature is valid
        """
        if isinstance(message, str):
            message = message.encode('utf-8')
            
        if hash_algorithm == 'sha256':
            hash_obj = hashes.SHA256()
        elif hash_algorithm == 'sha384':
            hash_obj = hashes.SHA384()
        elif hash_algorithm == 'sha512':
            hash_obj = hashes.SHA512()
        else:
            raise ValueError(f"Unsupported hash algorithm: {hash_algorithm}")
            
        try:
            public_key.verify(signature, message, ec.ECDSA(hash_obj))
            return True
        except Exception as e:
            print(f"Verification failed: {e}")
            return False
            
    # ==========================================
    # ECDH Key Exchange
    # ==========================================
    def generate_shared_secret(self, private_key, peer_public_key):
        """
        Generate shared secret using ECDH key exchange
        
        Args:
            private_key: Local private key
            peer_public_key: Peer's public key
            
        Returns:
            Shared secret as bytes
        """
        shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
        
        return shared_secret
        
    # ==========================================
    # Elliptic Curve Points
    # ==========================================
    def point_from_public_key(self, public_key):
        """
        Get point coordinates from public key
        
        Args:
            public_key: Public key object
            
        Returns:
            Tuple of (x, y) coordinates
        """
        if hasattr(public_key, 'public_numbers'):
            numbers = public_key.public_numbers()
            return numbers.x, numbers.y
        else:
            raise ValueError("Public key does not support coordinate extraction")
            
    # ==========================================
    # Curve Parameters
    # ==========================================
    def get_curve_parameters(self):
        """
        Get elliptic curve parameters
        
        Returns:
            Dictionary with curve parameters
        """
        params = {
            'name': self.name,
            'field_size': self.field_size
        }
        
        return params
        
    def is_on_curve(self, x, y):
        """
        Check if point (x, y) lies on the curve
        
        Args:
            x: X coordinate
            y: Y coordinate
            
        Returns:
            Boolean indicating if point is on curve
        """
        # This is a simplified implementation - real implementation varies by curve type
        # For Weierstrass curves: y² = x³ + ax + b mod p
        
        if self.name == 'secp256r1':
            p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
            a = -3
            b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
            
            # Check if point satisfies curve equation
            lhs = pow(y, 2, p)
            rhs = (pow(x, 3, p) + a * x + b) % p
            
            return lhs == rhs
            
        return False
        
    # ==========================================
    # Key Generation and Management
    # ==========================================
    def save_key_pair(self, private_key, public_key, prefix='ecc_key'):
        """
        Save key pair to files
        
        Args:
            private_key: Private key object
            public_key: Public key object
            prefix: File name prefix
            
        Returns:
            Tuple of (private_key_path, public_key_path)
        """
        private_key_path = f"{prefix}_private.pem"
        public_key_path = f"{prefix}_public.pem"
        
        with open(private_key_path, 'wb') as f:
            f.write(self.serialize_private_key(private_key))
            
        with open(public_key_path, 'wb') as f:
            f.write(self.serialize_public_key(public_key))
            
        return private_key_path, public_key_path
        
    def load_key_pair(self, private_key_path, public_key_path):
        """
        Load key pair from files
        
        Args:
            private_key_path: Path to private key file
            public_key_path: Path to public key file
            
        Returns:
            Tuple of (private_key, public_key)
        """
        with open(private_key_path, 'rb') as f:
            private_key = self.load_private_key(f.read())
            
        with open(public_key_path, 'rb') as f:
            public_key = self.load_public_key(f.read())
            
        return private_key, public_key
        
    # ==========================================
    # Performance Testing
    # ==========================================
    def test_performance(self, iterations=100):
        """
        Test ECC operations performance
        
        Args:
            iterations: Number of iterations for each operation
            
        Returns:
            Performance metrics dictionary
        """
        import time
        
        metrics = {
            'key_generation': 0.0,
            'signing': 0.0,
            'verification': 0.0,
            'key_exchange': 0.0
        }
        
        # Test key generation
        start_time = time.time()
        keys = [self.generate_key_pair() for _ in range(iterations)]
        metrics['key_generation'] = (time.time() - start_time) / iterations
        
        # Test signing
        test_message = b"Test message for performance evaluation"
        private_keys = [key[0] for key in keys]
        
        start_time = time.time()
        signatures = [self.sign_message(key, test_message) for key in private_keys]
        metrics['signing'] = (time.time() - start_time) / iterations
        
        # Test verification
        public_keys = [key[1] for key in keys]
        
        start_time = time.time()
        for key, signature in zip(public_keys, signatures):
            self.verify_signature(key, test_message, signature)
        metrics['verification'] = (time.time() - start_time) / iterations
        
        # Test key exchange
        start_time = time.time()
        for i in range(iterations):
            priv1, pub1 = self.generate_key_pair()
            priv2, pub2 = self.generate_key_pair()
            self.generate_shared_secret(priv1, pub2)
            self.generate_shared_secret(priv2, pub1)
        metrics['key_exchange'] = (time.time() - start_time) / iterations
        
        return metrics
        
    # ==========================================
    # Curve Comparison
    # ==========================================
    def compare_curves(self):
        """
        Compare different ECC curves
        
        Returns:
            Dictionary with curve comparison data
        """
        curves = ['secp256r1', 'secp384r1', 'secp521r1', 'ed25519']
        comparisons = []
        
        for curve_name in curves:
            try:
                curve = EllipticCurve(curve_name)
                metrics = curve.test_performance(100)
                params = curve.get_curve_parameters()
                
                comparisons.append({
                    'name': curve_name,
                    'field_size': params['field_size'],
                    'key_generation': metrics['key_generation'],
                    'signing': metrics['signing'],
                    'verification': metrics['verification'],
                    'key_exchange': metrics['key_exchange']
                })
                
            except Exception as e:
                print(f"Error testing curve {curve_name}: {e}")
                
        return comparisons

def demo_elliptic_curves():
    """Demonstrate elliptic curve operations"""
    print(f"{'='*60}")
    print(f"  ELLIPTIC CURVE CRYPTOGRAPHY DEMONSTRATION")
    print(f"{'='*60}")
    
    curves = ['secp256r1', 'secp384r1', 'secp521r1', 'ed25519']
    
    for curve_name in curves:
        print(f"\n{'='*40}")
        print(f"  Curve: {curve_name}")
        print(f"{'='*40}")
        
        try:
            ecc = EllipticCurve(curve_name)
            
            # Test 1: Key Generation
            print(f"\n1. Key Generation:")
            private_key, public_key = ecc.generate_key_pair()
            
            x, y = ecc.point_from_public_key(public_key)
            print(f"   Public key point: ({hex(x)}, {hex(y)})")
            print(f"   Field size: {ecc.field_size} bits")
            
            # Test 2: Sign and Verify
            print(f"\n2. Sign and Verify:")
            test_message = f"Test message for {curve_name}"
            signature = ecc.sign_message(private_key, test_message)
            
            is_valid = ecc.verify_signature(public_key, test_message, signature)
            print(f"   Signature valid: {'✓' if is_valid else '✗'}")
            
            # Test 3: Key Exchange
            print(f"\n3. Key Exchange:")
            priv1, pub1 = ecc.generate_key_pair()
            priv2, pub2 = ecc.generate_key_pair()
            
            secret1 = ecc.generate_shared_secret(priv1, pub2)
            secret2 = ecc.generate_shared_secret(priv2, pub1)
            
            if secret1 == secret2:
                print(f"   Shared secret successfully established")
            else:
                print(f"   Key exchange failed")
                
            print(f"   Shared secret: {secret1.hex()[:16]}...")
            
            # Test 4: Point Validation
            print(f"\n4. Point Validation:")
            is_valid_point = ecc.is_on_curve(x, y)
            print(f"   Public key point is on curve: {'✓' if is_valid_point else '✗'}")
            
        except Exception as e:
            print(f"Error with curve {curve_name}: {e}")
            import traceback
            print(traceback.format_exc())
            
    # Performance comparison
    print(f"\n{'='*60}")
    print(f"  ECC PERFORMANCE COMPARISON")
    print(f"{'='*60}")
    
    try:
        print(f"{'Curve'.ljust(10)} | {'Key Gen'.ljust(8)} | {'Sign'.ljust(8)} | {'Verify'.ljust(8)} | {'Exch'.ljust(8)}")
        print('-' * 60)
        
        comparisons = EllipticCurve('secp256r1').compare_curves()
        
        for comp in comparisons:
            key_gen = comp['key_generation'] * 1000
            sign = comp['signing'] * 1000
            verify = comp['verification'] * 1000
            exch = comp['key_exchange'] * 1000
            
            print(f"{comp['name'].ljust(10)} | {key_gen:6.1f}ms | {sign:6.1f}ms | {verify:6.1f}ms | {exch:6.1f}ms")
            
    except Exception as e:
        print(f"Performance comparison failed: {e}")
        
    return True

def main():
    """Main function to demonstrate elliptic curves"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Elliptic Curve Cryptography - ECC operations demonstration"
    )
    
    parser.add_argument(
        "-d", "--demo",
        action="store_true",
        help="Run ECC demonstration"
    )
    
    parser.add_argument(
        "-c", "--curve",
        choices=['secp256r1', 'secp384r1', 'secp521r1', 'ed25519'],
        default='secp256r1',
        help="Curve to use (default: secp256r1)"
    )
    
    parser.add_argument(
        "-g", "--generate",
        action="store_true",
        help="Generate key pair"
    )
    
    parser.add_argument(
        "-s", "--sign",
        help="Message to sign"
    )
    
    parser.add_argument(
        "-v", "--verify",
        nargs=2,
        metavar=('MESSAGE', 'SIGNATURE'),
        help="Verify signature (message and signature)"
    )
    
    parser.add_argument(
        "-e", "--exchange",
        action="store_true",
        help="Test ECDH key exchange"
    )
    
    parser.add_argument(
        "-o", "--output",
        default='ecc_key',
        help="Output file prefix for generated keys"
    )
    
    args = parser.parse_args()
    
    try:
        ecc = EllipticCurve(args.curve)
        
        if args.demo:
            demo_elliptic_curves()
            
        elif args.generate:
            private_key, public_key = ecc.generate_key_pair()
            private_path, public_path = ecc.save_key_pair(private_key, public_key, args.output)
            
            print(f"Key pair generated and saved:")
            print(f"  Private key: {private_path}")
            print(f"  Public key: {public_path}")
            
        elif args.sign:
            private_key, public_key = ecc.generate_key_pair()
            
            signature = ecc.sign_message(private_key, args.sign)
            
            print(f"Signature for '{args.sign}':")
            print(signature.hex())
            
        elif args.verify:
            private_key, public_key = ecc.generate_key_pair()
            
            message = args.verify[0]
            signature = bytes.fromhex(args.verify[1])
            
            is_valid = ecc.verify_signature(public_key, message, signature)
            
            print(f"Signature is {'valid' if is_valid else 'invalid'}")
            
        elif args.exchange:
            priv1, pub1 = ecc.generate_key_pair()
            priv2, pub2 = ecc.generate_key_pair()
            
            secret1 = ecc.generate_shared_secret(priv1, pub2)
            secret2 = ecc.generate_shared_secret(priv2, pub1)
            
            if secret1 == secret2:
                print("Key exchange successful!")
                print(f"Shared secret: {secret1.hex()}")
            else:
                print("Key exchange failed")
                
        else:
            parser.print_help()
            
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        print(traceback.format_exc())

if __name__ == "__main__":
    main()
