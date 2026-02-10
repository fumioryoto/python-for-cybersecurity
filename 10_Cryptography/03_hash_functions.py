#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cryptographic Hash Functions in Python for Cybersecurity
This script implements various hash functions and their applications:
- MD5 - Legacy, not collision resistant
- SHA-1 - Legacy, not collision resistant
- SHA-2 family (SHA-256, SHA-384, SHA-512)
- SHA-3 (Keccak)
- BLAKE2
- Hash applications (password hashing, file integrity, etc.)
Perfect for beginners!
"""

import hashlib
import binascii
import base64
import os
from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.backends import default_backend

class HashFunctions:
    """Class for cryptographic hash function operations"""
    
    def __init__(self):
        """Initialize hash functions class"""
        self.backend = default_backend()
        
    # ==========================================
    # Message Digest (One-Way) Hash Functions
    # ==========================================
    def md5(self, data):
        """
        Compute MD5 hash (legacy, not collision resistant)
        
        Args:
            data: Data to hash (string or bytes)
            
        Returns:
            MD5 hash as hexadecimal string
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        md5_hash = hashlib.md5()
        md5_hash.update(data)
        return md5_hash.hexdigest()
        
    def sha1(self, data):
        """
        Compute SHA-1 hash (legacy, not collision resistant)
        
        Args:
            data: Data to hash (string or bytes)
            
        Returns:
            SHA-1 hash as hexadecimal string
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        sha1_hash = hashlib.sha1()
        sha1_hash.update(data)
        return sha1_hash.hexdigest()
        
    def sha256(self, data):
        """
        Compute SHA-256 hash
        
        Args:
            data: Data to hash (string or bytes)
            
        Returns:
            SHA-256 hash as hexadecimal string
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        sha256_hash = hashlib.sha256()
        sha256_hash.update(data)
        return sha256_hash.hexdigest()
        
    def sha384(self, data):
        """
        Compute SHA-384 hash
        
        Args:
            data: Data to hash (string or bytes)
            
        Returns:
            SHA-384 hash as hexadecimal string
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        sha384_hash = hashlib.sha384()
        sha384_hash.update(data)
        return sha384_hash.hexdigest()
        
    def sha512(self, data):
        """
        Compute SHA-512 hash
        
        Args:
            data: Data to hash (string or bytes)
            
        Returns:
            SHA-512 hash as hexadecimal string
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        sha512_hash = hashlib.sha512()
        sha512_hash.update(data)
        return sha512_hash.hexdigest()
        
    def sha3_256(self, data):
        """
        Compute SHA-3-256 hash (Keccak)
        
        Args:
            data: Data to hash (string or bytes)
            
        Returns:
            SHA-3-256 hash as hexadecimal string
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        sha3_hash = hashlib.sha3_256()
        sha3_hash.update(data)
        return sha3_hash.hexdigest()
        
    def sha3_512(self, data):
        """
        Compute SHA-3-512 hash (Keccak)
        
        Args:
            data: Data to hash (string or bytes)
            
        Returns:
            SHA-3-512 hash as hexadecimal string
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        sha3_hash = hashlib.sha3_512()
        sha3_hash.update(data)
        return sha3_hash.hexdigest()
        
    def blake2b(self, data, digest_size=64):
        """
        Compute BLAKE2b hash
        
        Args:
            data: Data to hash (string or bytes)
            digest_size: Output hash size in bytes
            
        Returns:
            BLAKE2b hash as hexadecimal string
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        blake_hash = hashlib.blake2b(digest_size=digest_size)
        blake_hash.update(data)
        return blake_hash.hexdigest()
        
    def blake2s(self, data, digest_size=32):
        """
        Compute BLAKE2s hash
        
        Args:
            data: Data to hash (string or bytes)
            digest_size: Output hash size in bytes
            
        Returns:
            BLAKE2s hash as hexadecimal string
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        blake_hash = hashlib.blake2s(digest_size=digest_size)
        blake_hash.update(data)
        return blake_hash.hexdigest()
        
    # ==========================================
    # File Hashing
    # ==========================================
    def hash_file(self, filename, algorithm='sha256', chunk_size=4096):
        """
        Compute hash of entire file
        
        Args:
            filename: Path to file
            algorithm: Hash algorithm to use
            chunk_size: Chunk size for reading large files
            
        Returns:
            Hash as hexadecimal string
        """
        hash_obj = self._get_hash_object(algorithm)
        
        try:
            with open(filename, 'rb') as f:
                for chunk in iter(lambda: f.read(chunk_size), b""):
                    hash_obj.update(chunk)
                    
            return hash_obj.hexdigest()
            
        except Exception as e:
            raise Exception(f"Error hashing file: {e}")
            
    def verify_file_hash(self, filename, expected_hash, algorithm='sha256'):
        """
        Verify file integrity against expected hash
        
        Args:
            filename: Path to file
            expected_hash: Expected hash value
            algorithm: Hash algorithm used
            
        Returns:
            True if hash matches, False otherwise
        """
        try:
            file_hash = self.hash_file(filename, algorithm)
            return file_hash.lower() == expected_hash.lower()
            
        except Exception as e:
            raise Exception(f"Error verifying file hash: {e}")
            
    # ==========================================
    # Password Hashing
    # ==========================================
    def hash_password(self, password, salt=None, algorithm='sha256', iterations=100000):
        """
        Hash password using PBKDF2 (Password-Based Key Derivation Function)
        
        Args:
            password: Password to hash
            salt: Salt value (if None, generate new salt)
            algorithm: Hash algorithm to use
            iterations: Number of PBKDF2 iterations
            
        Returns:
            Tuple containing (hashed_password, salt)
        """
        if isinstance(password, str):
            password = password.encode('utf-8')
            
        if salt is None:
            salt = os.urandom(16)
            
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        
        if algorithm == 'sha256':
            hash_algorithm = crypto_hashes.SHA256()
        elif algorithm == 'sha512':
            hash_algorithm = crypto_hashes.SHA512()
        else:
            raise ValueError(f"Unsupported PBKDF2 algorithm: {algorithm}")
            
        kdf = PBKDF2HMAC(
            algorithm=hash_algorithm,
            length=32,
            salt=salt,
            iterations=iterations,
            backend=self.backend
        )
        
        hashed_password = kdf.derive(password)
        
        return hashed_password, salt
        
    def verify_password(self, password, hashed_password, salt, algorithm='sha256', iterations=100000):
        """
        Verify password against stored hash
        
        Args:
            password: Password to verify
            hashed_password: Stored hashed password
            salt: Salt value used for hashing
            algorithm: Hash algorithm used
            iterations: Number of PBKDF2 iterations
            
        Returns:
            True if password matches, False otherwise
        """
        try:
            test_hash, _ = self.hash_password(password, salt, algorithm, iterations)
            return self._constant_time_compare(test_hash, hashed_password)
            
        except Exception as e:
            raise Exception(f"Error verifying password: {e}")
            
    def _constant_time_compare(self, a, b):
        """
        Compare two strings in constant time to prevent timing attacks
        
        Args:
            a: First string
            b: Second string
            
        Returns:
            True if strings are equal, False otherwise
        """
        if len(a) != len(b):
            return False
            
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
            
        return result == 0
        
    # ==========================================
    # HMAC (Hash-based Message Authentication Code)
    # ==========================================
    def hmac_sha256(self, data, key):
        """
        Compute HMAC-SHA256
        
        Args:
            data: Data to authenticate
            key: Secret key
            
        Returns:
            HMAC as hexadecimal string
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        if isinstance(key, str):
            key = key.encode('utf-8')
            
        hmac_obj = hashlib.sha256(key)
        hmac_obj.update(data)
        return hmac_obj.hexdigest()
        
    def verify_hmac_sha256(self, data, hmac_value, key):
        """
        Verify HMAC-SHA256
        
        Args:
            data: Original data
            hmac_value: HMAC value to verify
            key: Secret key
            
        Returns:
            True if HMAC is valid, False otherwise
        """
        computed_hmac = self.hmac_sha256(data, key)
        
        if isinstance(hmac_value, str):
            hmac_value = hmac_value.lower()
            
        return self._constant_time_compare(computed_hmac.lower().encode('utf-8'), 
                                          hmac_value.encode('utf-8'))
        
    # ==========================================
    # Utility Methods
    # ==========================================
    def _get_hash_object(self, algorithm):
        """Get hash object for specified algorithm"""
        algorithms = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha384': hashlib.sha384,
            'sha512': hashlib.sha512,
            'sha3_256': hashlib.sha3_256,
            'sha3_512': hashlib.sha3_512,
            'blake2b': hashlib.blake2b,
            'blake2s': hashlib.blake2s
        }
        
        if algorithm not in algorithms:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")
            
        return algorithms[algorithm]()
        
    def hash_string(self, data, algorithm='sha256'):
        """
        Compute hash of string with various algorithms
        
        Args:
            data: Data to hash (string or bytes)
            algorithm: Hash algorithm to use
            
        Returns:
            Hash as hexadecimal string
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        hash_obj = self._get_hash_object(algorithm)
        hash_obj.update(data)
        
        return hash_obj.hexdigest()
        
    def hex_to_bytes(self, hex_str):
        """Convert hexadecimal string to bytes"""
        return binascii.unhexlify(hex_str)
        
    def bytes_to_hex(self, bytes_data):
        """Convert bytes to hexadecimal string"""
        return binascii.hexlify(bytes_data).decode('utf-8')
        
    def base64_to_bytes(self, base64_str):
        """Convert Base64 string to bytes"""
        return base64.b64decode(base64_str)
        
    def bytes_to_base64(self, bytes_data):
        """Convert bytes to Base64 string"""
        return base64.b64encode(bytes_data).decode('utf-8')
        
    # ==========================================
    # Hash Collision Testing (Demonstration)
    # ==========================================
    def find_collision(self, algorithm='md5', max_attempts=100000):
        """
        Attempt to find collision for a hash function (demonstration only)
        
        Args:
            algorithm: Hash algorithm to test
            max_attempts: Maximum number of attempts
            
        Returns:
            Tuple of collision strings if found, None otherwise
        """
        seen_hashes = {}
        
        for i in range(max_attempts):
            # Generate random test string
            test_str = os.urandom(16)
            test_hash = self.hash_string(test_str, algorithm)
            
            if test_hash in seen_hashes:
                return (seen_hashes[test_hash], test_str)
                
            seen_hashes[test_hash] = test_str
            
        return None
        
    # ==========================================
    # Hash Performance Benchmarking
    # ==========================================
    def benchmark_hash(self, algorithm='sha256', data_size=1024 * 1024, iterations=10):
        """
        Benchmark hash function performance
        
        Args:
            algorithm: Hash algorithm to benchmark
            data_size: Size of test data in bytes
            iterations: Number of test iterations
            
        Returns:
            Dictionary with performance metrics
        """
        import time
        
        test_data = os.urandom(data_size)
        
        # Warmup
        for i in range(1):
            self.hash_string(test_data, algorithm)
            
        # Actual benchmark
        times = []
        
        for i in range(iterations):
            start_time = time.time()
            self.hash_string(test_data, algorithm)
            times.append(time.time() - start_time)
            
        avg_time = sum(times) / len(times)
        throughput = data_size / avg_time  # bytes per second
        megabytes_per_sec = throughput / (1024 * 1024)
        
        return {
            'algorithm': algorithm,
            'data_size': data_size,
            'iterations': iterations,
            'avg_time': avg_time,
            'throughput': throughput,
            'mb_per_second': megabytes_per_sec
        }

def demo_hash_functions():
    """Demonstrate hash function functionality"""
    print(f"{'='*60}")
    print(f"  CRYPTOGRAPHIC HASH FUNCTIONS DEMONSTRATION")
    print(f"{'='*60}")
    
    hasher = HashFunctions()
    
    # Test 1: Basic Hash Functions
    print(f"\n1. BASIC HASH FUNCTIONS:")
    test_data = "This is a test message for hashing!"
    print(f"   Test data: {test_data}")
    
    print(f"\n   MD5: {hasher.md5(test_data)}")
    print(f"   SHA-1: {hasher.sha1(test_data)}")
    print(f"   SHA-256: {hasher.sha256(test_data)}")
    print(f"   SHA-384: {hasher.sha384(test_data)}")
    print(f"   SHA-512: {hasher.sha512(test_data)}")
    print(f"   SHA3-256: {hasher.sha3_256(test_data)}")
    print(f"   SHA3-512: {hasher.sha3_512(test_data)}")
    print(f"   BLAKE2b: {hasher.blake2b(test_data)}")
    print(f"   BLAKE2s: {hasher.blake2s(test_data)}")
    
    # Test 2: File Hashing
    print(f"\n2. FILE HASHING:")
    test_file = "test_hash_data.txt"
    
    with open(test_file, 'w', encoding='utf-8') as f:
        f.write("This is test data for file hashing!")
        
    file_hash = hasher.hash_file(test_file, 'sha256')
    print(f"   Test file '{test_file}' hash: {file_hash}")
    
    # Verify hash
    is_valid = hasher.verify_file_hash(test_file, file_hash, 'sha256')
    print(f"   Hash verification: {'✓ Valid' if is_valid else '✗ Invalid'}")
    
    # Test 3: Password Hashing
    print(f"\n3. PASSWORD HASHING (PBKDF2-SHA256):")
    password = "SecurePassword123!"
    
    hashed_password, salt = hasher.hash_password(password)
    is_correct = hasher.verify_password(password, hashed_password, salt)
    is_incorrect = hasher.verify_password("WrongPassword!", hashed_password, salt)
    
    print(f"   Password: {password}")
    print(f"   Salt: {hasher.bytes_to_hex(salt)}")
    print(f"   Hashed password: {hasher.bytes_to_hex(hashed_password)}")
    print(f"   Password verification (correct): {'✓ Success' if is_correct else '✗ Failure'}")
    print(f"   Password verification (incorrect): {'✓ Failed as expected' if not is_incorrect else '✗ Unexpected success'}")
    
    # Test 4: HMAC
    print(f"\n4. HMAC-SHA256:")
    secret_key = "MySecretKey123!"
    message = "This is a message to authenticate"
    
    hmac_value = hasher.hmac_sha256(message, secret_key)
    is_valid = hasher.verify_hmac_sha256(message, hmac_value, secret_key)
    is_invalid = hasher.verify_hmac_sha256("Tampered message", hmac_value, secret_key)
    
    print(f"   Message: {message}")
    print(f"   Secret key: {secret_key}")
    print(f"   HMAC-SHA256: {hmac_value}")
    print(f"   HMAC verification (valid): {'✓ Success' if is_valid else '✗ Failure'}")
    print(f"   HMAC verification (tampered): {'✓ Failed as expected' if not is_invalid else '✗ Unexpected success'}")
    
    # Test 5: Performance Benchmarking
    print(f"\n5. PERFORMANCE BENCHMARKING (1MB data):")
    
    algorithms = ['md5', 'sha1', 'sha256', 'sha512', 'sha3_256', 'sha3_512', 'blake2b', 'blake2s']
    
    results = []
    for algo in algorithms:
        try:
            result = hasher.benchmark_hash(algo, 1024 * 1024, 5)
            results.append(result)
        except Exception as e:
            print(f"   Error benchmarking {algo}: {e}")
            
    # Sort by performance
    results.sort(key=lambda x: x['avg_time'])
    
    for result in results:
        print(f"   {result['algorithm'].ljust(8)}: {result['avg_time']*1000:.1f}ms ({result['mb_per_second']:.1f} MB/s)")
    
    # Cleanup
    if os.path.exists(test_file):
        os.remove(test_file)
        
    return True

def main():
    """Main function to demonstrate hash functions"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Cryptographic Hash Functions - Demonstration and file hashing"
    )
    
    parser.add_argument(
        "-d", "--demo",
        action="store_true",
        help="Run hash functions demonstration"
    )
    
    parser.add_argument(
        "-f", "--file",
        help="File to hash"
    )
    
    parser.add_argument(
        "-a", "--algorithm",
        choices=['md5', 'sha1', 'sha256', 'sha384', 'sha512', 'sha3_256', 'sha3_512', 'blake2b', 'blake2s'],
        default='sha256',
        help="Hash algorithm (default: sha256)"
    )
    
    parser.add_argument(
        "-c", "--check",
        help="Expected hash value for verification"
    )
    
    parser.add_argument(
        "-p", "--password",
        help="Password to hash"
    )
    
    parser.add_argument(
        "-b", "--benchmark",
        action="store_true",
        help="Run hash performance benchmark"
    )
    
    args = parser.parse_args()
    
    try:
        hasher = HashFunctions()
        
        if args.demo:
            demo_hash_functions()
            
        elif args.file:
            if args.check:
                is_valid = hasher.verify_file_hash(args.file, args.check, args.algorithm)
                status = "✓ Valid" if is_valid else "✗ Invalid"
                print(f"File '{args.file}' hash verification: {status}")
                if not is_valid:
                    actual_hash = hasher.hash_file(args.file, args.algorithm)
                    print(f"  Actual {args.algorithm} hash: {actual_hash}")
                    
            else:
                file_hash = hasher.hash_file(args.file, args.algorithm)
                print(f"{args.algorithm} hash of '{args.file}': {file_hash}")
                
        elif args.password:
            hashed, salt = hasher.hash_password(args.password)
            print(f"Password hashed (PBKDF2-SHA256):")
            print(f"  Salt (hex): {hasher.bytes_to_hex(salt)}")
            print(f"  Hash (hex): {hasher.bytes_to_hex(hashed)}")
            
        elif args.benchmark:
            print("Hash Performance Benchmark (1MB data):")
            algorithms = ['md5', 'sha1', 'sha256', 'sha512', 'sha3_256', 'sha3_512', 'blake2b', 'blake2s']
            
            results = []
            for algo in algorithms:
                try:
                    result = hasher.benchmark_hash(algo, 1024 * 1024, 3)
                    results.append(result)
                except Exception as e:
                    print(f"  Error benchmarking {algo}: {e}")
                    
            results.sort(key=lambda x: x['avg_time'])
            
            print()
            print(f"{'Algorithm'.ljust(10)} | {'Time (ms)'.ljust(10)} | {'Speed (MB/s)'}")
            print('-' * 40)
            
            for result in results:
                print(f"{result['algorithm'].ljust(10)} | {result['avg_time']*1000:8.1f}ms | {result['mb_per_second']:6.1f}")
                
        else:
            parser.print_help()
            
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        print(traceback.format_exc())

if __name__ == "__main__":
    main()
