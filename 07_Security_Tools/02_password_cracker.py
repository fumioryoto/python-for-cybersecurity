#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Password Cracker Tool in Python for Cybersecurity
This script implements various password cracking methods including
brute force, dictionary attacks, and rainbow table lookups.
Perfect for beginners!
"""

import hashlib
import itertools
import string
import time
import random
from concurrent.futures import ThreadPoolExecutor

class PasswordCracker:
    """Password cracking tool with multiple attack methods"""
    
    def __init__(self, target_hash, algorithm='md5', max_length=8,
                 character_set='alphanumeric', wordlist=None):
        """
        Initialize the password cracker
        
        Args:
            target_hash: Hash of password to crack
            algorithm: Hashing algorithm (md5, sha1, sha256)
            max_length: Maximum password length for brute force
            character_set: Character set to use (alphanumeric, ascii, digits)
            wordlist: Path to wordlist file for dictionary attack
        """
        self.target_hash = target_hash.lower()
        self.algorithm = algorithm.lower()
        self.max_length = max_length
        
        # Define character sets
        self.char_sets = {
            'digits': string.digits,
            'lowercase': string.ascii_lowercase,
            'uppercase': string.ascii_uppercase,
            'alphanumeric': string.ascii_letters + string.digits,
            'ascii': string.printable[:-5],
            'extended': string.printable
        }
        
        self.characters = self.char_sets.get(character_set, string.ascii_letters + string.digits)
        self.wordlist = wordlist
        self.found_password = None
        
    def _hash_password(self, password):
        """Hash password using specified algorithm"""
        password_bytes = password.encode('utf-8')
        
        if self.algorithm == 'md5':
            return hashlib.md5(password_bytes).hexdigest()
        elif self.algorithm == 'sha1':
            return hashlib.sha1(password_bytes).hexdigest()
        elif self.algorithm == 'sha256':
            return hashlib.sha256(password_bytes).hexdigest()
        elif self.algorithm == 'sha512':
            return hashlib.sha512(password_bytes).hexdigest()
        else:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")
            
    def dictionary_attack(self, wordlist=None):
        """
        Perform dictionary attack using wordlist
        
        Args:
            wordlist: Path to wordlist file or list of passwords
            
        Returns:
            Tuple (success, password)
        """
        print(f"\n{'='*60}")
        print(f"  DICTIONARY ATTACK")
        print(f"{'='*60}")
        
        if wordlist is None:
            wordlist = self.wordlist
            
        if wordlist is None:
            print("Error: No wordlist provided")
            return False, None
            
        # Load wordlist
        if isinstance(wordlist, str):
            try:
                with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                    passwords = [line.strip() for line in f if line.strip()]
            except Exception as e:
                print(f"Error loading wordlist: {e}")
                return False, None
        else:
            passwords = wordlist
            
        print(f"Testing {len(passwords)} passwords from wordlist")
        
        for i, password in enumerate(passwords, 1):
            hashed = self._hash_password(password)
            
            if i % 1000 == 0:
                print(f"  Tested {i} passwords...")
                
            if hashed == self.target_hash:
                print(f"\n✅ SUCCESS! Password found: '{password}'")
                print(f"  Attempts: {i}")
                return True, password
                
        print("\n❌ FAILURE! Password not found in wordlist")
        return False, None
        
    def brute_force_attack(self, min_length=1, max_length=None):
        """
        Perform brute force attack
        
        Args:
            min_length: Minimum password length
            max_length: Maximum password length
            
        Returns:
            Tuple (success, password)
        """
        if max_length is None:
            max_length = self.max_length
            
        print(f"\n{'='*60}")
        print(f"  BRUTE FORCE ATTACK")
        print(f"{'='*60}")
        print(f"Character Set: {self.characters}")
        print(f"Password Length: {min_length}-{max_length}")
        
        attempts = 0
        
        for length in range(min_length, max_length + 1):
            print(f"\nTesting passwords of length {length}:")
            
            for password in itertools.product(self.characters, repeat=length):
                attempts += 1
                password = ''.join(password)
                hashed = self._hash_password(password)
                
                if attempts % 10000 == 0:
                    print(f"  Tested {attempts} passwords...")
                    
                if hashed == self.target_hash:
                    print(f"\n✅ SUCCESS! Password found: '{password}'")
                    print(f"  Attempts: {attempts}")
                    return True, password
                    
        print("\n❌ FAILURE! Password not found")
        return False, None
        
    def rainbow_table_attack(self):
        """
        Simple rainbow table attack using common passwords
        
        Returns:
            Tuple (success, password)
        """
        print(f"\n{'='*60}")
        print(f"  RAINBOW TABLE ATTACK")
        print(f"{'='*60}")
        
        # Common passwords to test
        common_passwords = [
            "password", "123456", "12345678", "qwerty", "abc123",
            "password1", "12345", "111111", "123123", "admin",
            "welcome", "login", "admin123", "letmein", "123456789",
            "1234567890", "iloveyou", "sunshine", "princess",
            "adminadmin", "passw0rd", "password123"
        ]
        
        print(f"Testing {len(common_passwords)} common passwords")
        
        for i, password in enumerate(common_passwords, 1):
            hashed = self._hash_password(password)
            
            if hashed == self.target_hash:
                print(f"\n✅ SUCCESS! Password found: '{password}'")
                print(f"  Attempts: {i}")
                return True, password
                
        print("\n❌ FAILURE! Password not in rainbow table")
        return False, None
        
    def hybrid_attack(self, wordlist=None):
        """
        Hybrid attack combining dictionary and brute force
        
        Args:
            wordlist: Path to wordlist file
            
        Returns:
            Tuple (success, password)
        """
        print(f"\n{'='*60}")
        print(f"  HYBRID ATTACK")
        print(f"{'='*60}")
        
        # First try dictionary attack
        success, password = self.dictionary_attack(wordlist)
        
        if success:
            return success, password
            
        # Then try rainbow table attack
        success, password = self.rainbow_table_attack()
        
        if success:
            return success, password
            
        # Fallback to brute force for short passwords
        print("\nFallback to brute force for short passwords (1-4 characters)...")
        return self.brute_force_attack(max_length=4)
        
    def run_all_attacks(self, wordlist=None):
        """Run all attack methods sequentially"""
        print(f"{'='*60}")
        print(f"  PASSWORD CRACKING")
        print(f"{'='*60}")
        print(f"Target Hash: {self.target_hash}")
        print(f"Algorithm: {self.algorithm.upper()}")
        print(f"Max Length: {self.max_length}")
        print(f"Character Set: {len(self.characters)} characters")
        print(f"{'='*60}")
        
        # Try attacks in order of increasing complexity
        methods = [
            ("Rainbow Table", self.rainbow_table_attack),
            ("Dictionary", lambda: self.dictionary_attack(wordlist)),
            ("Hybrid", lambda: self.hybrid_attack(wordlist)),
            ("Brute Force", lambda: self.brute_force_attack())
        ]
        
        for method_name, attack_func in methods:
            print(f"\n{'='*60}")
            print(f"  Trying {method_name} Attack")
            print(f"{'='*60}")
            
            start_time = time.time()
            success, password = attack_func()
            end_time = time.time()
            
            if success:
                self.found_password = password
                print(f"\n{'='*60}")
                print(f"  ATTACK SUCCESS")
                print(f"{'='*60}")
                print(f"Method: {method_name}")
                print(f"Password: '{password}'")
                print(f"Time: {end_time - start_time:.2f} seconds")
                return True, password
                
        return False, None

def test_cracker():
    """Test function with known passwords"""
    print(f"{'='*60}")
    print(f"  PASSWORD CRACKER DEMO")
    print(f"{'='*60}\n")
    
    # Test 1: Simple password with MD5
    print(f"Test 1: MD5 Hash of 'password'")
    test1_hash = '5f4dcc3b5aa765d61d8327deb882cf9'
    
    cracker1 = PasswordCracker(test1_hash, algorithm='md5')
    success, password = cracker1.run_all_attacks()
    
    print()
    
    # Test 2: Simple numeric password with SHA-256
    print(f"Test 2: SHA-256 Hash of '123456'")
    test2_hash = '8d969eef6ecad3c29a3a629280e686cf0c3f5d56586aff3a6ff6f6f4a3e72e6'
    
    cracker2 = PasswordCracker(test2_hash, algorithm='sha256', character_set='digits')
    success, password = cracker2.rainbow_table_attack()
    
    return success

def main():
    """Main function to run the password cracker"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Password Cracker Tool - Crack hashed passwords"
    )
    
    parser.add_argument(
        "hash",
        help="Target hash to crack"
    )
    
    parser.add_argument(
        "-a", "--algorithm",
        choices=['md5', 'sha1', 'sha256', 'sha512'],
        default='md5',
        help="Hashing algorithm (default: md5)"
    )
    
    parser.add_argument(
        "-w", "--wordlist",
        help="Path to wordlist file for dictionary attack"
    )
    
    parser.add_argument(
        "-c", "--charset",
        choices=['digits', 'lowercase', 'uppercase', 'alphanumeric', 'ascii', 'extended'],
        default='alphanumeric',
        help="Character set to use (default: alphanumeric)"
    )
    
    parser.add_argument(
        "-l", "--length",
        type=int,
        default=8,
        help="Maximum password length for brute force (default: 8)"
    )
    
    parser.add_argument(
        "-m", "--method",
        choices=['rainbow', 'dictionary', 'hybrid', 'brute', 'all'],
        default='all',
        help="Attack method to use (default: all)"
    )
    
    parser.add_argument(
        "-d", "--demo",
        action="store_true",
        help="Run demo with known passwords"
    )
    
    args = parser.parse_args()
    
    try:
        if args.demo:
            test_cracker()
        else:
            cracker = PasswordCracker(
                target_hash=args.hash,
                algorithm=args.algorithm,
                max_length=args.length,
                character_set=args.charset,
                wordlist=args.wordlist
            )
            
            if args.method == 'rainbow':
                cracker.rainbow_table_attack()
            elif args.method == 'dictionary':
                cracker.dictionary_attack()
            elif args.method == 'hybrid':
                cracker.hybrid_attack()
            elif args.method == 'brute':
                cracker.brute_force_attack()
            else:
                cracker.run_all_attacks()
                
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
