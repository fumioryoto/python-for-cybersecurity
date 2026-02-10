#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cryptanalysis Techniques in Python for Cybersecurity
This script implements various cryptanalysis techniques:
- Frequency analysis for substitution ciphers
- Brute force attacks on weak ciphers
- Cryptanalysis of weak hashes (MD5, SHA-1)
- Rainbow table attacks for password cracking
- Differential cryptanalysis basics
Perfect for beginners!
"""

import os
import sys
import random
import string
import collections
import itertools
from typing import List, Tuple, Dict
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

class Cryptanalysis:
    """Class for cryptanalysis techniques"""
    
    def __init__(self):
        """Initialize cryptanalysis class"""
        self.backend = default_backend()
        self.english_letter_frequency = {
            'e': 12.70, 't': 9.06, 'a': 8.17, 'o': 7.51,
            'i': 6.97, 'n': 6.75, 's': 6.33, 'h': 6.09,
            'r': 5.99, 'd': 4.25, 'l': 4.03, 'c': 2.78,
            'u': 2.76, 'm': 2.41, 'w': 2.36, 'f': 2.23,
            'g': 2.02, 'y': 1.97, 'p': 1.93, 'b': 1.49,
            'v': 0.98, 'k': 0.77, 'j': 0.15, 'x': 0.15,
            'q': 0.10, 'z': 0.07
        }
        
    # ==========================================
    # Frequency Analysis
    # ==========================================
    def frequency_analysis(self, ciphertext: str) -> Dict[str, float]:
        """
        Perform frequency analysis on ciphertext
        
        Args:
            ciphertext: Text to analyze
            
        Returns:
            Dictionary with letter frequencies as percentages
        """
        ciphertext = ciphertext.lower()
        filtered_text = ''.join([c for c in ciphertext if c.isalpha()])
        
        letter_counts = collections.Counter(filtered_text)
        total_letters = len(filtered_text)
        
        frequencies = {}
        for char, count in letter_counts.items():
            frequencies[char] = (count / total_letters) * 100
            
        return frequencies
        
    def generate_frequency_table(self, ciphertext: str) -> List[Tuple[str, float]]:
        """
        Generate frequency table from ciphertext
        
        Args:
            ciphertext: Text to analyze
            
        Returns:
            Sorted list of (character, frequency) pairs
        """
        frequencies = self.frequency_analysis(ciphertext)
        
        sorted_frequencies = sorted(
            frequencies.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        return sorted_frequencies
        
    def frequency_matching(self, ciphertext: str) -> Dict[str, str]:
        """
        Attempt to decrypt substitution cipher using frequency matching
        
        Args:
            ciphertext: Encrypted text
            
        Returns:
            Dictionary mapping ciphertext characters to plaintext characters
        """
        # Get letter frequencies
        cipher_freq = self.frequency_analysis(ciphertext)
        plain_freq = self.english_letter_frequency
        
        # Sort both frequency dictionaries
        sorted_cipher = sorted(cipher_freq.items(), key=lambda x: x[1], reverse=True)
        sorted_plain = sorted(plain_freq.items(), key=lambda x: x[1], reverse=True)
        
        # Create initial mapping
        substitution_map = {}
        
        for (cipher_char, _), (plain_char, _) in zip(sorted_cipher, sorted_plain):
            substitution_map[cipher_char] = plain_char
            
        return substitution_map
        
    def apply_substitution(self, text: str, substitution_map: Dict[str, str]) -> str:
        """
        Apply substitution cipher
        
        Args:
            text: Text to transform
            substitution_map: Character substitution dictionary
            
        Returns:
            Transformed text
        """
        transformed = []
        
        for char in text.lower():
            if char.isalpha():
                transformed.append(substitution_map.get(char, char))
            else:
                transformed.append(char)
                
        return ''.join(transformed)
        
    # ==========================================
    # Brute Force Attacks
    # ==========================================
    def brute_force_ceasar(self, ciphertext: str, max_shift: int = 26) -> List[Tuple[int, str]]:
        """
        Brute force Ceasar cipher
        
        Args:
            ciphertext: Encrypted text
            max_shift: Maximum shift to try
            
        Returns:
            List of (shift, decrypted_text) pairs
        """
        results = []
        
        for shift in range(1, max_shift + 1):
            decrypted = self.ceasar_decrypt(ciphertext, shift)
            results.append((shift, decrypted))
            
        return results
        
    def ceasar_decrypt(self, ciphertext: str, shift: int) -> str:
        """
        Decrypt Ceasar cipher
        
        Args:
            ciphertext: Encrypted text
            shift: Shift value
            
        Returns:
            Decrypted text
        """
        decrypted = []
        
        for char in ciphertext.lower():
            if char.isalpha():
                original_pos = ord(char) - ord('a')
                new_pos = (original_pos - shift) % 26
                decrypted_char = chr(new_pos + ord('a'))
                decrypted.append(decrypted_char)
            else:
                decrypted.append(char)
                
        return ''.join(decrypted)
        
    def brute_force_vigenere(self, ciphertext: str, max_key_length: int = 6) -> List[Tuple[str, str]]:
        """
        Brute force Vigenère cipher
        
        Args:
            ciphertext: Encrypted text
            max_key_length: Maximum key length to try
            
        Returns:
            List of (key, decrypted_text) pairs
        """
        results = []
        
        for key_length in range(1, max_key_length + 1):
            key = self.find_vigenere_key(ciphertext, key_length)
            decrypted = self.vigenere_decrypt(ciphertext, key)
            results.append((key, decrypted))
            
        return results
        
    def find_vigenere_key(self, ciphertext: str, key_length: int) -> str:
        """
        Find Vigenère cipher key using Kasiski examination
        
        Args:
            ciphertext: Encrypted text
            key_length: Length of key
            
        Returns:
            Possible key
        """
        filtered_text = ''.join([c for c in ciphertext if c.isalpha()]).lower()
        
        # Split ciphertext into columns based on key length
        columns = []
        for i in range(key_length):
            column = filtered_text[i::key_length]
            columns.append(column)
            
        # Find shift for each column using frequency analysis
        key = []
        
        for column in columns:
            column_freq = self.frequency_analysis(column)
            possible_shifts = self._find_possible_shifts(column_freq)
            
            if possible_shifts:
                key.append(possible_shifts[0])
                
        return ''.join(key)
        
    def _find_possible_shifts(self, frequency_dict: Dict[str, float]) -> List[str]:
        """
        Find possible shifts based on frequency analysis
        
        Args:
            frequency_dict: Character frequency dictionary
            
        Returns:
            List of possible shift values (as characters)
        """
        if not frequency_dict:
            return []
            
        most_common = max(frequency_dict.items(), key=lambda x: x[1])[0]
        
        # Try shifts that map most common character to 'e'
        shift = (ord(most_common) - ord('e')) % 26
        possible_key = chr(ord('a') + shift)
        
        return [possible_key]
        
    def vigenere_decrypt(self, ciphertext: str, key: str) -> str:
        """
        Decrypt Vigenère cipher
        
        Args:
            ciphertext: Encrypted text
            key: Decryption key
            
        Returns:
            Decrypted text
        """
        decrypted = []
        key_length = len(key)
        key_index = 0
        
        for char in ciphertext.lower():
            if char.isalpha():
                key_char = key[key_index % key_length]
                shift = ord(key_char) - ord('a')
                
                original_pos = ord(char) - ord('a')
                new_pos = (original_pos - shift) % 26
                decrypted_char = chr(new_pos + ord('a'))
                
                decrypted.append(decrypted_char)
                key_index += 1
            else:
                decrypted.append(char)
                
        return ''.join(decrypted)
        
    # ==========================================
    # Hash Cracking
    # ==========================================
    def brute_force_hash(self, target_hash: str, charset: str = string.ascii_lowercase,
                        max_length: int = 4, algorithm: str = 'md5') -> str:
        """
        Brute force hash cracking
        
        Args:
            target_hash: Target hash to crack
            charset: Character set to use
            max_length: Maximum length of password to try
            algorithm: Hash algorithm (md5, sha1, sha256)
            
        Returns:
            Cracked password if found, None otherwise
        """
        for length in range(1, max_length + 1):
            for password in itertools.product(charset, repeat=length):
                password_str = ''.join(password)
                hashed = self._hash_password(password_str, algorithm)
                
                if hashed == target_hash:
                    return password_str
                    
        return None
        
    def dictionary_attack(self, target_hash: str, wordlist: List[str],
                        algorithm: str = 'md5') -> str:
        """
        Dictionary attack on hash
        
        Args:
            target_hash: Target hash to crack
            wordlist: List of candidate passwords
            algorithm: Hash algorithm
            
        Returns:
            Cracked password if found, None otherwise
        """
        for word in wordlist:
            hashed = self._hash_password(word.strip(), algorithm)
            
            if hashed == target_hash:
                return word.strip()
                
        return None
        
    def rainbow_table_attack(self, target_hash: str, rainbow_table: Dict[str, str],
                           algorithm: str = 'md5') -> str:
        """
        Rainbow table attack on hash
        
        Args:
            target_hash: Target hash to crack
            rainbow_table: Precomputed hash table
            algorithm: Hash algorithm
            
        Returns:
            Cracked password if found, None otherwise
        """
        return rainbow_table.get(target_hash, None)
        
    def _hash_password(self, password: str, algorithm: str = 'md5') -> str:
        """
        Hash password using specified algorithm
        
        Args:
            password: Password to hash
            algorithm: Hash algorithm
            
        Returns:
            Hexadecimal hash string
        """
        if algorithm == 'md5':
            hash_obj = hashes.Hash(hashes.MD5(), self.backend)
        elif algorithm == 'sha1':
            hash_obj = hashes.Hash(hashes.SHA1(), self.backend)
        elif algorithm == 'sha256':
            hash_obj = hashes.Hash(hashes.SHA256(), self.backend)
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
            
        hash_obj.update(password.encode('utf-8'))
        return hash_obj.finalize().hex()
        
    # ==========================================
    # Cryptanalysis of Hash Functions
    # ==========================================
    def find_collision(self, algorithm: str = 'md5', max_attempts: int = 1000000) -> Tuple[str, str]:
        """
        Attempt to find hash collision
        
        Args:
            algorithm: Hash algorithm to test
            max_attempts: Maximum number of attempts
            
        Returns:
            Tuple of (text1, text2) with same hash
        """
        hash_map = {}
        
        for i in range(max_attempts):
            text = f"test{random.randint(0, 1000000000)}{i}"
            hashed = self._hash_password(text, algorithm)
            
            if hashed in hash_map:
                return (hash_map[hashed], text)
                
            hash_map[hashed] = text
            
        return None
        
    def find_preimage(self, target_hash: str, algorithm: str = 'md5',
                     max_attempts: int = 1000000) -> str:
        """
        Attempt to find preimage for hash
        
        Args:
            target_hash: Target hash value
            algorithm: Hash algorithm
            max_attempts: Maximum number of attempts
            
        Returns:
            Text with matching hash if found, None otherwise
        """
        for i in range(max_attempts):
            text = f"preimage{random.randint(0, 1000000000)}{i}"
            hashed = self._hash_password(text, algorithm)
            
            if hashed == target_hash:
                return text
                
        return None
        
    # ==========================================
    # Password Strength Analysis
    # ==========================================
    def analyze_password_strength(self, password: str) -> Dict[str, any]:
        """
        Analyze password strength
        
        Args:
            password: Password to analyze
            
        Returns:
            Dictionary with strength analysis results
        """
        strength = 0
        feedback = []
        
        # Check length
        if len(password) >= 8:
            strength += 20
        elif len(password) >= 6:
            strength += 10
            feedback.append("Password should be at least 8 characters long")
        else:
            feedback.append("Password is too short")
            
        # Check character types
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in string.punctuation for c in password)
        
        if has_lower and has_upper:
            strength += 20
        elif has_lower or has_upper:
            strength += 10
            feedback.append("Use both uppercase and lowercase letters")
            
        if has_digit:
            strength += 20
        else:
            feedback.append("Include numbers in your password")
            
        if has_special:
            strength += 20
        else:
            feedback.append("Include special characters")
            
        # Check common patterns
        if password.lower() in ['password', '123456', 'qwerty', 'admin', 'welcome']:
            strength = 0
            feedback.append("Password is too common")
            
        # Check sequential characters
        if len([c for c in password if c.isdigit()]) >= 3:
            digits = ''.join([c for c in password if c.isdigit()])
            if digits.isdigit() and (int(digits) == int(''.join(sorted(digits))) or
                                   int(digits) == int(''.join(sorted(digits, reverse=True)))):
                feedback.append("Avoid sequential or repeated digit patterns")
                
        # Calculate entropy
        charset_size = self._calculate_charset_size(password)
        entropy = len(password) * math.log2(charset_size)
        
        strength = min(strength, 100)
        
        return {
            'password': password,
            'length': len(password),
            'strength': strength,
            'strength_text': self._strength_to_text(strength),
            'entropy': entropy,
            'feedback': feedback,
            'crack_time_seconds': self._estimate_crack_time(entropy),
            'crack_time_text': self._format_crack_time(self._estimate_crack_time(entropy))
        }
        
    def _calculate_charset_size(self, password: str) -> int:
        """Calculate effective character set size for password"""
        charset = 0
        
        if any(c.islower() for c in password):
            charset += 26
        if any(c.isupper() for c in password):
            charset += 26
        if any(c.isdigit() for c in password):
            charset += 10
        if any(c in string.punctuation for c in password):
            charset += 32
            
        return max(charset, 26)
        
    def _strength_to_text(self, strength: int) -> str:
        """Convert strength percentage to text rating"""
        if strength < 25:
            return "Very Weak"
        elif strength < 50:
            return "Weak"
        elif strength < 75:
            return "Medium"
        elif strength < 90:
            return "Strong"
        else:
            return "Very Strong"
            
    def _estimate_crack_time(self, entropy: float) -> float:
        """Estimate password crack time in seconds at 100 million guesses per second"""
        # Assumes 100 million guesses per second
        guesses_per_second = 100000000
        possible_guesses = 2 ** entropy
        
        return possible_guesses / guesses_per_second
        
    def _format_crack_time(self, seconds: float) -> str:
        """Format crack time in human readable format"""
        if seconds < 60:
            return f"{seconds:.1f} seconds"
        elif seconds < 3600:
            return f"{seconds / 60:.1f} minutes"
        elif seconds < 86400:
            return f"{seconds / 3600:.1f} hours"
        elif seconds < 31536000:
            return f"{seconds / 86400:.1f} days"
        else:
            return f"{seconds / 31536000:.1f} years"
            
    # ==========================================
    # Block Cipher Cryptanalysis
    # ==========================================
    def detect_ecb_mode(self, ciphertext: bytes) -> float:
        """
        Detect ECB mode by finding repeated blocks
        
        Args:
            ciphertext: Encrypted data in bytes
            
        Returns:
            Score indicating likelihood of ECB mode (0-1)
        """
        block_size = 16
        blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)
                 if len(ciphertext[i:i+block_size]) == block_size]
        
        unique_blocks = set(blocks)
        repetition_score = 1 - (len(unique_blocks) / len(blocks))
        
        return repetition_score
        
    # ==========================================
    # Stream Cipher Cryptanalysis
    # ==========================================
    def crib_dragging(self, ciphertext1: str, ciphertext2: str, cribs: List[str]) -> List[str]:
        """
        Perform crib dragging attack on stream cipher
        
        Args:
            ciphertext1: First ciphertext
            ciphertext2: Second ciphertext
            cribs: List of possible plaintext fragments
            
        Returns:
            List of possible plaintexts
        """
        results = []
        
        # XOR ciphertexts to get keystream approximation
        keystream = ''.join([chr(ord(c1) ^ ord(c2)) for c1, c2 in zip(ciphertext1, ciphertext2)])
        
        # Try each crib at each possible offset
        for crib in cribs:
            for offset in range(len(keystream) - len(crib) + 1):
                possible_keystream = keystream[offset:offset+len(crib)]
                possible_plaintext = ''.join([chr(ord(c) ^ ord(k)) for c, k in zip(ciphertext1[offset:offset+len(crib)], possible_keystream)])
                
                if crib in possible_plaintext.lower():
                    results.append(possible_plaintext)
                    
        return results
        
    # ==========================================
    # Network Traffic Analysis
    # ==========================================
    def analyze_http_traffic(self, filename: str) -> List[Dict[str, any]]:
        """
        Analyze HTTP traffic from Wireshark capture
        
        Args:
            filename: Path to PCAP file
            
        Returns:
            List of HTTP request/response pairs
        """
        try:
            import scapy.all as scapy
            from scapy.layers.http import HTTPRequest, HTTPResponse
            
            packets = scapy.rdpcap(filename)
            http_traffic = []
            
            for packet in packets:
                if packet.haslayer(HTTPRequest):
                    request = packet[HTTPRequest]
                    http_traffic.append({
                        'type': 'request',
                        'method': request.Method.decode('utf-8'),
                        'path': request.Path.decode('utf-8'),
                        'version': request.Http_Version.decode('utf-8'),
                        'source_ip': packet[scapy.IP].src,
                        'destination_ip': packet[scapy.IP].dst,
                        'timestamp': packet.time
                    })
                    
                elif packet.haslayer(HTTPResponse):
                    response = packet[HTTPResponse]
                    http_traffic.append({
                        'type': 'response',
                        'status_code': response.Status_Code.decode('utf-8'),
                        'reason': response.Reason.decode('utf-8'),
                        'version': response.Http_Version.decode('utf-8'),
                        'source_ip': packet[scapy.IP].src,
                        'destination_ip': packet[scapy.IP].dst,
                        'timestamp': packet.time
                    })
                    
            return http_traffic
            
        except ImportError as e:
            print(f"Scapy not installed: {e}")
            print("Install with: pip install scapy")
            return []
        except Exception as e:
            print(f"Error analyzing traffic: {e}")
            return []

def demo_cryptanalysis():
    """Demonstrate cryptanalysis techniques"""
    print(f"{'='*60}")
    print(f"  CRYPTANALYSIS TECHNIQUES DEMONSTRATION")
    print(f"{'='*60}")
    
    crypt = Cryptanalysis()
    
    # Test 1: Frequency Analysis
    print(f"\n1. FREQUENCY ANALYSIS:")
    sample_text = "This is a sample text for frequency analysis. It demonstrates letter distribution in English language documents."
    frequencies = crypt.frequency_analysis(sample_text)
    sorted_freq = sorted(frequencies.items(), key=lambda x: x[1], reverse=True)
    
    print(f"   Top 5 most frequent characters:")
    for char, freq in sorted_freq[:5]:
        print(f"     '{char}': {freq:.2f}%")
        
    # Test 2: Ceasar Cipher Brute Force
    print(f"\n2. CEASAR CIPHER BRUTE FORCE:")
    ceasar_cipher = "grkkyzkuotmzayutqqzkyotmsqzgekkf"
    ceasar_results = crypt.brute_force_ceasar(ceasar_cipher, 26)
    
    for shift, decrypted in ceasar_results:
        # Look for meaningful English text
        if 'the' in decrypted or 'and' in decrypted or 'you' in decrypted:
            print(f"   Possible decryption (shift {shift}): {decrypted}")
            break
            
    # Test 3: Password Strength Analysis
    print(f"\n3. PASSWORD STRENGTH ANALYSIS:")
    test_passwords = ['password', '123456', 'P@ssw0rd123!', 'QwErTy123!@#', 'SuperStrongPassword123!']
    
    for password in test_passwords:
        analysis = crypt.analyze_password_strength(password)
        print(f"   '{password}' - {analysis['strength_text']} ({analysis['strength']}%)")
        
    # Test 4: Dictionary Attack
    print(f"\n4. DICTIONARY ATTACK:")
    wordlist = ['password', '123456', 'admin', 'welcome', 'letmein', 'test123', 'demo']
    target_hash = crypt._hash_password('admin')
    
    cracked = crypt.dictionary_attack(target_hash, wordlist)
    if cracked:
        print(f"   Hash '{target_hash}' cracked: '{cracked}'")
    else:
        print(f"   Hash '{target_hash}' not found in wordlist")
        
    # Test 5: ECB Detection
    print(f"\n5. ECB MODE DETECTION:")
    ecb_ciphertext = bytes([0]*16 + [1]*16 + [0]*16 + [2]*16 + [1]*16 + [0]*16)
    ecb_score = crypt.detect_ecb_mode(ecb_ciphertext)
    print(f"   ECB mode score: {ecb_score:.2f}")
    
    return True

def main():
    """Main function to demonstrate cryptanalysis techniques"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Cryptanalysis Techniques - Frequency analysis, brute force, and more"
    )
    
    parser.add_argument(
        "-d", "--demo",
        action="store_true",
        help="Run cryptanalysis demonstration"
    )
    
    parser.add_argument(
        "-f", "--frequency",
        help="Text to perform frequency analysis on"
    )
    
    parser.add_argument(
        "-c", "--ceasar",
        help="Ceasar cipher text to decrypt"
    )
    
    parser.add_argument(
        "-V", "--vigenere",
        help="Vigenère cipher text to decrypt"
    )
    
    parser.add_argument(
        "-H", "--hash",
        help="Hash value to crack"
    )
    
    parser.add_argument(
        "-W", "--wordlist",
        help="Wordlist file for dictionary attack"
    )
    
    parser.add_argument(
        "-a", "--algorithm",
        choices=['md5', 'sha1', 'sha256'],
        default='md5',
        help="Hash algorithm (default: md5)"
    )
    
    parser.add_argument(
        "-p", "--password",
        help="Password to analyze strength"
    )
    
    args = parser.parse_args()
    
    try:
        crypt = Cryptanalysis()
        
        if args.demo:
            demo_cryptanalysis()
            
        elif args.frequency:
            frequencies = crypt.frequency_analysis(args.frequency)
            sorted_freq = sorted(frequencies.items(), key=lambda x: x[1], reverse=True)
            
            print("Frequency Analysis Results:")
            for char, freq in sorted_freq:
                print(f"{char}: {freq:.2f}%")
                
        elif args.ceasar:
            results = crypt.brute_force_ceasar(args.ceasar)
            
            print("Ceasar Cipher Decryptions:")
            for shift, decrypted in results:
                print(f"Shift {shift:2}: {decrypted}")
                
        elif args.vigenere:
            results = crypt.brute_force_vigenere(args.vigenere)
            
            print("Vigenère Cipher Decryptions:")
            for key, decrypted in results:
                print(f"Key '{key}': {decrypted}")
                
        elif args.hash and args.wordlist:
            with open(args.wordlist, 'r', encoding='utf-8') as f:
                wordlist = f.read().splitlines()
                
            cracked = crypt.dictionary_attack(args.hash, wordlist, args.algorithm)
            
            if cracked:
                print(f"Password found: {cracked}")
            else:
                print("Password not found in wordlist")
                
        elif args.password:
            analysis = crypt.analyze_password_strength(args.password)
            
            print("Password Strength Analysis:")
            print(f"  Password: {analysis['password']}")
            print(f"  Length: {analysis['length']} characters")
            print(f"  Strength: {analysis['strength']}% ({analysis['strength_text']})")
            print(f"  Entropy: {analysis['entropy']:.2f} bits")
            print(f"  Crack Time: {analysis['crack_time_text']}")
            
            if analysis['feedback']:
                print(f"  Feedback:")
                for comment in analysis['feedback']:
                    print(f"    - {comment}")
                    
        else:
            parser.print_help()
            
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        print(traceback.format_exc())

if __name__ == "__main__":
    main()
