#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cryptographic Math Foundations in Python for Cybersecurity
This script covers the mathematical foundations of cryptography:
- Number theory basics
- Modular arithmetic
- Finite fields and groups
- Prime number generation
- Discrete logarithms
- Elliptic curve mathematics
Perfect for beginners!
"""

import math
import random
import sys
from typing import List, Tuple
from sympy import isprime, nextprime
import sympy

class CryptoMath:
    """Class containing cryptographic mathematics operations"""
    
    def __init__(self):
        """Initialize cryptographic math class"""
        self.primes = []
        self.moduli = []
        
    # ==========================================
    # Basic Number Theory
    # ==========================================
    def is_prime(self, n: int) -> bool:
        """
        Check if a number is prime
        
        Args:
            n: Number to check
            
        Returns:
            True if n is prime, False otherwise
        """
        if n <= 1:
            return False
        elif n <= 3:
            return True
        elif n % 2 == 0 or n % 3 == 0:
            return False
            
        i = 5
        while i * i <= n:
            if n % i == 0 or n % (i + 2) == 0:
                return False
            i += 6
            
        return True
        
    def generate_prime(self, bit_length: int = 1024) -> int:
        """
        Generate random prime number with specified bit length
        
        Args:
            bit_length: Number of bits in prime
            
        Returns:
            Random prime number
        """
        if bit_length < 2:
            raise ValueError("Bit length must be at least 2")
            
        min_val = 1 << (bit_length - 1)
        max_val = (1 << bit_length) - 1
        
        while True:
            candidate = random.randint(min_val, max_val)
            
            # Make sure candidate is odd
            if candidate % 2 == 0:
                candidate += 1
                
            if self.is_prime(candidate):
                return candidate
                
    def next_prime(self, n: int) -> int:
        """
        Find next prime number greater than n
        
        Args:
            n: Number to start from
            
        Returns:
            Next prime number
        """
        candidate = n + 1
        
        while True:
            if self.is_prime(candidate):
                return candidate
                
            candidate += 1
            
    def gcd(self, a: int, b: int) -> int:
        """
        Compute greatest common divisor using Euclidean algorithm
        
        Args:
            a: First number
            b: Second number
            
        Returns:
            GCD of a and b
        """
        while b != 0:
            a, b = b, a % b
            
        return a
        
    def extended_gcd(self, a: int, b: int) -> Tuple[int, int, int]:
        """
        Compute extended Euclidean algorithm
        
        Args:
            a: First number
            b: Second number
            
        Returns:
            Tuple containing (gcd, x, y) such that a*x + b*y = gcd
        """
        if a == 0:
            return (b, 0, 1)
            
        g, y, x = self.extended_gcd(b % a, a)
        
        return (g, x - (b // a) * y, y)
        
    def modular_inverse(self, a: int, m: int) -> int:
        """
        Compute modular inverse of a modulo m
        
        Args:
            a: Number to find inverse for
            m: Modulus
            
        Returns:
            Integer x such that (a * x) ≡ 1 mod m
        """
        g, x, y = self.extended_gcd(a, m)
        
        if g != 1:
            raise ValueError(f"No modular inverse exists for {a} modulo {m}")
            
        return x % m
        
    # ==========================================
    # Modular Arithmetic
    # ==========================================
    def modular_exponentiation(self, base: int, exponent: int, modulus: int) -> int:
        """
        Compute (base^exponent) mod modulus using efficient exponentiation
        
        Args:
            base: Base number
            exponent: Exponent
            modulus: Modulus
            
        Returns:
            (base^exponent) mod modulus
        """
        if modulus == 1:
            return 0
            
        result = 1
        base = base % modulus
        
        while exponent > 0:
            if exponent % 2 == 1:
                result = (result * base) % modulus
                
            base = (base * base) % modulus
            exponent = exponent // 2
            
        return result
        
    def modular_multiplicative_inverse(self, a: int, m: int) -> int:
        """
        Compute modular multiplicative inverse using Fermat's Little Theorem
        
        Args:
            a: Number to invert
            m: Modulus
            
        Returns:
            Modular inverse of a modulo m
        """
        if self.gcd(a, m) != 1:
            raise ValueError("Numbers must be coprime")
            
        return self.modular_exponentiation(a, m - 2, m)
        
    def crt(self, congruences: List[Tuple[int, int]]) -> int:
        """
        Solve system of linear congruences using Chinese Remainder Theorem
        
        Args:
            congruences: List of (a_i, m_i) where x ≡ a_i mod m_i
            
        Returns:
            Solution x
        """
        x = 0
        M = 1
        
        # Compute product of all moduli
        for a_i, m_i in congruences:
            M *= m_i
            
        # Compute solution for each congruence
        for a_i, m_i in congruences:
            Mi = M // m_i
            inv = self.modular_inverse(Mi, m_i)
            x += a_i * Mi * inv
            
        return x % M
        
    # ==========================================
    # Discrete Mathematics
    # ==========================================
    def discrete_logarithm(self, base: int, target: int, modulus: int) -> int:
        """
        Compute discrete logarithm using baby-step giant-step algorithm
        
        Args:
            base: Base of the logarithm
            target: Target value
            modulus: Modulus
            
        Returns:
            Integer x such that (base^x) ≡ target mod modulus
        """
        if modulus <= 1:
            raise ValueError("Modulus must be greater than 1")
            
        m = int(math.isqrt(modulus)) + 1
        
        # Baby step: compute base^j mod modulus for j in [0, m)
        baby_steps = {}
        current = 1
        
        for j in range(m):
            baby_steps[current] = j
            current = (current * base) % modulus
            
        # Giant step: compute target * (base^(-m))^i mod modulus for i in [0, m)
        base_inv = self.modular_inverse(self.modular_exponentiation(base, m, modulus), modulus)
        current = target
        
        for i in range(m):
            if current in baby_steps:
                return i * m + baby_steps[current]
                
            current = (current * base_inv) % modulus
            
        raise ValueError(f"Discrete logarithm not found: base={base}, target={target}, modulus={modulus}")
        
    # ==========================================
    # Finite Fields and Groups
    # ==========================================
    def generate_primitive_root(self, prime: int) -> int:
        """
        Find primitive root modulo prime
        
        Args:
            prime: Prime modulus
            
        Returns:
            Primitive root modulo prime
        """
        if not self.is_prime(prime):
            raise ValueError("Modulus must be prime")
            
        # Factor prime-1 into its prime factors
        factors = self._prime_factors(prime - 1)
        
        for candidate in range(2, prime):
            is_primitive = True
            
            for factor in factors:
                exponent = (prime - 1) // factor
                
                if self.modular_exponentiation(candidate, exponent, prime) == 1:
                    is_primitive = False
                    break
                    
            if is_primitive:
                return candidate
                
        raise ValueError(f"No primitive root found for prime {prime}")
        
    def _prime_factors(self, n: int) -> List[int]:
        """
        Find prime factors of a number
        
        Args:
            n: Number to factor
            
        Returns:
            List of prime factors
        """
        factors = []
        
        while n % 2 == 0:
            factors.append(2)
            n = n // 2
            
        i = 3
        max_factor = math.isqrt(n) + 1
        
        while i <= max_factor and n > 1:
            while n % i == 0:
                factors.append(i)
                n = n // i
                max_factor = math.isqrt(n) + 1
                
            i += 2
            
        if n > 1:
            factors.append(n)
            
        return list(set(factors))
        
    # ==========================================
    # Number Generation and Statistics
    # ==========================================
    def prime_counting(self, limit: int) -> int:
        """
        Count number of primes ≤ limit using sieve of Eratosthenes
        
        Args:
            limit: Upper limit
            
        Returns:
            Number of primes ≤ limit
        """
        if limit < 2:
            return 0
            
        sieve = [True] * (limit + 1)
        sieve[0] = sieve[1] = False
        
        for i in range(2, int(math.isqrt(limit)) + 1):
            if sieve[i]:
                for j in range(i*i, limit + 1, i):
                    sieve[j] = False
                    
        return sum(sieve)
        
    def prime_statistics(self, limit: int = 1000000):
        """
        Compute prime number statistics
        
        Args:
            limit: Upper limit for analysis
            
        Returns:
            Dictionary with prime number statistics
        """
        count = self.prime_counting(limit)
        density = count / limit
        
        return {
            'count': count,
            'density': density,
            'expected_density': math.log(limit),
            'log_error': abs(density - math.log(limit)),
            'limit': limit
        }
        
    # ==========================================
    # Probabilistic Primality Testing
    # ==========================================
    def miller_rabin(self, n: int, rounds: int = 40) -> bool:
        """
        Miller-Rabin primality test
        
        Args:
            n: Number to test
            rounds: Number of test rounds
            
        Returns:
            True if n is probably prime, False otherwise
        """
        if n <= 1:
            return False
        elif n <= 3:
            return True
        elif n % 2 == 0:
            return False
            
        # Write n-1 as d * 2^s
        d = n - 1
        s = 0
        
        while d % 2 == 0:
            d //= 2
            s += 1
            
        # Witness loop
        for _ in range(rounds):
            a = random.randint(2, n - 2)
            x = self.modular_exponentiation(a, d, n)
            
            if x == 1 or x == n - 1:
                continue
                
            for __ in range(s - 1):
                x = self.modular_exponentiation(x, 2, n)
                
                if x == n - 1:
                    break
            else:
                return False
                
        return True
        
    def probable_prime_generator(self, bit_length: int, confidence: float = 0.999999) -> int:
        """
        Generate probable prime number with high confidence
        
        Args:
            bit_length: Bit length of prime
            confidence: Probability that number is prime
            
        Returns:
            Probable prime number
        """
        if bit_length < 2:
            raise ValueError("Bit length must be at least 2")
            
        min_val = 1 << (bit_length - 1)
        max_val = (1 << bit_length) - 1
        
        while True:
            candidate = random.randint(min_val, max_val)
            
            if candidate % 2 == 0:
                candidate += 1
                
            if self.miller_rabin(candidate):
                return candidate
                
    # ==========================================
    # Cryptographically Secure Random Numbers
    # ==========================================
    def generate_random_number(self, bits: int) -> int:
        """
        Generate cryptographically secure random number
        
        Args:
            bits: Number of bits
            
        Returns:
            Random number with specified bit length
        """
        if bits < 1:
            raise ValueError("Number of bits must be at least 1")
            
        byte_length = (bits + 7) // 8
        random_bytes = random.randbytes(byte_length)
        
        number = int.from_bytes(random_bytes, 'big')
        
        # Ensure number has exactly 'bits' bits
        if bits % 8 == 0:
            number &= (1 << bits) - 1
        else:
            number &= (1 << bits) - 1
            number |= 1 << (bits - 1)
            
        return number
        
    def random_string(self, length: int) -> str:
        """
        Generate random string of specified length
        
        Args:
            length: Length of string
            
        Returns:
            Random string
        """
        import string
        
        return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))
        
    # ==========================================
    # Number Theory Applications
    # ==========================================
    def rsa_key_generation(self, bit_length: int = 2048):
        """
        Generate RSA key pair
        
        Args:
            bit_length: Bit length of modulus
            
        Returns:
            Dictionary with (public_key, private_key, modulus)
        """
        p = self.generate_prime(bit_length // 2)
        q = self.generate_prime(bit_length // 2)
        
        while q == p:
            q = self.generate_prime(bit_length // 2)
            
        n = p * q
        
        phi_n = (p - 1) * (q - 1)
        
        e = 65537
        
        while self.gcd(e, phi_n) != 1:
            e = self.next_prime(e)
            
        d = self.modular_inverse(e, phi_n)
        
        return {
            'public_key': e,
            'private_key': d,
            'modulus': n,
            'primes': (p, q)
        }
        
    def rsa_encrypt(self, plaintext: int, e: int, n: int) -> int:
        """
        RSA encryption
        
        Args:
            plaintext: Plaintext as integer
            e: Public exponent
            n: Modulus
            
        Returns:
            Ciphertext as integer
        """
        return self.modular_exponentiation(plaintext, e, n)
        
    def rsa_decrypt(self, ciphertext: int, d: int, n: int) -> int:
        """
        RSA decryption
        
        Args:
            ciphertext: Ciphertext as integer
            d: Private exponent
            n: Modulus
            
        Returns:
            Plaintext as integer
        """
        return self.modular_exponentiation(ciphertext, d, n)
        
    # ==========================================
    # Performance Testing
    # ==========================================
    def test_performance(self):
        """
        Test performance of various cryptographic math operations
        
        Returns:
            Dictionary with performance results
        """
        import time
        
        results = {
            'is_prime': {},
            'gcd': {},
            'modular_exponentiation': {},
            'miller_rabin': {}
        }
        
        # Test is_prime
        test_sizes = [1000000, 1000000000, 10**18]
        
        for n in test_sizes:
            start_time = time.time()
            self.is_prime(n)
            results['is_prime'][n] = time.time() - start_time
            
        # Test gcd
        a = 123456789
        b = 987654321
        
        start_time = time.time()
        for _ in range(10000):
            self.gcd(a, b)
        results['gcd'][(a, b)] = time.time() - start_time
        
        # Test modular exponentiation
        base = 12345
        exponent = 67890
        modulus = 99991
        
        start_time = time.time()
        for _ in range(1000):
            self.modular_exponentiation(base, exponent, modulus)
        results['modular_exponentiation'][(base, exponent, modulus)] = time.time() - start_time
        
        # Test Miller-Rabin
        test_numbers = [1000000007, 1000000009, 1000000021]
        
        for n in test_numbers:
            start_time = time.time()
            self.miller_rabin(n)
            results['miller_rabin'][n] = time.time() - start_time
            
        return results
        
    # ==========================================
    # Number Theory Visualization
    # ==========================================
    def visualize_prime_distribution(self, limit: int = 1000):
        """
        Visualize prime number distribution
        
        Args:
            limit: Upper limit for visualization
        """
        try:
            import matplotlib.pyplot as plt
            import numpy as np
            
            primes = []
            numbers = list(range(2, limit + 1))
            
            for num in numbers:
                if self.is_prime(num):
                    primes.append(1)
                else:
                    primes.append(0)
                    
            plt.figure(figsize=(10, 6))
            plt.plot(numbers, primes, 'o', markersize=3)
            plt.title(f"Prime Number Distribution up to {limit}")
            plt.xlabel("Number")
            plt.ylabel("Is Prime? (1 = Prime, 0 = Composite)")
            plt.grid(True, alpha=0.3)
            
            plt.savefig('prime_distribution.png')
            print(f"Prime distribution plot saved to prime_distribution.png")
            
        except ImportError as e:
            print(f"Visualization requires matplotlib: {e}")
            print("Install with: pip install matplotlib")
        except Exception as e:
            print(f"Visualization failed: {e}")

def demo_crypto_math():
    """Demonstrate cryptographic math operations"""
    print(f"{'='*60}")
    print(f"  CRYPTOGRAPHIC MATHEMATICS DEMONSTRATION")
    print(f"{'='*60}")
    
    math_ops = CryptoMath()
    
    # Test 1: Prime Testing
    print(f"\n1. PRIME TESTING:")
    test_numbers = [7, 15, 101, 1000, 2**20 - 1]
    
    for num in test_numbers:
        is_prime_result = math_ops.is_prime(num)
        print(f"   {num:10} is {'prime' if is_prime_result else 'composite'}")
        
    # Test 2: Prime Generation
    print(f"\n2. PRIME GENERATION:")
    prime1024 = math_ops.generate_prime(1024)
    print(f"   Generated 1024-bit prime (first 32 bits): {hex(prime1024)[:32]}...")
    
    # Test 3: GCD and Modular Inverse
    print(f"\n3. GCD AND MODULAR INVERSE:")
    a, b = 12345, 67890
    gcd_result = math_ops.gcd(a, b)
    print(f"   GCD of {a} and {b}: {gcd_result}")
    
    try:
        inv_result = math_ops.modular_inverse(7, 26)
        print(f"   Modular inverse of 7 modulo 26: {inv_result}")
    except ValueError as e:
        print(f"   Error: {e}")
        
    # Test 4: Modular Exponentiation
    print(f"\n4. MODULAR EXPONENTIATION:")
    base = 2
    exponent = 1000
    modulus = 1000000007
    
    result = math_ops.modular_exponentiation(base, exponent, modulus)
    print(f"   2^1000 mod 1000000007: {result}")
    
    # Test 5: Miller-Rabin Test
    print(f"\n5. MILLER-RABIN PRIMALITY TEST:")
    large_number = 2**127 - 1
    
    if math_ops.miller_rabin(large_number):
        print(f"   {large_number} is probably prime")
    else:
        print(f"   {large_number} is composite")
        
    # Test 6: Chinese Remainder Theorem
    print(f"\n6. CHINESE REMAINDER THEOREM:")
    congruences = [(2, 3), (3, 4), (1, 5)]
    
    try:
        crt_result = math_ops.crt(congruences)
        print(f"   System of congruences {congruences}")
        print(f"   Solution x ≡ {crt_result} mod {3*4*5}")
        
        # Verify solution
        for a_i, m_i in congruences:
            assert crt_result % m_i == a_i
            print(f"   x mod {m_i} = {crt_result % m_i} (expected {a_i})")
            
    except Exception as e:
        print(f"   Error: {e}")
        
    # Test 7: Prime Counting
    print(f"\n7. PRIME COUNTING:")
    limit = 10000
    
    prime_count = math_ops.prime_counting(limit)
    print(f"   Number of primes ≤ {limit}: {prime_count}")
    
    statistics = math_ops.prime_statistics(limit)
    print(f"   Prime density: {statistics['density']:.4f}")
    print(f"   Expected density (1/ln(n)): {1/statistics['expected_density']:.4f}")
    
    # Test 8: RSA Key Generation
    print(f"\n8. RSA KEY GENERATION:")
    try:
        rsa_keys = math_ops.rsa_key_generation(1024)
        
        print(f"   Public key (e, n): ({rsa_keys['public_key']},")
        print(f"                     {hex(rsa_keys['modulus'])[:32]}...)")
        print(f"   Private key (d, n): ({hex(rsa_keys['private_key'])[:32]}...,")
        print(f"                      {hex(rsa_keys['modulus'])[:32]}...)")
        
        # Test encryption/decryption
        test_message = 123456789
        ciphertext = math_ops.rsa_encrypt(test_message, rsa_keys['public_key'], rsa_keys['modulus'])
        decrypted = math_ops.rsa_decrypt(ciphertext, rsa_keys['private_key'], rsa_keys['modulus'])
        
        assert decrypted == test_message
        print(f"   Encryption/Decryption test passed")
        
    except Exception as e:
        print(f"   Error: {e}")
        
    # Test 9: Performance Testing
    print(f"\n9. PERFORMANCE TESTING:")
    try:
        performance = math_ops.test_performance()
        
        print(f"   Is Prime test:")
        for n, time_taken in performance['is_prime'].items():
            print(f"     {n:10}: {time_taken*1000:.1f}ms")
            
        print(f"   GCD test:")
        for (a, b), time_taken in performance['gcd'].items():
            print(f"     {a}, {b}: {time_taken*1000:.1f}ms per 10,000 iterations")
            
    except Exception as e:
        print(f"   Performance test failed: {e}")
        
    # Test 10: Visualization
    print(f"\n10. PRIME DISTRIBUTION VISUALIZATION:")
    math_ops.visualize_prime_distribution(1000)
    
    return True

def main():
    """Main function to demonstrate cryptographic math operations"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Cryptographic Mathematics - Number theory, modular arithmetic, and more"
    )
    
    parser.add_argument(
        "-d", "--demo",
        action="store_true",
        help="Run cryptographic math demonstration"
    )
    
    parser.add_argument(
        "-p", "--prime",
        type=int,
        help="Check if number is prime"
    )
    
    parser.add_argument(
        "-g", "--generate",
        type=int,
        default=1024,
        help="Generate prime number with specified bit length"
    )
    
    parser.add_argument(
        "-c", "--count",
        type=int,
        help="Count number of primes up to limit"
    )
    
    parser.add_argument(
        "-t", "--test",
        action="store_true",
        help="Run performance tests"
    )
    
    parser.add_argument(
        "-v", "--visualize",
        type=int,
        default=1000,
        help="Visualize prime distribution"
    )
    
    args = parser.parse_args()
    
    try:
        math_ops = CryptoMath()
        
        if args.demo:
            demo_crypto_math()
            
        elif args.prime:
            is_prime_result = math_ops.is_prime(args.prime)
            print(f"{args.prime} is {'prime' if is_prime_result else 'composite'}")
            
        elif args.generate:
            prime_num = math_ops.generate_prime(args.generate)
            print(f"Generated {args.generate}-bit prime: {hex(prime_num)}")
            
        elif args.count:
            prime_count = math_ops.prime_counting(args.count)
            print(f"Number of primes ≤ {args.count}: {prime_count}")
            
        elif args.test:
            performance = math_ops.test_performance()
            
            print("Performance Test Results:")
            for test, data in performance.items():
                print(f"\n{test.replace('_', ' ').title()}:")
                
                if isinstance(data, dict):
                    for key, value in data.items():
                        if isinstance(key, tuple):
                            key_str = ', '.join(str(x) for x in key)
                        else:
                            key_str = str(key)
                            
                        print(f"  {key_str:30}: {value*1000:.2f}ms")
                        
        elif args.visualize:
            math_ops.visualize_prime_distribution(args.visualize)
            
        else:
            parser.print_help()
            
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        print(traceback.format_exc())

if __name__ == "__main__":
    main()
