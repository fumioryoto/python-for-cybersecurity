#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Error Handling in Python for Cybersecurity
This script demonstrates Python error handling with cybersecurity examples.
"""

# ==========================================
# 1. Try-Except Blocks
# ==========================================
print("=== Try-Except Blocks ===\n")

# Basic try-except for file operations
print("=== Reading Configuration File ===\n")
try:
    with open("nonexistent_config.txt", "r") as file:
        config = file.read()
    print("Configuration file loaded successfully")
except FileNotFoundError:
    print("Error: Configuration file not found")
    print("Using default settings")
    config = "default_config"

print(f"Configuration value: {config}")
print()

# ==========================================
# 2. Catching Specific Exceptions
# ==========================================
print("=== Catching Specific Exceptions ===\n")

def parse_ip_address(ip_str):
    """Parse IP address with error handling"""
    try:
        octets = list(map(int, ip_str.split('.')))
        
        if len(octets) != 4:
            raise ValueError("IP address must have exactly 4 octets")
            
        for octet in octets:
            if octet < 0 or octet > 255:
                raise ValueError("Each octet must be between 0 and 255")
                
        return octets
    except ValueError as e:
        print(f"Error parsing IP address: {e}")
        return None
    except Exception as e:
        print(f"Unexpected error: {e}")
        return None

# Test valid IP
ip1 = parse_ip_address("192.168.1.1")
print(f"Valid IP parsed: {ip1}")

# Test invalid octet
parse_ip_address("256.0.0.1")

# Test invalid format
parse_ip_address("10.0.0")

print()

# ==========================================
# 3. Try-Except-Else
# ==========================================
print("=== Try-Except-Else ===\n")

def connect_to_server(ip, port):
    """Simulate server connection with error handling"""
    import time
    import random
    
    try:
        # Simulate connection attempt
        print(f"Attempting to connect to {ip}:{port}...")
        time.sleep(0.5)
        
        # Randomly fail for testing
        if random.choice([True, False]):
            raise ConnectionRefusedError("Connection refused by server")
            
        print("Connection successful!")
    except ConnectionRefusedError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
    else:
        print("Connection established - sending data...")
        print("Data transmission complete")
    finally:
        print("Connection attempt completed\n")

# Test connections
connect_to_server("192.168.1.1", 80)
connect_to_server("10.0.0.5", 22)
connect_to_server("172.16.0.10", 443)

print()

# ==========================================
# 4. Try-Except-Finally
# ==========================================
print("=== Try-Except-Finally ===\n")

def scan_port_with_timeout(ip, port, timeout=5):
    """
    Scan a port with timeout handling
    
    Args:
        ip: Target IP
        port: Target port
        timeout: Timeout in seconds
        
    Returns:
        Scan result string
    """
    import socket
    socket.setdefaulttimeout(timeout)
    
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ip, port))
        return f"Port {port} is open"
    except socket.timeout:
        return f"Port {port} timed out"
    except ConnectionRefusedError:
        return f"Port {port} is closed"
    except Exception as e:
        return f"Error scanning port {port}: {e}"
    finally:
        if sock:
            sock.close()
        print(f"Scan of port {port} completed")

# Test port scanning
results = []
for port in [80, 443, 22, 8080, 3389]:
    result = scan_port_with_timeout("127.0.0.1", port)
    results.append(result)

print("\nPort scan results:")
for result in results:
    print(result)

print()

# ==========================================
# 5. Raising Exceptions
# ==========================================
print("=== Raising Exceptions ===\n")

class SecurityException(Exception):
    """Custom exception for security-related errors"""
    pass

def validate_credentials(username, password):
    """Validate user credentials"""
    if len(username) < 3:
        raise SecurityException("Username must be at least 3 characters long")
        
    if len(password) < 8:
        raise SecurityException("Password must be at least 8 characters long")
        
    if not any(c.isdigit() for c in password):
        raise SecurityException("Password must contain at least one digit")
        
    print("Credentials are valid")

# Test credential validation
try:
    validate_credentials("admin", "password123")
    print()
    validate_credentials("u", "pass")
except SecurityException as e:
    print(f"Security error: {e}")

print()

# ==========================================
# 6. Assert Statements
# ==========================================
print("=== Assert Statements ===\n")

def check_packet_length(packet_data):
    """Check packet length with assertion"""
    min_length = 64
    max_length = 1518
    
    assert min_length <= len(packet_data) <= max_length, \
        f"Invalid packet length: {len(packet_data)} bytes. Must be between 64-1518 bytes."
        
    print(f"Packet length ({len(packet_data)} bytes) is valid")

# Test valid packet
valid_packet = b'x' * 100
try:
    check_packet_length(valid_packet)
except AssertionError as e:
    print(f"Assertion failed: {e}")

# Test invalid packet
invalid_packet = b'x' * 50
try:
    check_packet_length(invalid_packet)
except AssertionError as e:
    print(f"Assertion failed: {e}")

print()

# ==========================================
# 7. Context Managers and Error Handling
# ==========================================
print("=== Context Managers and Error Handling ===\n")

class NetworkSession:
    """Context manager for network connections"""
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.connected = False
        
    def __enter__(self):
        print(f"Establishing connection to {self.ip}:{self.port}")
        # Simulate connection
        import random
        if random.choice([True, False]):
            self.connected = True
            return self
        else:
            raise ConnectionError("Failed to establish connection")
            
    def __exit__(self, exc_type, exc_value, traceback):
        if self.connected:
            print(f"Closing connection to {self.ip}:{self.port}")
            self.connected = False
            
        if exc_type:
            print(f"Error in session: {exc_value}")
        
        return True  # Suppress the exception

# Using the context manager
try:
    with NetworkSession("10.0.0.5", 80) as session:
        print("Session established")
except ConnectionError as e:
    print(f"Connection failed: {e}")

print()

# ==========================================
# 8. Logging Exceptions
# ==========================================
print("=== Logging Exceptions ===\n")

import logging

# Configure logging
logging.basicConfig(
    filename='security_scan.log',
    level=logging.ERROR,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def scan_network(targets):
    """Scan network with error logging"""
    for target in targets:
        try:
            print(f"Scanning {target}...")
            raise Exception(f"Unknown host {target}")
        except Exception as e:
            logging.error(f"Failed to scan {target}: {e}", exc_info=True)
            print(f"Error: {e}")

# Test error logging
scan_network(["192.168.1.1", "192.168.1.256", "invalid_ip"])

print("\nError details logged to security_scan.log")
print("First 50 lines of log file:")
with open('security_scan.log', 'r') as log_file:
    for i, line in enumerate(log_file, 1):
        print(line.strip())
        if i == 50:
            break

print()

# ==========================================
# 9. Practical Examples
# ==========================================
print("=== Practical Examples ===\n")

# Example 1: Password Hash Cracker with Error Handling
print("=== Password Hash Cracker ===\n")

def crack_password_hash(target_hash, wordlist_file, algorithm="md5"):
    """
    Attempt to crack a password hash using a wordlist
    
    Args:
        target_hash: Hash to crack
        wordlist_file: Path to wordlist file
        algorithm: Hash algorithm (md5, sha1, sha256)
        
    Returns:
        Cracked password or None
    """
    import hashlib
    
    try:
        with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as file:
            wordlist = [line.strip() for line in file]
    except FileNotFoundError:
        print(f"Error: Wordlist file '{wordlist_file}' not found")
        return None
    except Exception as e:
        print(f"Error reading wordlist: {e}")
        return None
    
    print(f"Loaded {len(wordlist)} words from wordlist")
    
    try:
        for i, word in enumerate(wordlist):
            hash_obj = hashlib.new(algorithm)
            hash_obj.update(word.encode('utf-8'))
            word_hash = hash_obj.hexdigest()
            
            if word_hash == target_hash:
                print(f"Password found at position {i+1}: {word}")
                return word
                
            if (i + 1) % 1000 == 0:
                print(f"Processed {i+1} words...")
                
    except Exception as e:
        print(f"Error during cracking: {e}")
        return None
        
    print("Password not found in wordlist")
    return None

# Create a test wordlist
test_words = ["password", "123456", "qwerty", "abc123", "password123"]
with open('test_wordlist.txt', 'w') as f:
    for word in test_words:
        f.write(word + '\n')

# Test the cracker
target_hash = "482c811da5d5b4bc6d497ffa98491e3"  # MD5 of "password123"
cracked_password = crack_password_hash(target_hash, 'test_wordlist.txt')
if cracked_password:
    print(f"Successfully cracked password: {cracked_password}")

print()

# Example 2: Network Scan with Retry Logic
print("=== Network Scan with Retries ===\n")

def scan_with_retries(ip, port, max_retries=3, delay=1):
    """Scan port with retry logic"""
    import time
    
    for attempt in range(1, max_retries + 1):
        try:
            print(f"Attempt {attempt}: Scanning port {port} on {ip}")
            return scan_port_with_timeout(ip, port)
        except Exception as e:
            print(f"Attempt {attempt} failed: {e}")
            
            if attempt < max_retries:
                print(f"Retrying in {delay} seconds...")
                time.sleep(delay)
            else:
                print("Max retries reached - giving up")
                
    return "Failed to scan port"

# Test with retries
result = scan_with_retries("nonexistent_host", 80)
print(f"Final result: {result}")
