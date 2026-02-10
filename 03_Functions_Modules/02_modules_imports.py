#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Modules and Imports in Python for Cybersecurity
This script demonstrates Python's module system with cybersecurity examples.
Perfect for beginners!
"""

# ==========================================
# 1. Module Basics - What is a Module?
# ==========================================
print("=== Module Basics ===\n")

# Importing entire module
# A module is a file containing Python code that we can use in other programs
import socket
print("Socket module imported")
print(f"Module name: {socket.__name__}")
print(f"Module file: {socket.__file__}")
print()

# Importing specific functions
# We can import only the specific functions we need from a module
from random import randint, choice  # Import randint and choice from random module
print("Specific functions imported from random module")

# Generate a random port number between 1024 and 65535
random_port = randint(1024, 65535)

# List of common ports used in cybersecurity
common_ports = [80, 443, 22, 21, 53]

# Choose a random port from the common ports list
random_common_port = choice(common_ports)

print(f"Random port: {random_port}")
print(f"Random common port: {random_common_port}")
print()

# Importing with alias
# We can give modules an alias for easier use
import scapy.all as scapy
print("Scapy imported with alias 'scapy'")
print()

# ==========================================
# 2. Built-in Modules for Cybersecurity
# ==========================================
print("=== Built-in Modules for Cybersecurity ===\n")

# socket module - network programming
# The socket module is used for network communication
import socket

def scan_port(ip, port):
    """
    Scan a single port using socket module.
    
    Args:
        ip: IP address to scan
        port: Port number to scan
        
    Returns:
        True if port is open, False otherwise
    """
    # Create a socket object
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Set timeout for connection attempt (1 second)
    sock.settimeout(1)
    
    # Try to connect to port
    # connect_ex() returns error code instead of raising exception
    result = sock.connect_ex((ip, port))
    
    # Close the socket
    sock.close()
    
    # Return True if port is open (error code 0 means success)
    return result == 0

# Test port scanning on localhost (your own computer)
print("Socket module port scan:", scan_port("127.0.0.1", 80))
print()

# hashlib module - cryptographic hashes
# Used for calculating cryptographic hashes of data
import hashlib

def calculate_hash(text, algorithm="sha256"):
    """
    Calculate cryptographic hash of text using specified algorithm.
    
    Args:
        text: Text to hash
        algorithm: Hash algorithm to use (default: sha256)
        
    Returns:
        Hexadecimal string of the calculated hash
    """
    # Create a hash object for specified algorithm
    hash_obj = hashlib.new(algorithm)
    
    # Update hash with text (must be bytes, so we encode the string)
    hash_obj.update(text.encode('utf-8'))
    
    # Return hexadecimal representation of hash
    return hash_obj.hexdigest()

# Test hash calculation
test_text = "password123"
print(f"SHA-256 of '{test_text}': {calculate_hash(test_text)}")
print(f"MD5 of '{test_text}': {calculate_hash(test_text, 'md5')}")
print()

# random module - randomization
# Used for generating random numbers and values
import random

def generate_random_ip():
    """
    Generate a random IPv4 address.
    
    Returns:
        Random IPv4 address string (e.g., "192.168.1.100")
    """
    # Generate 4 random octets between 1 and 255
    octets = [str(random.randint(1, 255)) for _ in range(4)]
    return ".".join(octets)

def generate_random_mac():
    """
    Generate a random MAC address.
    
    Returns:
        Random MAC address string (e.g., "00:1A:2B:3C:4D:5E")
    """
    hex_chars = "0123456789ABCDEF"
    # Generate 6 pairs of hexadecimal characters
    mac = ":".join("".join(random.sample(hex_chars, 2)) for _ in range(6))
    return mac

# Test random generation functions
print("Random IP:", generate_random_ip())
print("Random MAC:", generate_random_mac())
print()

# datetime module - timestamps and dates
# Used for working with dates, times, and timestamps
import datetime

def log_event(event, severity="INFO"):
    """
    Log an event with timestamp and severity.
    
    Args:
        event: Event description to log
        severity: Severity level (default: INFO)
        
    Returns:
        Formatted log string with timestamp
    """
    # Get current time with milliseconds
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
    return f"[{timestamp}] [{severity.upper()}] {event}"

# Test log event function
print(log_event("Network scan completed"))
print(log_event("Vulnerability detected", "CRITICAL"))
print()

# ==========================================
# 3. Creating and Using Custom Modules
# ==========================================
print("=== Creating and Using Custom Modules ===\n")

# Create a simple custom module
with open('network_tools.py', 'w') as f:
    f.write('''#!/usr/bin/env python3
"""Network tools module for cybersecurity tasks"""

def validate_ip(ip_address):
    """Validate IPv4 address format"""
    parts = ip_address.split('.')
    if len(parts) != 4:
        return False
    for part in parts:
        try:
            num = int(part)
            if num < 0 or num > 255:
                return False
        except ValueError:
            return False
    return True

def ip_to_int(ip_address):
    """Convert IP address to integer for calculations"""
    octets = list(map(int, ip_address.split('.')))
    return octets[0] << 24 | octets[1] << 16 | octets[2] << 8 | octets[3]

def int_to_ip(ip_int):
    """Convert integer to IP address string"""
    octet1 = (ip_int >> 24) & 0xFF
    octet2 = (ip_int >> 16) & 0xFF
    octet3 = (ip_int >> 8) & 0xFF
    octet4 = ip_int & 0xFF
    return f"{octet1}.{octet2}.{octet3}.{octet4}"

def generate_ip_range(start_ip, end_ip):
    """Generate all IP addresses in a range"""
    start = ip_to_int(start_ip)
    end = ip_to_int(end_ip)
    return [int_to_ip(i) for i in range(start, end + 1)]
''')

# Import and use the custom module
import network_tools

# Test the module
print("IP validation test:")
print(f"192.168.1.1: {network_tools.validate_ip('192.168.1.1')}")
print(f"256.0.0.1: {network_tools.validate_ip('256.0.0.1')}")
print()

print("IP conversion test:")
ip_int = network_tools.ip_to_int('192.168.1.100')
print(f"IP to integer: {ip_int}")
print(f"Integer to IP: {network_tools.int_to_ip(ip_int)}")
print()

print("IP range generation:")
ip_range = network_tools.generate_ip_range('192.168.1.100', '192.168.1.105')
for ip in ip_range:
    print(f"  {ip}")
print()

# ==========================================
# 4. Package Structure
# ==========================================
print("=== Package Structure ===\n")

# Create a package structure
import os

package_name = 'security_toolkit'
if not os.path.exists(package_name):
    os.makedirs(package_name)
    
with open(os.path.join(package_name, '__init__.py'), 'w') as f:
    f.write('''"""Security toolkit package"""

__version__ = "1.0.0"
__author__ = "Security Team"

from .network import validate_ip, scan_port
from .crypto import calculate_hash, verify_hash
''')

# Network submodule
network_dir = os.path.join(package_name, 'network')
if not os.path.exists(network_dir):
    os.makedirs(network_dir)
    
with open(os.path.join(network_dir, '__init__.py'), 'w') as f:
    f.write('''"""Network security module"""

from .ip_tools import validate_ip
from .port_scanner import scan_port
''')

with open(os.path.join(network_dir, 'ip_tools.py'), 'w') as f:
    f.write('''def validate_ip(ip_address):
    parts = ip_address.split('.')
    if len(parts) != 4:
        return False
    for part in parts:
        try:
            num = int(part)
            if num < 0 or num > 255:
                return False
        except ValueError:
            return False
    return True

def ip_to_int(ip_address):
    octets = list(map(int, ip_address.split('.')))
    return octets[0] << 24 | octets[1] << 16 | octets[2] << 8 | octets[3]

def int_to_ip(ip_int):
    octet1 = (ip_int >> 24) & 0xFF
    octet2 = (ip_int >> 16) & 0xFF
    octet3 = (ip_int >> 8) & 0xFF
    octet4 = ip_int & 0xFF
    return f"{octet1}.{octet2}.{octet3}.{octet4}"
''')

with open(os.path.join(network_dir, 'port_scanner.py'), 'w') as f:
    f.write('''import socket

def scan_port(ip, port, timeout=1):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        return True
    except:
        return False
    finally:
        sock.close()

def scan_ports(ip, ports):
    open_ports = []
    for port in ports:
        if scan_port(ip, port):
            open_ports.append(port)
    return open_ports
''')

# Crypto submodule
crypto_dir = os.path.join(package_name, 'crypto')
if not os.path.exists(crypto_dir):
    os.makedirs(crypto_dir)
    
with open(os.path.join(crypto_dir, '__init__.py'), 'w') as f:
    f.write('''"""Cryptography module"""

from .hash_tools import calculate_hash, verify_hash
''')

with open(os.path.join(crypto_dir, 'hash_tools.py'), 'w') as f:
    f.write('''import hashlib

def calculate_hash(text, algorithm="sha256"):
    hash_obj = hashlib.new(algorithm)
    hash_obj.update(text.encode('utf-8'))
    return hash_obj.hexdigest()

def verify_hash(text, expected_hash, algorithm="sha256"):
    calculated_hash = calculate_hash(text, algorithm)
    return calculated_hash == expected_hash
''')

# Use the package
import security_toolkit

print("Security toolkit version:", security_toolkit.__version__)
print("Security toolkit author:", security_toolkit.__author__)
print()

# Test package functions
print("IP validation via package:", security_toolkit.validate_ip('10.0.0.1'))
print("Port scan via package:", security_toolkit.scan_port('127.0.0.1', 80))
print()

print("Hash calculation via package:")
test_hash = security_toolkit.calculate_hash('testdata')
print(f"Test data hash: {test_hash}")
print(f"Verify test data: {security_toolkit.verify_hash('testdata', test_hash)}")
print()

# ==========================================
# 5. Import Techniques
# ==========================================
print("=== Import Techniques ===\n")

# Different import styles
from security_toolkit.network import validate_ip
from security_toolkit.crypto import calculate_hash

print("From package import specific function:")
print(f"IP validation: {validate_ip('172.16.0.1')}")
print()

import security_toolkit.network as net
import security_toolkit.crypto as crypto

print("Import with alias:")
print(f"Network module available as 'net': {net.validate_ip('10.0.0.5')}")
print(f"Crypto module available as 'crypto': {len(crypto.calculate_hash('test'))} bytes")
print()

# Dynamic imports
module_name = 'security_toolkit'
module = __import__(module_name)
print(f"Dynamic import of '{module_name}': {module.__name__}")
print()

# ==========================================
# 6. Module Search Path
# ==========================================
print("=== Module Search Path ===\n")

import sys
print("Python module search path:")
for i, path in enumerate(sys.path):
    print(f"  {i+1}. {path}")
print()

print("Current script directory:", __file__)
print()

# ==========================================
# 7. Reloading Modules
# ==========================================
print("=== Reloading Modules ===\n")

import importlib
import network_tools

print("Original module attribute:", hasattr(network_tools, 'new_function'))

# Simulate module change by writing to it
with open('network_tools.py', 'a') as f:
    f.write('''

def new_function():
    return "This is a new function"
''')

# Reload the module
importlib.reload(network_tools)

print("After reload attribute check:", hasattr(network_tools, 'new_function'))
print("New function call:", network_tools.new_function())
print()

# ==========================================
# 8. Practical Examples
# ==========================================
print("=== Practical Examples ===\n")

# Example 1: Network scanner using custom module
print("=== Network Scanner ===\n")

from security_toolkit.network import scan_ports

target_ip = "127.0.0.1"
common_ports = [80, 443, 22, 21, 53, 3389]

print(f"Scanning {target_ip} for common ports...")
open_ports = scan_ports(target_ip, common_ports)

if open_ports:
    print(f"Open ports: {', '.join(map(str, open_ports))}")
else:
    print("No common ports found open")

print()

# Example 2: Password verifier using hashes
print("=== Password Verifier ===\n")

from security_toolkit.crypto import verify_hash

# Store hashed passwords instead of plain text
hashed_passwords = {
    "admin": "d033e22ae348aeb5660fc2140aec358",  # MD5 of "admin"
    "user1": "5f4dcc3b5aa765d61d8327deb882cf9"   # MD5 of "password"
}

def login(username, password):
    if username in hashed_passwords:
        expected_hash = hashed_passwords[username]
        if verify_hash(password, expected_hash, "md5"):
            return True
    return False

print("Login admin/admin:", login("admin", "admin"))
print("Login admin/test:", login("admin", "test"))
print("Login user1/password:", login("user1", "password"))
print("Login user1/123456:", login("user1", "123456"))

print()

# Example 3: IP range scanner
print("=== IP Range Scanner ===\n")

from security_toolkit.network import generate_ip_range
from security_toolkit.network import scan_port

start_ip = "192.168.1.1"
end_ip = "192.168.1.5"

print(f"Scanning IP range {start_ip} to {end_ip} for port 80...")

for ip in generate_ip_range(start_ip, end_ip):
    port_status = "open" if scan_port(ip, 80) else "closed"
    print(f"  {ip}:80 is {port_status}")

print()

# Example 4: Module-based configuration system
print("=== Module Configuration ===\n")

config_module = '''#!/usr/bin/env python3
"""Configuration module for security toolkit"""

# Network configuration
NETWORK = {
    "target_ip": "192.168.1.0/24",
    "scan_ports": [80, 443, 22, 21, 53],
    "timeout": 1.0,
    "threads": 50
}

# Vulnerability scanning configuration
VULNERABILITY = {
    "severity": ["Critical", "High", "Medium"],
    "exploits": True,
    "aggressive": False
}

# Reporting configuration
REPORTING = {
    "formats": ["html", "csv"],
    "email": {
        "enabled": False,
        "smtp_server": "smtp.example.com",
        "recipients": ["admin@example.com"]
    }
}

# Logging configuration
LOGGING = {
    "level": "INFO",
    "file": "security_toolkit.log",
    "max_size": 10 * 1024 * 1024  # 10MB
}
'''

with open('security_config.py', 'w') as f:
    f.write(config_module)

import security_config

print("Security configuration:")
print(f"  Target IP: {security_config.NETWORK['target_ip']}")
print(f"  Scan ports: {security_config.NETWORK['scan_ports']}")
print(f"  Severity: {security_config.VULNERABILITY['severity']}")
print(f"  Report formats: {security_config.REPORTING['formats']}")

print()

# ==========================================
# 9. Cleanup
# ==========================================
import os
import shutil

# Clean up temporary files
temp_files = [
    'network_tools.py',
    'security_config.py',
    'security_toolkit',
    'test_log.txt'
]

for file_path in temp_files:
    if os.path.isfile(file_path):
        os.remove(file_path)
    elif os.path.isdir(file_path):
        shutil.rmtree(file_path)

print("Temporary files cleaned up")
