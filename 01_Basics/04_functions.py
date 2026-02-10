#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Functions in Python for Cybersecurity
This script demonstrates Python functions with cybersecurity examples.
"""

# ==========================================
# 1. Basic Functions
# ==========================================
print("=== Basic Functions ===\n")

# Function without parameters
def print_banner():
    """Print a cybersecurity-themed banner"""
    print("=" * 50)
    print("         CYBERSECURITY TOOLKIT")
    print("=" * 50)

print_banner()
print()

# Function with parameters
def check_port_status(port):
    """
    Check if a port is in well-known, registered, or ephemeral range
    
    Args:
        port: Integer port number to check
        
    Returns:
        String indicating port range classification
    """
    if 0 < port < 1024:
        return "Well-known port"
    elif 1024 <= port < 49152:
        return "Registered port"
    elif 49152 <= port <= 65535:
        return "Ephemeral port"
    else:
        return "Invalid port number"

for port in [80, 8080, 50000, 65536, 0]:
    print(f"Port {port}: {check_port_status(port)}")

print()

# ==========================================
# 2. Functions with Return Values
# ==========================================
print("=== Functions with Return Values ===\n")

def calculate_network_address(ip, subnet_mask):
    """
    Calculate network address from IP and subnet mask
    
    Args:
        ip: IP address string (e.g., "192.168.1.100")
        subnet_mask: Subnet mask string (e.g., "255.255.255.0")
        
    Returns:
        Network address string
    """
    # Convert IP and mask to integers for calculation
    def ip_to_int(ip_str):
        octets = list(map(int, ip_str.split('.')))
        return octets[0] << 24 | octets[1] << 16 | octets[2] << 8 | octets[3]
    
    def int_to_ip(ip_int):
        octet1 = (ip_int >> 24) & 0xFF
        octet2 = (ip_int >> 16) & 0xFF
        octet3 = (ip_int >> 8) & 0xFF
        octet4 = ip_int & 0xFF
        return f"{octet1}.{octet2}.{octet3}.{octet4}"
    
    ip_int = ip_to_int(ip)
    mask_int = ip_to_int(subnet_mask)
    network_int = ip_int & mask_int
    return int_to_ip(network_int)

# Test the function
test_cases = [
    ("192.168.1.100", "255.255.255.0"),
    ("10.0.0.50", "255.255.0.0"),
    ("172.16.20.30", "255.255.255.192")
]

for ip, mask in test_cases:
    network = calculate_network_address(ip, mask)
    print(f"IP: {ip}, Mask: {mask}, Network: {network}")

print()

# ==========================================
# 3. Default Parameters
# ==========================================
print("=== Default Parameters ===\n")

def scan_port(ip, port, timeout=3):
    """
    Simulate port scanning with timeout
    
    Args:
        ip: Target IP address
        port: Target port
        timeout: Timeout in seconds (default: 3)
        
    Returns:
        String indicating scan result
    """
    import time
    time.sleep(0.1)  # Simulate network delay
    
    # Simulate random results
    import random
    result = random.choice(["open", "closed", "filtered"])
    return f"Port {port} on {ip} is {result} (timeout: {timeout}s)"

# Test with default timeout
print(scan_port("192.168.1.1", 80))
# Test with custom timeout
print(scan_port("192.168.1.1", 443, timeout=5))

print()

# ==========================================
# 4. Variable-length Arguments
# ==========================================
print("=== Variable-length Arguments ===\n")

def scan_ports(ip, *ports):
    """
    Scan multiple ports on a single IP
    
    Args:
        ip: Target IP address
        *ports: Variable number of ports to scan
        
    Returns:
        Dictionary with port scan results
    """
    results = {}
    for port in ports:
        results[port] = scan_port(ip, port)
    return results

# Scan multiple ports
results = scan_ports("192.168.1.1", 21, 22, 80, 443, 3389)
for port, result in results.items():
    print(f"Port {port}: {result}")

print()

# ==========================================
# 5. Keyword Arguments
# ==========================================
print("=== Keyword Arguments ===\n")

def log_message(message, level="INFO", timestamp=None):
    """
    Log a message with specified level and timestamp
    
    Args:
        message: Message to log
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        timestamp: Custom timestamp (or None for current time)
    """
    import datetime
    if timestamp is None:
        timestamp = datetime.datetime.now()
    
    print(f"[{timestamp}] [{level.upper()}] {message}")

# Using keyword arguments
log_message("System started", level="INFO")
log_message("Port scan completed", level="SUCCESS")
log_message("Connection failed", level="ERROR")

print()

# ==========================================
# 6. Lambda Functions
# ==========================================
print("=== Lambda Functions ===\n")

# Simple lambda for port validation
is_valid_port = lambda x: 1 <= x <= 65535

test_ports = [80, 0, 65535, 100000]
for port in test_ports:
    print(f"Port {port} is valid: {is_valid_port(port)}")

print()

# Lambda with filter for vulnerability scanning
vulnerability_scan = [
    {"port": 80, "vulnerable": False, "cvss": 5.0},
    {"port": 443, "vulnerable": True, "cvss": 8.5},
    {"port": 22, "vulnerable": False, "cvss": 3.0},
    {"port": 3389, "vulnerable": True, "cvss": 7.8}
]

# Filter for critical vulnerabilities (CVSS > 7.0)
critical_vulns = list(filter(lambda x: x["cvss"] > 7.0, vulnerability_scan))
print("Critical vulnerabilities:")
for vuln in critical_vulns:
    print(f"Port {vuln['port']} - CVSS: {vuln['cvss']}")

print()

# ==========================================
# 7. Function Decorators
# ==========================================
print("=== Function Decorators ===\n")

def audit_decorator(func):
    """
    Decorator to log function calls for audit purposes
    """
    def wrapper(*args, **kwargs):
        import datetime
        timestamp = datetime.datetime.now()
        print(f"[{timestamp}] Calling: {func.__name__}")
        print(f"  Args: {args}")
        print(f"  Keyword Args: {kwargs}")
        
        result = func(*args, **kwargs)
        
        print(f"[{timestamp}] Returned: {result}")
        return result
    return wrapper

@audit_decorator
def check_password_strength(password):
    """
    Check password strength (simple implementation)
    
    Args:
        password: Password to check
        
    Returns:
        Dictionary with strength assessment
    """
    strength = {
        "length": len(password) >= 8,
        "has_uppercase": any(c.isupper() for c in password),
        "has_lowercase": any(c.islower() for c in password),
        "has_digit": any(c.isdigit() for c in password),
        "has_special": any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
    }
    
    score = sum(strength.values())
    level = "Weak"
    if score == 5:
        level = "Very Strong"
    elif score == 4:
        level = "Strong"
    elif score == 3:
        level = "Medium"
    
    return {"password": password, "strength": level, "details": strength}

# Test the decorated function
result = check_password_strength("Password123!")
print(f"Password strength: {result['strength']}")

print()

# ==========================================
# 8. Recursive Functions
# ==========================================
print("=== Recursive Functions ===\n")

def calculate_subnet_bits(subnet_mask):
    """
    Calculate CIDR prefix length from subnet mask
    
    Args:
        subnet_mask: Subnet mask string (e.g., "255.255.255.0")
        
    Returns:
        CIDR prefix length (e.g., 24)
    """
    def count_bits(int_value):
        """Count number of 1 bits in an integer"""
        if int_value == 0:
            return 0
        return (int_value & 1) + count_bits(int_value >> 1)
    
    mask_int = 0
    for octet in subnet_mask.split('.'):
        mask_int = (mask_int << 8) | int(octet)
    
    return count_bits(mask_int)

test_masks = [
    "255.255.255.0",    # /24
    "255.255.0.0",      # /16
    "255.255.255.192",  # /26
    "255.0.0.0"         # /8
]

for mask in test_masks:
    bits = calculate_subnet_bits(mask)
    print(f"Subnet mask {mask} = /{bits}")

print()

# ==========================================
# 9. Practical Examples
# ==========================================
print("=== Practical Examples ===\n")

# Example 1: Password Generator
def generate_password(length=12, include_special=True):
    """
    Generate a random password
    
    Args:
        length: Password length (default: 12)
        include_special: Include special characters (default: True)
        
    Returns:
        Randomly generated password
    """
    import random
    import string
    
    characters = string.ascii_letters + string.digits
    if include_special:
        characters += "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    password = ''.join(random.choice(characters) for _ in range(length))
    return password

print("Generated passwords:")
for i in range(5):
    print(f"Password {i+1}: {generate_password()}")

print()

# Example 2: Hash Verifier
def verify_hash(text, hash_value, algorithm="md5"):
    """
    Verify text matches a hash value
    
    Args:
        text: Plain text to hash
        hash_value: Hash to verify against
        algorithm: Hash algorithm (md5, sha1, sha256)
        
    Returns:
        Boolean indicating if hash matches
    """
    import hashlib
    
    hash_obj = hashlib.new(algorithm)
    hash_obj.update(text.encode('utf-8'))
    calculated_hash = hash_obj.hexdigest()
    
    return calculated_hash == hash_value

test_text = "password123"
test_hash = "482c811da5d5b4bc6d497ffa98491e3"  # MD5 of "password123"

result = verify_hash(test_text, test_hash)
print(f"Hash verification: {'Success' if result else 'Failed'}")

print()

# Example 3: Port Range Scanner
def scan_port_range(ip, start_port, end_port, timeout=2):
    """
    Scan a range of ports
    
    Args:
        ip: Target IP address
        start_port: Start of port range
        end_port: End of port range
        timeout: Timeout in seconds (default: 2)
        
    Returns:
        Dictionary of port states
    """
    results = {}
    for port in range(start_port, end_port + 1):
        # Simulate scan
        import random
        state = random.choice(["open", "closed", "filtered"])
        results[port] = state
        
    return results

print("Port range scan:")
scan_results = scan_port_range("10.0.0.5", 1, 10)
for port, state in scan_results.items():
    print(f"Port {port}: {state}")
