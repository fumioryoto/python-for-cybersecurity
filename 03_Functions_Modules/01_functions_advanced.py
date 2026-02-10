#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced Functions in Python for Cybersecurity
This script demonstrates advanced Python functions with cybersecurity examples.
"""

# ==========================================
# 1. Nested Functions
# ==========================================
print("=== Nested Functions ===\n")

def network_scanner(target_ip):
    """Main network scanner function with nested helpers"""
    
    def validate_ip(ip_address):
        """Nested helper to validate IP address format"""
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
        
    def scan_port(ip, port):
        """Nested helper to scan a single port"""
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        try:
            sock.connect((ip, port))
            return True
        except:
            return False
        finally:
            sock.close()
            
    if not validate_ip(target_ip):
        return {"error": "Invalid IP address format"}
        
    results = {"target": target_ip, "open_ports": []}
    common_ports = [21, 22, 80, 443, 3389]
    
    for port in common_ports:
        if scan_port(target_ip, port):
            results["open_ports"].append(port)
            
    return results

# Usage example
scan_result = network_scanner("192.168.1.1")
print(f"Scan result: {scan_result}")

# Invalid IP test
invalid_result = network_scanner("invalid_ip")
print(f"Invalid IP result: {invalid_result}")

print()

# ==========================================
# 2. Closures
# ==========================================
print("=== Closures ===\n")

def create_port_scanner(timeout=1):
    """Create a port scanner with predefined timeout (closure)"""
    
    import socket
    
    def scanner(target_ip, port):
        """Inner function that uses outer variable"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((target_ip, port))
            return True
        except:
            return False
        finally:
            sock.close()
            
    return scanner

# Create scanners with different timeouts
fast_scanner = create_port_scanner(timeout=0.1)
slow_scanner = create_port_scanner(timeout=5)

# Usage
print(f"Fast scan result (80): {fast_scanner('192.168.1.1', 80)}")
print(f"Slow scan result (80): {slow_scanner('192.168.1.1', 80)}")

print()

# ==========================================
# 3. Decorators
# ==========================================
print("=== Decorators ===\n")

def audit_log(func):
    """Decorator to log function calls with timestamp"""
    import datetime
    def wrapper(*args, **kwargs):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] Calling {func.__name__}")
        print(f"  Args: {args}")
        print(f"  Kwargs: {kwargs}")
        result = func(*args, **kwargs)
        print(f"  Returned: {result}")
        return result
    return wrapper

@audit_log
def check_password_strength(password):
    """Check password strength with audit decorator"""
    strength = 0
    if len(password) >= 8:
        strength += 1
    if any(c.isupper() for c in password) and any(c.islower() for c in password):
        strength += 1
    if any(c.isdigit() for c in password):
        strength += 1
    if any(c in "!@#$%^&*" for c in password):
        strength += 1
    return strength

# Test with decorator
check_password_strength("Password123!")

print()

# ==========================================
# 4. Function Attributes
# ==========================================
print("=== Function Attributes ===\n")

def calculate_hash(data, algorithm="md5"):
    """Calculate hash of data using specified algorithm"""
    import hashlib
    hash_obj = hashlib.new(algorithm)
    hash_obj.update(data.encode('utf-8'))
    return hash_obj.hexdigest()

# Set function attributes
calculate_hash.version = "1.0"
calculate_hash.author = "Security Team"
calculate_hash.description = "Calculate cryptographic hash of input data"
calculate_hash.supports = ["md5", "sha1", "sha256", "sha512"]

# Access function attributes
print(f"Function name: {calculate_hash.__name__}")
print(f"Function docstring: {calculate_hash.__doc__}")
print(f"Version: {calculate_hash.version}")
print(f"Author: {calculate_hash.author}")
print(f"Supports algorithms: {', '.join(calculate_hash.supports)}")

# Test the function
test_hash = calculate_hash("password123", algorithm="sha256")
print(f"SHA-256 hash of 'password123': {test_hash}")

print()

# ==========================================
# 5. Partial Functions
# ==========================================
print("=== Partial Functions ===\n")

from functools import partial

def validate_input(input_str, min_length, max_length, allowed_chars):
    """Validate input against specified criteria"""
    if len(input_str) < min_length or len(input_str) > max_length:
        return False
    for char in input_str:
        if char not in allowed_chars:
            return False
    return True

# Create partial functions for common validation scenarios
validate_username = partial(
    validate_input,
    min_length=3,
    max_length=20,
    allowed_chars="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
)

validate_password = partial(
    validate_input,
    min_length=8,
    max_length=64,
    allowed_chars="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
)

# Test the partial functions
print(f"Username 'john_doe123': {validate_username('john_doe123')}")
print(f"Username 'j': {validate_username('j')}")
print(f"Password 'Password123!': {validate_password('Password123!')}")
print(f"Password 'pass': {validate_password('pass')}")

print()

# ==========================================
# 6. Function Overloading (Pythonic Way)
# ==========================================
print("=== Function Overloading ===\n")

from functools import singledispatch

@singledispatch
def process_data(data):
    """Process data with type-based dispatch"""
    print(f"Processing generic data: {data}")

@process_data.register(str)
def _(data):
    """Process string data"""
    print(f"Processing string: '{data}' ({len(data)} characters)")

@process_data.register(int)
def _(data):
    """Process integer data"""
    print(f"Processing integer: {data}")
    if data > 65535:
        print("  Warning: Value exceeds TCP port range")

@process_data.register(list)
def _(data):
    """Process list data"""
    print(f"Processing list: {data}")
    print(f"  Contains {len(data)} elements")

# Test the overloaded function
process_data("192.168.1.1")
process_data(8080)
process_data(65536)
process_data([80, 443, 22])
process_data(None)

print()

# ==========================================
# 7. Generators and Coroutines
# ==========================================
print("=== Generators ===\n")

def log_parser(log_file):
    """Generator to parse log file entries one by one"""
    with open(log_file, 'r') as f:
        for line in f:
            yield line.strip()

# Create a test log file
with open('test_log.txt', 'w') as f:
    f.write("192.168.1.100 - - [10/Oct/2023:13:55:36] \"GET / HTTP/1.1\" 200 1024\n")
    f.write("10.0.0.5 - - [10/Oct/2023:13:56:01] \"POST /login HTTP/1.1\" 401 200\n")
    f.write("172.16.0.15 - - [10/Oct/2023:13:57:12] \"GET /admin HTTP/1.1\" 403 150\n")

# Use the generator
print("Log file entries:")
for log in log_parser('test_log.txt'):
    print(log)

print()

# ==========================================
# 8. Context Managers
# ==========================================
print("=== Context Managers ===\n")

class NetworkSession:
    """Context manager for network connections"""
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.connection = None
        
    def __enter__(self):
        """Open the connection"""
        print(f"Establishing connection to {self.ip}:{self.port}")
        import socket
        self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connection.connect((self.ip, self.port))
        return self.connection
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Close the connection"""
        if self.connection:
            self.connection.close()
            print(f"Closed connection to {self.ip}:{self.port}")
            
        if exc_type:
            print(f"Error: {exc_val}")
        return False  # Don't suppress exceptions

# Usage example
try:
    with NetworkSession("google.com", 80) as sock:
        sock.sendall(b"GET / HTTP/1.1\r\nHost: google.com\r\n\r\n")
        response = sock.recv(1024)
        print(f"Received {len(response)} bytes")
        print(response.decode('utf-8', errors='ignore')[:200])
except Exception as e:
    print(f"Connection failed: {e}")

print()

# ==========================================
# 9. Practical Examples for Cybersecurity
# ==========================================
print("=== Practical Examples ===\n")

# Example 1: Vulnerability Scanner with Decorators
print("=== Vulnerability Scanner ===\n")

def vulnerability_check(func):
    """Decorator to log vulnerability check results"""
    def wrapper(*args, **kwargs):
        result = func(*args, **kwargs)
        severity = result.get("severity", "Medium")
        cve = result.get("cve", "Unknown")
        
        if severity == "Critical":
            print(f"🔴 CRITICAL VULNERABILITY: {cve}")
        elif severity == "High":
            print(f"🟠 HIGH VULNERABILITY: {cve}")
        elif severity == "Medium":
            print(f"🟡 MEDIUM VULNERABILITY: {cve}")
        else:
            print(f"🟢 LOW VULNERABILITY: {cve}")
            
        return result
    return wrapper

@vulnerability_check
def check_apache_vulnerability():
    return {
        "cve": "CVE-2023-1234",
        "product": "Apache HTTP Server",
        "severity": "Critical",
        "description": "Remote Code Execution"
    }

@vulnerability_check
def check_openssl_vulnerability():
    return {
        "cve": "CVE-2023-5678",
        "product": "OpenSSL",
        "severity": "High",
        "description": "Buffer Overflow"
    }

# Run vulnerability checks
check_apache_vulnerability()
check_openssl_vulnerability()

print()

# Example 2: Packet Analyzer with Generators
print("=== Packet Analyzer ===\n")

def packet_generator(pcap_file):
    """Generator to read packets from PCAP file"""
    import scapy.all as scapy
    
    packets = scapy.rdpcap(pcap_file)
    
    for i, packet in enumerate(packets):
        packet_info = {
            "index": i + 1,
            "timestamp": packet.time,
            "length": len(packet),
            "src_ip": None,
            "dst_ip": None,
            "src_port": None,
            "dst_port": None
        }
        
        if packet.haslayer(scapy.IP):
            packet_info["src_ip"] = packet[scapy.IP].src
            packet_info["dst_ip"] = packet[scapy.IP].dst
            
            if packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP):
                packet_info["src_port"] = packet.sport
                packet_info["dst_port"] = packet.dport
                
        yield packet_info

# Example usage (using dummy PCAP for testing)
try:
    import scapy.all as scapy
    test_pcap = "test_pcap.pcap"
    packets = []
    
    # Create dummy packets for testing
    for i in range(5):
        pkt = scapy.IP(src=f"192.168.1.{i+100}", dst=f"10.0.0.{i+1}")/scapy.TCP(sport=1024+i, dport=80+i)/b"Test Data"
        packets.append(pkt)
        
    scapy.wrpcap(test_pcap, packets)
    
    print("PCAP file generated:", test_pcap)
    
    for packet in packet_generator(test_pcap):
        print(f"Packet {packet['index']}:")
        print(f"  Time: {packet['timestamp']:.2f}")
        print(f"  Length: {packet['length']} bytes")
        print(f"  Source: {packet['src_ip']}:{packet['src_port']}")
        print(f"  Destination: {packet['dst_ip']}:{packet['dst_port']}")
        print()
        
except Exception as e:
    print(f"Error with scapy: {e}")

print()

# Example 3: Network Scanner with Threading
print("=== Network Scanner ===\n")

from concurrent.futures import ThreadPoolExecutor

def threaded_scan(ip, ports, threads=10):
    """Scan multiple ports using threading"""
    open_ports = []
    
    def scan_single_port(port):
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        try:
            sock.connect((ip, port))
            open_ports.append(port)
        except:
            pass
        finally:
            sock.close()
            
    with ThreadPoolExecutor(max_workers=threads) as executor:
        executor.map(scan_single_port, ports)
        
    return sorted(open_ports)

# Test the scanner
target_ip = "127.0.0.1"
port_range = range(1, 101)
open_ports = threaded_scan(target_ip, port_range)

print(f"Open ports on {target_ip}: {open_ports}")

print()

# Example 4: Configuration Management
print("=== Configuration Management ===\n")

import json

def config_manager(config_file):
    """Context manager for configuration file handling"""
    class ConfigManager:
        def __init__(self, filename):
            self.filename = filename
            self.config = {}
            
        def __enter__(self):
            try:
                with open(self.filename, 'r') as f:
                    self.config = json.load(f)
            except FileNotFoundError:
                print(f"Config file {self.filename} not found, creating new configuration")
                
            return self
            
        def __exit__(self, exc_type, exc_val, exc_tb):
            with open(self.filename, 'w') as f:
                json.dump(self.config, f, indent=2)
                
            if exc_type:
                print(f"Error: {exc_val}")
                
        def get(self, key, default=None):
            return self.config.get(key, default)
            
        def set(self, key, value):
            self.config[key] = value
            
        def update(self, data):
            self.config.update(data)
            
    return ConfigManager(config_file)

# Usage
try:
    with config_manager('scan_config.json') as config:
        # Set configuration values
        config.set('target_ip', '192.168.1.0/24')
        config.set('scan_ports', [21, 22, 80, 443])
        config.set('timeout', 1.0)
        config.set('threads', 50)
        
        # Get configuration values
        target = config.get('target_ip', '10.0.0.0/8')
        ports = config.get('scan_ports', [80])
        
        print("Current configuration:")
        print(f"  Target: {target}")
        print(f"  Ports: {ports}")
        print(f"  Timeout: {config.get('timeout')}")
        print(f"  Threads: {config.get('threads')}")
        
except Exception as e:
    print(f"Error: {e}")
