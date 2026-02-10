#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Variables and Data Types in Python
This script demonstrates Python's basic data types and variable usage
with cybersecurity-relevant examples.
"""

# ==========================================
# 1. Variables and Basic Data Types
# ==========================================
print("=== Variables and Basic Data Types ===\n")

# Integer - Whole numbers (used for port numbers, counts, etc.)
port_number = 80  # HTTP port
print(f"Port number (int): {port_number}")
print(f"Type: {type(port_number)}")
print()

# Float - Decimal numbers (used for measurements, calculations)
packet_loss = 0.05  # 5% packet loss
print(f"Packet loss (float): {packet_loss}")
print(f"Type: {type(packet_loss)}")
print()

# String - Text data (used for IP addresses, domain names, filenames)
ip_address = "192.168.1.1"  # IPv4 address
domain = "example.com"
print(f"IP Address (str): {ip_address}")
print(f"Domain (str): {domain}")
print(f"Type: {type(ip_address)}")
print()

# Boolean - True/False values (used for flags, conditions)
connection_established = True
vulnerable = False
print(f"Connection established (bool): {connection_established}")
print(f"Vulnerable (bool): {vulnerable}")
print(f"Type: {type(connection_established)}")
print()

# ==========================================
# 2. Type Conversion (Casting)
# ==========================================
print("=== Type Conversion ===\n")

# Convert integer to string (common when constructing commands)
port_str = str(port_number)
print(f"Port as string: '{port_str}'")
print(f"Type: {type(port_str)}")
print()

# Convert string to integer (when reading from configuration files)
port_from_config = "443"
port_int = int(port_from_config)
print(f"Port from config: {port_int}")
print(f"Type: {type(port_int)}")
print()

# Convert string to float
time_str = "1.5"
time_float = float(time_str)
print(f"Time as float: {time_float}")
print(f"Type: {type(time_float)}")
print()

# ==========================================
# 3. String Operations
# ==========================================
print("=== String Operations ===\n")

# Concatenation - combining strings
full_url = "https://" + domain + ":" + str(port_number)
print(f"Full URL: {full_url}")
print()

# String interpolation (f-strings - Python 3.6+)
full_url_formatted = f"https://{domain}:{port_number}"
print(f"Formatted URL: {full_url_formatted}")
print()

# String methods
print(f"Domain uppercase: {domain.upper()}")
print(f"IP address split: {ip_address.split('.')}")
print(f"Check if domain contains 'example': {'example' in domain}")
print(f"Count of '.' in IP: {ip_address.count('.')}")
print()

# ==========================================
# 4. Useful String Escaping
# ==========================================
print("=== String Escaping ===\n")

# Backslash for special characters
log_message = "Connection failed: Error \\x10"
print(f"Log message with hex: {log_message}")
print()

# Raw strings (useful for regex patterns)
regex_pattern = r"\d+\.\d+\.\d+\.\d+"
print(f"Raw string for regex: {regex_pattern}")
print()

# Multiline strings
http_response = """HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 1024
"""
print(f"Multiline HTTP response:\n{http_response}")
print()

# ==========================================
# 5. Constants (by convention)
# ==========================================
print("=== Constants ===\n")

# In Python, constants are usually uppercase (by convention)
MAX_PORT = 65535
MIN_PORT = 1
WELL_KNOWN_PORTS = range(1, 1024)

print(f"Max port value: {MAX_PORT}")
print(f"Min port value: {MIN_PORT}")
print()

# ==========================================
# 6. Practical Examples for Cybersecurity
# ==========================================
print("=== Practical Examples ===\n")

# Example: Validating IP address format
def is_valid_ip(ip):
    parts = ip.split('.')
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

test_ips = ["192.168.1.1", "256.0.0.1", "10.0.0", "172.16.0.abc"]
for ip in test_ips:
    print(f"IP {ip} is valid: {is_valid_ip(ip)}")

print()

# Example: Checking if port is well-known
def is_well_known_port(port):
    return port in WELL_KNOWN_PORTS

test_ports = [80, 443, 8080, 1024, 0, 65535]
for port in test_ports:
    print(f"Port {port} is well-known: {is_well_known_port(port)}")
