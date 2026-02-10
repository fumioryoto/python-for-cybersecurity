#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Variables and Data Types in Python - BEGINNER FRIENDLY
This script demonstrates Python's basic data types and variable usage
with cybersecurity-relevant examples. Each concept is explained in
simple terms so beginners can understand.
"""

# ========================================================================
# 1. Variables and Basic Data Types - THE BUILDING BLOCKS!
# ========================================================================
# Imagine variables as containers that hold information. Python has 4 main
# basic data types that you'll use ALL THE TIME in cybersecurity!
print("=== Variables and Basic Data Types ===\n")

# ------------------------------------------------------------------------
# INTEGERS - Whole numbers without decimals
# ------------------------------------------------------------------------
# Integers are used for:
# - Port numbers (like 80 for HTTP, 443 for HTTPS)
# - Counts of packets, connections, or vulnerabilities
# - IP address octets (192, 168, 1, 1)
# - File sizes and offsets

port_number = 80  # HTTP port (this is an integer variable)
print(f"Port number (int): {port_number}")
print(f"Type: {type(port_number)}")  # Shows it's an integer
print()

# ------------------------------------------------------------------------
# FLOATS - Numbers with decimal points
# ------------------------------------------------------------------------
# Floats are used for:
# - Packet loss percentages (5% = 0.05)
# - Network speeds in Mbps/Gbps
# - Version numbers (Python 3.10)
# - Time delays

packet_loss = 0.05  # 5% packet loss (this is a float variable)
print(f"Packet loss (float): {packet_loss}")
print(f"Type: {type(packet_loss)}")  # Shows it's a float
print()

# ------------------------------------------------------------------------
# STRINGS - Text and character data
# ------------------------------------------------------------------------
# Strings are used for:
# - IP addresses ("192.168.1.1")
# - Domain names ("example.com")
# - URLs ("https://malicious-site.com")
# - File paths ("/var/logs/access.log")
# - Command outputs

ip_address = "192.168.1.1"  # IPv4 address (this is a string)
domain = "example.com"      # Domain name (also a string)
print(f"IP Address (str): {ip_address}")
print(f"Domain (str): {domain}")
print(f"Type: {type(ip_address)}")  # Shows it's a string
print()

# ------------------------------------------------------------------------
# BOOLEANS - True/False values (YES/NO flags)
# ------------------------------------------------------------------------
# Booleans are used for:
# - Checking if a connection is established
# - Verifying if a system is vulnerable
# - Determining if a file exists
# - Flagging suspicious activity

connection_established = True  # Connection is active
vulnerable = False             # System is NOT vulnerable
print(f"Connection established (bool): {connection_established}")
print(f"Vulnerable (bool): {vulnerable}")
print(f"Type: {type(connection_established)}")  # Shows it's a boolean
print()

# ========================================================================
# 2. Type Conversion (Casting) - CHANGING ONE TYPE TO ANOTHER!
# ========================================================================
# Often, you need to convert one type to another. For example, when you
# want to combine a number (port 80) with text ("Port: 80").
print("=== Type Conversion ===\n")

# Convert integer to string (common when constructing messages/commands)
port_str = str(port_number)  # Converts 80 (integer) to "80" (string)
print(f"Port as string: '{port_str}'")
print(f"Type: {type(port_str)}")  # Now it's a string!
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
