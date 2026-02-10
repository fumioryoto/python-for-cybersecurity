#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Python Tuples for Cybersecurity
This script demonstrates Python tuples with cybersecurity examples.
"""

# ==========================================
# 1. Creating Tuples
# ==========================================
print("=== Creating Tuples ===\n")

# Basic tuple creation
ip_port = ("192.168.1.1", 80)
print(f"IP-Port tuple: {ip_port}")

# Tuple with single element
single_ip = ("10.0.0.5",)
print(f"Single IP tuple: {single_ip}")

# Empty tuple
empty_tuple = ()
print(f"Empty tuple: {empty_tuple}")

# Tuple from list
port_list = [22, 21, 53]
port_tuple = tuple(port_list)
print(f"Tuple from list: {port_tuple}")

# Packed tuple (multiple values without parentheses)
network_packet = "TCP", "192.168.1.100", "10.0.0.5", 1024
print(f"Packed packet tuple: {network_packet}")

print()

# ==========================================
# 2. Accessing Tuple Elements
# ==========================================
print("=== Accessing Tuple Elements ===\n")

# Indexing
print(f"Source IP: {network_packet[1]}")
print(f"Destination IP: {network_packet[2]}")
print(f"Source port: {network_packet[3]}")

# Slicing
print(f"IP addresses: {network_packet[1:3]}")
print(f"Protocol and ports: {network_packet[0::3]}")

# Negative indexing
print(f"Last element: {network_packet[-1]}")

# Unpacking tuples
protocol, src_ip, dst_ip, src_port = network_packet
print(f"Unpacked values:")
print(f"  Protocol: {protocol}")
print(f"  Source IP: {src_ip}")
print(f"  Destination IP: {dst_ip}")
print(f"  Source port: {src_port}")

# Unpacking with *
packet_data = ("HTTP/1.1", 200, "OK", "text/html", 1024, "2023-10-10 13:45:22")
version, status_code, reason, content_type, content_length, timestamp = packet_data
print()
print(f"Packet details:")
print(f"  HTTP Version: {version}")
print(f"  Status: {status_code} {reason}")

print()

# ==========================================
# 3. Tuple Operations
# ==========================================
print("=== Tuple Operations ===\n")

# Concatenation
tuple1 = ("192.168.1.1", 80)
tuple2 = ("TCP", "open")
full_info = tuple1 + tuple2
print(f"Concatenated tuple: {full_info}")

# Repetition
port_range = (80, 443) * 3
print(f"Port range repeated: {port_range}")

# Length
print(f"Number of elements: {len(network_packet)}")

# Membership
print(f"TCP in packet: {'TCP' in network_packet}")
print(f"UDP in packet: {'UDP' in network_packet}")

# Count occurrences
print(f"80 count: {port_range.count(80)}")
print(f"443 count: {port_range.count(443)}")

# Find index
try:
    port_index = port_range.index(443)
    print(f"First 443 at index: {port_index}")
except ValueError:
    print("Port not found")

print()

# ==========================================
# 4. Tuple Immutability
# ==========================================
print("=== Tuple Immutability ===\n")

# Tuples are immutable - can't modify elements
try:
    network_packet[0] = "UDP"
except TypeError as e:
    print(f"Error modifying tuple: {e}")

# But elements can be mutable if they're objects like lists or dictionaries
complex_tuple = ("192.168.1.1", [80, 443, 22], {"status": "running"})
print(f"Complex tuple before: {complex_tuple}")

# Modify list inside tuple
complex_tuple[1].append(8080)
# Modify dictionary inside tuple
complex_tuple[2]["uptime"] = "24 days"
print(f"Complex tuple after modification: {complex_tuple}")

# Create new tuple by replacing elements
original = ("10.0.0.5", 22)
updated = ("10.0.0.5", 22, "open")
print(f"Updated tuple: {updated}")

print()

# ==========================================
# 5. Practical Examples for Cybersecurity
# ==========================================
print("=== Practical Examples ===\n")

# Example 1: Network Packet Capture
print("=== Network Packet Capture ===\n")

# Tuple is ideal for packet data that shouldn't change
captured_packets = [
    ("192.168.1.100", "10.0.0.5", 1024, 80, "TCP", 1460),
    ("10.0.0.5", "192.168.1.100", 80, 1024, "TCP", 1024),
    ("172.16.0.10", "8.8.8.8", 1025, 53, "UDP", 64),
    ("192.168.1.100", "10.0.0.5", 1026, 443, "TCP", 512)
]

print("Captured packets:")
for i, packet in enumerate(captured_packets, 1):
    src_ip, dst_ip, src_port, dst_port, protocol, size = packet
    print(f"  Packet {i}: {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({protocol}), {size} bytes")

print()

# Calculate statistics
total_bytes = sum(packet[5] for packet in captured_packets)
tcp_packets = [p for p in captured_packets if p[4] == "TCP"]
udp_packets = [p for p in captured_packets if p[4] == "UDP"]

print(f"Statistics:")
print(f"  Total packets: {len(captured_packets)}")
print(f"  Total bytes: {total_bytes}")
print(f"  TCP packets: {len(tcp_packets)}")
print(f"  UDP packets: {len(udp_packets)}")
print()

# Example 2: Network Configuration
print("=== Network Configuration ===\n")

interface_configs = [
    ("eth0", "192.168.1.100", "255.255.255.0", "192.168.1.1"),
    ("wlan0", "10.0.0.5", "255.255.0.0", "10.0.0.1"),
    ("lo", "127.0.0.1", "255.0.0.0", None)
]

print("Network interface configurations:")
for iface, ip, netmask, gateway in interface_configs:
    print(f"  {iface}:")
    print(f"    IP: {ip}")
    print(f"    Netmask: {netmask}")
    if gateway:
        print(f"    Gateway: {gateway}")
    print()

# Find interface with specific IP
target_ip = "10.0.0.5"
for config in interface_configs:
    if config[1] == target_ip:
        print(f"Found interface with IP {target_ip}: {config[0]}")
        break

print()

# Example 3: Firewall Rules
print("=== Firewall Rules ===\n")

firewall_rules = [
    ("allow", "192.168.1.0/24", "any", 80, "TCP"),
    ("deny", "any", "192.168.1.0/24", 22, "TCP"),
    ("allow", "10.0.0.0/16", "172.16.0.0/12", 443, "TCP"),
    ("deny", "any", "any", 53, "UDP"),
    ("allow", "127.0.0.0/8", "any", "any", "any")
]

print("Firewall rules:")
for i, rule in enumerate(firewall_rules, 1):
    action, src, dst, port, protocol = rule
    print(f"Rule {i}: {action.upper()} {src} -> {dst}:{port} ({protocol})")

print()

# Count allow/deny rules
allow_rules = len([r for r in firewall_rules if r[0] == "allow"])
deny_rules = len([r for r in firewall_rules if r[0] == "deny"])
print(f"Rule counts: Allow={allow_rules}, Deny={deny_rules}")

print()

# Example 4: Vulnerability Tracking
print("=== Vulnerability Tracking ===\n")

vulnerabilities = [
    ("CVE-2023-1234", "Apache HTTP Server", "9.8", "Critical", "2023-06-15"),
    ("CVE-2023-5678", "OpenSSL", "7.5", "High", "2023-08-22"),
    ("CVE-2023-9012", "Windows SMB", "8.8", "High", "2023-10-01"),
    ("CVE-2023-3456", "Python", "5.3", "Medium", "2023-04-10")
]

print("Vulnerability report:")
print(f"{'CVE ID':<15} {'Product':<20} {'CVSS':<5} {'Severity':<10} {'Published'}")
print("-" * 75)
for cve, product, cvss, severity, published in vulnerabilities:
    print(f"{cve:<15} {product:<20} {cvss:<5} {severity:<10} {published}")

print()

# Find critical vulnerabilities
critical_vulns = [v for v in vulnerabilities if v[3] == "Critical"]
print(f"Critical vulnerabilities: {len(critical_vulns)}")
for vuln in critical_vulns:
    print(f"  {vuln[0]} - {vuln[1]} ({vuln[2]})")

# Calculate average CVSS score
avg_cvss = sum(float(v[2]) for v in vulnerabilities) / len(vulnerabilities)
print(f"Average CVSS score: {avg_cvss:.2f}")

print()

# Example 5: Hash Calculation
print("=== Hash Calculation ===\n")

import hashlib

file_hashes = [
    ("document.pdf", "5d41402abc4b2a76b9719d911017c592"),
    ("image.png", "d41d8cd98f00b204e9800998ecf8427e"),
    ("executable.exe", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85"),
    ("script.py", "a1b2c3d4e5f678901234567890abcdef")
]

# Verify file integrity
def verify_hash(file_path, expected_hash):
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
            md5_hash = hashlib.md5(content).hexdigest()
            return md5_hash == expected_hash
    except FileNotFoundError:
        return False

# Test hash verification (using dummy data for demo)
for filename, expected_hash in file_hashes:
    # Create dummy files for testing
    with open(filename, 'w') as f:
        f.write(f"Dummy content for {filename}")
        
    is_valid = verify_hash(filename, expected_hash)
    status = "✅" if is_valid else "❌"
    print(f"{status} {filename}: Hash {expected_hash[:8]}... {'valid' if is_valid else 'invalid'}")

# Clean up test files
import os
for filename, _ in file_hashes:
    if os.path.exists(filename):
        os.remove(filename)

print()

# Example 6: Malware Analysis
print("=== Malware Analysis ===\n")

malware_signatures = [
    ("Trojan.Ransom.WannaCry", "WannaCry", "WanaDecryptor", "ransomnote.txt"),
    ("Trojan.Dropper.Emotet", "Emotet", "payload.bin", "config.dat"),
    ("Ransomware.LockBit", "LockBit", "README.txt", "restore.exe"),
    ("Worm.Stuxnet", "Stuxnet", "mrxcls.sys", "mrxnet.sys")
]

# Analyze file strings against malware signatures
def analyze_file_strings(file_strings):
    matches = []
    for signature in malware_signatures:
        malware_name = signature[0]
        malware_strings = signature[1:]
        
        # Count how many signature strings match
        match_count = sum(1 for s in malware_strings if s in file_strings)
        if match_count > 0:
            matches.append((malware_name, match_count, len(malware_strings)))
            
    return sorted(matches, key=lambda x: x[1], reverse=True)

# Simulate file string extraction
test_file1_strings = ["WannaCry", "ransom", "WanaDecryptor", "aes", "encrypt"]
test_file2_strings = ["Emotet", "payload.bin", "http", "connect"]

print("Analyzing test file 1:")
matches1 = analyze_file_strings(test_file1_strings)
for malware, matches, total in matches1:
    print(f"  {malware}: {matches}/{total} signatures match")

print()
print("Analyzing test file 2:")
matches2 = analyze_file_strings(test_file2_strings)
for malware, matches, total in matches2:
    print(f"  {malware}: {matches}/{total} signatures match")

print()

# Example 7: Security Event Logging
print("=== Security Event Logging ===\n")

import datetime

security_events = [
    ("2023-10-10 13:45:22", "LOGIN_FAILURE", "192.168.1.100", "admin"),
    ("2023-10-10 13:46:15", "PORT_SCAN", "10.0.0.5", "80,443,22"),
    ("2023-10-10 13:47:30", "FIREWALL_BLOCK", "203.0.113.7", "8080"),
    ("2023-10-10 13:48:45", "LOGIN_SUCCESS", "192.168.1.100", "john"),
    ("2023-10-10 13:49:20", "PORT_SCAN", "172.16.0.10", "21,22,23")
]

# Find login-related events
login_events = [e for e in security_events if "LOGIN" in e[1]]
print(f"Login events: {len(login_events)}")
for event in login_events:
    print(f"  {event[0]} - {event[1]}: {event[2]} ({event[3]})")

print()

# Count events by type
event_counts = {}
for event in security_events:
    event_type = event[1]
    event_counts[event_type] = event_counts.get(event_type, 0) + 1

print("Event type counts:")
for event_type, count in event_counts.items():
    print(f"  {event_type}: {count}")
