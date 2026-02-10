#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Python Lists for Cybersecurity
This script demonstrates Python lists with cybersecurity examples.
"""

# ==========================================
# 1. Creating Lists
# ==========================================
print("=== Creating Lists ===\n")

# Basic list creation
target_ips = ["192.168.1.1", "10.0.0.5", "172.16.0.10"]
print(f"Target IPs list: {target_ips}")

# List of ports (common for scanning)
common_ports = [80, 443, 22, 21, 25, 53]
print(f"Common ports list: {common_ports}")

# Empty list for dynamic data
open_ports = []
print(f"Open ports (empty): {open_ports}")

# List with mixed data types (common in packet analysis)
packet_info = ["TCP", 80, "192.168.1.1", "10.0.0.5", 1024]
print(f"Packet info (mixed types): {packet_info}")

print()

# ==========================================
# 2. Accessing List Elements
# ==========================================
print("=== Accessing List Elements ===\n")

print(f"First target IP: {target_ips[0]}")
print(f"Second target IP: {target_ips[1]}")
print(f"Last common port: {common_ports[-1]}")
print(f"Port range (first 3): {common_ports[0:3]}")

# Slice from index 2 to end
print(f"Ports from index 2: {common_ports[2:]}")

# Reverse list
print(f"Common ports reversed: {common_ports[::-1]}")

print()

# ==========================================
# 3. Modifying Lists
# ==========================================
print("=== Modifying Lists ===\n")

# Add elements
target_ips.append("192.168.1.254")  # Add single element
print(f"After appending gateway: {target_ips}")

target_ips.extend(["10.0.0.6", "10.0.0.7"])  # Add multiple elements
print(f"After extending with more IPs: {target_ips}")

# Insert at specific position
common_ports.insert(1, 443)  # Insert 443 at index 1
print(f"After inserting HTTPS port: {common_ports}")

# Remove elements
common_ports.remove(443)  # Remove by value
print(f"After removing 443: {common_ports}")

last_ip = target_ips.pop()  # Remove and return last element
print(f"Removed IP: {last_ip}")

del target_ips[2]  # Delete by index
print(f"After deleting index 2: {target_ips}")

print()

# ==========================================
# 4. List Operations
# ==========================================
print("=== List Operations ===\n")

# Concatenation
all_ips = target_ips + ["172.16.0.11", "172.16.0.12"]
print(f"All IPs combined: {all_ips}")

# Repetition
port_range = [8080] * 5
print(f"Port range: {port_range}")

# Length
print(f"Number of targets: {len(target_ips)}")
print(f"Number of common ports: {len(common_ports)}")

# Membership checks (fast for lists)
print(f"80 in common ports: {80 in common_ports}")
print(f"23 in common ports: {23 in common_ports}")

# Count occurrences
test_list = [80, 443, 80, 22, 80]
print(f"Port 80 count: {test_list.count(80)}")

print()

# ==========================================
# 5. List Methods
# ==========================================
print("=== List Methods ===\n")

# Sorting
print(f"Original ports: {common_ports}")
common_ports.sort()
print(f"Sorted ports: {common_ports}")

common_ports.sort(reverse=True)
print(f"Reverse sorted: {common_ports}")

# Sorting custom objects (e.g., packets with timestamps)
packets = [
    {"time": 1001, "src": "192.168.1.1", "dst": "10.0.0.5"},
    {"time": 998, "src": "10.0.0.5", "dst": "192.168.1.1"},
    {"time": 1005, "src": "172.16.0.10", "dst": "10.0.0.5"}
]
packets_sorted = sorted(packets, key=lambda x: x["time"])
print("Packets sorted by time:")
for pkt in packets_sorted:
    print(f"  {pkt}")

# Reversing
common_ports.reverse()
print(f"Reversed list: {common_ports}")

# Finding elements
http_port = 80
if http_port in common_ports:
    print(f"HTTP port position: {common_ports.index(http_port)}")

# Copying lists
common_ports_copy = common_ports.copy()
print(f"Copy of common ports: {common_ports_copy}")

print()

# ==========================================
# 6. List Comprehensions
# ==========================================
print("=== List Comprehensions ===\n")

# Simple list comprehension
ipv4_octets = [octet for octet in range(256)]
print(f"First 5 IPv4 octets: {ipv4_octets[:5]}")

# Comprehension with condition
well_known_ports = [port for port in range(1024)]
print(f"Total well-known ports: {len(well_known_ports)}")

# Complex comprehension
scanned_ports = [80, 443, 22, 21, 25, 53, 110, 143]
open_ports = [port for port in scanned_ports if port % 2 == 0]  # Even open ports
print(f"Open even ports: {open_ports}")

# Nested comprehension (represent network ranges)
network_10 = [f"10.0.{subnet}.{host}" 
             for subnet in range(256) 
             for host in range(256)]
print(f"First 5 addresses in 10.0.0.0/16: {network_10[:5]}")

print()

# ==========================================
# 7. Working with Binary Data
# ==========================================
print("=== Working with Binary Data ===\n")

# List of bytes (network packet payload)
raw_packet = [0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00]
print(f"Raw packet data: {raw_packet}")

# Convert to bytes object
packet_bytes = bytes(raw_packet)
print(f"Packet bytes: {packet_bytes}")

# Convert to hex string
hex_str = ''.join(f"{byte:02x}" for byte in raw_packet)
print(f"Hex string: {hex_str}")

# Binary representation
binary_str = ''.join(f"{byte:08b}" for byte in raw_packet)
print(f"Binary string: {binary_str[:32]}...")

print()

# ==========================================
# 8. Practical Examples for Cybersecurity
# ==========================================
print("=== Practical Examples ===\n")

# Example 1: Network Range Generator
def generate_ip_range(start_ip, end_ip):
    """Generate all IP addresses in a range"""
    def ip_to_int(ip):
        octets = list(map(int, ip.split('.')))
        return octets[0] << 24 | octets[1] << 16 | octets[2] << 8 | octets[3]
    
    def int_to_ip(ip_int):
        return f"{(ip_int >> 24) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 8) & 0xFF}.{ip_int & 0xFF}"
    
    start = ip_to_int(start_ip)
    end = ip_to_int(end_ip)
    
    return [int_to_ip(i) for i in range(start, end + 1)]

# Generate IP range
ip_range = generate_ip_range("192.168.1.100", "192.168.1.105")
print("IP Range Generation:")
for ip in ip_range:
    print(f"  {ip}")

print()

# Example 2: Packet Filtering
print("=== Packet Filtering ===\n")
network_traffic = [
    {"src": "192.168.1.1", "dst": "10.0.0.5", "port": 80, "type": "TCP"},
    {"src": "10.0.0.5", "dst": "192.168.1.1", "port": 443, "type": "TCP"},
    {"src": "172.16.0.10", "dst": "10.0.0.5", "port": 53, "type": "UDP"},
    {"src": "192.168.1.1", "dst": "10.0.0.5", "port": 22, "type": "TCP"},
    {"src": "10.0.0.6", "dst": "10.0.0.5", "port": 8080, "type": "TCP"},
    {"src": "192.168.1.1", "dst": "10.0.0.5", "port": 443, "type": "TCP"}
]

# Filter HTTP packets
http_packets = [pkt for pkt in network_traffic 
                if pkt["port"] == 80 and pkt["type"] == "TCP"]
print(f"HTTP packets found: {len(http_packets)}")
for pkt in http_packets:
    print(f"  {pkt['src']} -> {pkt['dst']}:{pkt['port']}")

print()

# Filter unique source IPs with port 443
https_src_ips = list(set([pkt["src"] for pkt in network_traffic 
                          if pkt["port"] == 443]))
print(f"Unique HTTPS source IPs: {https_src_ips}")

print()

# Example 3: Vulnerability Scanner Results
print("=== Vulnerability Scanner Results ===\n")
vulnerability_results = [
    {"ip": "192.168.1.1", "port": 80, "cve": "CVE-2023-1234", "severity": "high"},
    {"ip": "10.0.0.5", "port": 443, "cve": "CVE-2023-5678", "severity": "critical"},
    {"ip": "192.168.1.1", "port": 22, "cve": "CVE-2023-9012", "severity": "medium"},
    {"ip": "172.16.0.10", "port": 3389, "cve": "CVE-2023-3456", "severity": "high"}
]

# Find critical vulnerabilities
critical_vulns = [vuln for vuln in vulnerability_results 
                  if vuln["severity"] == "critical"]
print(f"Critical vulnerabilities: {len(critical_vulns)}")
for vuln in critical_vulns:
    print(f"  {vuln['ip']}:{vuln['port']} - {vuln['cve']}")

print()

# Group vulnerabilities by IP
vulns_by_ip = {}
for vuln in vulnerability_results:
    ip = vuln["ip"]
    if ip not in vulns_by_ip:
        vulns_by_ip[ip] = []
    vulns_by_ip[ip].append(vuln)

print("Vulnerabilities by IP:")
for ip, vulns in vulns_by_ip.items():
    print(f"  {ip}: {len(vulns)} vulnerabilities")
    for vuln in vulns:
        print(f"    - Port {vuln['port']}: {vuln['cve']} ({vuln['severity']})")

print()

# Example 4: Log Analysis
print("=== Log File Analysis ===\n")
log_entries = [
    "192.168.1.100 - - [10/Oct/2023:13:55:36 +0000] \"GET / HTTP/1.1\" 200 1024",
    "10.0.0.5 - - [10/Oct/2023:13:56:01 +0000] \"POST /login HTTP/1.1\" 401 200",
    "172.16.0.15 - - [10/Oct/2023:13:57:12 +0000] \"GET /admin HTTP/1.1\" 403 150",
    "192.168.1.100 - - [10/Oct/2023:13:58:45 +0000] \"GET /api/users HTTP/1.1\" 200 5000",
    "203.0.113.7 - - [10/Oct/2023:13:59:20 +0000] \"GET /etc/passwd HTTP/1.1\" 404 100"
]

# Extract source IP addresses
source_ips = [entry.split()[0] for entry in log_entries]
print(f"Source IPs from logs: {source_ips}")

# Count occurrences of each IP
ip_counts = {}
for ip in source_ips:
    ip_counts[ip] = ip_counts.get(ip, 0) + 1

print("IP occurrence counts:")
for ip, count in ip_counts.items():
    print(f"  {ip}: {count} requests")
