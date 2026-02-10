#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Python Operators for Cybersecurity
This script demonstrates Python operators with cybersecurity examples.
"""

# ==========================================
# 1. Arithmetic Operators
# ==========================================
print("=== Arithmetic Operators ===\n")

# Addition
port1 = 80
port2 = 443
total_ports = port1 + port2
print(f"Total ports: {total_ports}")
print()

# Subtraction
total_bytes = 1024
used_bytes = 512
remaining_bytes = total_bytes - used_bytes
print(f"Remaining bytes: {remaining_bytes}")
print()

# Multiplication
packets_per_second = 1000
duration_seconds = 60
total_packets = packets_per_second * duration_seconds
print(f"Total packets in 60 seconds: {total_packets}")
print()

# Division (float)
total_traffic = 1024  # KB
time_minutes = 5
traffic_per_minute = total_traffic / time_minutes
print(f"Traffic per minute: {traffic_per_minute} KB")
print()

# Floor Division (integer)
filesize_bytes = 1500
block_size = 512
num_blocks = filesize_bytes // block_size
print(f"Number of 512-byte blocks: {num_blocks}")
print()

# Modulus (remainder)
remaining_bytes = filesize_bytes % block_size
print(f"Remaining bytes in last block: {remaining_bytes}")
print()

# Exponentiation
port_range = 2 ** 16  # 65536 possible TCP/UDP ports
print(f"Total TCP/UDP ports: {port_range}")
print()

# ==========================================
# 2. Comparison Operators
# ==========================================
print("=== Comparison Operators ===\n")

# Equality check
current_port = 80
http_port = 80
print(f"Is port 80 HTTP? {current_port == http_port}")
print()

# Inequality check
https_port = 443
print(f"Is port 80 HTTPS? {current_port != https_port}")
print()

# Greater/Less than
packet_count = 1001
threshold = 1000
print(f"Packet count {packet_count} exceeds {threshold}: {packet_count > threshold}")
print()

# Combined comparisons (chaining)
port = 8080
print(f"Port {port} is between 1024 and 65535: {1024 < port < 65535}")
print()

# ==========================================
# 3. Logical Operators
# ==========================================
print("=== Logical Operators ===\n")

# AND - both conditions must be true
port = 80
ip_valid = True
port_open = True
can_connect = ip_valid and port_open
print(f"Can connect to port {port}? {can_connect}")
print()

# OR - at least one condition must be true
firewall_enabled = False
intrusion_detected = True
alert_required = firewall_enabled or intrusion_detected
print(f"Alert required? {alert_required}")
print()

# NOT - negates the condition
is_vulnerable = False
print(f"System is secure? {not is_vulnerable}")
print()

# Complex conditions
port = 22
is_ssh_port = port == 22
is_open = True
is_secure = is_ssh_port and is_open
print(f"SSH port status: {is_secure}")
print()

# ==========================================
# 4. Bitwise Operators (Important for Exploits)
# ==========================================
print("=== Bitwise Operators ===\n")

# AND (&) - bitwise AND
# Used for checking flags and masking
# Example: Check if SYN flag is set in TCP header (bit 1)
tcp_flags = 0b00000010  # SYN flag set
syn_flag = 0b00000010
has_syn = tcp_flags & syn_flag != 0
print(f"SYN flag set: {has_syn}")
print()

# OR (|) - bitwise OR
# Used for setting flags
# Example: Set SYN and ACK flags
syn_ack_flags = 0b00000010 | 0b00000100
print(f"SYN+ACK flags: 0b{bin(syn_ack_flags)[2:].zfill(8)}")
print()

# NOT (~) - bitwise NOT (complement)
# Example: Complement of a byte
byte_value = 0b01010101
complement = ~byte_value
print(f"Byte: 0b{bin(byte_value)[2:].zfill(8)}")
print(f"Complement: 0b{bin(complement & 0xFF)[2:].zfill(8)}")
print()

# XOR (^) - bitwise XOR
# Used for simple encryption and checksum validation
# Example: Simple XOR encryption
plaintext = 0b10101010
key = 0b11001100
encrypted = plaintext ^ key
decrypted = encrypted ^ key
print(f"Plaintext: 0b{bin(plaintext)[2:]}")
print(f"Encrypted: 0b{bin(encrypted)[2:]}")
print(f"Decrypted: 0b{bin(decrypted)[2:]}")
print()

# Left Shift (<<) - multiply by 2^n
ip_octet = 192
shifted = ip_octet << 24
print(f"IP octet 192 shifted left 24 bits: 0x{hex(shifted)[2:]}")
print()

# Right Shift (>>) - divide by 2^n
long_value = 0x10000000
shifted_right = long_value >> 24
print(f"0x10000000 shifted right 24 bits: {shifted_right}")
print()

# ==========================================
# 5. Assignment Operators
# ==========================================
print("=== Assignment Operators ===\n")

# Basic assignment
packet_count = 100
print(f"Initial packet count: {packet_count}")
print()

# += operator
packet_count += 50  # Same as packet_count = packet_count + 50
print(f"After adding 50: {packet_count}")
print()

# -= operator
packet_count -= 25  # Same as packet_count = packet_count - 25
print(f"After subtracting 25: {packet_count}")
print()

# *= operator
packet_count *= 2  # Same as packet_count = packet_count * 2
print(f"After doubling: {packet_count}")
print()

# /= operator
packet_count /= 3  # Same as packet_count = packet_count / 3
print(f"After dividing by 3: {packet_count}")
print()

# &= operator
tcp_flags = 0b00000010
tcp_flags &= 0b11111110  # Clear last bit
print(f"TCP flags after clearing last bit: 0b{bin(tcp_flags)[2:].zfill(8)}")
print()

# | operator
tcp_flags = 0b00000000
tcp_flags |= 0b00000010  # Set SYN flag
print(f"TCP flags after setting SYN: 0b{bin(tcp_flags)[2:].zfill(8)}")
print()

# ==========================================
# 6. Membership Operators
# ==========================================
print("=== Membership Operators ===\n")

# 'in' operator - check if value exists in sequence
well_known_ports = [80, 443, 22, 21, 25]
port_to_check = 443
print(f"Port {port_to_check} in well-known ports: {port_to_check in well_known_ports}")
print()

# Check if domain contains substring
domain = "example.com"
print(f"Domain contains 'example': {'example' in domain}")
print(f"Domain contains '.gov': {'.gov' in domain}")
print()

# 'not in' operator
forbidden_ips = ["10.0.0.1", "192.168.1.100"]
client_ip = "172.16.0.5"
print(f"IP {client_ip} is forbidden: {client_ip in forbidden_ips}")
print(f"IP {client_ip} is allowed: {client_ip not in forbidden_ips}")
print()

# ==========================================
# 7. Identity Operators
# ==========================================
print("=== Identity Operators ===\n")

# 'is' operator - checks if two variables reference the same object
ip1 = "192.168.1.1"
ip2 = "192.168.1.1"
ip3 = ip1

print(f"ip1 is ip2: {ip1 is ip2}")
print(f"ip1 is ip3: {ip1 is ip3}")
print()

# 'is not' operator
print(f"ip1 is not ip2: {ip1 is not ip2}")
print()

# ==========================================
# 8. Operator Precedence
# ==========================================
print("=== Operator Precedence ===\n")

# Expressions are evaluated based on precedence
# Parentheses override precedence

# Without parentheses
result1 = 10 + 5 * 3
print(f"10 + 5 * 3 = {result1}")
print()

# With parentheses
result2 = (10 + 5) * 3
print(f"(10 + 5) * 3 = {result2}")
print()

# Complex security example: Calculate network address from IP and mask
ip = "192.168.1.100"
subnet_mask = "255.255.255.0"

def ip_to_int(ip_str):
    """Convert IP address string to integer for calculations"""
    parts = list(map(int, ip_str.split('.')))
    return parts[0] << 24 | parts[1] << 16 | parts[2] << 8 | parts[3]

def int_to_ip(ip_int):
    """Convert integer to IP address string"""
    octet1 = (ip_int >> 24) & 0xFF
    octet2 = (ip_int >> 16) & 0xFF
    octet3 = (ip_int >> 8) & 0xFF
    octet4 = ip_int & 0xFF
    return f"{octet1}.{octet2}.{octet3}.{octet4}"

ip_int = ip_to_int(ip)
mask_int = ip_to_int(subnet_mask)
network_int = ip_int & mask_int
network_address = int_to_ip(network_int)

print(f"IP Address: {ip}")
print(f"Subnet Mask: {subnet_mask}")
print(f"Network Address: {network_address}")
