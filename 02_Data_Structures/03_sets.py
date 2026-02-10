#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Python Sets for Cybersecurity
This script demonstrates Python sets with cybersecurity examples.
"""

# ==========================================
# 1. Creating Sets
# ==========================================
print("=== Creating Sets ===\n")

# Basic set creation
unique_ips = {"192.168.1.1", "10.0.0.5", "172.16.0.10"}
print(f"Unique IP addresses: {unique_ips}")

# Empty set
blocked_ips = set()
print(f"Empty blocked IPs set: {blocked_ips}")

# Convert list to set (remove duplicates)
ip_list = ["192.168.1.1", "10.0.0.5", "192.168.1.1", "172.16.0.10", "10.0.0.5"]
unique_ip_set = set(ip_list)
print(f"Unique IPs from list: {unique_ip_set}")

# Set with numbers
common_ports = {80, 443, 22, 21, 53}
print(f"Common ports: {common_ports}")

# Set comprehension
filtered_ports = {port for port in range(1, 1024) if port % 100 == 0}
print(f"Every 100th port: {filtered_ports}")

print()

# ==========================================
# 2. Set Operations
# ==========================================
print("=== Set Operations ===\n")

# Union - all elements from both sets
blocked_ips1 = {"192.168.1.100", "10.0.0.5", "172.16.0.10"}
blocked_ips2 = {"192.168.1.100", "10.0.0.6", "172.16.0.11"}
all_blocked = blocked_ips1.union(blocked_ips2)
print(f"All blocked IPs: {all_blocked}")

# Intersection - elements common to both sets
common_blocked = blocked_ips1.intersection(blocked_ips2)
print(f"Common blocked IPs: {common_blocked}")

# Difference - elements in first set not in second
only_in_first = blocked_ips1.difference(blocked_ips2)
print(f"Only in first blocklist: {only_in_first}")

# Symmetric difference - elements in either set but not both
unique_blocked = blocked_ips1.symmetric_difference(blocked_ips2)
print(f"Unique in each blocklist: {unique_blocked}")

print()

# ==========================================
# 3. Set Methods
# ==========================================
print("=== Set Methods ===\n")

# Adding elements
unique_ips.add("192.168.1.254")
print(f"After adding gateway: {unique_ips}")

# Adding multiple elements
unique_ips.update(["10.0.0.6", "10.0.0.7"])
print(f"After adding more IPs: {unique_ips}")

# Removing elements
unique_ips.remove("10.0.0.5")
print(f"After removing 10.0.0.5: {unique_ips}")

# Discard (safe remove)
unique_ips.discard("nonexistent_ip")  # No error
print(f"After discarding nonexistent: {unique_ips}")

# Pop (removes random element)
random_ip = unique_ips.pop()
print(f"Popped random IP: {random_ip}")

# Clear the set
temp_set = {"a", "b", "c"}
temp_set.clear()
print(f"Cleared set: {temp_set}")

print()

# ==========================================
# 4. Subset and Superset Checks
# ==========================================
print("=== Subset and Superset Checks ===\n")

port_range1 = {21, 22, 80, 443}
port_range2 = {80, 443}

print(f"Port range 2 is subset of range 1: {port_range2.issubset(port_range1)}")
print(f"Port range 1 is superset of range 2: {port_range1.issuperset(port_range2)}")

common_well_known = {80, 443, 22, 21, 53}
http_ports = {80, 443}
https_ports = {443}

print(f"HTTP ports are subset of well-known: {http_ports.issubset(common_well_known)}")
print(f"HTTPS ports are subset of HTTP ports: {https_ports.issubset(http_ports)}")

print()

# ==========================================
# 5. Membership and Length
# ==========================================
print("=== Membership and Length ===\n")

print(f"Port 80 in common ports: {80 in common_ports}")
print(f"Port 8080 in common ports: {8080 in common_ports}")

print(f"Number of common ports: {len(common_ports)}")

print()

# ==========================================
# 6. Frozen Sets (Immutable Sets)
# ==========================================
print("=== Frozen Sets ===\n")

# Create frozen set (cannot be modified)
frozen_ports = frozenset(common_ports)
print(f"Frozen ports set: {frozen_ports}")

# Frozen sets can be dictionary keys
port_categories = {
    frozenset([80, 443]): "Web Services",
    frozenset([22, 23]): "Remote Access",
    frozenset([53]): "DNS"
}

print(f"Port categories: {port_categories}")
print(f"Category for 80, 443: {port_categories[frozenset([80, 443])]}")

print()

# ==========================================
# 7. Practical Examples for Cybersecurity
# ==========================================
print("=== Practical Examples ===\n")

# Example 1: Unique Visitor Tracking
print("=== Unique Visitor Tracking ===\n")
web_logs = [
    "192.168.1.100 - - [10/Oct/2023:13:55:36 +0000] \"GET / HTTP/1.1\" 200 1024",
    "10.0.0.5 - - [10/Oct/2023:13:56:01 +0000] \"POST /login HTTP/1.1\" 401 200",
    "172.16.0.15 - - [10/Oct/2023:13:57:12 +0000] \"GET /admin HTTP/1.1\" 403 150",
    "192.168.1.100 - - [10/Oct/2023:13:58:45 +0000] \"GET /api/users HTTP/1.1\" 200 5000",
    "203.0.113.7 - - [10/Oct/2023:13:59:20 +0000] \"GET /etc/passwd HTTP/1.1\" 404 100"
]

# Extract unique source IPs
source_ips = set()
for log in web_logs:
    source_ip = log.split()[0]
    source_ips.add(source_ip)

print(f"Unique visitors: {len(source_ips)}")
print(f"Visitor IPs: {source_ips}")

print()

# Example 2: Network Scanner Duplicate Removal
print("=== Network Scanner Duplicate Removal ===\n")

scan_results = [
    {"ip": "192.168.1.1", "port": 80, "status": "open"},
    {"ip": "192.168.1.1", "port": 443, "status": "open"},
    {"ip": "10.0.0.5", "port": 80, "status": "filtered"},
    {"ip": "192.168.1.1", "port": 80, "status": "open"},
    {"ip": "172.16.0.10", "port": 22, "status": "closed"},
    {"ip": "10.0.0.5", "port": 80, "status": "filtered"}
]

# Remove duplicate results using frozenset of dict items as keys
unique_results = []
seen = set()

for result in scan_results:
    # Convert dict to hashable key (frozenset)
    key = frozenset(result.items())
    if key not in seen:
        seen.add(key)
        unique_results.append(result)

print(f"Original results: {len(scan_results)}")
print(f"Unique results: {len(unique_results)}")
for result in unique_results:
    print(f"  {result['ip']}:{result['port']} - {result['status']}")

print()

# Example 3: Intrusion Detection System (IDS)
print("=== Intrusion Detection System ===\n")

# Known malicious IP addresses (from threat intelligence)
known_malicious_ips = {
    "192.168.1.100", "203.0.113.7", "104.16.0.0", 
    "8.8.8.8"  # This is a test (Google DNS - not actually malicious)
}

# Normal IP addresses from white list
normal_ips = {"192.168.1.1", "10.0.0.5", "172.16.0.10", "8.8.8.8"}

# Blocklist (malicious but not in white list)
blocklist = known_malicious_ips - normal_ips
print(f"Blocklist (malicious and not in white list): {blocklist}")

# Check if IP is malicious but also in white list (potential whitelist bypass)
malicious_whitelisted = known_malicious_ips & normal_ips
print(f"Malicious IPs in white list: {malicious_whitelisted}")

# Check network packets for malicious IPs
network_traffic = [
    ("192.168.1.1", "10.0.0.5", "HTTP"),
    ("203.0.113.7", "172.16.0.10", "SSH"),
    ("8.8.8.8", "192.168.1.1", "DNS"),
    ("104.16.0.0", "10.0.0.5", "TCP"),
    ("192.168.1.100", "172.16.0.10", "UDP")
]

print()
print("Analyzing network traffic:")
for src_ip, dst_ip, protocol in network_traffic:
    if src_ip in blocklist or dst_ip in blocklist:
        print(f"ALERT: {protocol} packet with malicious IP detected! {src_ip} -> {dst_ip}")
    elif src_ip in known_malicious_ips and src_ip in normal_ips:
        print(f"WARNING: Malicious IP {src_ip} is in white list!")
    else:
        print(f"Normal packet: {src_ip} -> {dst_ip} ({protocol})")

print()

# Example 4: Vulnerability Database Management
print("=== Vulnerability Database Management ===\n")

# Current vulnerabilities in system A
system_a_vulns = {"CVE-2023-1234", "CVE-2023-5678", "CVE-2023-9012"}

# Current vulnerabilities in system B
system_b_vulns = {"CVE-2023-5678", "CVE-2023-3456", "CVE-2023-9012"}

# Vulnerabilities common to both systems
common_vulns = system_a_vulns & system_b_vulns
print(f"Vulnerabilities common to both systems: {common_vulns}")

# Vulnerabilities unique to each system
system_a_unique = system_a_vulns - system_b_vulns
system_b_unique = system_b_vulns - system_a_vulns
print(f"Vulnerabilities unique to System A: {system_a_unique}")
print(f"Vulnerabilities unique to System B: {system_b_unique}")

# All vulnerabilities across both systems
all_vulns = system_a_vulns | system_b_vulns
print(f"Total unique vulnerabilities: {len(all_vulns)}")

# Determine if System A's vulnerabilities are a subset of System B's
if system_a_vulns.issubset(system_b_vulns):
    print("System A's vulnerabilities are all present in System B")
elif system_b_vulns.issubset(system_a_vulns):
    print("System B's vulnerabilities are all present in System A")
else:
    print("Both systems have unique vulnerabilities")

print()

# Example 5: Firewall Rule Optimization
print("=== Firewall Rule Optimization ===\n")

# Existing firewall rules
firewall_rules = [
    {"source": "192.168.1.0/24", "dest": "any", "port": 80, "action": "allow"},
    {"source": "192.168.1.0/24", "dest": "any", "port": 443, "action": "allow"},
    {"source": "10.0.0.0/16", "dest": "any", "port": 22, "action": "deny"},
    {"source": "192.168.1.0/24", "dest": "any", "port": 80, "action": "allow"},
    {"source": "172.16.0.0/12", "dest": "any", "port": 53, "action": "allow"},
    {"source": "10.0.0.0/16", "dest": "any", "port": 22, "action": "deny"}
]

# Remove duplicate rules
unique_rules = []
rule_set = set()

for rule in firewall_rules:
    # Convert rule to hashable key
    rule_key = frozenset(rule.items())
    if rule_key not in rule_set:
        rule_set.add(rule_key)
        unique_rules.append(rule)

print(f"Original rules: {len(firewall_rules)}")
print(f"Unique rules: {len(unique_rules)}")

print()
print("Optimized rules:")
for i, rule in enumerate(unique_rules, 1):
    print(f"Rule {i}:")
    for key, value in rule.items():
        print(f"  {key}: {value}")
    print()

print()

# Example 6: Malware Signature Analysis
print("=== Malware Signature Analysis ===\n")

# Signature strings from malware A
malware_a_strings = {
    "WannaCry", "WanaDecryptor", "ransomnote.txt", 
    "aes256", "encrypt", "key"
}

# Signature strings from malware B
malware_b_strings = {
    "Emotet", "payload.bin", "config.dat", 
    "encrypt", "key", "password"
}

# Common signature strings (potential family relationship)
common_signatures = malware_a_strings & malware_b_strings
print(f"Common signature strings: {common_signatures}")

# Unique signature strings for classification
malware_a_unique = malware_a_strings - malware_b_strings
malware_b_unique = malware_b_strings - malware_a_strings
print(f"Malware A unique signatures: {malware_a_unique}")
print(f"Malware B unique signatures: {malware_b_unique}")

# Determine if one might be a variant of the other
if len(common_signatures) > len(malware_a_strings) * 0.5 or len(common_signatures) > len(malware_b_strings) * 0.5:
    print("These malware samples may be variants or share code")
else:
    print("These malware samples appear to be unrelated")
