#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Control Flow in Python for Cybersecurity
This script demonstrates Python control flow statements with cybersecurity examples.
"""

# ==========================================
# 1. If Statements
# ==========================================
print("=== If Statements ===\n")

# Basic if statement - check if port is well-known
port = 80
if port < 1024:
    print(f"Port {port} is a well-known port")

print()

# If-else statement - check connection status
connection_successful = False
if connection_successful:
    print("Connection established successfully")
else:
    print("Connection failed")

print()

# If-elif-else chain - check port service
port = 443
if port == 80:
    print("HTTP service")
elif port == 443:
    print("HTTPS service")
elif port == 22:
    print("SSH service")
elif port == 21:
    print("FTP service")
else:
    print("Unknown service")

print()

# ==========================================
# 2. For Loops
# ==========================================
print("=== For Loops ===\n")

# Loop through port range (common for scanning)
print("Scanning well-known ports:")
for port in range(1, 11):
    print(f"Checking port {port}")

print()

# Loop through list of IP addresses
target_ips = ["192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4"]
print("Scanning target IPs:")
for ip in target_ips:
    print(f"Scanning {ip}...")

print()

# Loop with enumerate (track index)
print("Port scan results:")
port_states = {80: "open", 443: "open", 22: "closed", 21: "filtered"}
for index, (port, state) in enumerate(port_states.items(), start=1):
    print(f"{index}. Port {port}: {state}")

print()

# ==========================================
# 3. While Loops
# ==========================================
print("=== While Loops ===\n")

# Connection retry loop with timeout
max_retries = 3
retries = 0
connected = False

print("Attempting to connect:")
while retries < max_retries and not connected:
    retries += 1
    print(f"Attempt {retries}...")
    # Simulate connection check
    # connected = check_connection()
    
    if retries == 3:
        connected = True
        print("Connection successful!")

print()

# Loop with break condition
print("Searching for vulnerable port:")
current_port = 1
found = False

while current_port <= 100:
    # Simulate vulnerability check
    if current_port == 80:
        print(f"Vulnerable port found: {current_port}")
        found = True
        break
    current_port += 1

if not found:
    print("No vulnerable ports found in range")

print()

# ==========================================
# 4. Loop Control Statements
# ==========================================
print("=== Loop Control Statements ===\n")

# Continue statement - skip filtered ports
print("Scanning ports (skipping filtered):")
port_states = [
    (21, "filtered"), (22, "open"), (23, "filtered"), 
    (80, "open"), (443, "open")
]

for port, state in port_states:
    if state == "filtered":
        print(f"Skipping filtered port {port}")
        continue
    print(f"Checking open port {port}")

print()

# Break statement - stop scan on first vulnerable port
print("Stopping scan on first vulnerable port:")
for port in range(1, 10):
    # Simulate vulnerability check
    if port == 5:
        print(f"Critical vulnerability found on port {port}!")
        break
    print(f"Port {port} is safe")

print()

# ==========================================
# 5. Ternary Operator
# ==========================================
print("=== Ternary Operator ===\n")

# Simple conditional assignment
port = 80
status = "Well-known" if port < 1024 else "Ephemeral"
print(f"Port {port}: {status}")

print()

# Inline condition for log messages
is_vulnerable = True
log_message = "ALERT: Vulnerable system detected!" if is_vulnerable else "System appears secure"
print(log_message)

print()

# ==========================================
# 6. Practical Examples
# ==========================================
print("=== Practical Examples ===\n")

# Example 1: Port Scanner with Service Detection
print("=== Port Scanner ===\n")

def scan_port(ip, port):
    """Simulate port scanning"""
    import random
    return random.choice([True, False, "filtered"])  # Simulate random results

def get_service(port):
    """Get service name for common ports"""
    services = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 443: "HTTPS", 3389: "RDP"
    }
    return services.get(port, "Unknown")

target_ip = "192.168.1.1"
scan_range = range(1, 11)

print(f"Scanning {target_ip}...\n")

for port in scan_range:
    print(f"Checking port {port} ({get_service(port)})...", end=" ")
    result = scan_port(target_ip, port)
    
    if result == True:
        print("✅ Open")
    elif result == "filtered":
        print("⚠️ Filtered")
    else:
        print("❌ Closed")

print()
print("Scan complete!")
print()

# Example 2: Log File Analyzer
print("=== Log File Analyzer ===\n")

# Simulate log file entries
log_entries = [
    "192.168.1.100 - - [10/Oct/2023:13:55:36 +0000] \"GET / HTTP/1.1\" 200 1024",
    "10.0.0.5 - - [10/Oct/2023:13:56:01 +0000] \"POST /login HTTP/1.1\" 401 200",
    "172.16.0.15 - - [10/Oct/2023:13:57:12 +0000] \"GET /admin HTTP/1.1\" 403 150",
    "192.168.1.100 - - [10/Oct/2023:13:58:45 +0000] \"GET /api/users HTTP/1.1\" 200 5000",
    "203.0.113.7 - - [10/Oct/2023:13:59:20 +0000] \"GET /etc/passwd HTTP/1.1\" 404 100"
]

suspicious_entries = []

for entry in log_entries:
    # Check for potentially malicious patterns
    if "/etc/passwd" in entry:
        suspicious_entries.append(entry)
    elif "401" in entry:  # Unauthorized access
        suspicious_entries.append(entry)
    elif "403" in entry:  # Forbidden access
        suspicious_entries.append(entry)

print(f"Found {len(suspicious_entries)} suspicious log entries:\n")
for i, log in enumerate(suspicious_entries, start=1):
    print(f"{i}. {log}")

print()

# Example 3: Brute Force Password Guesser
print("=== Brute Force Password Guesser ===\n")

def is_password_correct(attempt):
    """Simulate password check (actual would verify against hash)"""
    return attempt == "password123"

common_passwords = [
    "password", "123456", "12345678", "qwerty", "abc123",
    "password1", "12345", "admin", "welcome", "login",
    "password123", "123456789", "1234567890"
]

found = False
attempt_count = 0

print("Attempting to guess password:\n")
for password in common_passwords:
    attempt_count += 1
    print(f"Attempt {attempt_count}: {password}")
    
    if is_password_correct(password):
        print(f"\n✅ Password found: {password}")
        found = True
        break

if not found:
    print("\n❌ Password not in common list")
