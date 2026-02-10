#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Text File Handling in Python for Cybersecurity
This script demonstrates working with text files including log files,
configuration files, and other text-based security data.
"""

# ==========================================
# 1. Basic File Operations
# ==========================================
print("=== Basic File Operations ===\n")

# Writing to files
print("Writing to a new file:")
with open('test_log.txt', 'w') as file:
    file.write("192.168.1.100 - - [10/Oct/2023:13:55:36] \"GET / HTTP/1.1\" 200 1024\n")
    file.write("10.0.0.5 - - [10/Oct/2023:13:56:01] \"POST /login HTTP/1.1\" 401 200\n")
    file.write("172.16.0.15 - - [10/Oct/2023:13:57:12] \"GET /admin HTTP/1.1\" 403 150\n")
print("File created and written")
print()

# Reading entire file
print("Reading entire file:")
with open('test_log.txt', 'r') as file:
    content = file.read()
    print(content)
print()

# Reading line by line
print("Reading file line by line:")
with open('test_log.txt', 'r') as file:
    for i, line in enumerate(file, 1):
        print(f"Line {i}: {line.strip()}")
print()

# Appending to file
print("Appending to file:")
with open('test_log.txt', 'a') as file:
    file.write("203.0.113.7 - - [10/Oct/2023:13:58:45] \"GET /etc/passwd HTTP/1.1\" 404 100\n")

with open('test_log.txt', 'r') as file:
    lines = file.readlines()
    print(f"File now has {len(lines)} lines")
    print(f"Last line: {lines[-1].strip()}")
print()

# ==========================================
# 2. Log File Parsing
# ==========================================
print("=== Log File Parsing ===\n")

import re

def parse_apache_log(line):
    """Parse Apache log entry into dictionary"""
    pattern = re.compile(r'(\S+) - (\S+) \[(.*?)\] "(.*?)" (\d+) (\d+)')
    match = pattern.match(line.strip())
    
    if match:
        return {
            'ip': match.group(1),
            'ident': match.group(2),
            'time': match.group(3),
            'request': match.group(4),
            'status': int(match.group(5)),
            'size': int(match.group(6))
        }
    return None

# Parse log file
parsed_logs = []
with open('test_log.txt', 'r') as file:
    for line in file:
        parsed = parse_apache_log(line)
        if parsed:
            parsed_logs.append(parsed)

# Display parsed logs
print("Parsed Apache log entries:")
for log in parsed_logs:
    print(f"IP: {log['ip']:15} Time: {log['time']}")
    print(f"  Request: {log['request']}")
    print(f"  Status: {log['status']} Size: {log['size']} bytes")
print()

# Analyze log data
print("Log Analysis:")
ip_counts = {}
status_counts = {}

for log in parsed_logs:
    # Count IP addresses
    ip_counts[log['ip']] = ip_counts.get(log['ip'], 0) + 1
    
    # Count HTTP status codes
    status_counts[log['status']] = status_counts.get(log['status'], 0) + 1

print(f"Unique IP addresses: {len(ip_counts)}")
for ip, count in ip_counts.items():
    print(f"  {ip}: {count} requests")

print(f"HTTP status codes: {len(status_counts)}")
for status, count in status_counts.items():
    print(f"  {status}: {count} responses")
print()

# ==========================================
# 3. Configuration File Handling
# ==========================================
print("=== Configuration File Handling ===\n")

# Create configuration file
config_content = """[network]
target_ip = 192.168.1.0/24
scan_ports = 1-1024
timeout = 1.0
threads = 50

[vulnerability]
severity = Critical,High,Medium
exploits = true
aggressive = false

[reporting]
formats = html,csv,txt
email = true
smtp_server = smtp.example.com
recipients = admin@example.com,security@example.com

[logging]
level = INFO
file = security_toolkit.log
max_size = 10MB
"""

with open('security_config.ini', 'w') as file:
    file.write(config_content)
print("Configuration file created")
print()

# Read and parse INI file
import configparser

config = configparser.ConfigParser()
config.read('security_config.ini')

print("Configuration sections:")
for section in config.sections():
    print(f"  - {section}")
print()

print("Network configuration:")
print(f"  Target IP: {config['network']['target_ip']}")
print(f"  Scan ports: {config['network']['scan_ports']}")
print(f"  Timeout: {config['network']['timeout']}")
print(f"  Threads: {config['network']['threads']}")
print()

print("Vulnerability configuration:")
severity = config['vulnerability']['severity'].split(',')
print(f"  Severity: {', '.join(severity)}")
print(f"  Exploits: {config.getboolean('vulnerability', 'exploits')}")
print(f"  Aggressive: {config.getboolean('vulnerability', 'aggressive')}")
print()

# Update configuration file
config['network']['timeout'] = '2.0'
config['network']['threads'] = '100'

with open('security_config.ini', 'w') as configfile:
    config.write(configfile)
print("Configuration file updated")

with open('security_config.ini', 'r') as file:
    print("\nUpdated configuration:")
    print(file.read())
print()

# ==========================================
# 4. File Path Operations
# ==========================================
print("=== File Path Operations ===\n")

import os

print("Current working directory:", os.getcwd())
print()

# File information
print("File information:")
if os.path.exists('test_log.txt'):
    print(f"File exists")
    print(f"File size: {os.path.getsize('test_log.txt')} bytes")
    print(f"Modified time: {os.path.getmtime('test_log.txt')}")
    print(f"Is file: {os.path.isfile('test_log.txt')}")
    print(f"Is directory: {os.path.isdir('test_log.txt')}")
print()

# Path operations
print("Path operations:")
file_path = 'test_log.txt'
print(f"Absolute path: {os.path.abspath(file_path)}")
print(f"Directory name: {os.path.dirname(os.path.abspath(file_path))}")
print(f"File name: {os.path.basename(file_path)}")
print(f"File extension: {os.path.splitext(file_path)[1]}")
print()

# Directory operations
print("Directory operations:")
if not os.path.exists('security_logs'):
    os.mkdir('security_logs')
    print("Created security_logs directory")

# Move file to new directory
import shutil
if os.path.exists('test_log.txt') and os.path.exists('security_logs'):
    shutil.move('test_log.txt', 'security_logs/test_log.txt')
    print("Moved test_log.txt to security_logs directory")

print("\nFiles in security_logs directory:")
if os.path.exists('security_logs'):
    for filename in os.listdir('security_logs'):
        filepath = os.path.join('security_logs', filename)
        if os.path.isfile(filepath):
            print(f"  {filename} ({os.path.getsize(filepath)} bytes)")
print()

# ==========================================
# 5. JSON and CSV File Handling
# ==========================================
print("=== JSON and CSV File Handling ===\n")

import json

# Create scan results data
scan_results = {
    'target': '192.168.1.1',
    'timestamp': '2023-10-10T14:30:00',
    'scan_type': 'full',
    'open_ports': [80, 443, 22, 3389],
    'os_info': {
        'vendor': 'Microsoft',
        'product': 'Windows',
        'version': '10',
        'build': '19044'
    },
    'services': {
        80: {'name': 'http', 'version': 'Apache/2.4.41'},
        443: {'name': 'https', 'version': 'OpenSSL/1.1.1f'},
        22: {'name': 'ssh', 'version': 'OpenSSH/8.2p1'},
        3389: {'name': 'rdp', 'version': 'Remote Desktop Protocol'}
    },
    'vulnerabilities': [
        {'cve': 'CVE-2023-1234', 'severity': 'Critical', 'description': 'Remote code execution'},
        {'cve': 'CVE-2023-5678', 'severity': 'High', 'description': 'Buffer overflow'}
    ]
}

# Write to JSON file
with open('scan_results.json', 'w') as file:
    json.dump(scan_results, file, indent=2)
print("Scan results saved to scan_results.json")
print()

# Read and parse JSON file
with open('scan_results.json', 'r') as file:
    loaded_results = json.load(file)

print("Loaded scan results:")
print(f"Target: {loaded_results['target']}")
print(f"Open ports: {loaded_results['open_ports']}")
print(f"OS: {loaded_results['os_info']['vendor']} {loaded_results['os_info']['product']} {loaded_results['os_info']['version']}")

print("\nVulnerabilities:")
for vuln in loaded_results['vulnerabilities']:
    print(f"  - {vuln['cve']} ({vuln['severity']}): {vuln['description']}")
print()

# CSV file handling
import csv

# Write to CSV file
scan_data = [
    ['IP', 'Port', 'Service', 'Version', 'Status'],
    ['192.168.1.1', 80, 'HTTP', 'Apache/2.4.41', 'Open'],
    ['192.168.1.1', 443, 'HTTPS', 'OpenSSL/1.1.1f', 'Open'],
    ['192.168.1.1', 22, 'SSH', 'OpenSSH/8.2p1', 'Open'],
    ['192.168.1.1', 3389, 'RDP', 'Remote Desktop Protocol', 'Open']
]

with open('port_scan.csv', 'w', newline='') as file:
    writer = csv.writer(file)
    writer.writerows(scan_data)
print("Port scan data saved to port_scan.csv")
print()

# Read and parse CSV file
with open('port_scan.csv', 'r') as file:
    reader = csv.DictReader(file)
    port_data = list(reader)

print("Port scan data from CSV:")
for port in port_data:
    print(f"Port {port['Port']}: {port['Service']} ({port['Version']}) - {port['Status']}")
print()

# ==========================================
# 6. Error Handling
# ==========================================
print("=== Error Handling ===\n")

# File not found handling
try:
    with open('nonexistent_file.txt', 'r') as file:
        content = file.read()
except FileNotFoundError:
    print("Error: File not found")
except Exception as e:
    print(f"Error: {e}")

print()

# Permission error handling
try:
    with open('/etc/shadow', 'r') as file:
        content = file.read()
except PermissionError:
    print("Error: Permission denied")
except Exception as e:
    print(f"Error: {e}")

print()

# ==========================================
# 7. Secure File Handling
# ==========================================
print("=== Secure File Handling ===\n")

# File encryption (simple Caesar cipher for demonstration)
def caesar_cipher(text, shift):
    result = []
    for char in text:
        if char.isalpha():
            ascii_offset = ord('a') if char.islower() else ord('A')
            shifted = (ord(char) - ascii_offset + shift) % 26
            result.append(chr(shifted + ascii_offset))
        else:
            result.append(char)
    return ''.join(result)

# Encrypt sensitive data
sensitive_data = """[credentials]
username = admin
password = S3cur3P@ssw0rd!
api_key = ABC123DEF456GHI789
"""

encrypted_data = caesar_cipher(sensitive_data, 3)

with open('credentials.enc', 'w') as file:
    file.write(encrypted_data)
print("Credentials encrypted and saved to credentials.enc")
print()

# Decrypt data
with open('credentials.enc', 'r') as file:
    encrypted_content = file.read()

decrypted_content = caesar_cipher(encrypted_content, -3)
print("Decrypted credentials:")
print(decrypted_content)
print()

# Hash calculation for integrity checking
import hashlib

def calculate_file_hash(file_path, algorithm='sha256'):
    """Calculate hash of file content"""
    hash_obj = hashlib.new(algorithm)
    
    with open(file_path, 'rb') as file:
        # Read file in chunks to handle large files
        for chunk in iter(lambda: file.read(4096), b''):
            hash_obj.update(chunk)
            
    return hash_obj.hexdigest()

# Calculate and verify file hash
hash_sha256 = calculate_file_hash('scan_results.json')
hash_md5 = calculate_file_hash('scan_results.json', 'md5')

print(f"File hashes:")
print(f"  SHA-256: {hash_sha256}")
print(f"  MD5: {hash_md5}")
print()

# ==========================================
# 8. File Compression
# ==========================================
print("=== File Compression ===\n")

import zipfile

# Create ZIP archive
with zipfile.ZipFile('security_data.zip', 'w', zipfile.ZIP_DEFLATED) as zipf:
    zipf.write('security_config.ini')
    zipf.write('scan_results.json')
    zipf.write('port_scan.csv')
    zipf.write('credentials.enc')
    if os.path.exists('security_logs/test_log.txt'):
        zipf.write('security_logs/test_log.txt', 'test_log.txt')

print("Security data compressed to security_data.zip")
print(f"Zip file size: {os.path.getsize('security_data.zip')} bytes")
print()

# Read ZIP archive
with zipfile.ZipFile('security_data.zip', 'r') as zipf:
    print("Files in ZIP archive:")
    for info in zipf.infolist():
        print(f"  {info.filename:20} {info.file_size:8} bytes")
        
    print("\nExtracting files from ZIP...")
    zipf.extractall('extracted_data')

print("\nExtraction complete")
if os.path.exists('extracted_data'):
    print("Files in extracted_data directory:")
    for filename in os.listdir('extracted_data'):
        print(f"  {filename}")
print()

# ==========================================
# 9. Cleanup
# ==========================================
print("=== Cleanup ===\n")

# Remove temporary files and directories
import shutil

temp_files = [
    'security_config.ini',
    'scan_results.json',
    'port_scan.csv',
    'credentials.enc',
    'security_data.zip',
    'extracted_data'
]

for file_path in temp_files:
    if os.path.isfile(file_path):
        os.remove(file_path)
        print(f"Removed: {file_path}")
    elif os.path.isdir(file_path):
        shutil.rmtree(file_path)
        print(f"Removed directory: {file_path}")

if os.path.exists('security_logs/test_log.txt'):
    os.remove('security_logs/test_log.txt')
    print("Removed: security_logs/test_log.txt")

if os.path.exists('security_logs') and not os.listdir('security_logs'):
    os.rmdir('security_logs')
    print("Removed directory: security_logs")
