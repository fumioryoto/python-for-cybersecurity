#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Binary File Handling in Python for Cybersecurity
This script demonstrates working with binary files including
malware samples, packet captures, and binary data analysis.
"""

# ==========================================
# 1. Binary File Basics
# ==========================================
print("=== Binary File Basics ===\n")

# Create a binary file
binary_data = bytes([0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00,
                     0x40, 0x06, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x64,
                     0x0a, 0x00, 0x00, 0x05, 0x04, 0xd2, 0x00, 0x50,
                     0x1a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x80, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00])

with open('network_packet.bin', 'wb') as file:
    file.write(binary_data)
print("Binary file created: network_packet.bin")
print(f"File size: {len(binary_data)} bytes")
print()

# Read entire binary file
with open('network_packet.bin', 'rb') as file:
    read_data = file.read()
    print(f"Read {len(read_data)} bytes")
    print(f"Data: {read_data}")
    print()

# Read binary file in chunks
with open('network_packet.bin', 'rb') as file:
    print("Reading file in 8-byte chunks:")
    while True:
        chunk = file.read(8)
        if not chunk:
            break
        print(f"  {chunk.hex()}")
print()

# ==========================================
# 2. Network Packet Analysis
# ==========================================
print("=== Network Packet Analysis ===\n")

def parse_ip_header(data):
    """Parse IP packet header"""
    if len(data) < 20:
        return None
        
    header = {
        'version': data[0] >> 4,
        'ihl': data[0] & 0x0F,
        'tos': data[1],
        'length': int.from_bytes(data[2:4], 'big'),
        'id': int.from_bytes(data[4:6], 'big'),
        'flags': data[6] >> 5,
        'fragment_offset': int.from_bytes(data[6:8], 'big') & 0x1FFF,
        'ttl': data[8],
        'protocol': data[9],
        'checksum': int.from_bytes(data[10:12], 'big'),
        'source_ip': '.'.join(str(x) for x in data[12:16]),
        'dest_ip': '.'.join(str(x) for x in data[16:20])
    }
    
    protocol_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
    header['protocol'] = protocol_map.get(header['protocol'], f"Unknown ({header['protocol']})")
    
    return header

# Parse network packet
packet_header = parse_ip_header(binary_data)
if packet_header:
    print("IP Header Parse:")
    for key, value in packet_header.items():
        print(f"  {key}: {value}")
print()

# ==========================================
# 3. File Signature Analysis
# ==========================================
print("=== File Signature Analysis ===\n")

# File signatures (magic numbers)
file_signatures = {
    b'\x4D\x5A': 'Windows Executable (PE)',
    b'\x7F\x45\x4C\x46': 'ELF Executable',
    b'\xCA\xFE\xBA\xBE': 'Java Class File',
    b'\x50\x4B\x03\x04': 'ZIP Archive',
    b'\x89\x50\x4E\x47': 'PNG Image',
    b'\xFF\xD8\xFF': 'JPEG Image',
    b'\x49\x44\x33': 'MP3 Audio',
    b'\x47\x49\x46\x38': 'GIF Image'
}

def detect_file_type(file_path):
    """Detect file type from magic numbers"""
    with open(file_path, 'rb') as file:
        magic = file.read(4)
        
    detected = []
    for signature, file_type in file_signatures.items():
        if magic.startswith(signature):
            detected.append(file_type)
            
    if not detected:
        return 'Unknown file type'
        
    return ', '.join(detected)

# Create test files with magic numbers
test_files = {
    'test_pe.exe': b'\x4D\x5A' + b'\x00' * 98,
    'test_elf.bin': b'\x7F\x45\x4C\x46' + b'\x00' * 96,
    'test_zip.zip': b'\x50\x4B\x03\x04' + b'\x00' * 96,
    'test_png.png': b'\x89\x50\x4E\x47' + b'\x00' * 96
}

for filename, data in test_files.items():
    with open(filename, 'wb') as file:
        file.write(data)
    detected_type = detect_file_type(filename)
    print(f"{filename:15} - {detected_type}")
print()

# ==========================================
# 4. Memory Dump Analysis
# ==========================================
print("=== Memory Dump Analysis ===\n")

def analyze_memory_dump(data):
    """Analyze memory dump for patterns"""
    patterns = {
        'ASCII Strings': b'[ -~]{10,}',  # Strings with 10+ printable ASCII
        'IPv4 Addresses': b'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
        'Email Addresses': b'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        'URLs': b'https?://[^\s]+'
    }
    
    import re
    results = {}
    
    for pattern_name, pattern in patterns.items():
        matches = re.findall(pattern, data)
        unique_matches = set()
        
        for match in matches:
            try:
                decoded = match.decode('utf-8', errors='ignore')
                unique_matches.add(decoded)
            except:
                continue
                
        results[pattern_name] = list(unique_matches)
        
    return results

# Create a test memory dump
test_dump = b"""
Process: chrome.exe PID: 1234
Memory: 0x1000000-0x2000000
IP: 192.168.1.100 Port: 1024 -> 8.8.8.8:53
URL: https://www.google.com/search?q=python+cybersecurity
Email: user@example.com
Password: P@ssw0rd!
Another IP: 10.0.0.5
Website: http://localhost:8080/admin
"""

with open('memory_dump.bin', 'wb') as file:
    file.write(test_dump)

# Analyze memory dump
with open('memory_dump.bin', 'rb') as file:
    dump_data = file.read()

analysis = analyze_memory_dump(dump_data)

print("Memory Dump Analysis:")
for pattern, matches in analysis.items():
    print(f"\n{pattern}: ({len(matches)})")
    for match in matches:
        print(f"  {match}")
print()

# ==========================================
# 5. Binary Search and Modification
# ==========================================
print("=== Binary Search and Modification ===\n")

# Create a larger binary file
large_binary_data = b'\x00' * 100 + b'\x11\x22\x33\x44' + b'\x00' * 100

with open('large_file.bin', 'wb') as file:
    file.write(large_binary_data)
print("Created large_file.bin with pattern 0x11223344")

# Search for pattern in binary file
with open('large_file.bin', 'rb') as file:
    search_data = file.read()
    
target_pattern = b'\x11\x22\x33\x44'
offset = search_data.find(target_pattern)

if offset != -1:
    print(f"Pattern found at offset: {offset}")
    print(f"Data before: {search_data[offset-4:offset].hex()}")
    print(f"Pattern: {search_data[offset:offset+len(target_pattern)].hex()}")
    print(f"Data after: {search_data[offset+len(target_pattern):offset+len(target_pattern)+4].hex()}")
else:
    print("Pattern not found")
print()

# Modify binary file
new_pattern = b'\xFF\xEE\xDD\xCC'

with open('large_file.bin', 'rb+') as file:
    file.seek(offset)
    file.write(new_pattern)

with open('large_file.bin', 'rb') as file:
    modified_data = file.read()

new_offset = modified_data.find(new_pattern)
if new_offset != -1:
    print(f"Pattern replaced successfully at offset: {new_offset}")
    print(f"New value: {modified_data[new_offset:new_offset+len(new_pattern)].hex()}")
print()

# ==========================================
# 6. HEX Editor Functionality
# ==========================================
print("=== HEX Editor Functionality ===\n")

def hex_dump(data, bytes_per_line=16):
    """Generate hexadecimal dump of binary data"""
    lines = []
    for offset in range(0, len(data), bytes_per_line):
        chunk = data[offset:offset + bytes_per_line]
        
        # Hexadecimal representation
        hex_part = ' '.join(f"{byte:02X}" for byte in chunk)
        
        # ASCII representation (replace non-printable chars with .)
        ascii_part = ''.join(chr(byte) if 32 <= byte <= 126 else '.' for byte in chunk)
        
        # Pad to fixed width
        hex_part = hex_part.ljust(bytes_per_line * 3)
        ascii_part = ascii_part.ljust(bytes_per_line)
        
        lines.append(f"{offset:08X}  {hex_part}  |{ascii_part}|")
        
    return '\n'.join(lines)

# Display hex dump of our network packet
print("Hex Dump of Network Packet:")
print("=" * 78)
print(hex_dump(binary_data))
print("=" * 78)
print()

# ==========================================
# 7. Malware Signature Matching
# ==========================================
print("=== Malware Signature Matching ===\n")

# Create some dummy malware signatures
malware_signatures = {
    'WannaCry': b'\x57\x61\x6E\x6E\x61\x43\x72\x79',
    'Emotet': b'\x45\x6D\x6F\x74\x65\x74',
    'LockBit': b'\x4C\x6F\x63\x6B\x42\x69\x74',
    'Qakbot': b'\x51\x61\x6B\x62\x6F\x74'
}

# Create test "malware" samples
test_samples = {
    'sample1.bin': b'Some harmless data' + malware_signatures['WannaCry'] + b'more data',
    'sample2.bin': b'Another file' + malware_signatures['Emotet'] + b'with content',
    'sample3.bin': b'Completely harmless file without signatures'
}

# Write test samples
for filename, data in test_samples.items():
    with open(filename, 'wb') as file:
        file.write(data)

# Scan files for malware signatures
for filename in test_samples.keys():
    with open(filename, 'rb') as file:
        content = file.read()
        
    detected = []
    for malware_name, signature in malware_signatures.items():
        if signature in content:
            detected.append(malware_name)
            
    status = "✓ CLEAN"
    if detected:
        status = "⚠️ INFECTED"
        if len(detected) > 1:
            status += f" with {', '.join(detected)}"
        else:
            status += f" with {detected[0]}"
            
    print(f"{filename:15} - {status}")
print()

# ==========================================
# 8. File Integrity Verification
# ==========================================
print("=== File Integrity Verification ===\n")

import hashlib

def verify_file_integrity(file_path, expected_hash, hash_algorithm='sha256'):
    """Verify file integrity using cryptographic hash"""
    hash_obj = hashlib.new(hash_algorithm)
    
    with open(file_path, 'rb') as file:
        while True:
            data = file.read(4096)
            if not data:
                break
            hash_obj.update(data)
            
    calculated_hash = hash_obj.hexdigest()
    return calculated_hash == expected_hash, calculated_hash

# Calculate and verify file integrity
test_files_to_verify = ['test_pe.exe', 'test_elf.bin', 'network_packet.bin']

print("File Integrity Checks:")
for filename in test_files_to_verify:
    if os.path.exists(filename):
        # Calculate and store initial hash
        with open(filename, 'rb') as file:
            file_data = file.read()
            initial_hash = hashlib.sha256(file_data).hexdigest()
            
        # Verify integrity
        is_valid, calculated_hash = verify_file_integrity(filename, initial_hash)
        
        status = "✅ Valid"
        if not is_valid:
            status = f"❌ Invalid (Expected: {initial_hash[:12]}..., Got: {calculated_hash[:12]}...)"
            
        print(f"{filename:15} - {status}")
print()

# ==========================================
# 9. Large File Handling
# ==========================================
print("=== Large File Handling ===\n")

# Create a large test file
large_file_size = 10 * 1024 * 1024  # 10MB
chunk_size = 1024 * 1024  # 1MB chunks

print(f"Creating {large_file_size // (1024*1024)}MB test file...")
with open('large_test_file.bin', 'wb') as file:
    for i in range(large_file_size // chunk_size):
        file.write(b'\x00' * chunk_size)

print(f"File created: {os.path.getsize('large_test_file.bin'):,} bytes")

# Analyze large file without loading entirely into memory
hash_obj = hashlib.sha256()
with open('large_test_file.bin', 'rb') as file:
    while True:
        chunk = file.read(chunk_size)
        if not chunk:
            break
        hash_obj.update(chunk)
        
print(f"SHA-256: {hash_obj.hexdigest()}")

# Search for patterns in large file
search_pattern = b'\x00' * 1024  # 1KB of zeros
found = False
with open('large_test_file.bin', 'rb') as file:
    while True:
        chunk = file.read(chunk_size)
        if not chunk:
            break
        if search_pattern in chunk:
            found = True
            break
            
print(f"Pattern found: {found}")
print()

# ==========================================
# 10. Cleanup
# ==========================================
print("=== Cleanup ===\n")

import os
import shutil

# Remove all test files
temp_files = ['network_packet.bin', 'memory_dump.bin', 'large_file.bin', 'large_test_file.bin']
for filename in temp_files:
    if os.path.exists(filename):
        os.remove(filename)
        print(f"Removed: {filename}")

for filename in test_files.keys():
    if os.path.exists(filename):
        os.remove(filename)
        print(f"Removed: {filename}")
        
for filename in test_samples.keys():
    if os.path.exists(filename):
        os.remove(filename)
        print(f"Removed: {filename}")
