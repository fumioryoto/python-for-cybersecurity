#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Python Dictionaries for Cybersecurity
This script demonstrates Python dictionaries with cybersecurity examples.
"""

# ==========================================
# 1. Creating Dictionaries
# ==========================================
print("=== Creating Dictionaries ===\n")

# Basic dictionary creation
port_services = {
    80: "HTTP",
    443: "HTTPS",
    22: "SSH",
    21: "FTP",
    53: "DNS"
}
print(f"Port services: {port_services}")

# Empty dictionary
network_info = {}
print(f"Empty dictionary: {network_info}")

# Dictionary with mixed data types
scan_result = {
    "target": "192.168.1.1",
    "ports": [80, 443, 22],
    "status": "completed",
    "timestamp": "2023-10-10 13:45:22",
    "vulnerabilities": None
}
print(f"Scan result (mixed types): {scan_result}")

# Dictionary comprehension
subnet_mask = {octet: f"{octet:08b}" for octet in range(0, 256, 64)}
print(f"Subnet masks (binary): {subnet_mask}")

print()

# ==========================================
# 2. Accessing Dictionary Values
# ==========================================
print("=== Accessing Dictionary Values ===\n")

print(f"Port 80 service: {port_services[80]}")
print(f"Port 443 service: {port_services.get(443)}")

# Safe access with default
print(f"Port 8080 service: {port_services.get(8080, 'Unknown')}")

# Accessing nested values
packet_data = {
    "header": {
        "source_ip": "192.168.1.100",
        "dest_ip": "10.0.0.5",
        "protocol": "TCP",
        "ports": {"src": 1024, "dst": 80}
    },
    "payload": "GET / HTTP/1.1..."
}
print(f"Source port: {packet_data['header']['ports']['src']}")

# Getting all keys
print(f"Port numbers: {list(port_services.keys())}")

# Getting all values
print(f"Services: {list(port_services.values())}")

# Getting items (key-value pairs)
print(f"Port-service pairs: {list(port_services.items())}")

print()

# ==========================================
# 3. Modifying Dictionaries
# ==========================================
print("=== Modifying Dictionaries ===\n")

# Adding new entries
port_services[25] = "SMTP"
print(f"After adding SMTP: {port_services}")

# Updating existing entries
port_services[80] = "HTTP (Hypertext Transfer Protocol)"
print(f"After updating HTTP: {port_services}")

# Deleting entries
del port_services[21]  # Delete by key
print(f"After deleting FTP: {port_services}")

# Pop method (removes and returns value)
ssh_service = port_services.pop(22)
print(f"Removed SSH service: {ssh_service}")
print(f"Dictionary after pop: {port_services}")

# Update method (merge dictionaries)
more_ports = {110: "POP3", 143: "IMAP", 3306: "MySQL"}
port_services.update(more_ports)
print(f"After updating with more ports: {port_services}")

print()

# ==========================================
# 4. Dictionary Operations
# ==========================================
print("=== Dictionary Operations ===\n")

# Length
print(f"Number of port services: {len(port_services)}")

# Membership checks
print(f"Port 80 exists: {80 in port_services}")
print(f"Port 22 exists: {22 in port_services}")

# Dictionary iteration
print("\nPort services:")
for port, service in port_services.items():
    print(f"  Port {port}: {service}")

# Sorting dictionaries
sorted_ports = dict(sorted(port_services.items()))
print("\nSorted by port number:")
for port, service in sorted_ports.items():
    print(f"  Port {port}: {service}")

sorted_by_service = dict(sorted(port_services.items(), key=lambda x: x[1]))
print("\nSorted by service name:")
for port, service in sorted_by_service.items():
    print(f"  Port {port}: {service}")

print()

# ==========================================
# 5. Dictionary Methods
# ==========================================
print("=== Dictionary Methods ===\n")

# Copying dictionaries
port_services_copy = port_services.copy()
print(f"Copy created: {len(port_services_copy)} entries")

# Clear method
temp_dict = {"a": 1, "b": 2}
temp_dict.clear()
print(f"Cleared dictionary: {temp_dict}")

# From keys (create new dictionary)
new_dict = dict.fromkeys([80, 443, 22], "Open")
print(f"Dictionary from keys: {new_dict}")

# Get method with default
print(f"Port 8080: {port_services.get(8080, 'Filtered')}")

print()

# ==========================================
# 6. Nested Dictionaries
# ==========================================
print("=== Nested Dictionaries ===\n")

# Complex network configuration
network_config = {
    "interfaces": {
        "eth0": {
            "ip": "192.168.1.100",
            "netmask": "255.255.255.0",
            "gateway": "192.168.1.1",
            "status": "up"
        },
        "wlan0": {
            "ip": "10.0.0.5",
            "netmask": "255.255.0.0",
            "gateway": "10.0.0.1",
            "status": "down"
        }
    },
    "firewall": {
        "enabled": True,
        "rules": [
            {"source": "192.168.1.0/24", "destination": "any", "port": 80, "action": "allow"},
            {"source": "any", "destination": "any", "port": 22, "action": "deny"}
        ]
    },
    "services": {
        "http": {"port": 80, "status": "running"},
        "ssh": {"port": 22, "status": "stopped"},
        "mysql": {"port": 3306, "status": "running"}
    }
}

# Access nested data
print(f"Ethernet IP: {network_config['interfaces']['eth0']['ip']}")
print(f"Firewall enabled: {network_config['firewall']['enabled']}")
print(f"HTTP service status: {network_config['services']['http']['status']}")

# Modify nested values
network_config['interfaces']['wlan0']['status'] = "up"
network_config['firewall']['rules'].append({
    "source": "10.0.0.0/16",
    "destination": "any",
    "port": 443,
    "action": "allow"
})

print("\nModified network configuration:")
for iface, config in network_config['interfaces'].items():
    print(f"  {iface}: {config['ip']} ({config['status']})")

print()

# ==========================================
# 7. Practical Examples for Cybersecurity
# ==========================================
print("=== Practical Examples ===\n")

# Example 1: Network Scanner Results
print("=== Network Scanner Results ===\n")
scan_results = {
    "192.168.1.1": {
        "open_ports": [80, 443, 22],
        "os": "Linux Ubuntu",
        "vulnerabilities": ["CVE-2023-1234", "CVE-2023-5678"],
        "uptime": "24 days"
    },
    "192.168.1.2": {
        "open_ports": [80, 443],
        "os": "Windows Server 2019",
        "vulnerabilities": [],
        "uptime": "15 days"
    },
    "192.168.1.100": {
        "open_ports": [22, 3389],
        "os": "Windows 10",
        "vulnerabilities": ["CVE-2023-9012"],
        "uptime": "2 days"
    }
}

# Display scan results
for ip, info in scan_results.items():
    print(f"\n=== {ip} ===")
    print(f"  OS: {info['os']}")
    print(f"  Open Ports: {', '.join(map(str, info['open_ports']))}")
    print(f"  Vulnerabilities: {', '.join(info['vulnerabilities']) if info['vulnerabilities'] else 'None'}")
    print(f"  Uptime: {info['uptime']}")

print()

# Example 2: Connection Tracker
print("=== Connection Tracker ===\n")
connection_tracker = {}

def track_connection(src_ip, dst_ip, src_port, dst_port, protocol):
    """Track network connections"""
    key = (src_ip, dst_ip, src_port, dst_port, protocol)
    
    if key not in connection_tracker:
        connection_tracker[key] = {
            "count": 0,
            "packets": [],
            "bytes": 0
        }
    
    connection_tracker[key]["count"] += 1

# Simulate connections
track_connection("192.168.1.100", "10.0.0.5", 1024, 80, "TCP")
track_connection("192.168.1.100", "10.0.0.5", 1024, 80, "TCP")
track_connection("172.16.0.10", "10.0.0.5", 1025, 53, "UDP")
track_connection("192.168.1.100", "10.0.0.6", 1026, 443, "TCP")

print(f"Total tracked connections: {len(connection_tracker)}")
for conn, stats in connection_tracker.items():
    src_ip, dst_ip, src_port, dst_port, protocol = conn
    print(f"  {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({protocol}): {stats['count']} connections")

print()

# Example 3: Vulnerability Database
print("=== Vulnerability Database ===\n")
cve_database = {
    "CVE-2023-1234": {
        "title": "Apache HTTP Server Remote Code Execution",
        "description": "Path traversal and file disclosure vulnerability in Apache HTTP Server versions 2.4.0-2.4.54",
        "cvss_score": 9.8,
        "severity": "critical",
        "affected_versions": ["2.4.0-2.4.54"],
        "reference": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-1234"
    },
    "CVE-2023-5678": {
        "title": "OpenSSL Buffer Overflow",
        "description": "Buffer overflow vulnerability in OpenSSL affecting DTLS applications",
        "cvss_score": 7.5,
        "severity": "high",
        "affected_versions": ["3.0.0-3.0.8"],
        "reference": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-5678"
    },
    "CVE-2023-9012": {
        "title": "Windows SMB Remote Code Execution",
        "description": "Remote code execution vulnerability in Windows SMBv3 affecting Windows 10 and Server versions",
        "cvss_score": 8.8,
        "severity": "high",
        "affected_versions": ["Windows 10 1709+", "Windows Server 2019+"],
        "reference": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-9012"
    }
}

# Find vulnerabilities by severity
critical_vulns = [cve for cve, info in cve_database.items() if info["severity"] == "critical"]
print(f"Critical vulnerabilities: {len(critical_vulns)}")
for cve in critical_vulns:
    print(f"  {cve}: {cve_database[cve]['title']}")

print()

# Calculate average CVSS score
average_score = sum(info["cvss_score"] for info in cve_database.values()) / len(cve_database)
print(f"Average CVSS score: {average_score:.2f}")

print()

# Example 4: Malware Signature Database
print("=== Malware Signature Database ===\n")
malware_signatures = {
    "Trojan.Ransom.WannaCry": {
        "md5": "d41d8cd98f00b204e9800998ecf8427e",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85",
        "file_size": 3145728,
        "file_type": "PE32 executable",
        "behavior": ["encrypts files", "connects to C2", "modifies registry"],
        "strings": ["WannaCry", "WanaDecryptor", "ransomnote.txt"]
    },
    "Trojan.Dropper.Emotet": {
        "md5": "a1b2c3d4e5f678901234567890abcdef",
        "sha256": "abc123def4567890abc123def4567890abc123def4567890abc123def4567890",
        "file_size": 1048576,
        "file_type": "DLL",
        "behavior": ["downloads additional modules", "steals credentials", "evades AV"],
        "strings": ["Emotet", "payload.bin", "config.dat"]
    }
}

# Check file against signatures
def check_file_signature(file_hash, hash_type="md5"):
    """Check if file matches any known malware signature"""
    for malware, info in malware_signatures.items():
        if info[hash_type] == file_hash:
            return malware
    return None

# Test signature check
test_hash = "d41d8cd98f00b204e9800998ecf8427e"
detected = check_file_signature(test_hash)
print(f"File hash {test_hash[:16]}... matches: {detected}")

test_hash = "unknownhash"
detected = check_file_signature(test_hash)
print(f"File hash {test_hash} matches: {detected}")

print()

# Example 5: Configuration Management
print("=== Configuration Management ===\n")
tool_config = {
    "scanner": {
        "targets": ["192.168.1.0/24", "10.0.0.0/16"],
        "ports": [80, 443, 22, 21, 53],
        "timeout": 5,
        "retries": 3,
        "threads": 10
    },
    "exploiter": {
        "enabled": True,
        "auto_exploit": False,
        "vulnerabilities": ["CVE-2023-1234", "CVE-2023-5678"],
        "payload": "meterpreter/reverse_tcp"
    },
    "reporting": {
        "format": ["html", "csv"],
        "output_dir": "./reports",
        "email": {
            "enabled": False,
            "smtp_server": "smtp.example.com",
            "recipients": ["admin@example.com"]
        }
    }
}

# Modify configuration
tool_config["scanner"]["threads"] = 20
tool_config["reporting"]["email"]["enabled"] = True

# Save configuration
import json
with open('config.json', 'w') as f:
    json.dump(tool_config, f, indent=2)

# Load and verify configuration
with open('config.json', 'r') as f:
    loaded_config = json.load(f)

print(f"Scanner targets: {loaded_config['scanner']['targets']}")
print(f"Threads: {loaded_config['scanner']['threads']}")
print(f"Email notifications enabled: {loaded_config['reporting']['email']['enabled']}")
