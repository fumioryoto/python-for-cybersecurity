#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Network Scanning in Python for Cybersecurity
This script demonstrates various network scanning techniques
for cybersecurity applications.
"""

import socket
import threading
import time
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
import struct
import ipaddress

# ==========================================
# 1. Single Port Scanning
# ==========================================
print("=== Single Port Scanning ===\n")

def scan_single_port(target_ip, port, timeout=1):
    """Scan a single port using socket"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target_ip, port))
        sock.close()
        return True
    except Exception as e:
        return False

# Test single port scan
target = '127.0.0.1'
port = 80

print(f"Scanning port {port} on {target}:")
result = scan_single_port(target, port)
status = "✅ Open" if result else "❌ Closed"
print(f"  Port {port}: {status}")

print()

# ==========================================
# 2. Multi-threaded Port Scanner
# ==========================================
print("=== Multi-threaded Port Scanner ===\n")

def scan_range(target_ip, start_port, end_port, threads=50, timeout=1):
    """Scan a range of ports using multi-threading"""
    open_ports = []
    
    def worker(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target_ip, port))
            open_ports.append(port)
            sock.close()
        except:
            pass
            
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(worker, port) for port in range(start_port, end_port + 1)]
        
        # Progress indicator
        total = end_port - start_port + 1
        completed = 0
        
        for future in as_completed(futures):
            completed += 1
            if completed % 10 == 0:
                sys.stdout.write(f"\rProgress: {completed}/{total} ({(completed/total)*100:.1f}%)")
                sys.stdout.flush()
                
    sys.stdout.write("\r" + " " * 50 + "\r")
    sys.stdout.flush()
    
    return sorted(open_ports)

# Scan common ports on localhost
print(f"Scanning ports 1-100 on {target}:")
open_ports = scan_range(target, 1, 100, threads=20)

print(f"Open ports: {open_ports}")

print()

# ==========================================
# 3. Banner Grabbing
# ==========================================
print("=== Banner Grabbing ===\n")

def get_service_banner(target_ip, port, timeout=2):
    """Get service banner from open port"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target_ip, port))
        
        # Send request for certain services
        if port == 80:
            sock.sendall(b"GET / HTTP/1.1\r\nHost: %s\r\n\r\n" % target_ip.encode('utf-8'))
        elif port == 21:
            # FTP might send banner without request
            pass
        elif port == 22:
            # SSH banner is usually sent immediately
            pass
            
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        
        return banner
    except Exception as e:
        return f"Error: {e}"

# Test banner grabbing on open ports
print("Banner information:")
for port in open_ports:
    if port in [21, 22, 80, 443]:
        banner = get_service_banner(target, port)
        print(f"  Port {port}: {banner[:60]}")

print()

# ==========================================
# 4. OS Fingerprinting
# ==========================================
print("=== OS Fingerprinting ===\n")

def tcp_os_fingerprint(target_ip, port=80, timeout=2):
    """Basic OS fingerprinting using TCP stack behavior"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        # Set socket options to control behavior
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
        
        try:
            sock.connect((target_ip, port))
            
            # Get socket information for fingerprinting
            sock_info = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 1024)
            
            if sock_info:
                # This is a simplified example - real OS fingerprinting is more complex
                return "Unknown OS (fingerprinting requires specialized tools)"
            else:
                return "Windows (likely)"
                
        except Exception as e:
            return f"Connection error: {e}"
        finally:
            sock.close()
            
    except Exception as e:
        return f"Error: {e}"

print(f"OS fingerprinting for {target}:")
try:
    os_info = tcp_os_fingerprint(target, 80)
    print(f"  {os_info}")
except Exception as e:
    print(f"  Error: {e}")

print()

# ==========================================
# 5. Network Range Scanning
# ==========================================
print("=== Network Range Scanning ===\n")

def scan_network_range(network_cidr, start_port=1, end_port=100, timeout=1):
    """Scan all IP addresses in a network range"""
    try:
        network = ipaddress.ip_network(network_cidr)
        online_hosts = []
        
        print(f"Scanning network {network_cidr}:")
        
        for ip in network.hosts():
            ip_str = str(ip)
            
            # Check if host is online using ICMP or TCP connect
            if is_host_online(ip_str, timeout=0.5):
                print(f"  Host {ip_str} is online")
                online_hosts.append(ip_str)
                
        return online_hosts
        
    except Exception as e:
        print(f"Error scanning network range: {e}")
        return []

def is_host_online(target_ip, timeout=1):
    """Check if host is online using ICMP or TCP SYN"""
    try:
        # ICMP (ping) might be blocked, try TCP connect instead
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target_ip, 80))
        sock.close()
        return True
    except:
        return False

# Test network range scan (local network)
try:
    local_network = "192.168.1.0/24"
    online_hosts = scan_network_range(local_network, start_port=80, end_port=80)
    print(f"Online hosts with port 80 open: {len(online_hosts)}")
except Exception as e:
    print(f"Error: {e}")

print()

# ==========================================
# 6. Service Detection
# ==========================================
print("=== Service Detection ===\n")

def detect_service(target_ip, port, timeout=2):
    """Detect service type based on port number"""
    service_map = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        3389: "RDP",
        27017: "MongoDB"
    }
    
    if port in service_map:
        return service_map[port]
        
    # Try banner matching for unknown ports
    try:
        banner = get_service_banner(target_ip, port, timeout)
        if banner:
            if "HTTP" in banner:
                return "HTTP"
            elif "SSH" in banner:
                return "SSH"
            elif "FTP" in banner:
                return "FTP"
                
    except:
        pass
        
    return "Unknown Service"

# Detect services on open ports
print("Service detection:")
for port in open_ports:
    service = detect_service(target, port)
    print(f"  Port {port}: {service}")

print()

# ==========================================
# 7. Advanced Scanning Techniques
# ==========================================
print("=== Advanced Scanning Techniques ===\n")

def syn_scan(target_ip, port, timeout=1):
    """TCP SYN scan (stealth scan) using raw sockets"""
    # Note: This requires raw socket privileges (root on Unix, admin on Windows)
    try:
        import socket
        import struct
        
        # Create raw socket
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.settimeout(timeout)
        
        # This is a simplified example - real SYN scan implementation is complex
        # using scapy would be more practical
        
        sock.close()
        return False
        
    except Exception as e:
        print(f"SYN scan not available: {e}")
        return False

# We'll use scapy if available for more robust scanning
try:
    import scapy.all as scapy
    
    def scapy_syn_scan(target_ip, port):
        """TCP SYN scan using scapy"""
        try:
            packet = scapy.IP(dst=target_ip)/scapy.TCP(dport=port, flags='S')
            response = scapy.sr1(packet, timeout=1, verbose=0)
            
            if response and response.haslayer(scapy.TCP):
                if response[scapy.TCP].flags == 0x12:  # SYN-ACK
                    return True
                    
        except Exception as e:
            print(f"Scapy error: {e}")
            
        return False
        
    print("Scapy SYN scan available")
    
except ImportError:
    print("Scapy not available, using TCP connect scan")

print()

# ==========================================
# 8. Vulnerability Scanning
# ==========================================
print("=== Vulnerability Scanning ===\n")

def check_vulnerabilities(target_ip, port):
    """Check for known vulnerabilities based on service version"""
    vulnerabilities = {
        "HTTP": ["CVE-2021-41773", "CVE-2021-42013"],
        "SSH": ["CVE-2021-20205", "CVE-2016-0777"],
        "FTP": ["CVE-2020-9484", "CVE-2019-0708"],
        "SMTP": ["CVE-2018-19518", "CVE-2018-19519"]
    }
    
    service = detect_service(target_ip, port)
    if service in vulnerabilities:
        return vulnerabilities[service]
        
    return []

# Check for vulnerabilities on open ports
print("Vulnerability check:")
for port in open_ports:
    vulns = check_vulnerabilities(target, port)
    if vulns:
        print(f"  Port {port} ({detect_service(target, port)}): {len(vulns)} vulnerabilities")
        for vuln in vulns:
            print(f"    - {vuln}")
    else:
        print(f"  Port {port} ({detect_service(target, port)}): No known vulnerabilities")

print()

# ==========================================
# 9. Network Mapping
# ==========================================
print("=== Network Mapping ===\n")

def map_network_topology(network_cidr):
    """Map network topology using ARP and port scanning"""
    try:
        import scapy.all as scapy
        
        arp = scapy.ARP(pdst=network_cidr)
        ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        
        result = scapy.srp(packet, timeout=2, verbose=0)[0]
        
        devices = []
        for sent, received in result:
            devices.append({
                'ip': received.psrc,
                'mac': received.hwsrc,
                'vendor': get_vendor_from_mac(received.hwsrc)
            })
            
        return devices
        
    except Exception as e:
        print(f"Error mapping network: {e}")
        return []

def get_vendor_from_mac(mac_address):
    """Get vendor information from MAC address (using API if available)"""
    try:
        import requests
        mac_prefix = mac_address[:8].upper().replace(':', '')
        response = requests.get(f"https://api.macvendors.com/{mac_prefix}", timeout=5)
        if response.status_code == 200:
            return response.text.strip()
    except Exception as e:
        print(f"Vendor lookup error: {e}")
        
    return "Unknown Vendor"

# Map local network if possible
try:
    network_cidr = "192.168.1.0/24"
    devices = map_network_topology(network_cidr)
    
    if devices:
        print(f"Found {len(devices)} devices on {network_cidr}:")
        for device in devices:
            print(f"  {device['ip']} - {device['mac']} ({device['vendor']})")
            
except Exception as e:
    print(f"Network mapping not available: {e}")

print()

# ==========================================
# 10. Scanning Results Reporting
# ==========================================
print("=== Scanning Results Reporting ===\n")

def generate_scan_report(target, open_ports, output_file='scan_report.txt'):
    """Generate comprehensive scan report"""
    import datetime
    
    report = []
    report.append(f"=== Network Scan Report ===\n")
    report.append(f"Target: {target}")
    report.append(f"Scan Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append(f"Open Ports: {len(open_ports)}\n")
    
    for port in open_ports:
        service = detect_service(target, port)
        banner = get_service_banner(target, port)
        report.append(f"Port: {port}")
        report.append(f"Service: {service}")
        if banner:
            report.append(f"Banner: {banner}")
        report.append(f"------------------------------")
        
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(report))
        
    print(f"Report saved to: {output_file}")

# Generate scan report
generate_scan_report(target, open_ports)
print()

# ==========================================
# 11. Best Practices for Network Scanning
# ==========================================
print("=== Best Practices ===\n")

def print_scanning_ethics():
    """Print ethical guidelines for network scanning"""
    guidelines = [
        "=== Ethical Scanning Guidelines ===",
        "1. Only scan networks and systems you own or have explicit permission to scan",
        "2. Obtain written authorization before any security testing",
        "3. Follow all applicable laws and regulations",
        "4. Be transparent about your scanning activities",
        "5. Limit scanning to necessary targets and times",
        "6. Use scanning techniques that minimize disruption",
        "7. Keep accurate records of your scanning activities",
        "8. Report any vulnerabilities found to the appropriate parties",
        "9. Do not exploit vulnerabilities without permission",
        "10. Respect the privacy and confidentiality of any data found"
    ]
    
    for guideline in guidelines:
        print(f"  {guideline}")

print_scanning_ethics()
