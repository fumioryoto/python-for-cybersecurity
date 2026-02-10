#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Socket Programming in Python for Cybersecurity
This script demonstrates socket programming for network communication
and security applications.
"""

import socket
import sys
import threading
import time
import struct
from datetime import datetime

# ==========================================
# 1. TCP Socket Basics
# ==========================================
print("=== TCP Socket Basics ===\n")

# TCP Server example
def tcp_server(host='localhost', port=12345):
    """Simple TCP server that responds to client connections"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((host, port))
            s.listen(5)
            print(f"TCP server listening on {host}:{port}")
            
            conn, addr = s.accept()
            with conn:
                print(f"Connected by {addr}")
                while True:
                    data = conn.recv(1024)
                    if not data:
                        break
                    print(f"Received: {data.decode('utf-8')}")
                    conn.sendall(data)
                    
    except Exception as e:
        print(f"TCP server error: {e}")

# TCP Client example
def tcp_client(host='localhost', port=12345):
    """Simple TCP client that sends data to server"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, port))
            message = f"Hello from client at {datetime.now().isoformat()}"
            s.sendall(message.encode('utf-8'))
            data = s.recv(1024)
            print(f"Received from server: {data.decode('utf-8')}")
            
    except Exception as e:
        print(f"TCP client error: {e}")

# Run TCP server and client in separate threads
server_thread = threading.Thread(target=tcp_server, daemon=True)
server_thread.start()
time.sleep(1)
tcp_client()

print()

# ==========================================
# 2. UDP Socket Basics
# ==========================================
print("=== UDP Socket Basics ===\n")

# UDP Server example
def udp_server(host='localhost', port=12346):
    """Simple UDP server that responds to client messages"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind((host, port))
            print(f"UDP server listening on {host}:{port}")
            
            while True:
                data, addr = s.recvfrom(1024)
                print(f"Received from {addr}: {data.decode('utf-8')}")
                response = f"Server received {len(data)} bytes"
                s.sendto(response.encode('utf-8'), addr)
                
    except Exception as e:
        print(f"UDP server error: {e}")

# UDP Client example
def udp_client(host='localhost', port=12346):
    """Simple UDP client that sends messages to server"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            message = f"UDP message from client at {datetime.now().isoformat()}"
            s.sendto(message.encode('utf-8'), (host, port))
            data, addr = s.recvfrom(1024)
            print(f"Received from server: {data.decode('utf-8')}")
            
    except Exception as e:
        print(f"UDP client error: {e}")

# Run UDP server and client in separate threads
server_thread = threading.Thread(target=udp_server, daemon=True)
server_thread.start()
time.sleep(1)
udp_client()

print()

# ==========================================
# 3. Port Scanning Basics
# ==========================================
print("=== Port Scanning Basics ===\n")

def scan_port(ip, port, timeout=1):
    """Scan a single port to check if it's open"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            return True
    except:
        return False

# Scan common ports on localhost
target_ip = '127.0.0.1'
common_ports = [21, 22, 23, 80, 443, 3389]

print(f"Scanning common ports on {target_ip}:")
for port in common_ports:
    is_open = scan_port(target_ip, port)
    status = "✅ Open" if is_open else "❌ Closed"
    print(f"  Port {port}: {status}")

print()

# ==========================================
# 4. Banner Grabbing
# ==========================================
print("=== Banner Grabbing ===\n")

def get_banner(ip, port, timeout=2):
    """Get banner information from open port"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            
            # Some services require a request to send banner
            if port == 80:
                s.sendall(b"GET / HTTP/1.1\r\nHost: %s\r\n\r\n" % ip.encode('utf-8'))
                
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner
    except Exception as e:
        return f"Error: {e}"

# Test banner grabbing on localhost
print(f"Banner grabbing on {target_ip}:")
for port in common_ports:
    if scan_port(target_ip, port):
        banner = get_banner(target_ip, port)
        print(f"  Port {port}: {banner[:80]}")

print()

# ==========================================
# 5. Network Information Gathering
# ==========================================
print("=== Network Information Gathering ===\n")

def get_host_info(host):
    """Get host information including IP addresses"""
    try:
        ip_address = socket.gethostbyname(host)
        print(f"IP address for {host}: {ip_address}")
        
        try:
            hostname, aliases, ips = socket.gethostbyaddr(ip_address)
            print(f"Hostname: {hostname}")
            if aliases:
                print(f"Aliases: {', '.join(aliases)}")
            if ips:
                print(f"IP addresses: {', '.join(ips)}")
        except:
            print("No PTR record found")
            
    except Exception as e:
        print(f"Error: {e}")

get_host_info('google.com')
print()

# ==========================================
# 6. DNS Operations
# ==========================================
print("=== DNS Operations ===\n")

def dns_query(host, qtype='A'):
    """Perform DNS query using socket"""
    # This is a simplified DNS query implementation
    import dnslib
    import struct
    
    try:
        # Create DNS query
        dns = dnslib.DNSRecord.question(host, qtype)
        query = dns.pack()
        
        # Send query to DNS server
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(2)
            s.sendto(query, ('8.8.8.8', 53))
            response, _ = s.recvfrom(1024)
            
        # Parse response
        dns_response = dnslib.DNSRecord.parse(response)
        answers = []
        
        for rr in dns_response.rr:
            answers.append(str(rr))
            
        return answers
        
    except Exception as e:
        return [f"Error: {e}"]

# Test DNS queries
print("DNS queries for 'google.com':")
for qtype in ['A', 'AAAA', 'MX', 'NS']:
    print(f"\n  {qtype} records:")
    try:
        responses = dns_query('google.com', qtype)
        for resp in responses:
            print(f"    {resp}")
    except Exception as e:
        print(f"    Error: {e}")

print()

# ==========================================
# 7. Network Packet Analysis
# ==========================================
print("=== Network Packet Analysis ===\n")

def capture_packets(interface, count=5):
    """Capture and analyze network packets using scapy"""
    try:
        import scapy.all as scapy
        
        print(f"Capturing {count} packets on {interface}...")
        packets = scapy.sniff(iface=interface, count=count)
        
        for i, packet in enumerate(packets):
            print(f"\nPacket {i+1}: {packet.summary()}")
            if packet.haslayer(scapy.IP):
                ip_layer = packet[scapy.IP]
                print(f"  Source: {ip_layer.src}")
                print(f"  Destination: {ip_layer.dst}")
                print(f"  Protocol: {ip_layer.proto}")
                
                if packet.haslayer(scapy.TCP):
                    tcp_layer = packet[scapy.TCP]
                    print(f"  TCP: {tcp_layer.sport} -> {tcp_layer.dport}")
                    print(f"  Flags: {tcp_layer.flags}")
                    
                elif packet.haslayer(scapy.UDP):
                    udp_layer = packet[scapy.UDP]
                    print(f"  UDP: {udp_layer.sport} -> {udp_layer.dport}")
                    
    except Exception as e:
        print(f"Error capturing packets: {e}")

# Test packet capture (this might require admin privileges)
try:
    import scapy.all as scapy
    interfaces = scapy.get_if_list()
    if interfaces:
        print(f"Available interfaces: {interfaces}")
        # Note: On some systems, you might need to run as administrator
except Exception as e:
    print(f"Scapy not available: {e}")

print()

# ==========================================
# 8. HTTP Request Handling
# ==========================================
print("=== HTTP Request Handling ===\n")

def send_http_request(host, port=80, path='/'):
    """Send custom HTTP request using socket"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, port))
            request = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            s.sendall(request.encode('utf-8'))
            
            response = b''
            while True:
                data = s.recv(1024)
                if not data:
                    break
                response += data
                
            return response.decode('utf-8', errors='ignore')
            
    except Exception as e:
        return f"Error: {e}"

# Test HTTP request
response = send_http_request('example.com')
print(f"HTTP Response from example.com ({len(response)} bytes):")
print(response[:200] + "...")

print()

# ==========================================
# 9. Network Security Examples
# ==========================================
print("=== Network Security Examples ===\n")

def detect_network_change():
    """Detect network interface changes"""
    try:
        import scapy.all as scapy
        interfaces = scapy.get_if_list()
        
        print(f"Current interfaces: {len(interfaces)}")
        for iface in interfaces:
            print(f"  {iface}")
            
    except Exception as e:
        print(f"Error detecting network changes: {e}")

detect_network_change()

print()

def analyze_packet_for_suspicious_content():
    """Analyze captured packets for suspicious content"""
    import scapy.all as scapy
    
    try:
        # Load saved packet capture (create one for testing)
        test_pcap = 'test.pcap'
        if not __import__('os').path.exists(test_pcap):
            # Create a dummy pcap file for testing
            packets = []
            for i in range(3):
                pkt = scapy.IP(src=f"192.168.1.{i+100}", dst=f"10.0.0.{i+1}")/scapy.TCP(sport=1024+i, dport=80+i)/b"Test data"
                packets.append(pkt)
            scapy.wrpcap(test_pcap, packets)
            print(f"Created test capture file: {test_pcap}")
            
        # Read and analyze packets
        packets = scapy.rdpcap(test_pcap)
        
        print(f"Analyzing {len(packets)} packets from {test_pcap}:")
        for i, packet in enumerate(packets):
            if packet.haslayer(scapy.Raw):
                payload = packet[scapy.Raw].load
                # Check for common exploit patterns
                suspicious_patterns = [b'sql', b'xss', b'command', b'admin']
                for pattern in suspicious_patterns:
                    if pattern in payload.lower():
                        print(f"Packet {i+1} contains suspicious content '{pattern.decode()}'")
                        
    except Exception as e:
        print(f"Error analyzing packets: {e}")

analyze_packet_for_suspicious_content()

print()

# ==========================================
# 10. Cleanup
# ==========================================
print("=== Cleanup ===\n")

import os
if os.path.exists('test.pcap'):
    os.remove('test.pcap')
    print("Removed test.pcap file")
