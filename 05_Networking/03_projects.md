# Networking Projects

## Project 1: Advanced Port Scanner

### Description

Create a multi-threaded port scanner with service detection, banner grabbing, and OS fingerprinting capabilities.

### Features

- Scan multiple ports on a single target
- Scan entire network ranges (CIDR notation)
- Multi-threaded scanning for fast performance
- Service detection based on port number
- Banner grabbing to identify service versions
- OS fingerprinting using TCP/IP stack behavior
- Generate detailed scan reports

### Requirements

- Python 3.x
- socket module (built-in)
- threading module (built-in)
- concurrent.futures module (built-in)
- ipaddress module (built-in)
- scapy library

### Starter Code

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced Port Scanner - Main Application
"""

import argparse
import socket
import threading
import time
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
from datetime import datetime
import os

class AdvancedPortScanner:
    """Advanced port scanner with multiple scanning capabilities"""

    def __init__(self, target, ports=None, threads=50, timeout=1):
        self.target = target
        self.threads = threads
        self.timeout = timeout

        if ports:
            self.ports = self._parse_port_range(ports)
        else:
            self.ports = range(1, 1024)

        self.open_ports = []
        self.scan_results = []

    def _parse_port_range(self, port_spec):
        """Parse port specification (e.g., '1-100,443' or '80')"""
        ports = []

        if ',' in port_spec:
            ranges = port_spec.split(',')
        else:
            ranges = [port_spec]

        for rng in ranges:
            rng = rng.strip()

            if '-' in rng:
                start, end = map(int, rng.split('-'))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(rng))

        return sorted(set(ports))

    def scan_single_port(self, port):
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, port))
            sock.close()

            # Get service information
            service_info = self._get_service_info(port)

            return {
                'port': port,
                'status': 'open',
                'service': service_info['service'],
                'banner': service_info['banner']
            }

        except Exception as e:
            return {
                'port': port,
                'status': 'closed',
                'service': 'Unknown',
                'banner': ''
            }

    def _get_service_info(self, port):
        """Get service information from open port"""
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

        service = service_map.get(port, "Unknown")
        banner = self._get_banner(port)

        return {
            'service': service,
            'banner': banner
        }

    def _get_banner(self, port):
        """Get service banner from open port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target, port))

            if port == 80:
                sock.sendall(b"GET / HTTP/1.1\r\nHost: %s\r\n\r\n" % self.target.encode('utf-8'))

            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()

            return banner

        except:
            return ""

    def scan(self):
        """Main scan method"""
        print(f"Scanning {self.target} for {len(self.ports)} ports...")
        start_time = time.time()

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self.scan_single_port, port) for port in self.ports]

            completed = 0
            total = len(self.ports)

            for future in as_completed(futures):
                result = future.result()
                self.scan_results.append(result)

                if result['status'] == 'open':
                    self.open_ports.append(result['port'])

                completed += 1
                self._print_progress(completed, total)

        self.scan_time = time.time() - start_time
        print("\nScan complete!")

    def _print_progress(self, completed, total):
        """Print scan progress"""
        percentage = (completed / total) * 100
        sys.stdout.write(f"\rProgress: {completed}/{total} ({percentage:.1f}%)")
        sys.stdout.flush()

    def print_report(self):
        """Print scan report to console"""
        print(f"\n{'='*60}")
        print(f"PORT SCAN REPORT - {self.target}")
        print(f"{'='*60}")
        print(f"Scan Time: {self.scan_time:.2f} seconds")
        print(f"Open Ports: {len(self.open_ports)}")
        print(f"{'='*60}")
        print(f"{'Port':<8} {'Status':<10} {'Service':<20} {'Banner':<50}")
        print(f"-"*100)

        for result in sorted(self.scan_results, key=lambda x: x['port']):
            if result['status'] == 'open':
                port_str = f"{result['port']}"
                status = f"✅ Open"
                service = result['service']
                banner = result['banner'][:45] + '...' if len(result['banner']) > 45 else result['banner']

                print(f"{port_str:<8} {status:<10} {service:<20} {banner:<50}")

    def save_report(self, filename):
        """Save scan report to file"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"PORT SCAN REPORT - {self.target}\n")
                f.write(f"Scan Time: {self.scan_time:.2f} seconds\n")
                f.write(f"Open Ports: {len(self.open_ports)}\n")
                f.write("\n")
                f.write(f"{'Port':<8} {'Status':<10} {'Service':<20} {'Banner':<50}\n")
                f.write(f"-"*100 + "\n")

                for result in sorted(self.scan_results, key=lambda x: x['port']):
                    if result['status'] == 'open':
                        line = f"{result['port']:<8} {'Open':<10} {result['service']:<20} {result['banner'][:45]:<50}\n"
                        f.write(line)

            print(f"Report saved to: {filename}")

        except Exception as e:
            print(f"Error saving report: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="Advanced Port Scanner for Cybersecurity"
    )

    parser.add_argument(
        "target",
        help="Target IP address or host name to scan"
    )

    parser.add_argument(
        "-p", "--ports", default="1-1024",
        help="Port range to scan (e.g., '1-100,443' or '80') (default: 1-1024)"
    )

    parser.add_argument(
        "-t", "--threads", type=int, default=50,
        help="Number of concurrent threads (default: 50)"
    )

    parser.add_argument(
        "-T", "--timeout", type=float, default=1.0,
        help="Connection timeout in seconds (default: 1.0)"
    )

    parser.add_argument(
        "-o", "--output",
        help="Output file for scan report"
    )

    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable verbose output"
    )

    args = parser.parse_args()

    try:
        scanner = AdvancedPortScanner(
            args.target,
            args.ports,
            args.threads,
            args.timeout
        )

        scanner.scan()
        scanner.print_report()

        if args.output:
            scanner.save_report(args.output)

    except Exception as e:
        print(f"Error: {e}")
        if args.verbose:
            import traceback
            print(traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    main()
```

### Challenges

1. Implement TCP SYN scanning using raw sockets
2. Add UDP port scanning capabilities
3. Implement OS fingerprinting using TCP options
4. Add vulnerability detection based on banner information
5. Create graphical user interface (GUI) for scanner
6. Implement network range scanning with CIDR notation
7. Add export to CSV/JSON formats

## Project 2: Network Sniffer and Analyzer

### Description

Create a network packet sniffer and analyzer that can capture, decode, and analyze network traffic.

### Features

- Capture network packets using raw sockets
- Decode various network protocols (Ethernet, IP, TCP, UDP, etc.)
- Extract and display packet information (source/destination addresses, ports, protocols, etc.)
- Detect suspicious network activity
- Save captured packets to PCAP file
- Load and analyze PCAP files
- Generate analysis reports

### Requirements

- Python 3.x
- scapy library (for packet capture and decoding)
- matplotlib (for visualization)
- numpy (for data analysis)

### Starter Code

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Network Sniffer and Analyzer - Main Application
"""

import argparse
import sys
import os
import scapy.all as scapy
from datetime import datetime
import matplotlib.pyplot as plt
import numpy as np
from collections import Counter

class NetworkSniffer:
    """Network packet sniffer and analyzer"""

    def __init__(self, interface=None, output_file=None):
        self.interface = interface
        self.output_file = output_file
        self.captured_packets = []
        self.protocol_counts = Counter()
        self.source_ips = Counter()
        self.destination_ips = Counter()
        self.source_ports = Counter()
        self.destination_ports = Counter()

    def capture_packets(self, count=100, duration=None):
        """Capture network packets"""
        print(f"Starting packet capture {'on ' + self.interface if self.interface else ''}...")

        if duration:
            self.captured_packets = scapy.sniff(
                iface=self.interface,
                timeout=duration,
                store=True
            )
        else:
            self.captured_packets = scapy.sniff(
                iface=self.interface,
                count=count,
                store=True
            )

        print(f"Captured {len(self.captured_packets)} packets")

        if self.output_file:
            scapy.wrpcap(self.output_file, self.captured_packets)
            print(f"Packets saved to {self.output_file}")

    def load_packets(self, filename):
        """Load packets from PCAP file"""
        print(f"Loading packets from {filename}...")

        if not os.path.exists(filename):
            raise FileNotFoundError(f"File not found: {filename}")

        self.captured_packets = scapy.rdpcap(filename)
        print(f"Loaded {len(self.captured_packets)} packets")

    def analyze_packets(self):
        """Analyze captured packets"""
        print("Analyzing packets...")

        for packet in self.captured_packets:
            self._analyze_packet(packet)

        print(f"Analysis complete:")
        print(f"  Total packets: {len(self.captured_packets)}")
        print(f"  Protocols: {dict(self.protocol_counts)}")
        print(f"  Source IPs: {len(self.source_ips)} unique addresses")
        print(f"  Destination IPs: {len(self.destination_ips)} unique addresses")

    def _analyze_packet(self, packet):
        """Analyze individual packet"""
        # Protocol detection
        if packet.haslayer(scapy.IP):
            proto = packet[scapy.IP].proto
            self.protocol_counts[proto] += 1

            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            self.source_ips[src_ip] += 1
            self.destination_ips[dst_ip] += 1

            if packet.haslayer(scapy.TCP):
                src_port = packet[scapy.TCP].sport
                dst_port = packet[scapy.TCP].dport
                self.source_ports[src_port] += 1
                self.destination_ports[dst_port] += 1

            elif packet.haslayer(scapy.UDP):
                src_port = packet[scapy.UDP].sport
                dst_port = packet[scapy.UDP].dport
                self.source_ports[src_port] += 1
                self.destination_ports[dst_port] += 1

    def print_summary(self):
        """Print packet analysis summary"""
        print(f"\n{'='*60}")
        print(f"NETWORK TRAFFIC SUMMARY")
        print(f"{'='*60}")

        # Protocol distribution
        print(f"\nProtocol Distribution:")
        for proto, count in sorted(self.protocol_counts.items()):
            protocol_name = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(proto, f"Unknown ({proto})")
            percentage = (count / len(self.captured_packets)) * 100
            print(f"  {protocol_name:<8} : {count:4} packets ({percentage:.1f}%)")

        # Top source IPs
        print(f"\nTop 5 Source IPs:")
        for ip, count in self.source_ips.most_common(5):
            percentage = (count / len(self.captured_packets)) * 100
            print(f"  {ip:<15} : {count:4} packets ({percentage:.1f}%)")

        # Top destination IPs
        print(f"\nTop 5 Destination IPs:")
        for ip, count in self.destination_ips.most_common(5):
            percentage = (count / len(self.captured_packets)) * 100
            print(f"  {ip:<15} : {count:4} packets ({percentage:.1f}%)")

        # Top ports
        print(f"\nTop 5 Source Ports:")
        for port, count in self.source_ports.most_common(5):
            percentage = (count / len(self.captured_packets)) * 100
            print(f"  {port:<5} : {count:4} packets ({percentage:.1f}%)")

        print(f"\nTop 5 Destination Ports:")
        for port, count in self.destination_ports.most_common(5):
            percentage = (count / len(self.captured_packets)) * 100
            print(f"  {port:<5} : {count:4} packets ({percentage:.1f}%)")

    def generate_charts(self, output_dir="charts"):
        """Generate visualization charts"""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        # Protocol distribution pie chart
        protocols = [
            {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(proto, f"Unknown ({proto})")
            for proto, count in self.protocol_counts.items()
        ]
        counts = list(self.protocol_counts.values())

        plt.figure(figsize=(8, 6))
        plt.pie(counts, labels=protocols, autopct='%1.1f%%')
        plt.title('Protocol Distribution')
        plt.savefig(os.path.join(output_dir, 'protocol_distribution.png'), dpi=300, bbox_inches='tight')

        # Top source IPs bar chart
        plt.figure(figsize=(10, 6))
        top_ips = self.source_ips.most_common(10)
        ips, counts = zip(*top_ips)
        plt.bar(ips, counts)
        plt.title('Top 10 Source IPs')
        plt.xlabel('IP Address')
        plt.ylabel('Packet Count')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'top_source_ips.png'), dpi=300, bbox_inches='tight')

        print(f"Charts saved to: {os.path.abspath(output_dir)}")

    def save_analysis_report(self, filename="analysis_report.txt"):
        """Save analysis report to file"""
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"NETWORK TRAFFIC ANALYSIS REPORT\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Packets: {len(self.captured_packets)}\n")
            f.write("\n" + "-"*60 + "\n\n")

            f.write(self._format_protocol_counts())
            f.write("\n" + "-"*60 + "\n")
            f.write(self._format_ip_summary())
            f.write("\n" + "-"*60 + "\n")
            f.write(self._format_port_summary())

        print(f"Report saved to: {filename}")

    def _format_protocol_counts(self):
        """Format protocol distribution report"""
        report = []
        report.append("Protocol Distribution:")

        sorted_protocols = sorted(self.protocol_counts.items(), key=lambda x: x[1], reverse=True)

        for proto, count in sorted_protocols:
            protocol_name = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(proto, f"Unknown ({proto})")
            percentage = (count / len(self.captured_packets)) * 100
            report.append(f"  {protocol_name:<8} : {count:4} packets ({percentage:.1f}%)")

        return "\n".join(report)

    def _format_ip_summary(self):
        """Format IP address summary report"""
        report = []
        report.append("Top Source IP Addresses:")

        for ip, count in self.source_ips.most_common(10):
            percentage = (count / len(self.captured_packets)) * 100
            report.append(f"  {ip:<15} : {count:4} packets ({percentage:.1f}%)")

        report.append("")
        report.append("Top Destination IP Addresses:")

        for ip, count in self.destination_ips.most_common(10):
            percentage = (count / len(self.captured_packets)) * 100
            report.append(f"  {ip:<15} : {count:4} packets ({percentage:.1f}%)")

        return "\n".join(report)

    def _format_port_summary(self):
        """Format port summary report"""
        report = []
        report.append("Top Source Ports:")

        for port, count in self.source_ports.most_common(10):
            percentage = (count / len(self.captured_packets)) * 100
            report.append(f"  {port:<5} : {count:4} packets ({percentage:.1f}%)")

        report.append("")
        report.append("Top Destination Ports:")

        for port, count in self.destination_ports.most_common(10):
            percentage = (count / len(self.captured_packets)) * 100
            report.append(f"  {port:<5} : {count:4} packets ({percentage:.1f}%)")

        return "\n".join(report)

def main():
    parser = argparse.ArgumentParser(
        description="Network Sniffer and Analyzer"
    )

    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument(
        "-c", "--capture", action="store_true",
        help="Capture packets from network interface"
    )
    mode_group.add_argument(
        "-r", "--read", metavar="PCAP_FILE",
        help="Read packets from existing PCAP file"
    )

    parser.add_argument(
        "-i", "--interface",
        help="Network interface to capture from (e.g., eth0)"
    )

    parser.add_argument(
        "-n", "--count", type=int, default=100,
        help="Number of packets to capture (default: 100)"
    )

    parser.add_argument(
        "-t", "--time", type=int,
        help="Capture duration in seconds (overrides packet count)"
    )

    parser.add_argument(
        "-o", "--output", metavar="PCAP_FILE",
        help="Output file for captured packets"
    )

    parser.add_argument(
        "-a", "--analyze", action="store_true",
        help="Analyze captured packets"
    )

    parser.add_argument(
        "-s", "--summary", action="store_true",
        help="Print packet analysis summary"
    )

    parser.add_argument(
        "-g", "--graphs", metavar="OUTPUT_DIR",
        help="Generate analysis charts in specified directory"
    )

    parser.add_argument(
        "-R", "--report", metavar="OUTPUT_FILE",
        help="Save analysis report to file"
    )

    args = parser.parse_args()

    try:
        sniffer = NetworkSniffer(
            interface=args.interface,
            output_file=args.output
        )

        if args.capture:
            if args.time:
                sniffer.capture_packets(duration=args.time)
            else:
                sniffer.capture_packets(count=args.count)

        elif args.read:
            sniffer.load_packets(args.read)

        if args.analyze:
            sniffer.analyze_packets()

        if args.summary:
            sniffer.print_summary()

        if args.graphs:
            sniffer.generate_charts(args.graphs)

        if args.report:
            sniffer.save_analysis_report(args.report)

    except Exception as e:
        print(f"Error: {e}")
        if args.debug:
            import traceback
            print(traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    main()
```

### Challenges

1. Implement advanced protocol decoding (HTTP, DNS, SSL/TLS)
2. Add packet filtering by protocol, source/destination IP, port
3. Detect suspicious network activity (port scans, DDOS, etc.)
4. Create real-time packet capture and visualization
5. Implement packet injection and modification capabilities
6. Add support for more packet formats and protocols
7. Create web-based interface for analysis results

## Project 3: Network Intrusion Detection System (NIDS)

### Description

Create a network intrusion detection system that monitors network traffic and detects potential security threats.

### Features

- Monitor network interfaces in real-time
- Detect common network attacks and suspicious activity
- Use signature-based and anomaly-based detection methods
- Generate alerts and notifications
- Analyze network traffic patterns
- Log events to files for later analysis
- Provide visualization of network activity

### Requirements

- Python 3.x
- scapy library
- pandas library
- numpy library
- scikit-learn (for machine learning-based anomaly detection)

### Starter Code

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Network Intrusion Detection System (NIDS)
"""

import argparse
import sys
import time
import scapy.all as scapy
from datetime import datetime
import json
import os
from collections import deque, defaultdict

class NetworkIntrusionDetector:
    """Network Intrusion Detection System"""

    def __init__(self, interface, log_file="intrusion_log.txt"):
        self.interface = interface
        self.log_file = log_file
        self.attack_signatures = self._load_attack_signatures()
        self.connection_tracker = defaultdict(deque)
        self.anomaly_detector = None

    def _load_attack_signatures(self):
        """Load attack signatures from file"""
        signatures = {
            "port_scan": {
                "name": "Port Scan Detection",
                "description": "Multiple connection attempts to different ports on the same host",
                "threshold": 10,  # More than 10 unique ports in 60 seconds
                "time_window": 60
            },
            "ddos_attack": {
                "name": "DDoS Attack Detection",
                "description": "Excessive traffic from a single source",
                "threshold": 1000,  # More than 1000 packets in 60 seconds
                "time_window": 60
            },
            "tcp_syn_flood": {
                "name": "TCP SYN Flood",
                "description": "Excessive SYN packets without corresponding ACK packets",
                "threshold": 100,
                "time_window": 60
            }
        }

        # Try to load signatures from file
        sig_file = "attack_signatures.json"
        if os.path.exists(sig_file):
            try:
                with open(sig_file, 'r', encoding='utf-8') as f:
                    loaded = json.load(f)
                    signatures.update(loaded)
            except Exception as e:
                print(f"Warning: Failed to load signatures: {e}")

        return signatures

    def start_monitoring(self, duration=60):
        """Start network monitoring"""
        print(f"Starting NIDS on interface {self.interface}")
        print("Press Ctrl+C to stop")

        start_time = time.time()

        try:
            while True:
                # Capture packets
                packets = scapy.sniff(
                    iface=self.interface,
                    timeout=1,
                    count=100
                )

                for packet in packets:
                    self._analyze_packet(packet)

                # Remove expired entries from connection tracker
                self._cleanup_expired_connections()

                # Check if we've reached duration
                if duration and (time.time() - start_time) > duration:
                    break

        except KeyboardInterrupt:
            print("\nMonitoring stopped by user")
        except Exception as e:
            print(f"Error: {e}")

        print("\nMonitoring complete")

    def _analyze_packet(self, packet):
        """Analyze individual packet for attacks"""
        # Track connection information
        if packet.haslayer(scapy.IP) and (packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP)):
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst

            if packet.haslayer(scapy.TCP):
                src_port = packet[scapy.TCP].sport
                dst_port = packet[scapy.TCP].dport
                proto = "TCP"
                flags = str(packet[scapy.TCP].flags)
            else:
                src_port = packet[scapy.UDP].sport
                dst_port = packet[scapy.UDP].dport
                proto = "UDP"
                flags = ""

            # Create connection key
            conn_key = (src_ip, dst_ip, src_port, dst_port, proto)
            self.connection_tracker[conn_key].append(datetime.now())

            # Check for attacks
            self._check_for_attacks(src_ip, dst_ip, src_port, dst_port, proto, flags)

    def _check_for_attacks(self, src_ip, dst_ip, src_port, dst_port, proto, flags):
        """Check for attacks based on packet information"""
        current_time = datetime.now()

        # Check for port scan
        if self._detect_port_scan(src_ip, current_time):
            self._alert("port_scan", src_ip, dst_ip)

        # Check for DDoS attack
        if self._detect_ddos(src_ip, current_time):
            self._alert("ddos_attack", src_ip, dst_ip)

        # Check for TCP SYN flood
        if proto == "TCP" and flags == "S" and self._detect_syn_flood(src_ip, current_time):
            self._alert("tcp_syn_flood", src_ip, dst_ip)

    def _detect_port_scan(self, src_ip, current_time):
        """Detect port scan based on multiple destination ports from same source"""
        # Get all connections from this source IP
        src_connections = [
            conn for conn, timestamps in self.connection_tracker.items()
            if conn[0] == src_ip
        ]

        # Check if there are connections to many different ports
        unique_dst_ports = set(conn[3] for conn in src_connections)

        # Check if any of the connections are recent
        recent_connections = []
        for conn in src_connections:
            if self.connection_tracker[conn] and (current_time - self.connection_tracker[conn][-1]).total_seconds() < self.attack_signatures["port_scan"]["time_window"]:
                recent_connections.append(conn)

        unique_recent_ports = set(conn[3] for conn in recent_connections)

        return len(unique_recent_ports) > self.attack_signatures["port_scan"]["threshold"]

    def _detect_ddos(self, src_ip, current_time):
        """Detect DDoS attack based on packet rate"""
        # Count packets from this source in time window
        packet_count = 0

        for conn, timestamps in self.connection_tracker.items():
            if conn[0] == src_ip:
                for ts in timestamps:
                    if (current_time - ts).total_seconds() < self.attack_signatures["ddos_attack"]["time_window"]:
                        packet_count += 1

        return packet_count > self.attack_signatures["ddos_attack"]["threshold"]

    def _detect_syn_flood(self, src_ip, current_time):
        """Detect TCP SYN flood based on SYN packet rate"""
        syn_packets = 0

        for conn, timestamps in self.connection_tracker.items():
            if conn[0] == src_ip and conn[4] == "TCP":
                # Check if this connection has been active
                if timestamps and (current_time - timestamps[-1]).total_seconds() < self.attack_signatures["tcp_syn_flood"]["time_window"]:
                    syn_packets += 1

        return syn_packets > self.attack_signatures["tcp_syn_flood"]["threshold"]

    def _cleanup_expired_connections(self):
        """Remove connections older than time window from tracker"""
        current_time = datetime.now()

        connections_to_remove = []

        for conn, timestamps in self.connection_tracker.items():
            # Keep only recent timestamps
            recent_timestamps = [
                ts for ts in timestamps
                if (current_time - ts).total_seconds() < max(signature["time_window"] for signature in self.attack_signatures.values())
            ]

            if recent_timestamps:
                self.connection_tracker[conn] = deque(recent_timestamps)
            else:
                connections_to_remove.append(conn)

        for conn in connections_to_remove:
            del self.connection_tracker[conn]

    def _alert(self, attack_type, src_ip, dst_ip):
        """Generate alert for detected attack"""
        alert = {
            "timestamp": datetime.now().isoformat(),
            "attack_type": attack_type,
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "description": self.attack_signatures[attack_type]["description"]
        }

        print(f"ALERT: [{alert['timestamp']}] {alert['attack_type']} from {alert['source_ip']} to {alert['destination_ip']}")

        # Log alert
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                json.dump(alert, f)
                f.write('\n')
        except Exception as e:
            print(f"Error logging alert: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="Network Intrusion Detection System"
    )

    parser.add_argument(
        "-i", "--interface", required=True,
        help="Network interface to monitor (e.g., eth0)"
    )

    parser.add_argument(
        "-l", "--log", default="intrusion_log.txt",
        help="Log file for intrusion alerts"
    )

    parser.add_argument(
        "-t", "--time", type=int, default=60,
        help="Monitoring duration in seconds (default: 60)"
    )

    args = parser.parse_args()

    try:
        nids = NetworkIntrusionDetector(args.interface, args.log)
        nids.start_monitoring(duration=args.time)

        print(f"Log file saved to: {os.path.abspath(args.log)}")

    except Exception as e:
        print(f"Error: {e}")
        import traceback
        print(traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    main()
```

### Challenges

1. Implement signature-based detection for common attack patterns
2. Add machine learning-based anomaly detection
3. Create real-time visualization of network traffic
4. Implement alerting mechanisms (email, Slack notifications)
5. Add support for more attack types and detection methods
6. Create web-based interface for NIDS management and visualization
7. Implement integration with firewall systems for automated response
