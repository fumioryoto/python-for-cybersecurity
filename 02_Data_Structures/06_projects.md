# Data Structures - Projects

## Project 1: Network Packet Analyzer

### Description

Create a network packet analyzer that captures, stores, and analyzes network packets using various data structures for efficient processing and reporting.

### Requirements

- Capture network packets and store them in appropriate data structures
- Analyze packet data for patterns and anomalies
- Provide statistics and reports on network traffic
- Support filtering and searching of packets
- Visualize packet flows

### Starter Code

```python
#!/usr/bin/env python3
import scapy.all as scapy
from collections import deque, defaultdict
import datetime
import argparse

class PacketAnalyzer:
    """Network packet analyzer using Scapy"""

    def __init__(self):
        self.packet_queue = deque()
        self.packet_count = 0
        self.traffic_by_protocol = defaultdict(int)
        self.traffic_by_ip = defaultdict(int)
        self.connection_tracker = defaultdict(list)
        self.packet_history = deque(maxlen=1000)

    def packet_callback(self, packet):
        """Callback for captured packets"""
        self.packet_count += 1
        self.packet_queue.append(packet)
        self.packet_history.append(packet)

        # Track traffic by protocol
        if packet.haslayer(scapy.IP):
            protocol = packet[scapy.IP].proto
            self.traffic_by_protocol[protocol] += 1

            # Track traffic by IP
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            self.traffic_by_ip[src_ip] += 1
            self.traffic_by_ip[dst_ip] += 1

            # Track connections
            if packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP):
                src_port = packet.sport
                dst_port = packet.dport
                connection_key = (src_ip, dst_ip, src_port, dst_port)
                self.connection_tracker[connection_key].append({
                    "timestamp": datetime.datetime.now(),
                    "size": len(packet),
                    "flags": self._get_tcp_flags(packet)
                })

    def _get_tcp_flags(self, packet):
        """Extract TCP flags from packet"""
        flags = []
        if packet.haslayer(scapy.TCP):
            tcp_flags = packet[scapy.TCP].flags
            flag_dict = {
                'F': 'FIN', 'S': 'SYN', 'R': 'RST', 'P': 'PSH',
                'A': 'ACK', 'U': 'URG', 'E': 'ECE', 'C': 'CWR'
            }
            flags = [flag_dict.get(flag, flag) for flag in tcp_flags]
        return flags

    def analyze_packets(self):
        """Analyze captured packets"""
        while self.packet_queue:
            packet = self.packet_queue.popleft()

            # Example: Detect SYN packets (SYN flood attempt)
            if packet.haslayer(scapy.TCP) and packet[scapy.TCP].flags == 0x02:
                print(f"SYN packet detected from {packet[scapy.IP].src}:{packet[scapy.TCP].sport}")

            # Example: Detect large packets (> 1000 bytes)
            if len(packet) > 1000:
                print(f"Large packet detected: {len(packet)} bytes from {packet[scapy.IP].src}")

    def print_statistics(self):
        """Print network traffic statistics"""
        print(f"\n=== Network Traffic Statistics ===")
        print(f"Total packets captured: {self.packet_count}")
        print(f"\nTraffic by Protocol:")
        for protocol, count in self.traffic_by_protocol.items():
            print(f"  Protocol {protocol}: {count} packets")
        print(f"\nTraffic by IP Address:")
        for ip, count in sorted(self.traffic_by_ip.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"  {ip}: {count} packets")
        print(f"\nActive connections: {len(self.connection_tracker)}")

    def start_sniffing(self, interface, count=0, timeout=None):
        """Start packet capture"""
        print(f"Sniffing packets on {interface}")
        if timeout:
            scapy.sniff(iface=interface, prn=self.packet_callback, count=count, timeout=timeout)
        else:
            scapy.sniff(iface=interface, prn=self.packet_callback, count=count)

        print(f"Stopped sniffing after capturing {self.packet_count} packets")

    def save_packets(self, filename):
        """Save packets to PCAP file"""
        try:
            scapy.wrpcap(filename, list(self.packet_history))
            print(f"Packets saved to {filename}")
        except Exception as e:
            print(f"Error saving packets: {e}")

    def load_packets(self, filename):
        """Load packets from PCAP file"""
        try:
            packets = scapy.rdpcap(filename)
            for packet in packets:
                self.packet_callback(packet)
            print(f"Loaded {len(packets)} packets from {filename}")
        except Exception as e:
            print(f"Error loading packets: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="Network Packet Analyzer"
    )
    parser.add_argument(
        "-i", "--interface", default="eth0",
        help="Network interface to sniff on (default: eth0)"
    )
    parser.add_argument(
        "-c", "--count", type=int, default=0,
        help="Number of packets to capture (0 for unlimited)"
    )
    parser.add_argument(
        "-t", "--timeout", type=int,
        help="Sniffing duration in seconds"
    )
    parser.add_argument(
        "-r", "--read",
        help="Read packets from PCAP file instead of live capture"
    )
    parser.add_argument(
        "-w", "--write",
        help="Save captured packets to PCAP file"
    )

    args = parser.parse_args()

    analyzer = PacketAnalyzer()

    if args.read:
        analyzer.load_packets(args.read)
    else:
        analyzer.start_sniffing(args.interface, args.count, args.timeout)

    analyzer.analyze_packets()
    analyzer.print_statistics()

    if args.write:
        analyzer.save_packets(args.write)

if __name__ == "__main__":
    main()
```

### Challenges

1. Implement more advanced packet filtering (by protocol, port, IP)
2. Add real-time visualization of packet flows
3. Implement anomaly detection algorithms
4. Create interactive reports and dashboards
5. Support live packet injection for testing

## Project 2: Vulnerability Management System

### Description

Create a vulnerability management system that tracks and prioritizes security vulnerabilities using various data structures for efficient management.

### Requirements

- Track vulnerabilities with detailed information
- Prioritize vulnerabilities based on CVSS score
- Manage remediation status
- Generate comprehensive reports
- Support for multiple scan inputs and formats

### Starter Code

```python
#!/usr/bin/env python3
import json
import csv
import heapq
from collections import defaultdict

class Vulnerability:
    """Vulnerability class with all relevant details"""
    def __init__(self, cve, product, cvss_score, severity, description, published_date):
        self.cve = cve
        self.product = product
        self.cvss_score = cvss_score
        self.severity = severity
        self.description = description
        self.published_date = published_date
        self.status = "Open"
        self.remediation_date = None

    def __lt__(self, other):
        """Compare vulnerabilities by CVSS score (for heap)"""
        return self.cvss_score > other.cvss_score

class VulnerabilityManager:
    """Manager for vulnerability tracking and prioritization"""
    def __init__(self):
        self.vulnerabilities = {}
        self.vulnerability_heap = []
        self.vulnerabilities_by_product = defaultdict(list)
        self.vulnerabilities_by_severity = defaultdict(list)

    def add_vulnerability(self, cve, product, cvss_score, severity, description, published_date):
        """Add vulnerability to system"""
        vulnerability = Vulnerability(
            cve, product, cvss_score, severity, description, published_date
        )
        self.vulnerabilities[cve] = vulnerability
        self.vulnerabilities_by_product[product].append(vulnerability)
        self.vulnerabilities_by_severity[severity].append(vulnerability)
        heapq.heappush(self.vulnerability_heap, vulnerability)

    def get_top_vulnerabilities(self, count=10):
        """Get top N vulnerabilities by CVSS score"""
        return heapq.nsmallest(count, self.vulnerability_heap)

    def update_vulnerability_status(self, cve, status, remediation_date=None):
        """Update vulnerability status"""
        if cve in self.vulnerabilities:
            self.vulnerabilities[cve].status = status
            if remediation_date:
                self.vulnerabilities[cve].remediation_date = remediation_date

    def get_vulnerabilities_by_product(self, product):
        """Get vulnerabilities for specific product"""
        return self.vulnerabilities_by_product.get(product, [])

    def get_vulnerabilities_by_severity(self, severity):
        """Get vulnerabilities by severity level"""
        return self.vulnerabilities_by_severity.get(severity, [])

    def generate_report(self):
        """Generate comprehensive vulnerability report"""
        report = {
            "total": len(self.vulnerabilities),
            "by_severity": {
                severity: len(vulns)
                for severity, vulns in self.vulnerabilities_by_severity.items()
            },
            "by_product": {
                product: len(vulns)
                for product, vulns in self.vulnerabilities_by_product.items()
            },
            "by_status": defaultdict(int),
            "top_vulnerabilities": [v.cve for v in self.get_top_vulnerabilities(10)]
        }

        for vulnerability in self.vulnerabilities.values():
            report["by_status"][vulnerability.status] += 1

        return report

    def load_from_json(self, filename):
        """Load vulnerabilities from JSON file"""
        with open(filename, 'r') as f:
            data = json.load(f)

        for vuln in data:
            self.add_vulnerability(
                vuln.get("cve"),
                vuln.get("product"),
                vuln.get("cvss_score"),
                vuln.get("severity"),
                vuln.get("description"),
                vuln.get("published_date")
            )

    def save_to_json(self, filename):
        """Save vulnerabilities to JSON file"""
        data = []
        for vuln in self.vulnerabilities.values():
            data.append({
                "cve": vuln.cve,
                "product": vuln.product,
                "cvss_score": vuln.cvss_score,
                "severity": vuln.severity,
                "description": vuln.description,
                "published_date": vuln.published_date,
                "status": vuln.status,
                "remediation_date": vuln.remediation_date
            })

        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)

    def export_csv(self, filename):
        """Export vulnerabilities to CSV file"""
        with open(filename, 'w', newline='') as csvfile:
            fieldnames = ["CVE", "Product", "CVSS Score", "Severity",
                        "Status", "Published Date", "Remediation Date"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            writer.writeheader()
            for vuln in self.vulnerabilities.values():
                writer.writerow({
                    "CVE": vuln.cve,
                    "Product": vuln.product,
                    "CVSS Score": vuln.cvss_score,
                    "Severity": vuln.severity,
                    "Status": vuln.status,
                    "Published Date": vuln.published_date,
                    "Remediation Date": vuln.remediation_date
                })

def main():
    # Sample vulnerability data
    sample_vulnerabilities = [
        {"cve": "CVE-2023-1234", "product": "Apache HTTP Server", "cvss_score": 9.8,
         "severity": "Critical", "description": "Remote code execution",
         "published_date": "2023-06-15"},
        {"cve": "CVE-2023-5678", "product": "OpenSSL", "cvss_score": 7.5,
         "severity": "High", "description": "Buffer overflow",
         "published_date": "2023-08-22"},
        {"cve": "CVE-2023-9012", "product": "Windows SMB", "cvss_score": 8.8,
         "severity": "High", "description": "Remote code execution",
         "published_date": "2023-10-01"},
        {"cve": "CVE-2023-3456", "product": "Python", "cvss_score": 5.3,
         "severity": "Medium", "description": "Integer overflow",
         "published_date": "2023-04-10"}
    ]

    manager = VulnerabilityManager()

    for vuln in sample_vulnerabilities:
        manager.add_vulnerability(**vuln)

    print("=== Vulnerability Management System ===")
    print(f"Total vulnerabilities: {len(manager.vulnerabilities)}")

    print("\nTop 10 Vulnerabilities:")
    for i, vuln in enumerate(manager.get_top_vulnerabilities(), 1):
        print(f"{i}. {vuln.cve} - {vuln.product} ({vuln.cvss_score})")

    print("\nVulnerabilities by Severity:")
    for severity, count in manager.vulnerabilities_by_severity.items():
        print(f"  {severity}: {len(count)}")

    report = manager.generate_report()
    print("\n=== Detailed Report ===")
    print(json.dumps(report, indent=2))

    manager.save_to_json("vulnerabilities.json")
    manager.export_csv("vulnerabilities.csv")
    print("\nData saved to vulnerabilities.json and vulnerabilities.csv")

if __name__ == "__main__":
    main()
```

### Challenges

1. Implement vulnerability search and filtering capabilities
2. Add support for integrating with vulnerability scanners (Nessus, OpenVAS)
3. Create interactive vulnerability dashboards
4. Implement email alerting for critical vulnerabilities
5. Add remediation tracking with deadlines and assignments

## Project 3: Network Topology Visualizer

### Description

Create a network topology visualization tool that maps devices and connections in a network using graph theory and data structures.

### Requirements

- Discover and map network devices
- Display network topology visually
- Track device status and connections
- Provide detailed device information
- Detect and alert on changes

### Starter Code

```python
#!/usr/bin/env python3
import scapy.all as scapy
import networkx as nx
import matplotlib.pyplot as plt
import random
import time

class NetworkTopology:
    """Network topology mapper and visualizer"""

    def __init__(self):
        self.topology = nx.Graph()
        self.devices = {}
        self.connections = []

    def scan_network(self, ip_range):
        """Scan network using ARP to find devices"""
        print(f"Scanning network: {ip_range}")

        arp_request = scapy.ARP(pdst=ip_range)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_broadcast = broadcast/arp_request

        answered_list = scapy.srp(arp_broadcast, timeout=1, verbose=False)[0]

        for element in answered_list:
            device_info = {
                "ip": element[1].psrc,
                "mac": element[1].hwsrc,
                "vendor": self._get_vendor(element[1].hwsrc)
            }

            self.devices[device_info["ip"]] = device_info
            self.topology.add_node(
                device_info["ip"],
                mac=device_info["mac"],
                vendor=device_info["vendor"]
            )

        print(f"Found {len(self.devices)} devices")

    def _get_vendor(self, mac_address):
        """Get vendor from MAC address (simulated for demo)"""
        vendors = {
            "00:11:22": "Cisco Systems",
            "00:22:44": "Dell Inc.",
            "00:33:66": "HP Inc.",
            "00:44:88": "Apple Inc.",
            "00:55:aa": "Microsoft Corporation"
        }

        prefix = mac_address[:8].upper().replace(':', '')
        for vendor_prefix, vendor_name in vendors.items():
            if prefix.startswith(vendor_prefix):
                return vendor_name

        return "Unknown"

    def map_connections(self):
        """Map device connections (simulated)"""
        device_ips = list(self.devices.keys())

        for i, src_ip in enumerate(device_ips):
            for dst_ip in device_ips[i+1:]:
                if random.random() < 0.3:  # 30% chance of connection
                    self.connections.append((src_ip, dst_ip))
                    self.topology.add_edge(src_ip, dst_ip, bandwidth=100)

        print(f"Found {len(self.connections)} connections")

    def visualize_topology(self):
        """Visualize network topology"""
        plt.figure(figsize=(12, 8))

        # Device colors based on vendor
        colors = []
        for node in self.topology.nodes():
            vendor = self.topology.nodes[node]["vendor"]
            color = {
                "Cisco Systems": "#009933",
                "Dell Inc.": "#0066cc",
                "HP Inc.": "#ff6600",
                "Apple Inc.": "#666666",
                "Microsoft Corporation": "#00a4ef",
                "Unknown": "#999999"
            }.get(vendor, "#999999")
            colors.append(color)

        pos = nx.spring_layout(self.topology, seed=42)

        nx.draw_networkx_nodes(
            self.topology, pos,
            node_color=colors,
            node_size=2000,
            alpha=0.8
        )

        nx.draw_networkx_edges(
            self.topology, pos,
            edge_color="#cccccc",
            width=2,
            alpha=0.6
        )

        nx.draw_networkx_labels(
            self.topology, pos,
            labels={node: node for node in self.topology.nodes()},
            font_size=8
        )

        # Add vendor information as edge labels
        edge_labels = {}
        for src, dst in self.topology.edges():
            src_vendor = self.topology.nodes[src]["vendor"]
            dst_vendor = self.topology.nodes[dst]["vendor"]
            bandwidth = self.topology.edges[src, dst]["bandwidth"]
            edge_labels[(src, dst)] = f"{bandwidth} Mbps"

        nx.draw_networkx_edge_labels(
            self.topology, pos,
            edge_labels=edge_labels,
            font_size=7
        )

        plt.title("Network Topology", fontsize=14)
        plt.axis('off')
        plt.tight_layout()
        plt.savefig("network_topology.png", dpi=300)
        print("Topology saved as network_topology.png")
        plt.show()

    def export_topology(self, filename):
        """Export topology to JSON file"""
        topology_data = {
            "devices": list(self.devices.values()),
            "connections": self.connections
        }

        with open(filename, 'w') as f:
            import json
            json.dump(topology_data, f, indent=2)

        print(f"Topology exported to {filename}")

    def print_summary(self):
        """Print topology summary"""
        print("\n=== Network Topology Summary ===")
        print(f"Total devices: {self.topology.number_of_nodes()}")
        print(f"Total connections: {self.topology.number_of_edges()}")

        print("\nDevices by Vendor:")
        vendors = {}
        for node in self.topology.nodes():
            vendor = self.topology.nodes[node]["vendor"]
            vendors[vendor] = vendors.get(vendor, 0) + 1

        for vendor, count in vendors.items():
            print(f"  {vendor}: {count} devices")

        print("\nConnections by Device:")
        for node in self.topology.nodes():
            print(f"  {node}: {self.topology.degree(node)} connections")

def main():
    topology = NetworkTopology()

    # Scan your network (replace with your actual network range)
    network_range = "192.168.1.1/24"
    topology.scan_network(network_range)

    # Map connections between devices
    topology.map_connections()

    # Visualize the topology
    topology.visualize_topology()

    # Export and print summary
    topology.export_topology("network_topology.json")
    topology.print_summary()

if __name__ == "__main__":
    main()
```

### Challenges

1. Implement real network device detection and connection mapping
2. Add support for IPv6 networks
3. Create interactive topology visualization with clickable nodes
4. Implement device status monitoring and alerting
5. Add support for network discovery protocols (SNMP, LLDP)

## Project 4: Intrusion Detection System (IDS)

### Description

Create an intrusion detection system that monitors network traffic and detects suspicious activities using various data structures and algorithms.

### Requirements

- Monitor network traffic in real-time
- Detect common attack patterns (SYN floods, port scans, etc.)
- Maintain connection states
- Provide alerts and notifications
- Support signature-based and anomaly-based detection

### Starter Code

```python
#!/usr/bin/env python3
import scapy.all as scapy
import datetime
from collections import defaultdict, deque

class IntrusionDetector:
    """Network intrusion detection system"""

    def __init__(self):
        self.connection_states = defaultdict(list)
        self.suspicious_connections = []
        self.packet_queue = deque()
        self.attack_signatures = {
            "syn_flood": self._detect_syn_flood,
            "port_scan": self._detect_port_scan,
            "large_packet": self._detect_large_packet
        }

    def packet_callback(self, packet):
        """Callback for captured packets"""
        self.packet_queue.append(packet)
        self._track_connection_states(packet)

    def _track_connection_states(self, packet):
        """Track TCP connection states"""
        if packet.haslayer(scapy.TCP) and packet.haslayer(scapy.IP):
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            src_port = packet[scapy.TCP].sport
            dst_port = packet[scapy.TCP].dport

            connection_key = (src_ip, dst_ip, src_port, dst_port)
            self.connection_states[connection_key].append({
                "timestamp": datetime.datetime.now(),
                "flags": packet[scapy.TCP].flags
            })

    def _detect_syn_flood(self, packet):
        """Detect SYN flood attacks"""
        if packet.haslayer(scapy.TCP) and packet[scapy.TCP].flags == 0x02:
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst

            syn_packets = [p for p in self.packet_queue if
                         p.haslayer(scapy.IP) and
                         p.haslayer(scapy.TCP) and
                         p[scapy.IP].src == src_ip and
                         p[scapy.IP].dst == dst_ip and
                         p[scapy.TCP].flags == 0x02]

            if len(syn_packets) > 50:
                return True

        return False

    def _detect_port_scan(self, packet):
        """Detect port scanning activities"""
        if packet.haslayer(scapy.TCP) and packet.haslayer(scapy.IP):
            src_ip = packet[scapy.IP].src

            # Check if source IP is connecting to multiple ports on same target
            target_connections = defaultdict(set)

            for p in self.packet_queue:
                if (p.haslayer(scapy.IP) and p.haslayer(scapy.TCP) and
                    p[scapy.IP].src == src_ip):
                    target_connections[p[scapy.IP].dst].add(p[scapy.TCP].dport)

            for dst_ip, ports in target_connections.items():
                if len(ports) > 10:
                    return True

        return False

    def _detect_large_packet(self, packet):
        """Detect abnormally large packets"""
        if len(packet) > 1500:
            return True

        return False

    def detect_intrusions(self):
        """Check for intrusion signatures in packet queue"""
        intrusions = []

        for packet in self.packet_queue:
            for signature_name, detector in self.attack_signatures.items():
                if detector(packet):
                    intrusion_info = {
                        "timestamp": datetime.datetime.now(),
                        "signature": signature_name,
                        "src_ip": packet[scapy.IP].src if packet.haslayer(scapy.IP) else None,
                        "dst_ip": packet[scapy.IP].dst if packet.haslayer(scapy.IP) else None,
                        "src_port": packet.sport if hasattr(packet, 'sport') else None,
                        "dst_port": packet.dport if hasattr(packet, 'dport') else None
                    }
                    intrusions.append(intrusion_info)

        return intrusions

    def print_intrusions(self, intrusions):
        """Print detected intrusions"""
        if intrusions:
            print(f"\n=== INTRUSIONS DETECTED ===")
            for intrusion in intrusions:
                print(f"[{intrusion['timestamp']}] {intrusion['signature'].upper()}")
                if intrusion['src_ip'] and intrusion['dst_ip']:
                    print(f"  Source: {intrusion['src_ip']}:{intrusion['src_port']}")
                    print(f"  Destination: {intrusion['dst_ip']}:{intrusion['dst_port']}")
                print()

    def start_sniffing(self, interface, duration=30):
        """Start sniffing network traffic"""
        print(f"Monitoring network on interface {interface}")
        try:
            scapy.sniff(
                iface=interface,
                prn=self.packet_callback,
                timeout=duration
            )

            print(f"Stopped monitoring after {duration} seconds")

            intrusions = self.detect_intrusions()
            self.print_intrusions(intrusions)

            print(f"\n=== Statistics ===")
            print(f"Total packets processed: {len(self.packet_queue)}")
            print(f"Intrusions detected: {len(intrusions)}")

        except Exception as e:
            print(f"Error starting IDS: {e}")

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Network Intrusion Detection System"
    )
    parser.add_argument(
        "-i", "--interface", default="eth0",
        help="Network interface to monitor (default: eth0)"
    )
    parser.add_argument(
        "-t", "--time", type=int, default=30,
        help="Monitoring duration in seconds (default: 30)"
    )

    args = parser.parse_args()

    ids = IntrusionDetector()
    ids.start_sniffing(args.interface, args.time)

if __name__ == "__main__":
    main()
```

### Challenges

1. Implement more advanced attack detection signatures
2. Add support for payload analysis and heuristic detection
3. Create real-time visualization of network activity and intrusions
4. Implement correlation of events across multiple time windows
5. Add integration with network defense systems (firewalls, IPS)

## Getting Started with Projects

### Prerequisites

- Install required libraries: `pip install scapy networkx matplotlib`
- For packet capturing, you may need to run as root/administrator
- For network scanning, ensure you have proper authorization

### How to Use These Projects

1. Copy the starter code into new Python files
2. Read and understand the code (it's well-commented!)
3. Run the scripts from your terminal: `python script_name.py [arguments]`
4. Modify and expand the functionality based on the challenges
5. Test your implementations in safe, controlled environments

### Important Notes

- Always obtain proper authorization before testing on any system you don't own
- Use these tools responsibly for ethical hacking and learning purposes
- Keep your tools updated and be aware of legal implications

Remember, these projects are just starting points. As you learn more about Python and cybersecurity, you'll want to expand these tools with more advanced features, better error handling, and additional functionality tailored to your needs.
