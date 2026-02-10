# Functions and Modules - Projects

## Project 1: Network Scanner Toolkit

### Description

Create a comprehensive network scanner toolkit with modular architecture that includes port scanning, OS detection, and service enumeration.

### Requirements

- Scan for open ports on target hosts
- Detect operating systems using fingerprinting
- Identify running services and versions
- Save scan results in various formats
- Provide user-friendly interface

### Starter Code

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Network Scanner Toolkit - Main Entry Point
"""

import argparse
import sys
import time
from datetime import datetime
import csv
import json

from network_scanner.port_scanner import PortScanner
from network_scanner.os_detector import OSDetector
from network_scanner.service_detector import ServiceDetector

class NetworkScannerToolkit:
    """Main toolkit class for network scanning"""

    def __init__(self, target, ports=None, threads=50, timeout=1):
        self.target = target
        self.ports = ports if ports else range(1, 1024)
        self.threads = threads
        self.timeout = timeout
        self.results = {}

    def scan_ports(self):
        """Scan for open ports on target"""
        print(f"Scanning {self.target} for open ports...")
        scanner = PortScanner(self.target, self.ports, self.threads, self.timeout)
        self.results['open_ports'] = scanner.scan()
        print(f"Found {len(self.results['open_ports'])} open ports")

    def detect_os(self):
        """Detect operating system on target"""
        print(f"Detecting OS on {self.target}...")
        detector = OSDetector(self.target)
        self.results['os_info'] = detector.detect()

    def detect_services(self):
        """Detect services on open ports"""
        if 'open_ports' not in self.results or not self.results['open_ports']:
            print("No open ports to scan for services")
            return

        print("Detecting services on open ports...")
        detector = ServiceDetector(self.target, self.results['open_ports'], self.timeout)
        self.results['services'] = detector.detect()

    def run_full_scan(self):
        """Run complete network scan"""
        print("Starting full network scan...")
        start_time = time.time()

        self.scan_ports()
        self.detect_os()
        self.detect_services()

        self.results['scan_info'] = {
            'target': self.target,
            'ports_scanned': list(self.ports),
            'scan_time': time.time() - start_time,
            'timestamp': datetime.now().isoformat()
        }

        print(f"Scan completed in {self.results['scan_info']['scan_time']:.2f} seconds")

    def save_results(self, output_file, format='json'):
        """Save results to file"""
        print(f"Saving results to {output_file}")

        if format == 'json':
            with open(output_file, 'w') as f:
                json.dump(self.results, f, indent=2, default=str)

        elif format == 'csv':
            with open(output_file, 'w', newline='') as f:
                writer = csv.writer(f)

                # Write scan info
                writer.writerow(["Target", self.results['scan_info']['target']])
                writer.writerow(["Scan Time", f"{self.results['scan_info']['scan_time']:.2f} seconds"])
                writer.writerow(["Timestamp", self.results['scan_info']['timestamp']])
                writer.writerow([])

                # Write open ports
                writer.writerow(["Open Ports"])
                for port in sorted(self.results['open_ports']):
                    writer.writerow([port])
                writer.writerow([])

                # Write OS info
                if 'os_info' in self.results:
                    writer.writerow(["OS Detection"])
                    for key, value in self.results['os_info'].items():
                        writer.writerow([key, value])
                    writer.writerow([])

                # Write services
                if 'services' in self.results:
                    writer.writerow(["Services"])
                    for port, service in self.results['services'].items():
                        writer.writerow([port, service])

        elif format == 'txt':
            with open(output_file, 'w') as f:
                f.write("=" * 80 + "\n")
                f.write(f"NETWORK SCAN RESULTS for {self.target}\n")
                f.write("=" * 80 + "\n")
                f.write(f"\nScan Time: {self.results['scan_info']['scan_time']:.2f} seconds\n")
                f.write(f"Timestamp: {self.results['scan_info']['timestamp']}\n")

                f.write("\nOpen Ports:\n")
                for port in sorted(self.results['open_ports']):
                    f.write(f"  - Port {port}\n")

                if 'os_info' in self.results:
                    f.write("\nOS Information:\n")
                    for key, value in self.results['os_info'].items():
                        f.write(f"  {key}: {value}\n")

                if 'services' in self.results:
                    f.write("\nServices:\n")
                    for port, service in self.results['services'].items():
                        f.write(f"  Port {port}: {service}\n")

    def print_results(self):
        """Print scan results to console"""
        print("=" * 80)
        print(f"NETWORK SCAN RESULTS for {self.target}")
        print("=" * 80)

        print(f"\nScan Time: {self.results['scan_info']['scan_time']:.2f} seconds")
        print(f"Timestamp: {self.results['scan_info']['timestamp']}")

        print("\nOpen Ports:")
        for port in sorted(self.results['open_ports']):
            print(f"  - Port {port}")

        if 'os_info' in self.results:
            print("\nOS Information:")
            for key, value in self.results['os_info'].items():
                print(f"  {key}: {value}")

        if 'services' in self.results:
            print("\nServices:")
            for port, service in self.results['services'].items():
                print(f"  Port {port}: {service}")

def main():
    parser = argparse.ArgumentParser(
        description="Network Scanner Toolkit - Port scanning, OS detection, and service enumeration"
    )

    parser.add_argument("target", help="Target IP address or hostname to scan")
    parser.add_argument("-p", "--ports", help="Port range to scan (e.g., 1-1024)")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Number of threads (default: 50)")
    parser.add_argument("-T", "--timeout", type=float, default=1, help="Connection timeout (default: 1 second)")
    parser.add_argument("-o", "--output", help="Output file for results")
    parser.add_argument("-f", "--format", choices=["json", "csv", "txt"], default="json", help="Output format (default: json)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    args = parser.parse_args()

    # Parse port range
    if args.ports:
        if '-' in args.ports:
            start, end = map(int, args.ports.split('-'))
            ports = range(start, end + 1)
        else:
            ports = [int(args.ports)]
    else:
        ports = range(1, 1024)

    # Create and run scanner
    try:
        scanner = NetworkScannerToolkit(
            args.target,
            ports=ports,
            threads=args.threads,
            timeout=args.timeout
        )

        scanner.run_full_scan()

        if args.verbose:
            scanner.print_results()

        if args.output:
            scanner.save_results(args.output, args.format)

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
```

### Project Structure

```
network_scanner/
├── __init__.py
├── port_scanner.py
├── os_detector.py
└── service_detector.py
```

### Challenges

1. Implement multi-host scanning
2. Add advanced service fingerprinting
3. Implement vulnerability detection
4. Create GUI interface
5. Add network mapping capabilities

## Project 2: Password Manager with Encryption

### Description

Create a secure password manager that encrypts and stores passwords with modular architecture for different storage backends and encryption methods.

### Requirements

- Generate strong passwords
- Encrypt and decrypt passwords
- Support multiple storage backends
- Search and manage passwords
- Provide secure access control

### Starter Code

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Secure Password Manager - Main Entry Point
"""

import argparse
import sys
import getpass
from datetime import datetime

from password_manager.crypto_engine import CryptoEngine
from password_manager.password_generator import PasswordGenerator
from password_manager.storage_backend import FileStorage
from password_manager.manager import PasswordManager

class PasswordManagerTool:
    """Main password manager application"""

    def __init__(self, storage_file, master_password):
        self.crypto = CryptoEngine(master_password)
        self.storage = FileStorage(storage_file)
        self.manager = PasswordManager(self.storage, self.crypto)

    def add_password(self, name, username, password=None, url=None):
        """Add a new password entry"""
        if not password:
            generator = PasswordGenerator()
            password = generator.generate()

        entry = {
            'name': name,
            'username': username,
            'password': password,
            'url': url,
            'created': datetime.now().isoformat(),
            'modified': datetime.now().isoformat()
        }

        self.manager.add_entry(entry)
        print(f"Password entry '{name}' added successfully")

    def get_password(self, name):
        """Get password entry by name"""
        entry = self.manager.get_entry(name)

        if entry:
            print(f"Name: {entry['name']}")
            print(f"Username: {entry['username']}")
            print(f"Password: {entry['password']}")
            if entry['url']:
                print(f"URL: {entry['url']}")
            print(f"Created: {entry['created']}")
            print(f"Modified: {entry['modified']}")
        else:
            print(f"No entry found with name '{name}'")

    def update_password(self, name, new_password=None):
        """Update an existing password entry"""
        if new_password:
            self.manager.update_entry(name, 'password', new_password)
        else:
            generator = PasswordGenerator()
            new_password = generator.generate()
            self.manager.update_entry(name, 'password', new_password)

        self.manager.update_entry(name, 'modified', datetime.now().isoformat())
        print(f"Password entry '{name}' updated successfully")

    def delete_password(self, name):
        """Delete a password entry"""
        self.manager.delete_entry(name)
        print(f"Password entry '{name}' deleted successfully")

    def list_passwords(self):
        """List all password entries"""
        entries = self.manager.list_entries()

        if entries:
            print("Password entries:")
            for entry in entries:
                print(f"  - {entry['name']}")
        else:
            print("No password entries found")

    def search_passwords(self, query):
        """Search for password entries containing query"""
        entries = self.manager.search_entries(query)

        if entries:
            print("Search results:")
            for entry in entries:
                print(f"  - {entry['name']}")
        else:
            print(f"No entries found containing '{query}'")

    def generate_password(self, length=16, include_special=True):
        """Generate a strong password"""
        generator = PasswordGenerator()
        password = generator.generate(length, include_special)
        print(f"Generated password: {password}")

def main():
    parser = argparse.ArgumentParser(
        description="Secure Password Manager - Store and manage encrypted passwords"
    )

    # Global options
    parser.add_argument("-f", "--file", default="passwords.db", help="Storage file (default: passwords.db)")

    # Subcommands
    subparsers = parser.add_subparsers(title="Commands", dest="command")

    # Add command
    add_parser = subparsers.add_parser("add", help="Add new password entry")
    add_parser.add_argument("name", help="Name for password entry")
    add_parser.add_argument("username", help="Username for password entry")
    add_parser.add_argument("-p", "--password", help="Password (will generate if not provided)")
    add_parser.add_argument("-u", "--url", help="URL associated with entry")

    # Get command
    get_parser = subparsers.add_parser("get", help="Get password entry")
    get_parser.add_argument("name", help="Name of password entry")

    # Update command
    update_parser = subparsers.add_parser("update", help="Update password entry")
    update_parser.add_argument("name", help="Name of password entry to update")
    update_parser.add_argument("-p", "--password", help="New password (will generate if not provided)")

    # Delete command
    delete_parser = subparsers.add_parser("delete", help="Delete password entry")
    delete_parser.add_argument("name", help="Name of password entry to delete")

    # List command
    subparsers.add_parser("list", help="List all password entries")

    # Search command
    search_parser = subparsers.add_parser("search", help="Search password entries")
    search_parser.add_argument("query", help="Search query")

    # Generate command
    generate_parser = subparsers.add_parser("generate", help="Generate strong password")
    generate_parser.add_argument("-l", "--length", type=int, default=16, help="Password length")
    generate_parser.add_argument("-s", "--no-special", action="store_true", help="Exclude special characters")

    args = parser.parse_args()

    # Get master password
    master_password = getpass.getpass("Enter master password: ")

    try:
        manager = PasswordManagerTool(args.file, master_password)

        if args.command == "add":
            manager.add_password(
                args.name, args.username, args.password, args.url
            )
        elif args.command == "get":
            manager.get_password(args.name)
        elif args.command == "update":
            manager.update_password(args.name, args.password)
        elif args.command == "delete":
            manager.delete_password(args.name)
        elif args.command == "list":
            manager.list_passwords()
        elif args.command == "search":
            manager.search_passwords(args.query)
        elif args.command == "generate":
            manager.generate_password(
                args.length, not args.no_special
            )
        else:
            parser.print_help()

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
```

### Project Structure

```
password_manager/
├── __init__.py
├── crypto_engine.py
├── password_generator.py
├── storage_backend.py
└── manager.py
```

### Challenges

1. Implement database backend for storage
2. Add two-factor authentication
3. Create web interface
4. Implement browser integration
5. Add password strength analyzer

## Project 3: Malware Analysis Framework

### Description

Create a modular malware analysis framework that extracts signatures, analyzes behavior, and identifies patterns in suspicious files.

### Requirements

- Extract file metadata and hashes
- Analyze file behavior
- Generate malware signatures
- Detect known malware patterns
- Provide comprehensive reports

### Starter Code

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Malware Analysis Framework - Main Entry Point
"""

import argparse
import sys
import os
from datetime import datetime

from malware_analyzer.file_analyzer import FileAnalyzer
from malware_analyzer.metadata_extractor import MetadataExtractor
from malware_analyzer.hash_extractor import HashExtractor
from malware_analyzer.string_analyzer import StringAnalyzer
from malware_analyzer.report_generator import ReportGenerator
from malware_analyzer.signature_matcher import SignatureMatcher

class MalwareAnalyzerFramework:
    """Main malware analysis framework"""

    def __init__(self, sample_file, signatures_file=None):
        self.sample_file = sample_file
        self.analyzers = []

        # Initialize analyzers
        self.analyzers.append(MetadataExtractor())
        self.analyzers.append(HashExtractor())
        self.analyzers.append(StringAnalyzer())

        if signatures_file and os.path.exists(signatures_file):
            self.analyzers.append(SignatureMatcher(signatures_file))

        self.analyzers.append(FileAnalyzer())

    def analyze_file(self):
        """Analyze the malware sample file"""
        results = {}

        for analyzer in self.analyzers:
            analyzer_name = type(analyzer).__name__
            try:
                result = analyzer.analyze(self.sample_file)
                results[analyzer_name] = result
            except Exception as e:
                results[analyzer_name] = {
                    'error': str(e),
                    'success': False
                }

        return results

    def generate_report(self, results, output_file):
        """Generate analysis report"""
        reporter = ReportGenerator()
        reporter.generate_report(self.sample_file, results, output_file)
        print(f"Analysis report saved to {output_file}")

    def print_summary(self, results):
        """Print analysis summary"""
        print("=" * 80)
        print(f"MALWARE ANALYSIS SUMMARY for {self.sample_file}")
        print("=" * 80)

        for analyzer_name, result in results.items():
            print(f"\n{analyzer_name}:")
            if isinstance(result, dict):
                for key, value in result.items():
                    print(f"  {key}: {value}")
            else:
                print(f"  {result}")

def main():
    parser = argparse.ArgumentParser(
        description="Malware Analysis Framework - Analyze and detect malicious files"
    )

    parser.add_argument("sample", help="Path to malware sample file")
    parser.add_argument("-s", "--signatures", help="Path to malware signatures database")
    parser.add_argument("-o", "--output", default="analysis_report.html", help="Output report file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-t", "--test", action="store_true", help="Run test analysis (quick mode)")

    args = parser.parse_args()

    if not os.path.exists(args.sample):
        print(f"Error: File not found: {args.sample}")
        sys.exit(1)

    try:
        analyzer = MalwareAnalyzerFramework(args.sample, args.signatures)

        print(f"Starting analysis of {args.sample}...")
        results = analyzer.analyze_file()

        if args.verbose:
            analyzer.print_summary(results)

        analyzer.generate_report(results, args.output)
        print(f"Analysis completed successfully")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
```

### Project Structure

```
malware_analyzer/
├── __init__.py
├── file_analyzer.py
├── metadata_extractor.py
├── hash_extractor.py
├── string_analyzer.py
├── report_generator.py
└── signature_matcher.py
```

### Challenges

1. Implement behavioral analysis sandbox
2. Add anti-evasion techniques
3. Create interactive visualization
4. Implement machine learning detection
5. Add network behavior analysis

## Project 4: Log Analysis and Intrusion Detection System

### Description

Create a modular log analysis and intrusion detection system that monitors log files, detects suspicious activities, and provides alerts.

### Requirements

- Parse various log formats
- Detect intrusion patterns
- Provide real-time alerts
- Generate detailed reports
- Support multiple log sources

### Starter Code

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Log Analysis and Intrusion Detection System - Main Entry Point
"""

import argparse
import sys
import os
from datetime import datetime

from log_analyzer.log_parser import LogParser
from log_analyzer.intrusion_detector import IntrusionDetector
from log_analyzer.alert_manager import AlertManager
from log_analyzer.report_generator import ReportGenerator

class LogAnalysisSystem:
    """Main log analysis and intrusion detection system"""

    def __init__(self, log_files, config_file=None):
        self.log_files = log_files
        self.config_file = config_file
        self.parser = LogParser()
        self.detector = IntrusionDetector(config_file)
        self.alert_manager = AlertManager()
        self.reporter = ReportGenerator()

    def analyze_logs(self):
        """Analyze all specified log files"""
        results = []

        for log_file in self.log_files:
            if not os.path.exists(log_file):
                print(f"Error: Log file not found: {log_file}")
                continue

            try:
                print(f"Analyzing log file: {log_file}")
                log_entries = self.parser.parse(log_file)
                analysis_result = self.detector.detect_intrusions(log_entries)

                results.append({
                    'log_file': log_file,
                    'entries_processed': len(log_entries),
                    'intrusions_detected': len(analysis_result['intrusions']),
                    'details': analysis_result
                })

                if analysis_result['intrusions']:
                    self.alert_manager.alert(analysis_result['intrusions'])

            except Exception as e:
                print(f"Error analyzing {log_file}: {e}")

        return results

    def generate_report(self, results, output_file):
        """Generate detailed analysis report"""
        self.reporter.generate_report(results, output_file)
        print(f"Analysis report saved to {output_file}")

    def print_summary(self, results):
        """Print analysis summary"""
        print("=" * 80)
        print(f"LOG ANALYSIS SUMMARY")
        print("=" * 80)

        for result in results:
            print(f"\nLog File: {result['log_file']}")
            print(f"Entries Processed: {result['entries_processed']}")
            print(f"Intrusions Detected: {result['intrusions_detected']}")

            if result['intrusions_detected'] > 0:
                print(f"Suspicious Activities:")
                for intrusion in result['details']['intrusions']:
                    print(f"  - {intrusion['type']}: {intrusion['description']}")

def main():
    parser = argparse.ArgumentParser(
        description="Log Analysis and Intrusion Detection System"
    )

    parser.add_argument("log_files", nargs="+", help="Path to log files to analyze")
    parser.add_argument("-c", "--config", help="Path to configuration file")
    parser.add_argument("-o", "--output", default="log_analysis_report.html", help="Output report file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-a", "--alerts", action="store_true", help="Enable real-time alerts")
    parser.add_argument("-t", "--test", action="store_true", help="Run test analysis")

    args = parser.parse_args()

    try:
        analyzer = LogAnalysisSystem(args.log_files, args.config)

        print(f"Starting log analysis...")
        results = analyzer.analyze_logs()

        if args.verbose:
            analyzer.print_summary(results)

        analyzer.generate_report(results, args.output)
        print(f"Analysis completed successfully")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
```

### Project Structure

```
log_analyzer/
├── __init__.py
├── log_parser.py
├── intrusion_detector.py
├── alert_manager.py
└── report_generator.py
```

### Challenges

1. Implement real-time log monitoring
2. Add more intrusion detection patterns
3. Create interactive visualization
4. Integrate with SIEM systems
5. Implement machine learning based detection

## Getting Started

### Setting Up Projects

1. Create project directory structure
2. Implement each module with required functionality
3. Test individual modules
4. Test complete project functionality
5. Create documentation

### Best Practices

1. Use virtual environments for each project
2. Write tests for each module
3. Document all functionality
4. Follow PEP8 coding standards
5. Use version control

### Requirements

Each project requires different dependencies. Create `requirements.txt` files and install dependencies using:

```bash
pip install -r requirements.txt
```

Remember, these projects are designed to demonstrate advanced Python concepts in real-world security scenarios. Take time to understand each component and customize them for your specific needs.
