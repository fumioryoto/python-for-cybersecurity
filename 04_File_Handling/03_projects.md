# File Handling - Projects

## Project 1: Security Log Analyzer

### Description

Create a powerful security log analyzer that can parse, analyze, and report on various types of security logs.

### Requirements

- Parse common log formats (Apache, Nginx, Windows Event Logs)
- Detect security events (failed logins, port scans, etc.)
- Generate detailed reports
- Provide visualization capabilities
- Support multiple log sources

### Starter Code

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Security Log Analyzer - Main Application
"""

import argparse
import os
import sys
import re
import json
import csv
import matplotlib.pyplot as plt
from collections import Counter, defaultdict
from datetime import datetime

class SecurityLogAnalyzer:
    """Main security log analyzer class"""

    def __init__(self, log_files, output_dir="reports"):
        self.log_files = log_files
        self.output_dir = output_dir
        self.results = defaultdict(list)
        self.analysis = {}

        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

    def parse_log_file(self, log_file):
        """Parse log file based on format"""
        if log_file.endswith('.log') or log_file.endswith('.txt'):
            return self._parse_text_log(log_file)
        elif log_file.endswith('.json'):
            return self._parse_json_log(log_file)
        elif log_file.endswith('.csv'):
            return self._parse_csv_log(log_file)
        else:
            print(f"Warning: Unknown file format for {log_file}")
            return []

    def _parse_text_log(self, log_file):
        """Parse Apache/Nginx access log format"""
        apache_pattern = re.compile(
            r'(\S+) - (\S+) \[(.*?)\] "(.*?)" (\d+) (\d+)'
        )

        with open(log_file, 'r') as file:
            lines = file.readlines()

        entries = []
        for line in lines:
            match = apache_pattern.match(line.strip())
            if match:
                try:
                    entries.append({
                        'source_ip': match.group(1),
                        'ident': match.group(2),
                        'timestamp': self._parse_timestamp(match.group(3)),
                        'request': match.group(4),
                        'status_code': int(match.group(5)),
                        'size': int(match.group(6)),
                        'log_file': log_file
                    })
                except:
                    continue

        return entries

    def _parse_json_log(self, log_file):
        """Parse JSON-formatted log file"""
        with open(log_file, 'r') as file:
            data = json.load(file)

        entries = []
        for entry in data:
            if isinstance(entry, dict):
                entry['log_file'] = log_file
                entries.append(entry)

        return entries

    def _parse_csv_log(self, log_file):
        """Parse CSV-formatted log file"""
        entries = []

        with open(log_file, 'r') as file:
            reader = csv.DictReader(file)
            for row in reader:
                row['log_file'] = log_file
                entries.append(row)

        return entries

    def _parse_timestamp(self, timestamp_str):
        """Parse timestamp from various formats"""
        try:
            # Apache log format: 01/Jan/2023:12:00:00 +0000
            return datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S %z")
        except:
            return None

    def analyze_logs(self):
        """Analyze parsed log entries"""
        print("Analyzing logs...")

        # Collect all log entries
        all_entries = []
        for log_file in self.log_files:
            entries = self.parse_log_file(log_file)
            self.results[log_file] = entries
            all_entries.extend(entries)

        # Perform analysis
        self.analysis['total_entries'] = len(all_entries)
        self.analysis['log_files'] = len(self.log_files)

        # Analyze by source IP
        ip_counts = Counter()
        for entry in all_entries:
            if 'source_ip' in entry and entry['source_ip']:
                ip_counts[entry['source_ip']] += 1

        self.analysis['top_ips'] = ip_counts.most_common(10)
        self.analysis['unique_ips'] = len(ip_counts)

        # Analyze by status code
        status_counts = Counter()
        for entry in all_entries:
            if 'status_code' in entry and entry['status_code']:
                status_counts[entry['status_code']] += 1

        self.analysis['status_codes'] = status_counts

        # Analyze failed login attempts
        self.analysis['failed_logins'] = []
        for entry in all_entries:
            if 'request' in entry and 'login' in str(entry['request']).lower() and \
               ('status_code' in entry and entry['status_code'] == 401 or
                'status' in entry and 'failed' in str(entry['status']).lower()):
                self.analysis['failed_logins'].append(entry)

        # Analyze port scan attempts
        self.analysis['port_scans'] = []
        ip_port_counts = defaultdict(set)

        for entry in all_entries:
            if 'source_ip' in entry and 'destination_port' in entry:
                ip_port_counts[entry['source_ip']].add(entry['destination_port'])

        for ip, ports in ip_port_counts.items():
            if len(ports) > 10:
                self.analysis['port_scans'].append({
                    'source_ip': ip,
                    'ports_scanned': len(ports)
                })

    def generate_report(self, report_format='html'):
        """Generate analysis report"""
        if report_format == 'html':
            self._generate_html_report()
        elif report_format == 'json':
            self._generate_json_report()
        elif report_format == 'csv':
            self._generate_csv_report()

    def _generate_html_report(self):
        """Generate HTML report"""
        template = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Security Log Analysis Report</title>
            <style>
                body {{
                    font-family: 'Arial', sans-serif;
                    background: #f4f4f4;
                    margin: 0;
                    padding: 20px;
                }}
                .container {{
                    max-width: 1200px;
                    margin: 0 auto;
                    background: white;
                    padding: 20px;
                    border-radius: 8px;
                    box-shadow: 0 0 10px rgba(0,0,0,0.1);
                }}
                h1 {{ color: #333; }}
                .section {{ margin-bottom: 30px; }}
                .stats {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 20px;
                }}
                .stat-card {{
                    background: #f8f9fa;
                    padding: 20px;
                    border-radius: 5px;
                    text-align: center;
                }}
                .stat-value {{
                    font-size: 24px;
                    font-weight: bold;
                    color: #007bff;
                }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin-top: 10px;
                }}
                th, td {{
                    border: 1px solid #ddd;
                    padding: 12px;
                    text-align: left;
                }}
                th {{ background: #f2f2f2; }}
                .warning {{ color: #ffc107; }}
                .danger {{ color: #dc3545; }}
                .success {{ color: #28a745; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Security Log Analysis Report</h1>

                <div class="section stats">
                    <div class="stat-card">
                        <div class="stat-value">{total_entries}</div>
                        <div>Total Log Entries</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{log_files}</div>
                        <div>Log Files</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{unique_ips}</div>
                        <div>Unique IP Addresses</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{failed_logins}</div>
                        <div>Failed Logins</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">{port_scans}</div>
                        <div>Port Scan Attempts</div>
                    </div>
                </div>

                <div class="section">
                    <h2>Top Source IP Addresses</h2>
                    <table>
                        <tr>
                            <th>Rank</th>
                            <th>IP Address</th>
                            <th>Count</th>
                        </tr>
                        {top_ips_table}
                    </table>
                </div>

                <div class="section">
                    <h2>HTTP Status Codes</h2>
                    <table>
                        <tr>
                            <th>Status Code</th>
                            <th>Count</th>
                        </tr>
                        {status_codes_table}
                    </table>
                </div>

                {failed_logins_section}
                {port_scans_section}
            </div>
        </body>
        </html>
        """

        # Render template
        context = {
            'total_entries': self.analysis['total_entries'],
            'log_files': self.analysis['log_files'],
            'unique_ips': self.analysis['unique_ips'],
            'failed_logins': len(self.analysis['failed_logins']),
            'port_scans': len(self.analysis['port_scans']),
            'top_ips_table': '',
            'status_codes_table': '',
            'failed_logins_section': '',
            'port_scans_section': ''
        }

        # Top IPs table
        for rank, (ip, count) in enumerate(self.analysis['top_ips'], 1):
            context['top_ips_table'] += f"<tr><td>{rank}</td><td>{ip}</td><td>{count}</td></tr>"

        # Status codes table
        for code, count in self.analysis['status_codes'].items():
            context['status_codes_table'] += f"<tr><td>{code}</td><td>{count}</td></tr>"

        # Failed logins section
        if self.analysis['failed_logins']:
            context['failed_logins_section'] = """
            <div class="section">
                <h2>Failed Login Attempts</h2>
                <table>
                    <tr>
                        <th>IP Address</th>
                        <th>Timestamp</th>
                        <th>Request</th>
                        <th>Status</th>
                    </tr>
            """

            for entry in self.analysis['failed_logins'][:10]:  # Show first 10
                context['failed_logins_section'] += f"""
                <tr>
                    <td>{entry.get('source_ip', 'N/A')}</td>
                    <td>{entry.get('timestamp', 'N/A')}</td>
                    <td>{entry.get('request', 'N/A')}</td>
                    <td class="danger">{entry.get('status_code', entry.get('status', 'N/A'))}</td>
                </tr>
                """

            context['failed_logins_section'] += """
                </table>
            </div>
            """

        # Port scans section
        if self.analysis['port_scans']:
            context['port_scans_section'] = """
            <div class="section">
                <h2>Port Scan Attempts</h2>
                <table>
                    <tr>
                        <th>Source IP</th>
                        <th>Ports Scanned</th>
                    </tr>
            """

            for scan in self.analysis['port_scans']:
                context['port_scans_section'] += f"""
                <tr>
                    <td>{scan['source_ip']}</td>
                    <td class="warning">{scan['ports_scanned']}</td>
                </tr>
                """

            context['port_scans_section'] += """
                </table>
            </div>
            """

        report_content = template.format(**context)

        with open(os.path.join(self.output_dir, 'security_analysis.html'), 'w') as file:
            file.write(report_content)

        print(f"HTML report saved to: {os.path.join(self.output_dir, 'security_analysis.html')}")

    def _generate_json_report(self):
        """Generate JSON report"""
        report_data = {
            'analysis': self.analysis,
            'results': dict(self.results)
        }

        with open(os.path.join(self.output_dir, 'security_analysis.json'), 'w') as file:
            json.dump(report_data, file, indent=2, default=str)

        print(f"JSON report saved to: {os.path.join(self.output_dir, 'security_analysis.json')}")

    def _generate_csv_report(self):
        """Generate CSV report with summary statistics"""
        with open(os.path.join(self.output_dir, 'security_analysis.csv'), 'w', newline='') as file:
            writer = csv.writer(file)

            writer.writerow(['Metric', 'Value'])
            writer.writerow(['Total Log Entries', self.analysis['total_entries']])
            writer.writerow(['Log Files', self.analysis['log_files']])
            writer.writerow(['Unique IP Addresses', self.analysis['unique_ips']])
            writer.writerow(['Failed Logins', len(self.analysis['failed_logins'])])
            writer.writerow(['Port Scan Attempts', len(self.analysis['port_scans'])])
            writer.writerow([])
            writer.writerow(['Top Source IP Addresses'])
            writer.writerow(['Rank', 'IP Address', 'Count'])

            for rank, (ip, count) in enumerate(self.analysis['top_ips'], 1):
                writer.writerow([rank, ip, count])

            writer.writerow([])
            writer.writerow(['HTTP Status Codes'])
            writer.writerow(['Status Code', 'Count'])

            for code, count in self.analysis['status_codes'].items():
                writer.writerow([code, count])

        print(f"CSV report saved to: {os.path.join(self.output_dir, 'security_analysis.csv')}")

    def generate_charts(self):
        """Generate visualization charts"""
        plt.figure(figsize=(12, 6))

        # Top IPs bar chart
        ips, counts = zip(*self.analysis['top_ips'])
        plt.subplot(1, 2, 1)
        plt.bar(ips, counts)
        plt.xlabel('IP Addresses')
        plt.ylabel('Count')
        plt.title('Top Source IP Addresses')
        plt.xticks(rotation=45, ha='right')

        # Status codes pie chart
        codes = list(self.analysis['status_codes'].keys())
        code_counts = list(self.analysis['status_codes'].values())
        plt.subplot(1, 2, 2)
        plt.pie(code_counts, labels=codes, autopct='%1.1f%%')
        plt.title('HTTP Status Codes Distribution')

        plt.tight_layout()
        chart_path = os.path.join(self.output_dir, 'security_charts.png')
        plt.savefig(chart_path, dpi=300, bbox_inches='tight')
        plt.close()

        print(f"Charts saved to: {chart_path}")

def main():
    parser = argparse.ArgumentParser(
        description="Security Log Analyzer - Parse and analyze security log files"
    )

    parser.add_argument(
        "log_files", nargs="+",
        help="Path to log files to analyze"
    )

    parser.add_argument(
        "-o", "--output", default="reports",
        help="Output directory for reports (default: reports)"
    )

    parser.add_argument(
        "-f", "--format", choices=["html", "json", "csv"], default="html",
        help="Report format (default: html)"
    )

    parser.add_argument(
        "-c", "--charts", action="store_true",
        help="Generate visualization charts"
    )

    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable verbose output"
    )

    args = parser.parse_args()

    # Validate files exist
    valid_files = []
    for file_path in args.log_files:
        if os.path.exists(file_path):
            valid_files.append(file_path)
        else:
            print(f"Warning: File not found: {file_path}")

    if not valid_files:
        print("Error: No valid log files provided")
        sys.exit(1)

    try:
        analyzer = SecurityLogAnalyzer(valid_files, args.output)
        analyzer.analyze_logs()
        analyzer.generate_report(args.format)

        if args.charts:
            analyzer.generate_charts()

        print("\nAnalysis complete!")
        print(f"Report saved to: {os.path.abspath(args.output)}")

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

1. Add support for more log formats (Windows Event Logs, syslog, etc.)
2. Implement real-time log monitoring
3. Add machine learning-based anomaly detection
4. Create interactive dashboard with JavaScript
5. Implement alerting system (email, Slack notifications)
6. Add support for log aggregation from multiple sources

## Project 2: Malware Analysis Tool

### Description

Create a basic malware analysis tool that can analyze suspicious files, extract signatures, and provide detection capabilities.

### Requirements

- Detect file types using magic numbers
- Extract strings and patterns from binary files
- Calculate file hashes (MD5, SHA-1, SHA-256)
- Search for known malware signatures
- Provide basic file behavior analysis
- Generate detailed analysis reports

### Starter Code

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Malware Analysis Tool - Main Application
"""

import argparse
import os
import sys
import hashlib
import re
import json
from datetime import datetime

class MalwareAnalyzer:
    """Main malware analysis class"""

    def __init__(self, sample_path, signatures_file="malware_signatures.json"):
        self.sample_path = sample_path
        self.signatures_file = signatures_file
        self.analysis_results = {
            'filename': os.path.basename(sample_path),
            'path': os.path.abspath(sample_path),
            'size': os.path.getsize(sample_path),
            'timestamp': datetime.now().isoformat(),
            'analysis': {}
        }

        # Load signatures
        self.signatures = self._load_signatures()

    def _load_signatures(self):
        """Load malware signatures from file"""
        if os.path.exists(self.signatures_file):
            try:
                with open(self.signatures_file, 'r') as file:
                    return json.load(file)
            except Exception as e:
                print(f"Warning: Failed to load signatures: {e}")

        # Default signatures if none found
        return {
            'WannaCry': b'\x57\x61\x6E\x6E\x61\x43\x72\x79',
            'Emotet': b'\x45\x6D\x6F\x74\x65\x74',
            'LockBit': b'\x4C\x6F\x63\x6B\x42\x69\x74',
            'Qakbot': b'\x51\x61\x6B\x62\x6F\x74'
        }

    def analyze_file(self):
        """Perform complete malware analysis"""
        print(f"Analyzing file: {self.sample_path}")

        # File type detection
        self._detect_file_type()

        # Hash calculation
        self._calculate_hashes()

        # String extraction
        self._extract_strings()

        # Signature matching
        self._match_signatures()

        # File behavior analysis
        self._analyze_behavior()

        return self.analysis_results

    def _detect_file_type(self):
        """Detect file type using magic numbers"""
        signatures = {
            b'\x4D\x5A': 'Windows Executable (PE)',
            b'\x7F\x45\x4C\x46': 'ELF Executable',
            b'\xCA\xFE\xBA\xBE': 'Java Class File',
            b'\x50\x4B\x03\x04': 'ZIP Archive',
            b'\x89\x50\x4E\x47': 'PNG Image',
            b'\xFF\xD8\xFF': 'JPEG Image'
        }

        with open(self.sample_path, 'rb') as file:
            magic = file.read(4)

        detected = []
        for sig, name in signatures.items():
            if magic.startswith(sig):
                detected.append(name)

        self.analysis_results['analysis']['file_type'] = detected if detected else ['Unknown']

    def _calculate_hashes(self):
        """Calculate cryptographic hashes of file"""
        hashes = {}

        for algo in ['md5', 'sha1', 'sha256']:
            try:
                hash_obj = hashlib.new(algo)
                with open(self.sample_path, 'rb') as file:
                    for chunk in iter(lambda: file.read(4096), b''):
                        hash_obj.update(chunk)
                hashes[algo] = hash_obj.hexdigest()
            except Exception as e:
                hashes[algo] = f"Error: {e}"

        self.analysis_results['analysis']['hashes'] = hashes

    def _extract_strings(self):
        """Extract printable strings from binary file"""
        min_length = 4
        strings = set()

        with open(self.sample_path, 'rb') as file:
            content = file.read()

        # Find sequences of printable ASCII characters
        matches = re.findall(b'[ -~]{' + str(min_length) + ',}', content)

        for match in matches:
            try:
                decoded = match.decode('utf-8', errors='ignore')
                strings.add(decoded)
            except:
                continue

        self.analysis_results['analysis']['strings'] = list(strings)

    def _match_signatures(self):
        """Match file content against known malware signatures"""
        matches = []

        with open(self.sample_path, 'rb') as file:
            content = file.read()

        for name, signature in self.signatures.items():
            if signature in content:
                matches.append(name)

        self.analysis_results['analysis']['malware_matches'] = matches

    def _analyze_behavior(self):
        """Analyze file behavior indicators"""
        behavior = {
            'suspicious_imports': [],
            'network_indicators': [],
            'file_operations': [],
            'registry_operations': []
        }

        # Check for suspicious strings in file content
        with open(self.sample_path, 'rb') as file:
            content = file.read()

        # Network indicators (IP addresses, URLs)
        ip_pattern = re.compile(b'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        url_pattern = re.compile(b'https?://[^\s]+')

        ips = set()
        for match in ip_pattern.findall(content):
            try:
                ips.add(match.decode('utf-8'))
            except:
                continue

        urls = set()
        for match in url_pattern.findall(content):
            try:
                urls.add(match.decode('utf-8'))
            except:
                continue

        behavior['network_indicators'] = {
            'ips': list(ips),
            'urls': list(urls)
        }

        # File operations (common malware operations)
        file_ops = [
            b'CreateFile', b'DeleteFile', b'MoveFile',
            b'CopyFile', b'WriteFile', b'ReadFile'
        ]

        for op in file_ops:
            if op in content:
                behavior['file_operations'].append(op.decode('utf-8'))

        # Registry operations
        reg_ops = [
            b'RegCreateKey', b'RegSetValue', b'RegDeleteKey',
            b'RegDeleteValue', b'Run\\', b'Software\\Microsoft\\Windows\\CurrentVersion\\Run'
        ]

        for op in reg_ops:
            if op in content:
                behavior['registry_operations'].append(op.decode('utf-8'))

        self.analysis_results['analysis']['behavior'] = behavior

    def generate_report(self, output_dir="reports"):
        """Generate analysis report"""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        filename = os.path.join(
            output_dir,
            f"malware_analysis_{os.path.basename(self.sample_path)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )

        with open(filename, 'w') as file:
            json.dump(self.analysis_results, file, indent=2, default=str)

        print(f"Analysis report saved to: {filename}")

        # Print summary
        self._print_summary()

    def _print_summary(self):
        """Print analysis summary to console"""
        print("\n=== Malware Analysis Summary ===")
        print(f"File: {self.analysis_results['filename']}")
        print(f"Size: {self.analysis_results['size']:,} bytes")
        print(f"Type: {', '.join(self.analysis_results['analysis']['file_type'])}")

        print("\nHashes:")
        for algo, hash_val in self.analysis_results['analysis']['hashes'].items():
            print(f"  {algo.upper()}: {hash_val}")

        if self.analysis_results['analysis']['malware_matches']:
            print(f"\n❌ Malware signatures found:")
            for match in self.analysis_results['analysis']['malware_matches']:
                print(f"  - {match}")
        else:
            print("\n✅ No known malware signatures found")

        # Print network indicators if present
        behavior = self.analysis_results['analysis']['behavior']
        if behavior['network_indicators']['ips'] or behavior['network_indicators']['urls']:
            print("\nNetwork Indicators:")
            if behavior['network_indicators']['ips']:
                print(f"  IP Addresses: {', '.join(behavior['network_indicators']['ips'])}")
            if behavior['network_indicators']['urls']:
                print(f"  URLs: {', '.join(behavior['network_indicators']['urls'])}")

def main():
    parser = argparse.ArgumentParser(
        description="Malware Analysis Tool - Analyze suspicious files"
    )

    parser.add_argument(
        "sample_path",
        help="Path to the file to analyze"
    )

    parser.add_argument(
        "-s", "--signatures", default="malware_signatures.json",
        help="Path to malware signatures file (default: malware_signatures.json)"
    )

    parser.add_argument(
        "-o", "--output", default="reports",
        help="Output directory for reports (default: reports)"
    )

    args = parser.parse_args()

    # Validate file exists
    if not os.path.exists(args.sample_path):
        print(f"Error: File not found: {args.sample_path}")
        sys.exit(1)

    try:
        analyzer = MalwareAnalyzer(args.sample_path, args.signatures)
        results = analyzer.analyze_file()
        analyzer.generate_report(args.output)

    except Exception as e:
        print(f"Error: {e}")
        import traceback
        print(traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    main()
```

### Challenges

1. Implement more advanced signature matching with YARA rules
2. Add API integration with VirusTotal or other threat intelligence services
3. Implement sandbox analysis for dynamic behavior
4. Create a web interface for file upload and analysis
5. Add integration with malware sandboxes (Cuckoo Sandbox, etc.)
6. Implement machine learning-based detection

## Project 3: Configuration File Management System

### Description

Create a comprehensive configuration file management system for security tools and systems.

### Requirements

- Support various configuration formats (INI, JSON, YAML, XML)
- Encrypt sensitive configuration data
- Version control configurations
- Validate configurations against schema
- Compare configuration versions
- Backup and restore configurations
- Manage multiple environments (development, staging, production)

### Starter Code

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Configuration Management System - Main Application
"""

import argparse
import os
import sys
import json
import yaml
import configparser
import xml.etree.ElementTree as ET
import hashlib
from datetime import datetime
from cryptography.fernet import Fernet

class ConfigManager:
    """Main configuration management class"""

    def __init__(self, config_dir="configurations", backup_dir="backups",
                 encryption_key=None):
        self.config_dir = config_dir
        self.backup_dir = backup_dir
        self.encryption_key = encryption_key or self._generate_key()
        self.cipher = Fernet(self.encryption_key)

        # Ensure directories exist
        for directory in [config_dir, backup_dir]:
            if not os.path.exists(directory):
                os.makedirs(directory)

    def _generate_key(self):
        """Generate encryption key if not provided"""
        key_file = "config_encryption.key"

        if os.path.exists(key_file):
            with open(key_file, 'rb') as file:
                return file.read()

        key = Fernet.generate_key()
        with open(key_file, 'wb') as file:
            file.write(key)

        return key

    def _detect_format(self, filename):
        """Detect configuration file format based on extension"""
        ext = filename.lower().split('.')[-1]

        format_map = {
            'json': 'json',
            'yaml': 'yaml',
            'yml': 'yaml',
            'ini': 'ini',
            'xml': 'xml'
        }

        return format_map.get(ext, 'json')

    def _read_config(self, config_file):
        """Read configuration from file based on format"""
        config_format = self._detect_format(config_file)

        try:
            with open(config_file, 'r', encoding='utf-8') as file:
                if config_format == 'json':
                    return json.load(file)
                elif config_format == 'yaml':
                    return yaml.safe_load(file)
                elif config_format == 'ini':
                    config = configparser.ConfigParser()
                    config.read(config_file)
                    return {section: dict(config[section]) for section in config.sections()}
                elif config_format == 'xml':
                    tree = ET.parse(config_file)
                    root = tree.getroot()
                    return self._xml_to_dict(root)

        except Exception as e:
            print(f"Error reading config file {config_file}: {e}")
            return None

    def _write_config(self, config_file, data):
        """Write configuration to file based on format"""
        config_format = self._detect_format(config_file)

        try:
            with open(config_file, 'w', encoding='utf-8') as file:
                if config_format == 'json':
                    json.dump(data, file, indent=2)
                elif config_format == 'yaml':
                    yaml.safe_dump(data, file)
                elif config_format == 'ini':
                    config = configparser.ConfigParser()
                    for section, values in data.items():
                        config[section] = values
                    config.write(file)
                elif config_format == 'xml':
                    root = self._dict_to_xml(data, 'config')
                    tree = ET.ElementTree(root)
                    tree.write(file, encoding='utf-8', xml_declaration=True)

            return True

        except Exception as e:
            print(f"Error writing config file {config_file}: {e}")
            return False

    def _xml_to_dict(self, element):
        """Convert XML element to dictionary"""
        result = {}

        if element.attrib:
            result.update(element.attrib)

        if element.text and element.text.strip():
            result['_text'] = element.text.strip()

        for child in element:
            child_data = self._xml_to_dict(child)

            if child.tag in result:
                if not isinstance(result[child.tag], list):
                    result[child.tag] = [result[child.tag]]
                result[child.tag].append(child_data)
            else:
                result[child.tag] = child_data

        return result

    def _dict_to_xml(self, data, root_name='root'):
        """Convert dictionary to XML element"""
        root = ET.Element(root_name)

        for key, value in data.items():
            if key == '_text':
                root.text = value
            elif isinstance(value, dict):
                child = self._dict_to_xml(value, key)
                root.append(child)
            elif isinstance(value, list):
                for item in value:
                    child = self._dict_to_xml(item, key)
                    root.append(child)
            else:
                child = ET.SubElement(root, key)
                child.text = str(value)

        return root

    def encrypt_config(self, config_file):
        """Encrypt configuration file"""
        if not os.path.exists(config_file):
            print(f"Error: File not found: {config_file}")
            return False

        try:
            with open(config_file, 'rb') as file:
                content = file.read()

            encrypted_content = self.cipher.encrypt(content)

            encrypted_file = config_file + '.enc'
            with open(encrypted_file, 'wb') as file:
                file.write(encrypted_content)

            print(f"Configuration encrypted: {encrypted_file}")
            return True

        except Exception as e:
            print(f"Error encrypting configuration: {e}")
            return False

    def decrypt_config(self, encrypted_file, output_file=None):
        """Decrypt encrypted configuration file"""
        if not os.path.exists(encrypted_file):
            print(f"Error: File not found: {encrypted_file}")
            return False

        try:
            with open(encrypted_file, 'rb') as file:
                encrypted_content = file.read()

            decrypted_content = self.cipher.decrypt(encrypted_content)

            if not output_file:
                output_file = encrypted_file.replace('.enc', '')

            with open(output_file, 'wb') as file:
                file.write(decrypted_content)

            print(f"Configuration decrypted: {output_file}")
            return True

        except Exception as e:
            print(f"Error decrypting configuration: {e}")
            return False

    def backup_config(self, config_file, description=""):
        """Backup configuration file with versioning"""
        if not os.path.exists(config_file):
            print(f"Error: File not found: {config_file}")
            return False

        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = os.path.basename(config_file)
            backup_name = f"{os.path.splitext(filename)[0]}_{timestamp}.bak"
            backup_path = os.path.join(self.backup_dir, backup_name)

            import shutil
            shutil.copy2(config_file, backup_path)

            print(f"Configuration backed up: {backup_path}")
            return True

        except Exception as e:
            print(f"Error backing up configuration: {e}")
            return False

    def restore_config(self, backup_file, target_file):
        """Restore configuration from backup"""
        if not os.path.exists(backup_file):
            print(f"Error: Backup file not found: {backup_file}")
            return False

        try:
            import shutil
            shutil.copy2(backup_file, target_file)
            print(f"Configuration restored to: {target_file}")
            return True

        except Exception as e:
            print(f"Error restoring configuration: {e}")
            return False

    def validate_config(self, config_file, schema=None):
        """Validate configuration against schema (JSON Schema)"""
        if schema is None:
            print("No validation schema provided. Skipping validation.")
            return True

        try:
            import jsonschema
            config = self._read_config(config_file)

            with open(schema, 'r') as file:
                schema_data = json.load(file)

            jsonschema.validate(config, schema_data)
            print("Configuration is valid against schema")
            return True

        except Exception as e:
            print(f"Configuration validation failed: {e}")
            return False

    def compare_configs(self, config1, config2):
        """Compare two configuration files and show differences"""
        config1_data = self._read_config(config1)
        config2_data = self._read_config(config2)

        if not config1_data or not config2_data:
            return False

        differences = self._compare_dicts(config1_data, config2_data)

        if differences:
            print(f"Differences between {config1} and {config2}:")
            for diff in differences:
                print(diff)
        else:
            print("Configurations are identical")

        return True

    def _compare_dicts(self, dict1, dict2, prefix=''):
        """Recursively compare two dictionaries and find differences"""
        differences = []

        all_keys = set(dict1.keys()).union(dict2.keys())

        for key in all_keys:
            full_key = f"{prefix}.{key}" if prefix else key

            if key not in dict1:
                differences.append(f"{full_key} - Added in config2")
                continue

            if key not in dict2:
                differences.append(f"{full_key} - Removed from config1")
                continue

            value1 = dict1[key]
            value2 = dict2[key]

            if isinstance(value1, dict) and isinstance(value2, dict):
                nested_diffs = self._compare_dicts(value1, value2, full_key)
                differences.extend(nested_diffs)
            elif value1 != value2:
                differences.append(f"{full_key} - '{value1}' vs '{value2}'")

        return differences

def main():
    parser = argparse.ArgumentParser(
        description="Configuration Management System - Manage and secure configurations"
    )

    parser.add_argument(
        "command",
        choices=["encrypt", "decrypt", "backup", "restore", "validate", "compare"],
        help="Command to execute"
    )

    parser.add_argument(
        "files", nargs="+",
        help="Files to operate on"
    )

    parser.add_argument(
        "-d", "--config-dir", default="configurations",
        help="Configuration directory (default: configurations)"
    )

    parser.add_argument(
        "-b", "--backup-dir", default="backups",
        help="Backup directory (default: backups)"
    )

    parser.add_argument(
        "-k", "--key",
        help="Encryption key file (default: config_encryption.key)"
    )

    parser.add_argument(
        "-s", "--schema",
        help="JSON schema file for validation"
    )

    args = parser.parse_args()

    try:
        manager = ConfigManager(args.config_dir, args.backup_dir)

        if args.command == "encrypt":
            for file_path in args.files:
                manager.encrypt_config(file_path)

        elif args.command == "decrypt":
            for file_path in args.files:
                manager.decrypt_config(file_path)

        elif args.command == "backup":
            for file_path in args.files:
                manager.backup_config(file_path)

        elif args.command == "restore":
            if len(args.files) < 2:
                print("Error: Need both backup file and target file for restore")
                sys.exit(1)
            manager.restore_config(args.files[0], args.files[1])

        elif args.command == "validate":
            if len(args.files) < 1:
                print("Error: Need configuration file for validation")
                sys.exit(1)
            manager.validate_config(args.files[0], args.schema)

        elif args.command == "compare":
            if len(args.files) < 2:
                print("Error: Need two configuration files to compare")
                sys.exit(1)
            manager.compare_configs(args.files[0], args.files[1])

    except Exception as e:
        print(f"Error: {e}")
        import traceback
        print(traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    main()
```

### Challenges

1. Implement configuration version control with Git integration
2. Add configuration template management
3. Create a web interface for configuration management
4. Implement audit logging for configuration changes
5. Add integration with configuration management tools (Ansible, Chef, etc.)
6. Implement configuration drift detection
7. Add support for secret management systems (HashiCorp Vault, AWS Secrets Manager)

## Getting Started with Projects

### Setting Up the Project

1. Create a new Python project directory
2. Set up a virtual environment: `python -m venv venv`
3. Activate the virtual environment:
   - On Windows: `venv\Scripts\activate`
   - On macOS/Linux: `source venv/bin/activate`
4. Install required dependencies: `pip install -r requirements.txt`
5. Create the project structure as described

### Running the Projects

1. Each project has a main entry point (e.g., `security_log_analyzer.py`)
2. Run the main script with appropriate command-line arguments
3. For help, use the `-h` or `--help` option: `python script.py --help`

### Project Structure

```
your_project/
├── src/
│   ├── __init__.py
│   ├── core/
│   ├── modules/
│   └── utils/
├── config/
├── reports/
├── tests/
├── requirements.txt
└── README.md
```

### Best Practices

1. **Code Organization**: Follow the Python package structure with clear separation of concerns
2. **Error Handling**: Implement robust error handling and logging
3. **Security**: Ensure sensitive data is encrypted and access controlled
4. **Testing**: Write comprehensive tests for all functionality
5. **Documentation**: Document all modules, classes, and functions
6. **Version Control**: Use Git for version control and follow GitFlow workflow

These projects provide a foundation for file handling and security automation. Customize and extend them based on your specific cybersecurity requirements and challenges.
