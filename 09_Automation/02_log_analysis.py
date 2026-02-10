#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Log Analysis Automation in Python for Cybersecurity
This script automates log analysis for security monitoring:
- Log file parsing and processing
- Anomaly detection
- Threat pattern matching
- Alert generation
- Reporting and visualization
Perfect for beginners!
"""

import os
import re
import json
import csv
import datetime
import time
import glob
import statistics
import matplotlib.pyplot as plt
import pandas as pd

class LogAnalyzer:
    """Class for log analysis automation"""
    
    def __init__(self, log_dir='logs', output_dir='results'):
        """
        Initialize log analyzer
        
        Args:
            log_dir: Directory containing log files
            output_dir: Directory for results
        """
        self.log_dir = log_dir
        self.output_dir = output_dir
        
        # Create directories if they don't exist
        for directory in [log_dir, output_dir]:
            if not os.path.exists(directory):
                os.makedirs(directory)
                
        self.log_patterns = {
            'apache': [r'^\d+\.\d+\.\d+\.\d+ - .* \[.*\] ".*" \d+ \d+',],
            'nginx': [r'^\d+\.\d+\.\d+\.\d+ - .* \[.*\] ".*" \d+ \d+',],
            'syslog': [r'^[A-Z][a-z]{2} \d+ \d+:\d+:\d+ .*',],
            'windows': [r'^\d{4}-\d{2}-\d{2} \d+:\d+:\d+.*',],
        }
        
        self.threat_patterns = {
            'sql_injection': [
                r'\b(union|select.*from|insert.*into|update.*set|delete.*from|drop.*table|create.*table|alter.*table)\b',
                r'\'\s*or\s*1\s*=\s*1',
                r'--|/\*.*\*/',
                r';.*(--|/\*.*\*/)'
            ],
            'xss': [
                r'<script.*>',
                r'onload.*=',
                r'onerror.*=',
                r'document\.cookie',
                r'javascript:',
                r'eval\(',
                r'alert\('
            ],
            'command_injection': [
                r'\|.*(cat|ls|whoami|rm|cp|mv|chmod)',
                r';.*(cat|ls|whoami|rm|cp|mv|chmod)',
                r'&.*(cat|ls|whoami|rm|cp|mv|chmod)',
                r'\$(cat|ls|whoami|rm|cp|mv|chmod)',
                r'`.*(cat|ls|whoami|rm|cp|mv|chmod)`'
            ],
            'brute_force': [
                r'Failed password for.*from',
                r'Connection closed by .*\[preauth\]',
                r'multiple invalid login attempts',
                r'Too many failed login attempts'
            ],
            'malware': [
                r'\.(exe|dll|vbs|js|ps1|bat|cmd)$',
                r'powershell.*-EncodedCommand',
                r'wscript.*shell\.run',
                r'vbs.*execute',
                r'mshta.*vbscript'
            ]
        }
        
        self.results = {
            'logs_parsed': 0,
            'total_entries': 0,
            'threats_detected': 0,
            'by_type': {},
            'by_severity': {},
            'timeline': []
        }
        
    # ==========================================
    # Log File Discovery and Parsing
    # ==========================================
    def discover_log_files(self, extensions=['.log', '.txt', '.csv']):
        """
        Discover log files in log directory
        
        Args:
            extensions: List of log file extensions to find
            
        Returns:
            List of log file paths
        """
        log_files = []
        
        for ext in extensions:
            log_files.extend(glob.glob(f"{self.log_dir}/*{ext}"))
            
        return log_files
        
    def parse_log_file(self, file_path, log_type='auto'):
        """
        Parse log file based on type
        
        Args:
            file_path: Path to log file
            log_type: Log format type (auto, apache, nginx, syslog, windows)
            
        Returns:
            List of parsed log entries
        """
        print(f"Parsing log file: {file_path}")
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            
        parsed_entries = []
        
        for i, line in enumerate(lines):
            line = line.strip()
            
            if not line or line.startswith('#'):
                continue
                
            try:
                entry = self._parse_line(line, log_type)
                if entry:
                    parsed_entries.append(entry)
                    
            except Exception as e:
                print(f"Error parsing line {i+1} in {file_path}: {e}")
                
        self.results['logs_parsed'] += 1
        self.results['total_entries'] += len(parsed_entries)
        
        return parsed_entries
        
    def _parse_line(self, line, log_type):
        """Parse individual log line based on format"""
        if log_type == 'apache' or log_type == 'nginx':
            return self._parse_apache_line(line)
        elif log_type == 'syslog':
            return self._parse_syslog_line(line)
        elif log_type == 'windows':
            return self._parse_windows_line(line)
        else:
            return self._parse_generic_line(line)
            
    def _parse_apache_line(self, line):
        """Parse Apache/NGINX log line (CLF format)"""
        # Common Log Format: 127.0.0.1 - user [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.0" 200 1234
        pattern = r'^(\d+\.\d+\.\d+\.\d+) - (.*?) \[(.*?)\] "(.*?)" (\d+) (\d+)'
        match = re.match(pattern, line)
        
        if match:
            return {
                'source_ip': match.group(1),
                'user': match.group(2),
                'timestamp': self._parse_apache_timestamp(match.group(3)),
                'request': match.group(4),
                'status': int(match.group(5)),
                'size': int(match.group(6)),
                'type': 'apache'
            }
            
        return None
        
    def _parse_apache_timestamp(self, timestamp_str):
        """Parse Apache timestamp format"""
        try:
            return datetime.datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S %z')
        except:
            return None
            
    def _parse_syslog_line(self, line):
        """Parse syslog line format"""
        # Syslog format: Jan  1 00:00:00 hostname daemon: message
        pattern = r'^(\w{3}\s+\d+\s+\d+:\d+:\d+) (\S+) (\S+): (.*)$'
        match = re.match(pattern, line)
        
        if match:
            return {
                'timestamp': self._parse_syslog_timestamp(match.group(1)),
                'hostname': match.group(2),
                'daemon': match.group(3),
                'message': match.group(4),
                'type': 'syslog'
            }
            
        return None
        
    def _parse_syslog_timestamp(self, timestamp_str):
        """Parse syslog timestamp format"""
        try:
            return datetime.datetime.strptime(timestamp_str, '%b %d %H:%M:%S')
        except:
            return None
            
    def _parse_windows_line(self, line):
        """Parse Windows event log line"""
        # Windows format: 2024-01-01 00:00:00,123 - Information - EventId: 1234 - ...
        pattern = r'^(\d{4}-\d{2}-\d{2} \d+:\d+:\d+),?\d* - (\w+) - (.*)$'
        match = re.match(pattern, line)
        
        if match:
            return {
                'timestamp': datetime.datetime.strptime(match.group(1), '%Y-%m-%d %H:%M:%S'),
                'level': match.group(2),
                'message': match.group(3),
                'type': 'windows'
            }
            
        return None
        
    def _parse_generic_line(self, line):
        """Parse generic log line"""
        return {
            'raw': line,
            'type': 'generic',
            'timestamp': datetime.datetime.now()
        }
        
    # ==========================================
    # Threat Detection
    # ==========================================
    def detect_threats(self, log_entries):
        """
        Detect threats in parsed log entries
        
        Args:
            log_entries: List of parsed log entries
            
        Returns:
            List of detected threats
        """
        threats = []
        
        for entry in log_entries:
            detected = self._scan_entry_for_threats(entry)
            if detected:
                threats.extend(detected)
                
        return threats
        
    def _scan_entry_for_threats(self, entry):
        """Scan individual log entry for threats"""
        threats = []
        
        # Check each threat pattern
        for threat_type, patterns in self.threat_patterns.items():
            for pattern in patterns:
                # Search in all string fields of the entry
                for key, value in entry.items():
                    if isinstance(value, str):
                        if re.search(pattern, value, re.IGNORECASE):
                            threat = {
                                'timestamp': entry.get('timestamp', datetime.datetime.now()),
                                'entry': entry,
                                'threat_type': threat_type,
                                'pattern': pattern,
                                'severity': self._determine_severity(threat_type)
                            }
                            
                            threats.append(threat)
                            self._update_results(threat)
                            
                            # Stop checking other patterns for this entry if threat found
                            break
                            
        return threats
        
    def _determine_severity(self, threat_type):
        """Determine severity of threat type"""
        severity_map = {
            'sql_injection': 'critical',
            'command_injection': 'critical',
            'xss': 'high',
            'brute_force': 'high',
            'malware': 'critical'
        }
        
        return severity_map.get(threat_type, 'medium')
        
    def _update_results(self, threat):
        """Update results statistics"""
        self.results['threats_detected'] += 1
        
        # Update by type count
        if threat['threat_type'] not in self.results['by_type']:
            self.results['by_type'][threat['threat_type']] = 0
        self.results['by_type'][threat['threat_type']] += 1
        
        # Update by severity count
        if threat['severity'] not in self.results['by_severity']:
            self.results['by_severity'][threat['severity']] = 0
        self.results['by_severity'][threat['severity']] += 1
        
        # Add to timeline
        self.results['timeline'].append({
            'timestamp': threat['timestamp'].isoformat() if hasattr(threat['timestamp'], 'isoformat') else str(threat['timestamp']),
            'threat_type': threat['threat_type'],
            'severity': threat['severity']
        })
        
    # ==========================================
    # Analysis and Reporting
    # ==========================================
    def generate_analysis_summary(self):
        """Generate comprehensive analysis summary"""
        summary = {
            'statistics': {
                'logs_parsed': self.results['logs_parsed'],
                'total_entries': self.results['total_entries'],
                'threats_detected': self.results['threats_detected'],
                'by_type': self.results['by_type'],
                'by_severity': self.results['by_severity']
            },
            'top_sources': self._find_top_sources(),
            'timeline': self.results['timeline']
        }
        
        return summary
        
    def _find_top_sources(self):
        """Find top sources of threats"""
        sources = {}
        
        # This is a placeholder - real implementation would track IPs from entries
        sample_sources = {
            '192.168.1.100': 5,
            '10.0.0.50': 3,
            '172.16.0.25': 2
        }
        
        return sorted(sample_sources.items(), key=lambda x: x[1], reverse=True)
        
    def save_report(self, report, format='json'):
        """Save analysis report to file"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.output_dir}/log_analysis_report_{timestamp}"
        
        if format == 'json':
            filename += '.json'
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, default=str)
                
        elif format == 'csv':
            filename += '.csv'
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=['timestamp', 'threat_type', 'severity'])
                writer.writeheader()
                
                for entry in report['statistics']['by_type']:
                    writer.writerow({
                        'timestamp': 'N/A',
                        'threat_type': entry,
                        'severity': report['statistics']['by_type'][entry]
                    })
                    
        elif format == 'html':
            filename += '.html'
            self._save_html_report(report, filename)
            
        else:
            raise ValueError(f"Unsupported format: {format}")
            
        return filename
        
    def _save_html_report(self, report, filename):
        """Generate HTML report"""
        html = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Log Analysis Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .report {{ max-width: 1200px; margin: 0 auto; }}
                .header {{ background: #f0f0f0; padding: 20px; border-radius: 5px; }}
                .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }}
                .stat-box {{ padding: 15px; border-radius: 5px; color: white; font-weight: bold; }}
                .critical {{ background: #dc3545; }}
                .high {{ background: #fd7e14; }}
                .medium {{ background: #ffc107; }}
                .low {{ background: #28a745; }}
                .table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                .table th, .table td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                .table th {{ background: #f0f0f0; }}
                h1, h2 {{ color: #333; }}
            </style>
        </head>
        <body>
            <div class="report">
                <div class="header">
                    <h1>Log Analysis Report</h1>
                    <p>Generated: {datetime.datetime.now().isoformat()}</p>
                </div>
                
                <div class="summary">
                    <div class="stat-box">
                        Logs Parsed: {report['statistics']['logs_parsed']}
                    </div>
                    <div class="stat-box">
                        Total Entries: {report['statistics']['total_entries']}
                    </div>
                    <div class="stat-box">
                        Threats Detected: {report['statistics']['threats_detected']}
                    </div>
                </div>
                
                <h2>Threat Severity</h2>
                <div class="summary">
                    <div class="stat-box critical">
                        Critical: {report['statistics']['by_severity'].get('critical', 0)}
                    </div>
                    <div class="stat-box high">
                        High: {report['statistics']['by_severity'].get('high', 0)}
                    </div>
                    <div class="stat-box medium">
                        Medium: {report['statistics']['by_severity'].get('medium', 0)}
                    </div>
                    <div class="stat-box low">
                        Low: {report['statistics']['by_severity'].get('low', 0)}
                    </div>
                </div>
                
                <h2>Threat Types</h2>
                <table class="table">
                    <tr>
                        <th>Threat Type</th>
                        <th>Count</th>
                    </tr>
        """
        
        for threat_type, count in report['statistics']['by_type'].items():
            html += f"""
                <tr>
                    <td>{threat_type.replace('_', ' ').capitalize()}</td>
                    <td>{count}</td>
                </tr>
            """
            
        html += """
                </table>
                
                <h2>Top Source IPs</h2>
                <table class="table">
                    <tr>
                        <th>Source IP</th>
                        <th>Threat Count</th>
                    </tr>
        """
        
        for source_ip, count in report['top_sources']:
            html += f"""
                <tr>
                    <td>{source_ip}</td>
                    <td>{count}</td>
                </tr>
            """
            
        html += """
                </table>
                
                <h2>Threat Timeline</h2>
                <p>Chart visualization of threats over time would appear here</p>
            </div>
            </body>
            </html>
        """
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
            
    # ==========================================
    # Alert Generation
    # ==========================================
    def generate_alerts(self, threats, severity_threshold='medium'):
        """
        Generate alerts for threats above severity threshold
        
        Args:
            threats: List of detected threats
            severity_threshold: Minimum severity for alerts
            
        Returns:
            List of alerts
        """
        alerts = []
        
        severity_levels = {
            'info': 1,
            'low': 2,
            'medium': 3,
            'high': 4,
            'critical': 5
        }
        
        min_level = severity_levels.get(severity_threshold, 3)
        
        for threat in threats:
            threat_level = severity_levels.get(threat['severity'], 3)
            
            if threat_level >= min_level:
                alerts.append({
                    'timestamp': threat['timestamp'],
                    'threat_type': threat['threat_type'],
                    'severity': threat['severity'],
                    'description': f"Detected {threat['threat_type']} attack",
                    'pattern': threat['pattern'],
                    'entry': threat['entry']
                })
                
        return alerts
        
    def send_alerts(self, alerts, method='email'):
        """
        Send alerts using specified method
        
        Args:
            alerts: List of alerts to send
            method: Alert method (email, slack, syslog)
            
        Returns:
            Success status
        """
        print(f"Generating {len(alerts)} alerts using {method}")
        
        # In real implementation, this would send actual alerts
        for alert in alerts:
            print(f"ALERT [{alert['severity']}]: {alert['description']}")
            
        return True
        
    # ==========================================
    # Data Visualization
    # ==========================================
    def visualize_threat_timeline(self, threats):
        """Visualize threat occurrences over time"""
        if not threats:
            print("No threats to visualize")
            return None
            
        # Group threats by time interval
        time_groups = {}
        
        for threat in threats:
            time_key = threat['timestamp'].strftime('%Y-%m-%d %H')
            
            if time_key not in time_groups:
                time_groups[time_key] = {
                    'count': 0,
                    'by_type': {}
                }
                
            time_groups[time_key]['count'] += 1
            
            threat_type = threat['threat_type']
            if threat_type not in time_groups[time_key]['by_type']:
                time_groups[time_key]['by_type'][threat_type] = 0
            time_groups[time_key]['by_type'][threat_type] += 1
            
        # Create timeline chart
        dates = sorted(time_groups.keys())
        counts = [time_groups[date]['count'] for date in dates]
        
        plt.figure(figsize=(12, 6))
        plt.plot(dates, counts, marker='o', linestyle='-', color='#dc3545')
        plt.title('Threats Over Time')
        plt.xlabel('Time')
        plt.ylabel('Number of Threats')
        plt.xticks(rotation=45)
        plt.grid(True)
        plt.tight_layout()
        
        output_file = f"{self.output_dir}/threat_timeline_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        plt.savefig(output_file)
        plt.close()
        
        return output_file
        
    def visualize_severity_distribution(self, threats):
        """Visualize threat severity distribution"""
        severity_counts = {}
        
        for threat in threats:
            severity = threat['severity']
            if severity not in severity_counts:
                severity_counts[severity] = 0
            severity_counts[severity] += 1
            
        plt.figure(figsize=(8, 6))
        colors = {
            'critical': '#dc3545',
            'high': '#fd7e14',
            'medium': '#ffc107',
            'low': '#28a745',
            'info': '#17a2b8'
        }
        
        plt.pie(
            severity_counts.values(),
            labels=[f"{k} ({v})" for k, v in severity_counts.items()],
            colors=[colors.get(k, '#6c757d') for k in severity_counts.keys()],
            autopct='%1.1f%%'
        )
        
        plt.title('Threat Severity Distribution')
        
        output_file = f"{self.output_dir}/severity_distribution_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        plt.savefig(output_file)
        plt.close()
        
        return output_file
        
    # ==========================================
    # Analysis Workflow
    # ==========================================
    def analyze_logs(self):
        """Run complete log analysis workflow"""
        print(f"{'='*60}")
        print(f"  STARTING LOG ANALYSIS")
        print(f"  Log Directory: {self.log_dir}")
        print(f"{'='*60}")
        
        # Step 1: Discover log files
        log_files = self.discover_log_files()
        print(f"Found {len(log_files)} log files")
        
        # Step 2: Parse log files
        all_entries = []
        
        for file_path in log_files:
            try:
                entries = self.parse_log_file(file_path)
                all_entries.extend(entries)
            except Exception as e:
                print(f"Error parsing {file_path}: {e}")
                
        print(f"Total parsed entries: {len(all_entries)}")
        
        # Step 3: Detect threats
        threats = self.detect_threats(all_entries)
        print(f"Threats detected: {len(threats)}")
        
        # Step 4: Generate alerts
        alerts = self.generate_alerts(threats)
        print(f"Alerts generated: {len(alerts)}")
        self.send_alerts(alerts)
        
        # Step 5: Generate report and visualize
        report = self.generate_analysis_summary()
        report_file = self.save_report(report, 'html')
        
        if threats:
            timeline_file = self.visualize_threat_timeline(threats)
            severity_file = self.visualize_severity_distribution(threats)
        
        print(f"Report saved to: {report_file}")
        
        return report

def main():
    """Main function to demonstrate log analysis automation"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Log Analysis Automation - Automate log processing and threat detection"
    )
    
    parser.add_argument(
        "-l", "--log-dir",
        default="logs",
        help="Log directory (default: logs)"
    )
    
    parser.add_argument(
        "-o", "--output-dir",
        default="results",
        help="Output directory (default: results)"
    )
    
    parser.add_argument(
        "-f", "--format",
        choices=['json', 'csv', 'html'],
        default='html',
        help="Report format (default: HTML)"
    )
    
    parser.add_argument(
        "-s", "--severity",
        choices=['info', 'low', 'medium', 'high', 'critical'],
        default='medium',
        help="Minimum severity for alerts (default: medium)"
    )
    
    args = parser.parse_args()
    
    try:
        analyzer = LogAnalyzer(args.log_dir, args.output_dir)
        report = analyzer.analyze_logs()
        
        print(f"\n{'='*60}")
        print(f"  ANALYSIS COMPLETED")
        print(f"{'='*60}")
        print(f"Total threats detected: {report['statistics']['threats_detected']}")
        print(f"By severity:")
        for severity, count in report['statistics']['by_severity'].items():
            print(f"  - {severity}: {count}")
        print(f"By type:")
        for threat_type, count in report['statistics']['by_type'].items():
            print(f"  - {threat_type}: {count}")
            
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        print(traceback.format_exc())

if __name__ == "__main__":
    main()
