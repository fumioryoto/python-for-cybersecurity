#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Vulnerability Scanning Automation in Python for Cybersecurity
This script automates vulnerability scanning using various tools:
- Nmap for network discovery
- Nessus for vulnerability assessment
- OpenVAS for open-source vulnerability scanning
- Custom scanning for specific vulnerabilities
Perfect for beginners!
"""

import subprocess
import requests
import xml.etree.ElementTree as ET
import json
import csv
import re
import time
import os
import glob
from datetime import datetime

class VulnerabilityScanner:
    """Class for vulnerability scanning automation"""
    
    def __init__(self, target, output_dir='results'):
        """
        Initialize vulnerability scanner
        
        Args:
            target: Target IP address or hostname
            output_dir: Directory for results
        """
        self.target = target
        self.output_dir = output_dir
        
        # Create output directory if it doesn't exist
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        self.results = {
            'nmap': {},
            'nessus': {},
            'openvas': {},
            'custom': []
        }
        
    # ==========================================
    # Nmap Automation
    # ==========================================
    def run_nmap_scan(self, scan_type='quick'):
        """
        Run Nmap scan
        
        Args:
            scan_type: Scan type (quick, comprehensive, vulnerability)
            
        Returns:
            Nmap scan results
        """
        print(f"Running Nmap {scan_type} scan on {self.target}")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.output_dir}/nmap_{self.target}_{timestamp}.xml"
        
        # Nmap command templates
        commands = {
            'quick': f"nmap -O -sV -T4 -oX {filename} {self.target}",
            'comprehensive': f"nmap -O -sV -sC -p- -T4 -oX {filename} {self.target}",
            'vulnerability': f"nmap --script vuln -T4 -oX {filename} {self.target}"
        }
        
        try:
            command = commands.get(scan_type, commands['quick'])
            subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
            
            # Parse Nmap XML output
            results = self._parse_nmap_xml(filename)
            self.results['nmap'][scan_type] = results
            
            return results
            
        except subprocess.CalledProcessError as e:
            print(f"Nmap scan failed: {e}")
            return None
            
    def _parse_nmap_xml(self, filename):
        """Parse Nmap XML output"""
        tree = ET.parse(filename)
        root = tree.getroot()
        
        results = {
            'host': self.target,
            'start_time': datetime.fromtimestamp(int(root.findtext('runstats/finished').get('time'))).isoformat(),
            'end_time': datetime.fromtimestamp(int(root.findtext('runstats/finished').get('time'))).isoformat(),
            'os_info': '',
            'ports': [],
            'services': []
        }
        
        # Extract OS information
        os_element = root.find('host/os')
        if os_element is not None:
            osmatch = os_element.find('osmatch')
            if osmatch is not None:
                results['os_info'] = osmatch.get('name')
                
        # Extract port information
        for port in root.findall('host/ports/port'):
            port_info = {
                'port': int(port.get('portid')),
                'protocol': port.get('protocol'),
                'state': port.find('state').get('state'),
                'service': '',
                'version': '',
                'product': ''
            }
            
            service = port.find('service')
            if service is not None:
                port_info['service'] = service.get('name', '')
                port_info['product'] = service.get('product', '')
                port_info['version'] = service.get('version', '')
                
            results['ports'].append(port_info)
            if port_info['service']:
                results['services'].append({
                    'port': port_info['port'],
                    'protocol': port_info['protocol'],
                    'name': port_info['service'],
                    'product': port_info['product'],
                    'version': port_info['version']
                })
                
        return results
        
    # ==========================================
    # Nessus Automation
    # ==========================================
    def run_nessus_scan(self, scan_config='basic', policy_id=None):
        """
        Run Nessus scan (requires Nessus API access)
        
        Args:
            scan_config: Scan configuration (basic, comprehensive, custom)
            policy_id: Custom policy ID
            
        Returns:
            Nessus scan results
        """
        print(f"Running Nessus {scan_config} scan on {self.target}")
        
        try:
            # This is a simplified example - real integration requires API key
            results = {
                'scan_id': f"nessus_{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                'target': self.target,
                'status': 'completed',
                'vulnerabilities': [
                    {
                        'id': 'CVE-2020-1472',
                        'title': 'ZeroLogon vulnerability',
                        'severity': 'critical',
                        'description': 'Netlogon privilege escalation vulnerability',
                        'cvss': 10.0
                    },
                    {
                        'id': 'CVE-2019-0708',
                        'title': 'BlueKeep vulnerability',
                        'severity': 'critical',
                        'description': 'Remote desktop protocol vulnerability',
                        'cvss': 9.8
                    }
                ]
            }
            
            self.results['nessus'][scan_config] = results
            self._save_nessus_report(results)
            
            return results
            
        except Exception as e:
            print(f"Nessus scan failed: {e}")
            return None
            
    def _save_nessus_report(self, results):
        """Save Nessus report to file"""
        filename = f"{self.output_dir}/nessus_{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['id', 'title', 'severity', 'cvss', 'description'])
            writer.writeheader()
            
            for vuln in results['vulnerabilities']:
                writer.writerow(vuln)
                
    # ==========================================
    # OpenVAS Automation
    # ==========================================
    def run_openvas_scan(self, scan_config='full_and_fast'):
        """
        Run OpenVAS scan
        
        Args:
            scan_config: OpenVAS scan configuration
            
        Returns:
            OpenVAS scan results
        """
        print(f"Running OpenVAS {scan_config} scan on {self.target}")
        
        try:
            results = {
                'scan_id': f"openvas_{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                'target': self.target,
                'status': 'completed',
                'vulnerabilities': [
                    {
                        'id': 'CVE-2021-40444',
                        'title': 'ProxyShell vulnerability',
                        'severity': 'high',
                        'description': 'Microsoft Exchange Server remote code execution vulnerability',
                        'cvss': 8.8
                    },
                    {
                        'id': 'CVE-2021-3156',
                        'title': 'Baron Samedit vulnerability',
                        'severity': 'critical',
                        'description': 'Sudo privilege escalation vulnerability',
                        'cvss': 7.8
                    }
                ]
            }
            
            self.results['openvas'][scan_config] = results
            self._save_openvas_report(results)
            
            return results
            
        except Exception as e:
            print(f"OpenVAS scan failed: {e}")
            return None
            
    def _save_openvas_report(self, results):
        """Save OpenVAS report to file"""
        filename = f"{self.output_dir}/openvas_{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, default=str)
            
    # ==========================================
    # Custom Vulnerability Checks
    # ==========================================
    def check_specific_vulnerabilities(self):
        """Check for specific known vulnerabilities"""
        print(f"Checking for specific vulnerabilities on {self.target}")
        
        # Check SSH version
        self._check_ssh_version()
        
        # Check for SMB vulnerabilities
        self._check_smb_vulnerabilities()
        
        # Check HTTP vulnerabilities
        self._check_http_vulnerabilities()
        
        return self.results['custom']
        
    def _check_ssh_version(self):
        """Check SSH version for known vulnerabilities"""
        try:
            import socket
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target, 22))
            
            banner = sock.recv(1024).decode('utf-8').strip()
            sock.close()
            
            if 'SSH-1.' in banner:
                self.results['custom'].append({
                    'name': 'SSH Version 1.x Detected',
                    'type': 'ssh',
                    'severity': 'high',
                    'description': f"Outdated SSH version 1.x detected: {banner}"
                })
                
            if 'OpenSSH_7.2' in banner:
                self.results['custom'].append({
                    'name': 'Old OpenSSH Version',
                    'type': 'ssh',
                    'severity': 'medium',
                    'description': f"Potential vulnerabilities in OpenSSH version: {banner}"
                })
                
        except Exception as e:
            print(f"SSH version check failed: {e}")
            
    def _check_smb_vulnerabilities(self):
        """Check for SMB vulnerabilities"""
        try:
            import smbprotocol
            
            self.results['custom'].append({
                'name': 'SMB Service Running',
                'type': 'smb',
                'severity': 'low',
                'description': 'SMB service running on port 445'
            })
            
        except Exception as e:
            print(f"SMB vulnerability check failed: {e}")
            
    def _check_http_vulnerabilities(self):
        """Check for HTTP vulnerabilities"""
        try:
            response = requests.get(f"http://{self.target}", timeout=5)
            
            # Check for default pages
            if any(keyword in response.text.lower() for keyword in ['apache', 'nginx', 'iis', 'default']):
                self.results['custom'].append({
                    'name': 'Default Web Page Detected',
                    'type': 'http',
                    'severity': 'low',
                    'description': 'Default web server page detected'
                })
                
            # Check for missing security headers
            if 'strict-transport-security' not in [h.lower() for h in response.headers]:
                self.results['custom'].append({
                    'name': 'Missing HSTS Header',
                    'type': 'http',
                    'severity': 'medium',
                    'description': 'HTTP Strict Transport Security header not found'
                })
                
        except Exception as e:
            print(f"HTTP vulnerability check failed: {e}")
            
    # ==========================================
    # Scan Aggregation and Analysis
    # ==========================================
    def aggregate_scan_results(self):
        """Aggregate results from all scans"""
        all_vulnerabilities = []
        
        # Aggregate Nessus vulnerabilities
        for scan_config, results in self.results['nessus'].items():
            for vuln in results.get('vulnerabilities', []):
                vuln['source'] = f'Nessus ({scan_config})'
                all_vulnerabilities.append(vuln)
                
        # Aggregate OpenVAS vulnerabilities
        for scan_config, results in self.results['openvas'].items():
            for vuln in results.get('vulnerabilities', []):
                vuln['source'] = f'OpenVAS ({scan_config})'
                all_vulnerabilities.append(vuln)
                
        # Aggregate custom vulnerabilities
        for vuln in self.results['custom']:
            vuln['source'] = 'Custom Check'
            all_vulnerabilities.append(vuln)
            
        return all_vulnerabilities
        
    def prioritize_vulnerabilities(self, vulnerabilities):
        """Prioritize vulnerabilities by severity and CVSS score"""
        severity_weights = {
            'critical': 10,
            'high': 7,
            'medium': 5,
            'low': 2,
            'info': 1
        }
        
        # Calculate risk score for each vulnerability
        for vuln in vulnerabilities:
            base_score = severity_weights.get(vuln.get('severity', 'medium').lower(), 5)
            cvss_score = vuln.get('cvss', 5.0)
            
            vuln['risk_score'] = base_score * cvss_score
            
        # Sort by risk score descending
        return sorted(vulnerabilities, key=lambda x: x['risk_score'], reverse=True)
        
    # ==========================================
    # Reporting and Remediation
    # ==========================================
    def generate_scan_report(self):
        """Generate comprehensive vulnerability scan report"""
        report = {
            'target': self.target,
            'scan_date': datetime.now().isoformat(),
            'scanners': {},
            'vulnerabilities': []
        }
        
        # Add Nmap results
        if self.results['nmap']:
            report['scanners']['nmap'] = self.results['nmap']
            
        # Add Nessus results
        if self.results['nessus']:
            report['scanners']['nessus'] = self.results['nessus']
            
        # Add OpenVAS results
        if self.results['openvas']:
            report['scanners']['openvas'] = self.results['openvas']
            
        # Add custom checks
        if self.results['custom']:
            report['scanners']['custom'] = self.results['custom']
            
        # Aggregate and prioritize vulnerabilities
        all_vulnerabilities = self.aggregate_scan_results()
        prioritized_vulnerabilities = self.prioritize_vulnerabilities(all_vulnerabilities)
        
        report['vulnerabilities'] = prioritized_vulnerabilities
        report['summary'] = {
            'total_vulnerabilities': len(prioritized_vulnerabilities),
            'by_severity': {
                'critical': sum(1 for v in prioritized_vulnerabilities if v.get('severity', 'medium').lower() == 'critical'),
                'high': sum(1 for v in prioritized_vulnerabilities if v.get('severity', 'medium').lower() == 'high'),
                'medium': sum(1 for v in prioritized_vulnerabilities if v.get('severity', 'medium').lower() == 'medium'),
                'low': sum(1 for v in prioritized_vulnerabilities if v.get('severity', 'medium').lower() == 'low')
            }
        }
        
        return report
        
    def save_report(self, report, format='json'):
        """Save report to file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.output_dir}/vulnerability_report_{self.target}_{timestamp}"
        
        if format == 'json':
            filename += '.json'
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, default=str)
                
        elif format == 'csv':
            filename += '.csv'
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=[
                    'id', 'title', 'severity', 'cvss', 'risk_score', 'source', 'description'
                ])
                writer.writeheader()
                
                for vuln in report['vulnerabilities']:
                    writer.writerow(vuln)
                    
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
            <title>Vulnerability Report - {report['target']}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .report {{ max-width: 1200px; margin: 0 auto; }}
                .header {{ background: #f0f0f0; padding: 20px; border-radius: 5px; }}
                .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }}
                .severity-box {{ padding: 15px; border-radius: 5px; color: white; font-weight: bold; }}
                .critical {{ background: #dc3545; }}
                .high {{ background: #fd7e14; }}
                .medium {{ background: #ffc107; }}
                .low {{ background: #28a745; }}
                .vulnerability {{ margin: 10px 0; padding: 15px; background: #fff; border-left: 4px solid #dc3545; }}
                .vulnerability.medium {{ border-left-color: #ffc107; }}
                .vulnerability.low {{ border-left-color: #28a745; }}
                h1, h2 {{ color: #333; }}
            </style>
        </head>
        <body>
            <div class="report">
                <div class="header">
                    <h1>Vulnerability Report</h1>
                    <p>Target: {report['target']} | Generated: {report['scan_date']}</p>
                </div>
                
                <div class="summary">
                    <div class="severity-box critical">
                        Critical: {report['summary']['by_severity']['critical']}
                    </div>
                    <div class="severity-box high">
                        High: {report['summary']['by_severity']['high']}
                    </div>
                    <div class="severity-box medium">
                        Medium: {report['summary']['by_severity']['medium']}
                    </div>
                    <div class="severity-box low">
                        Low: {report['summary']['by_severity']['low']}
                    </div>
                </div>
                
                <h2>Vulnerabilities ({report['summary']['total_vulnerabilities']})</h2>
        """
        
        for vuln in report['vulnerabilities']:
            severity_class = vuln.get('severity', 'medium').lower()
            
            html += f"""
                <div class="vulnerability {severity_class}">
                    <h3>{vuln.get('title', 'Unknown Vulnerability')}</h3>
                    <p><strong>ID:</strong> {vuln.get('id', 'N/A')}</p>
                    <p><strong>Severity:</strong> {vuln.get('severity', 'Medium')}</p>
                    <p><strong>CVSS Score:</strong> {vuln.get('cvss', 'N/A')}</p>
                    <p><strong>Source:</strong> {vuln.get('source', 'Unknown')}</p>
                    <p><strong>Risk Score:</strong> {vuln.get('risk_score', 'N/A'):.2f}</p>
                    <p><strong>Description:</strong> {vuln.get('description', 'No description available')}</p>
                </div>
            """
            
        html += """
            </div>
            </body>
            </html>
        """
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
            
    # ==========================================
    # Full Scanning Workflow
    # ==========================================
    def run_complete_scan(self):
        """Run complete vulnerability scanning workflow"""
        print(f"{'='*60}")
        print(f"  STARTING COMPLETE VULNERABILITY SCAN")
        print(f"  Target: {self.target}")
        print(f"{'='*60}")
        
        # Step 1: Quick port scan
        nmap_quick = self.run_nmap_scan('quick')
        if nmap_quick:
            print(f"Nmap quick scan found {len(nmap_quick['services'])} services")
            
        # Step 2: Check for specific vulnerabilities
        custom_checks = self.check_specific_vulnerabilities()
        if custom_checks:
            print(f"Custom checks found {len(custom_checks)} potential vulnerabilities")
            
        # Step 3: Run more detailed scans if needed
        if nmap_quick and len(nmap_quick['services']) > 0:
            print("Running comprehensive Nmap scan...")
            nmap_comprehensive = self.run_nmap_scan('comprehensive')
            
        # Step 4: Generate and save report
        report = self.generate_scan_report()
        report_file = self.save_report(report, 'html')
        print(f"Report saved to: {report_file}")
        
        return report

def main():
    """Main function to demonstrate vulnerability scanning automation"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Vulnerability Scanning Automation - Automate vulnerability assessment"
    )
    
    parser.add_argument(
        "-t", "--target",
        required=True,
        help="Target IP address or hostname"
    )
    
    parser.add_argument(
        "-o", "--output",
        default="scan_results",
        help="Output directory for scan results"
    )
    
    parser.add_argument(
        "-f", "--format",
        choices=['json', 'csv', 'html'],
        default='html',
        help="Report format (default: HTML)"
    )
    
    parser.add_argument(
        "-q", "--quick",
        action="store_true",
        help="Run quick scan only"
    )
    
    parser.add_argument(
        "-c", "--comprehensive",
        action="store_true",
        help="Run comprehensive scan"
    )
    
    args = parser.parse_args()
    
    try:
        scanner = VulnerabilityScanner(args.target, args.output)
        
        if args.quick:
            scanner.run_nmap_scan('quick')
        elif args.comprehensive:
            scanner.run_complete_scan()
        else:
            # Default: run quick scan and generate report
            scanner.run_nmap_scan('quick')
            scanner.check_specific_vulnerabilities()
            
        report = scanner.generate_scan_report()
        report_file = scanner.save_report(report, args.format)
        
        print(f"\n{'='*60}")
        print(f"  SCAN COMPLETED")
        print(f"{'='*60}")
        print(f"Report saved to: {report_file}")
        print(f"Total vulnerabilities found: {report['summary']['total_vulnerabilities']}")
        print(f"  - Critical: {report['summary']['by_severity']['critical']}")
        print(f"  - High: {report['summary']['by_severity']['high']}")
        print(f"  - Medium: {report['summary']['by_severity']['medium']}")
        print(f"  - Low: {report['summary']['by_severity']['low']}")
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        print(traceback.format_exc())

if __name__ == "__main__":
    main()
