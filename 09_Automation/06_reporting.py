#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Security Reporting Automation in Python
This script automates security reporting for various scenarios:
- Penetration testing reports
- Vulnerability assessment reports
- Compliance reports
- Incident response reports
- Audit reports
Perfect for beginners!
"""

import os
import sys
import json
import yaml
import csv
import datetime
import time
import socket
import re
import hashlib
import logging
from pathlib import Path
from typing import Dict, List, Any

class SecurityReporting:
    """Class for security reporting automation"""
    
    def __init__(self, config_file='config/reporting_config.yaml'):
        """
        Initialize security reporting system
        
        Args:
            config_file: Configuration file path
        """
        self.config = self._load_config(config_file)
        self.reports = []
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('logs/reporting.log'),
                logging.StreamHandler()
            ]
        )
        
        self.logger = logging.getLogger(__name__)
        
        # Create directories if they don't exist
        self._create_directories()
        
    def _load_config(self, config_file):
        """Load configuration from file"""
        default_config = {
            'report_types': ['penetration_testing', 'vulnerability_assessment', 'compliance', 'incident_response', 'audit'],
            'formats': ['json', 'csv', 'html', 'markdown', 'pdf'],
            'templates': {
                'penetration_testing': 'templates/penetration_testing.md',
                'vulnerability_assessment': 'templates/vulnerability_assessment.md',
                'compliance': 'templates/compliance.md',
                'incident_response': 'templates/incident_response.md',
                'audit': 'templates/audit.md'
            },
            'notification': {
                'email_recipients': ['security@example.com'],
                'slack_channels': ['#security-reports'],
                'sms_recipients': ['+1234567890']
            },
            'delivery': {
                'email': True,
                'slack': False,
                'sms': False,
                'file': True
            },
            'retention': {
                'days': 365,
                'storage_path': 'reports',
                'backup': True
            },
            'metadata': {
                'company': 'Example Corporation',
                'reporting_team': 'Security Team',
                'contact': 'security@example.com',
                'logo': 'assets/logo.png'
            }
        }
        
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    user_config = yaml.safe_load(f)
                return {**default_config, **user_config}
            except Exception as e:
                self.logger.error(f"Error loading config: {e}")
                return default_config
                
        return default_config
        
    def _create_directories(self):
        """Create necessary directories for reporting"""
        directories = [
            'reports',
            'templates',
            'assets',
            'logs'
        ]
        
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
            
    # ==========================================
    # Report Generation Methods
    # ==========================================
    def generate_report(self, report_type: str, data: Dict[str, Any], format: str = 'html') -> str:
        """
        Generate security report
        
        Args:
            report_type: Type of report to generate
            data: Report data
            format: Output format
            
        Returns:
            Path to generated report file
        """
        if report_type not in self.config['report_types']:
            raise ValueError(f"Unsupported report type: {report_type}")
            
        if format not in self.config['formats']:
            raise ValueError(f"Unsupported format: {format}")
            
        self.logger.info(f"Generating {report_type} report in {format} format")
        
        # Validate report data
        self._validate_report_data(data)
        
        # Load template
        template = self._load_template(report_type)
        
        # Render report
        rendered_content = self._render_report(template, data)
        
        # Generate filename
        filename = self._generate_filename(report_type, format)
        
        # Write report
        self._write_report(rendered_content, filename, format)
        
        # Store report metadata
        self._store_report_metadata(filename, report_type, format)
        
        return filename
        
    def _validate_report_data(self, data: Dict[str, Any]):
        """Validate report data structure"""
        required_fields = ['title', 'description', 'scope', 'date', 'findings']
        
        for field in required_fields:
            if field not in data:
                raise ValueError(f"Missing required field: {field}")
                
        if not data['findings']:
            raise ValueError("No findings specified")
            
        # Validate findings structure
        for finding in data['findings']:
            required_finding_fields = ['title', 'description', 'severity', 'recommendation']
            
            for field in required_finding_fields:
                if field not in finding:
                    raise ValueError(f"Finding missing field: {field}")
                    
            # Validate severity levels
            if finding['severity'] not in ['Critical', 'High', 'Medium', 'Low', 'Info']:
                raise ValueError(f"Invalid severity level: {finding['severity']}")
                
    def _load_template(self, report_type: str) -> str:
        """Load report template"""
        template_path = self.config['templates'][report_type]
        
        if not os.path.exists(template_path):
            raise FileNotFoundError(f"Template not found: {template_path}")
            
        with open(template_path, 'r', encoding='utf-8') as f:
            return f.read()
            
    def _render_report(self, template: str, data: Dict[str, Any]) -> str:
        """Render report template with data"""
        # Add system information to data
        data['system_info'] = self._get_system_info()
        
        # Calculate report statistics
        data['statistics'] = self._calculate_statistics(data['findings'])
        
        # Render template using simple string formatting
        # In real implementation, use Jinja2 or other template engine
        try:
            rendered = template.format(**data)
            return rendered
        except KeyError as e:
            raise ValueError(f"Missing template variable: {e}")
            
    def _generate_filename(self, report_type: str, format: str) -> str:
        """Generate report filename"""
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_report_type = report_type.replace(' ', '_').lower()
        filename = f"{safe_report_type}_{timestamp}.{format}"
        
        return os.path.join('reports', filename)
        
    def _write_report(self, content: str, filename: str, format: str):
        """Write report to file"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(content)
                
            self.logger.info(f"Report written to: {filename}")
            
        except Exception as e:
            raise Exception(f"Failed to write report: {e}")
            
    def _store_report_metadata(self, filename: str, report_type: str, format: str):
        """Store report metadata"""
        metadata = {
            'filename': filename,
            'report_type': report_type,
            'format': format,
            'timestamp': datetime.datetime.now().isoformat(),
            'size': os.path.getsize(filename),
            'hash': self._calculate_file_hash(filename)
        }
        
        self.reports.append(metadata)
        
    # ==========================================
    # Report Delivery Methods
    # ==========================================
    def deliver_report(self, filename: str, delivery_methods: List[str] = None):
        """
        Deliver report using configured methods
        
        Args:
            filename: Path to report file
            delivery_methods: List of delivery methods (email, slack, sms, file)
        """
        if delivery_methods is None:
            delivery_methods = self._get_configured_delivery_methods()
            
        for method in delivery_methods:
            try:
                self._deliver_report(method, filename)
            except Exception as e:
                self.logger.error(f"Failed to deliver report via {method}: {e}")
                
    def _get_configured_delivery_methods(self) -> List[str]:
        """Get configured delivery methods"""
        methods = []
        
        if self.config['delivery']['email']:
            methods.append('email')
            
        if self.config['delivery']['slack']:
            methods.append('slack')
            
        if self.config['delivery']['sms']:
            methods.append('sms')
            
        if self.config['delivery']['file']:
            methods.append('file')
            
        return methods
        
    def _deliver_report(self, method: str, filename: str):
        """Deliver report using specific method"""
        self.logger.info(f"Delivering report via {method}")
        
        if method == 'email':
            self._send_email(filename)
        elif method == 'slack':
            self._send_slack(filename)
        elif method == 'sms':
            self._send_sms(filename)
        elif method == 'file':
            self._store_file(filename)
        else:
            raise ValueError(f"Unknown delivery method: {method}")
            
    def _send_email(self, filename: str):
        """Send report via email"""
        recipients = self.config['notification']['email_recipients']
        
        if not recipients:
            self.logger.warning("No email recipients configured")
            return
            
        # In real implementation, use SMTP to send emails with attachment
        self.logger.info(f"Email sent to: {', '.join(recipients)}")
        
    def _send_slack(self, filename: str):
        """Send report via Slack"""
        channels = self.config['notification']['slack_channels']
        
        if not channels:
            self.logger.warning("No Slack channels configured")
            return
            
        # In real implementation, use Slack API to send files
        self.logger.info(f"Slack message sent to: {', '.join(channels)}")
        
    def _send_sms(self, filename: str):
        """Send report via SMS"""
        recipients = self.config['notification']['sms_recipients']
        
        if not recipients:
            self.logger.warning("No SMS recipients configured")
            return
            
        # In real implementation, use SMS gateway API
        self.logger.info(f"SMS sent to: {', '.join(recipients)}")
        
    def _store_file(self, filename: str):
        """Store report file"""
        # File is already stored in reports directory
        self.logger.info(f"Report stored in: {filename}")
        
    # ==========================================
    # Report Management Methods
    # ==========================================
    def list_reports(self, report_type: str = None, format: str = None, date_range: str = None) -> List[Dict[str, Any]]:
        """List generated reports with optional filters"""
        filtered_reports = self.reports
        
        if report_type:
            filtered_reports = [r for r in filtered_reports if r['report_type'] == report_type]
            
        if format:
            filtered_reports = [r for r in filtered_reports if r['format'] == format]
            
        if date_range:
            start_date, end_date = self._parse_date_range(date_range)
            filtered_reports = [
                r for r in filtered_reports 
                if start_date <= datetime.datetime.fromisoformat(r['timestamp']) <= end_date
            ]
            
        return sorted(filtered_reports, key=lambda x: x['timestamp'], reverse=True)
        
    def _parse_date_range(self, date_range: str):
        """Parse date range string (e.g., '2024-01-01:2024-01-31')"""
        start_str, end_str = date_range.split(':')
        
        start_date = datetime.datetime.fromisoformat(start_str)
        end_date = datetime.datetime.fromisoformat(end_str)
        
        return start_date, end_date
        
    def delete_report(self, filename: str) -> bool:
        """Delete report file"""
        if os.path.exists(filename):
            try:
                os.remove(filename)
                
                # Remove from metadata
                self.reports = [r for r in self.reports if r['filename'] != filename]
                
                self.logger.info(f"Report deleted: {filename}")
                return True
                
            except Exception as e:
                self.logger.error(f"Failed to delete report: {e}")
                return False
                
        return False
        
    def backup_reports(self, backup_path: str = None) -> bool:
        """Backup generated reports"""
        if backup_path is None:
            backup_path = os.path.join(self.config['retention']['storage_path'], 'backup')
            
        os.makedirs(backup_path, exist_ok=True)
        
        for report in self.reports:
            try:
                if os.path.exists(report['filename']):
                    import shutil
                    backup_filename = os.path.join(
                        backup_path,
                        os.path.basename(report['filename'])
                    )
                    
                    shutil.copy2(report['filename'], backup_filename)
                    self.logger.info(f"Report backed up: {report['filename']} -> {backup_filename}")
                    
            except Exception as e:
                self.logger.error(f"Failed to backup report {report['filename']}: {e}")
                
        return True
        
    def cleanup_reports(self, days: int = None) -> int:
        """Cleanup old reports based on retention policy"""
        if days is None:
            days = self.config['retention']['days']
            
        cutoff_date = datetime.datetime.now() - datetime.timedelta(days=days)
        deleted_count = 0
        
        for report in list(self.reports):
            report_date = datetime.datetime.fromisoformat(report['timestamp'])
            
            if report_date < cutoff_date:
                if self.delete_report(report['filename']):
                    deleted_count += 1
                    
        self.logger.info(f"Cleanup completed: {deleted_count} reports deleted")
        return deleted_count
        
    # ==========================================
    # Utility Methods
    # ==========================================
    def _calculate_file_hash(self, filename: str) -> str:
        """Calculate SHA-256 hash of file"""
        hash_sha256 = hashlib.sha256()
        
        with open(filename, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                hash_sha256.update(byte_block)
                
        return hash_sha256.hexdigest()
        
    def _get_system_info(self) -> Dict[str, str]:
        """Get system information"""
        try:
            import platform
            return {
                'hostname': socket.gethostname(),
                'os': platform.platform(),
                'architecture': platform.machine(),
                'python_version': platform.python_version(),
                'user': os.getenv('USER', 'Unknown')
            }
        except Exception as e:
            return {
                'hostname': socket.gethostname(),
                'os': 'Unknown',
                'architecture': 'Unknown',
                'python_version': 'Unknown',
                'user': 'Unknown'
            }
            
    def _calculate_statistics(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate statistics from findings"""
        statistics = {
            'total': len(findings),
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        for finding in findings:
            severity = finding['severity'].lower()
            if severity in statistics:
                statistics[severity] += 1
                
        statistics['percentages'] = {
            'critical': int(statistics['critical'] / statistics['total'] * 100),
            'high': int(statistics['high'] / statistics['total'] * 100),
            'medium': int(statistics['medium'] / statistics['total'] * 100),
            'low': int(statistics['low'] / statistics['total'] * 100),
            'info': int(statistics['info'] / statistics['total'] * 100)
        }
        
        return statistics
        
    # ==========================================
    # Template Management
    # ==========================================
    def create_template(self, report_type: str, content: str) -> str:
        """Create new report template"""
        template_path = self.config['templates'][report_type]
        
        with open(template_path, 'w', encoding='utf-8') as f:
            f.write(content)
            
        self.logger.info(f"Template created: {template_path}")
        return template_path
        
    def get_template(self, report_type: str) -> str:
        """Get template content"""
        return self._load_template(report_type)
        
    def update_template(self, report_type: str, content: str) -> str:
        """Update existing report template"""
        return self.create_template(report_type, content)
        
    def list_templates(self) -> List[str]:
        """List available report templates"""
        templates = []
        
        for report_type, template_path in self.config['templates'].items():
            if os.path.exists(template_path):
                templates.append({
                    'report_type': report_type,
                    'path': template_path,
                    'size': os.path.getsize(template_path)
                })
                
        return templates
        
    # ==========================================
    # Example Data Generators
    # ==========================================
    def generate_penetration_testing_data(self) -> Dict[str, Any]:
        """Generate sample penetration testing data"""
        return {
            'title': 'Penetration Test Report',
            'description': 'Comprehensive security assessment of target systems',
            'scope': '192.168.1.0/24 network',
            'date': datetime.datetime.now().isoformat(),
            'findings': [
                {
                    'title': 'SQL Injection Vulnerability',
                    'description': 'Web application vulnerable to SQL injection attacks',
                    'severity': 'Critical',
                    'recommendation': 'Implement parameterized queries and input validation',
                    'cvss_score': 9.8,
                    'remediation_status': 'In Progress'
                },
                {
                    'title': 'Weak Password Policy',
                    'description': 'Password policy allows easily guessable passwords',
                    'severity': 'High',
                    'recommendation': 'Enforce minimum password length and complexity requirements',
                    'cvss_score': 7.2,
                    'remediation_status': 'Pending'
                },
                {
                    'title': 'Missing Security Headers',
                    'description': 'HTTP responses lack security headers',
                    'severity': 'Medium',
                    'recommendation': 'Add Content-Security-Policy and X-Frame-Options headers',
                    'cvss_score': 5.3,
                    'remediation_status': 'Pending'
                },
                {
                    'title': 'Outdated Software Version',
                    'description': 'Apache web server is running an outdated version',
                    'severity': 'Low',
                    'recommendation': 'Upgrade Apache to latest version',
                    'cvss_score': 3.9,
                    'remediation_status': 'Pending'
                }
            ]
        }
        
    def generate_vulnerability_assessment_data(self) -> Dict[str, Any]:
        """Generate sample vulnerability assessment data"""
        return {
            'title': 'Vulnerability Assessment Report',
            'description': 'Network vulnerability assessment',
            'scope': 'Internet-facing systems',
            'date': datetime.datetime.now().isoformat(),
            'findings': [
                {
                    'title': 'Heartbleed Vulnerability',
                    'description': 'OpenSSL vulnerability allowing memory disclosure',
                    'severity': 'Critical',
                    'recommendation': 'Upgrade OpenSSL to version 1.0.1g or later',
                    'cvss_score': 7.5,
                    'remediation_status': 'In Progress'
                },
                {
                    'title': 'POODLE Attack Vulnerability',
                    'description': 'SSL 3.0 vulnerability allowing downgrade attacks',
                    'severity': 'High',
                    'recommendation': 'Disable SSL 3.0 and TLS 1.0 protocols',
                    'cvss_score': 5.0,
                    'remediation_status': 'Pending'
                },
                {
                    'title': 'Weak Ciphers Enabled',
                    'description': 'Weak SSL/TLS ciphers are enabled',
                    'severity': 'Medium',
                    'recommendation': 'Disable RC4 and DES ciphers',
                    'cvss_score': 4.3,
                    'remediation_status': 'Pending'
                }
            ]
        }
        
    def generate_compliance_data(self) -> Dict[str, Any]:
        """Generate sample compliance report data"""
        return {
            'title': 'Compliance Report',
            'description': 'PCI DSS compliance assessment',
            'scope': 'Cardholder data environment',
            'date': datetime.datetime.now().isoformat(),
            'findings': [
                {
                    'title': 'Unauthorized Access',
                    'description': 'Weak access controls to cardholder data',
                    'severity': 'Critical',
                    'recommendation': 'Implement strong access controls and least privilege',
                    'cvss_score': 8.1,
                    'remediation_status': 'In Progress'
                },
                {
                    'title': 'Encryption Issue',
                    'description': 'Cardholder data not encrypted in transit',
                    'severity': 'High',
                    'recommendation': 'Enable TLS encryption for all connections',
                    'cvss_score': 7.5,
                    'remediation_status': 'Pending'
                },
                {
                    'title': 'Logging Insufficient',
                    'description': 'Security logging does not capture all required events',
                    'severity': 'Medium',
                    'recommendation': 'Enhance security logging and monitoring',
                    'cvss_score': 5.9,
                    'remediation_status': 'Pending'
                }
            ]
        }
        
    # ==========================================
    # Main Reporting Workflow
    # ==========================================
    def run_reporting_workflow(self, report_types: List[str] = None, formats: List[str] = None):
        """
        Run complete reporting workflow
        
        Args:
            report_types: List of report types to generate
            formats: List of formats to generate
        """
        if report_types is None:
            report_types = self.config['report_types']
            
        if formats is None:
            formats = self.config['formats']
            
        self.logger.info("Starting reporting workflow")
        
        # Generate reports
        generated_reports = []
        
        for report_type in report_types:
            for format in formats:
                try:
                    # Generate data based on report type
                    if report_type == 'penetration_testing':
                        data = self.generate_penetration_testing_data()
                    elif report_type == 'vulnerability_assessment':
                        data = self.generate_vulnerability_assessment_data()
                    elif report_type == 'compliance':
                        data = self.generate_compliance_data()
                    elif report_type == 'incident_response':
                        data = self.generate_incident_response_data()
                    elif report_type == 'audit':
                        data = self.generate_audit_data()
                    else:
                        self.logger.warning(f"Unknown report type: {report_type}")
                        continue
                        
                    # Generate report
                    filename = self.generate_report(report_type, data, format)
                    generated_reports.append(filename)
                    
                    # Deliver report
                    self.deliver_report(filename)
                    
                except Exception as e:
                    self.logger.error(f"Failed to generate {report_type} report in {format} format: {e}")
                    
        # Cleanup old reports
        if self.config['retention']['days'] > 0:
            try:
                self.cleanup_reports()
            except Exception as e:
                self.logger.error(f"Report cleanup failed: {e}")
                
        # Backup reports
        if self.config['retention']['backup']:
            try:
                self.backup_reports()
            except Exception as e:
                self.logger.error(f"Report backup failed: {e}")
                
        self.logger.info(f"Reporting workflow completed. Generated {len(generated_reports)} reports")
        
        return generated_reports
        
    # ==========================================
    # Additional Data Generators
    # ==========================================
    def generate_incident_response_data(self) -> Dict[str, Any]:
        """Generate sample incident response data"""
        return {
            'title': 'Incident Response Report',
            'description': 'Security incident response details',
            'scope': 'Network and endpoints',
            'date': datetime.datetime.now().isoformat(),
            'findings': [
                {
                    'title': 'Malware Infection',
                    'description': 'Ransomware infection detected on workstation',
                    'severity': 'Critical',
                    'recommendation': 'Isolate affected machine and restore from backup',
                    'cvss_score': 10.0,
                    'remediation_status': 'In Progress'
                },
                {
                    'title': 'Unauthorized Access',
                    'description': 'Suspicious login attempts from external IP address',
                    'severity': 'High',
                    'recommendation': 'Block malicious IP address and reset passwords',
                    'cvss_score': 8.5,
                    'remediation_status': 'Pending'
                }
            ]
        }
        
    def generate_audit_data(self) -> Dict[str, Any]:
        """Generate sample audit report data"""
        return {
            'title': 'Security Audit Report',
            'description': 'Security controls audit',
            'scope': 'Information systems',
            'date': datetime.datetime.now().isoformat(),
            'findings': [
                {
                    'title': 'Firewall Misconfiguration',
                    'description': 'Firewall rules allow unauthorized access',
                    'severity': 'Critical',
                    'recommendation': 'Review and update firewall rules',
                    'cvss_score': 9.1,
                    'remediation_status': 'In Progress'
                },
                {
                    'title': 'Unpatched Systems',
                    'description': 'Operating systems are missing critical patches',
                    'severity': 'High',
                    'recommendation': 'Implement patch management program',
                    'cvss_score': 7.6,
                    'remediation_status': 'Pending'
                }
            ]
        }

def main():
    """Main function to demonstrate security reporting"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Security Reporting Automation"
    )
    
    parser.add_argument(
        "-c", "--config",
        default="config/reporting_config.yaml",
        help="Configuration file"
    )
    
    parser.add_argument(
        "-t", "--type",
        choices=['penetration_testing', 'vulnerability_assessment', 'compliance', 'incident_response', 'audit', 'all'],
        default='all',
        help="Report type to generate"
    )
    
    parser.add_argument(
        "-f", "--format",
        choices=['json', 'csv', 'html', 'markdown', 'pdf'],
        default='html',
        help="Output format"
    )
    
    parser.add_argument(
        "-d", "--deliver",
        action="store_true",
        help="Deliver report after generation"
    )
    
    parser.add_argument(
        "-b", "--backup",
        action="store_true",
        help="Backup generated reports"
    )
    
    parser.add_argument(
        "-C", "--cleanup",
        action="store_true",
        help="Cleanup old reports"
    )
    
    args = parser.parse_args()
    
    try:
        reporter = SecurityReporting(args.config)
        
        if args.cleanup:
            deleted = reporter.cleanup_reports()
            print(f"Cleanup completed: {deleted} reports deleted")
            
        # Determine which reports to generate
        if args.type == 'all':
            report_types = reporter.config['report_types']
        else:
            report_types = [args.type]
            
        # Generate reports
        generated_reports = []
        
        for report_type in report_types:
            # Generate appropriate data
            if report_type == 'penetration_testing':
                data = reporter.generate_penetration_testing_data()
            elif report_type == 'vulnerability_assessment':
                data = reporter.generate_vulnerability_assessment_data()
            elif report_type == 'compliance':
                data = reporter.generate_compliance_data()
            elif report_type == 'incident_response':
                data = reporter.generate_incident_response_data()
            elif report_type == 'audit':
                data = reporter.generate_audit_data()
            else:
                print(f"Unknown report type: {report_type}")
                continue
                
            try:
                filename = reporter.generate_report(report_type, data, args.format)
                generated_reports.append(filename)
                print(f"Report generated: {filename}")
                
                if args.deliver:
                    reporter.deliver_report(filename)
                    
            except Exception as e:
                print(f"Error generating {report_type} report: {e}")
                continue
                
        if args.backup:
            reporter.backup_reports()
            print("Reports backed up successfully")
            
        # List generated reports
        print(f"\nGenerated Reports: {len(generated_reports)}")
        for report in generated_reports:
            print(f"  {report}")
            
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        print(traceback.format_exc())

if __name__ == "__main__":
    main()
