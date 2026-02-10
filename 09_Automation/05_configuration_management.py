#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Configuration Management in Python for Cybersecurity
This script automates configuration management for security purposes:
- System hardening and configuration
- Baseline checking and validation
- Compliance monitoring (e.g., CIS benchmarks)
- Configuration drift detection
- Security policy enforcement
Perfect for beginners!
"""

import os
import sys
import json
import yaml
import csv
import datetime
import time
import subprocess
import socket
import re
import hashlib
import logging
from pathlib import Path
from typing import Dict, List, Any

class ConfigurationManager:
    """Class for configuration management automation"""
    
    def __init__(self, config_file='config/configuration_management.yaml'):
        """
        Initialize configuration manager
        
        Args:
            config_file: Configuration file path
        """
        self.config = self._load_config(config_file)
        self.results = {
            'hardening': [],
            'baseline': [],
            'drift': [],
            'compliance': []
        }
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('logs/configuration_management.log'),
                logging.StreamHandler()
            ]
        )
        
        self.logger = logging.getLogger(__name__)
        
    def _load_config(self, config_file):
        """Load configuration from file"""
        default_config = {
            'hardening': {
                'system': True,
                'network': True,
                'services': True,
                'firewall': True
            },
            'baseline': {
                'files_to_check': [
                    '/etc/passwd',
                    '/etc/shadow',
                    '/etc/ssh/sshd_config',
                    '/etc/nginx/nginx.conf'
                ],
                'services_to_check': [
                    'sshd',
                    'apache2',
                    'nginx',
                    'iptables'
                ]
            },
            'drift': {
                'check_interval': 3600,  # 1 hour
                'alert_threshold': 5,
                'notification_methods': ['email']
            },
            'compliance': {
                'benchmarks': ['CIS', 'PCI DSS'],
                'rules_to_check': [
                    'password_policy',
                    'ssh_configuration',
                    'network_services',
                    'firewall_rules'
                ]
            },
            'notification': {
                'email_recipients': ['security@example.com'],
                'slack_channels': ['#security-config'],
                'sms_recipients': ['+1234567890']
            },
            'remediation': {
                'automatic': False,
                'max_attempts': 3
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
        
    # ==========================================
    # System Hardening
    # ==========================================
    def harden_system(self):
        """Harden system based on configured rules"""
        self.logger.info("Starting system hardening")
        
        results = []
        
        if self.config['hardening']['system']:
            system_hardening = self._harden_system_settings()
            results.extend(system_hardening)
            
        if self.config['hardening']['network']:
            network_hardening = self._harden_network_settings()
            results.extend(network_hardening)
            
        if self.config['hardening']['services']:
            service_hardening = self._harden_services()
            results.extend(service_hardening)
            
        if self.config['hardening']['firewall']:
            firewall_hardening = self._harden_firewall()
            results.extend(firewall_hardening)
            
        self.results['hardening'] = results
        
        return results
        
    def _harden_system_settings(self):
        """Harden system settings"""
        self.logger.info("Hardening system settings")
        
        settings = [
            {
                'name': 'Password Policy',
                'description': 'Enforce strong password policy',
                'method': self._configure_password_policy,
                'requires_reboot': False
            },
            {
                'name': 'User Permissions',
                'description': 'Configure user permissions and groups',
                'method': self._configure_user_permissions,
                'requires_reboot': False
            },
            {
                'name': 'System Auditing',
                'description': 'Enable system auditing and logging',
                'method': self._enable_system_auditing,
                'requires_reboot': False
            }
        ]
        
        return self._execute_hardening_settings(settings)
        
    def _harden_network_settings(self):
        """Harden network settings"""
        self.logger.info("Hardening network settings")
        
        settings = [
            {
                'name': 'Network Services',
                'description': 'Disable unnecessary network services',
                'method': self._disable_unnecessary_services,
                'requires_reboot': False
            },
            {
                'name': 'IP Configuration',
                'description': 'Configure network IP settings',
                'method': self._configure_ip_settings,
                'requires_reboot': False
            },
            {
                'name': 'Firewall Rules',
                'description': 'Configure firewall rules',
                'method': self._configure_firewall_rules,
                'requires_reboot': False
            }
        ]
        
        return self._execute_hardening_settings(settings)
        
    def _harden_services(self):
        """Harden system services"""
        self.logger.info("Hardening system services")
        
        settings = [
            {
                'name': 'SSH Configuration',
                'description': 'Harden SSH service configuration',
                'method': self._harden_ssh_config,
                'requires_reboot': False
            },
            {
                'name': 'Web Services',
                'description': 'Harden web server configuration',
                'method': self._harden_web_services,
                'requires_reboot': False
            },
            {
                'name': 'Database Services',
                'description': 'Harden database configuration',
                'method': self._harden_database_config,
                'requires_reboot': False
            }
        ]
        
        return self._execute_hardening_settings(settings)
        
    def _harden_firewall(self):
        """Harden firewall configuration"""
        self.logger.info("Hardening firewall configuration")
        
        settings = [
            {
                'name': 'Firewall Policy',
                'description': 'Configure default firewall policy',
                'method': self._configure_default_policy,
                'requires_reboot': False
            },
            {
                'name': 'Firewall Rules',
                'description': 'Configure specific firewall rules',
                'method': self._configure_firewall_rules,
                'requires_reboot': False
            },
            {
                'name': 'IPv6 Configuration',
                'description': 'Disable IPv6 if not needed',
                'method': self._configure_ipv6,
                'requires_reboot': True
            }
        ]
        
        return self._execute_hardening_settings(settings)
        
    def _execute_hardening_settings(self, settings):
        """Execute hardening settings with error handling"""
        results = []
        
        for setting in settings:
            try:
                result = setting['method']()
                results.append({
                    'name': setting['name'],
                    'description': setting['description'],
                    'result': result,
                    'requires_reboot': setting['requires_reboot'],
                    'timestamp': datetime.datetime.now().isoformat(),
                    'success': True
                })
                
                self.logger.info(f"Successfully applied: {setting['name']}")
                
            except Exception as e:
                results.append({
                    'name': setting['name'],
                    'description': setting['description'],
                    'result': str(e),
                    'requires_reboot': setting['requires_reboot'],
                    'timestamp': datetime.datetime.now().isoformat(),
                    'success': False
                })
                
                self.logger.error(f"Failed to apply {setting['name']}: {e}")
                
        return results
        
    # ==========================================
    # Baseline Configuration
    # ==========================================
    def check_baseline(self):
        """Check system against configured baseline"""
        self.logger.info("Checking system baseline configuration")
        
        baseline_results = []
        
        # Check files
        for file_path in self.config['baseline']['files_to_check']:
            try:
                file_result = self._check_file_baseline(file_path)
                baseline_results.append(file_result)
            except Exception as e:
                baseline_results.append({
                    'type': 'file',
                    'path': file_path,
                    'result': str(e),
                    'timestamp': datetime.datetime.now().isoformat(),
                    'success': False
                })
                
        # Check services
        for service_name in self.config['baseline']['services_to_check']:
            try:
                service_result = self._check_service_baseline(service_name)
                baseline_results.append(service_result)
            except Exception as e:
                baseline_results.append({
                    'type': 'service',
                    'name': service_name,
                    'result': str(e),
                    'timestamp': datetime.datetime.now().isoformat(),
                    'success': False
                })
                
        self.results['baseline'] = baseline_results
        
        return baseline_results
        
    def _check_file_baseline(self, file_path):
        """Check file against baseline configuration"""
        baseline_file = self._get_baseline_file_path(file_path)
        
        if not os.path.exists(baseline_file):
            raise Exception(f"Baseline file not found: {baseline_file}")
            
        # Calculate current file hash
        current_hash = self._calculate_file_hash(file_path)
        
        # Read baseline hash
        with open(baseline_file, 'r', encoding='utf-8') as f:
            baseline_hash = f.read().strip()
            
        result = {
            'type': 'file',
            'path': file_path,
            'current_hash': current_hash,
            'baseline_hash': baseline_hash,
            'matches': current_hash == baseline_hash,
            'timestamp': datetime.datetime.now().isoformat(),
            'success': True
        }
        
        return result
        
    def _get_baseline_file_path(self, file_path):
        """Get baseline file path for a given configuration file"""
        safe_filename = file_path.replace('/', '_').replace('\\', '_').strip('_')
        return os.path.join('baselines', f"{safe_filename}.hash")
        
    def _calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash of file"""
        hash_sha256 = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                hash_sha256.update(byte_block)
                
        return hash_sha256.hexdigest()
        
    def _check_service_baseline(self, service_name):
        """Check service configuration against baseline"""
        baseline_file = self._get_baseline_file_path(f"service_{service_name}")
        
        if not os.path.exists(baseline_file):
            raise Exception(f"Baseline file not found: {baseline_file}")
            
        try:
            # Get current service status
            if sys.platform.startswith('win32'):
                status = self._get_windows_service_status(service_name)
            else:
                status = self._get_linux_service_status(service_name)
                
            with open(baseline_file, 'r', encoding='utf-8') as f:
                baseline_status = f.read().strip()
                
            result = {
                'type': 'service',
                'name': service_name,
                'current_status': status,
                'baseline_status': baseline_status,
                'matches': status == baseline_status,
                'timestamp': datetime.datetime.now().isoformat(),
                'success': True
            }
            
            return result
            
        except Exception as e:
            raise Exception(f"Failed to check service {service_name}: {e}")
            
    def _get_linux_service_status(self, service_name):
        """Get Linux service status"""
        try:
            result = subprocess.run(['systemctl', 'is-active', service_name], 
                                 capture_output=True, text=True, check=True)
            return result.stdout.strip()
            
        except subprocess.CalledProcessError as e:
            return 'inactive'
            
    def _get_windows_service_status(self, service_name):
        """Get Windows service status"""
        try:
            result = subprocess.run(['sc', 'query', service_name], 
                                 capture_output=True, text=True, check=True)
            if 'RUNNING' in result.stdout:
                return 'active'
            return 'inactive'
            
        except subprocess.CalledProcessError as e:
            return 'inactive'
            
    # ==========================================
    # Configuration Drift Detection
    # ==========================================
    def detect_configuration_drift(self):
        """Detect configuration drift from baseline"""
        self.logger.info("Detecting configuration drift")
        
        baseline_results = self.check_baseline()
        drift_results = []
        
        for result in baseline_results:
            if result['success'] and not result['matches']:
                drift = {
                    'type': result['type'],
                    'path': result.get('path', result.get('name')),
                    'current': result.get('current_hash', result.get('current_status')),
                    'expected': result.get('baseline_hash', result.get('baseline_status')),
                    'drift_detected': True,
                    'timestamp': result['timestamp']
                }
                
                drift_results.append(drift)
                
        self.results['drift'] = drift_results
        
        if drift_results and len(drift_results) >= self.config['drift']['alert_threshold']:
            self._send_drift_notification(drift_results)
            
        return drift_results
        
    def _send_drift_notification(self, drifts):
        """Send configuration drift notifications"""
        self.logger.warning(f"Configuration drift detected: {len(drifts)} changes")
        
        notification = {
            'subject': 'Configuration Drift Alert',
            'body': f"Detected {len(drifts)} configuration changes\n\n"
        }
        
        for drift in drifts:
            notification['body'] += f"Type: {drift['type']}\n"
            notification['body'] += f"Path: {drift['path']}\n"
            notification['body'] += f"Current: {drift['current']}\n"
            notification['body'] += f"Expected: {drift['expected']}\n"
            notification['body'] += f"Time: {drift['timestamp']}\n\n"
            
        self._send_notification(notification)
        
    # ==========================================
    # Compliance Monitoring
    # ==========================================
    def check_compliance(self):
        """Check system compliance with security benchmarks"""
        self.logger.info("Checking compliance with security benchmarks")
        
        compliance_results = []
        
        for rule in self.config['compliance']['rules_to_check']:
            try:
                rule_result = self._check_compliance_rule(rule)
                compliance_results.append(rule_result)
            except Exception as e:
                compliance_results.append({
                    'rule': rule,
                    'result': str(e),
                    'passed': False,
                    'timestamp': datetime.datetime.now().isoformat()
                })
                
        self.results['compliance'] = compliance_results
        
        return compliance_results
        
    def _check_compliance_rule(self, rule_name):
        """Check specific compliance rule"""
        rules = {
            'password_policy': self._check_password_policy,
            'ssh_configuration': self._check_ssh_configuration,
            'network_services': self._check_network_services,
            'firewall_rules': self._check_firewall_rules
        }
        
        if rule_name not in rules:
            raise Exception(f"Unknown compliance rule: {rule_name}")
            
        result = rules[rule_name]()
        
        return {
            'rule': rule_name,
            'result': result['description'],
            'passed': result['passed'],
            'timestamp': datetime.datetime.now().isoformat(),
            'details': result.get('details', {})
        }
        
    def _check_password_policy(self):
        """Check password policy compliance"""
        password_policy = {
            'min_length': 8,
            'require_uppercase': True,
            'require_lowercase': True,
            'require_numbers': True,
            'require_special': True
        }
        
        # In real implementation, check /etc/login.defs or PAM configuration
        return {
            'description': 'Password policy checks',
            'passed': True,
            'details': password_policy
        }
        
    def _check_ssh_configuration(self):
        """Check SSH configuration compliance"""
        ssh_config = {
            'permit_root_login': False,
            'password_authentication': False,
            'max_auth_tries': 3,
            'client_alive_interval': 300,
            'protocol': 2
        }
        
        # In real implementation, check /etc/ssh/sshd_config
        return {
            'description': 'SSH configuration checks',
            'passed': True,
            'details': ssh_config
        }
        
    def _check_network_services(self):
        """Check network services compliance"""
        services = [
            'sshd',
            'apache2',
            'nginx',
            'iptables'
        ]
        
        # In real implementation, check running services
        return {
            'description': 'Network services checks',
            'passed': True,
            'details': services
        }
        
    def _check_firewall_rules(self):
        """Check firewall rules compliance"""
        required_rules = [
            'Allow SSH from management network',
            'Allow HTTP/HTTPS from internet',
            'Deny all other incoming connections',
            'Allow all outgoing connections'
        ]
        
        # In real implementation, check iptables/ufw rules
        return {
            'description': 'Firewall rules checks',
            'passed': True,
            'details': required_rules
        }
        
    # ==========================================
    # Configuration Management Methods
    # ==========================================
    def _configure_password_policy(self):
        """Configure password policy settings"""
        # In real implementation, this would modify /etc/login.defs and PAM configuration
        return "Password policy configured"
        
    def _configure_user_permissions(self):
        """Configure user permissions and groups"""
        # In real implementation, this would manage user accounts and groups
        return "User permissions configured"
        
    def _enable_system_auditing(self):
        """Enable system auditing and logging"""
        # In real implementation, this would configure auditd or other logging systems
        return "System auditing enabled"
        
    def _disable_unnecessary_services(self):
        """Disable unnecessary network services"""
        # In real implementation, this would disable unused services
        return "Unnecessary services disabled"
        
    def _configure_ip_settings(self):
        """Configure network IP settings"""
        # In real implementation, this would configure network parameters
        return "IP settings configured"
        
    def _configure_firewall_rules(self):
        """Configure firewall rules"""
        # In real implementation, this would configure iptables/ufw rules
        return "Firewall rules configured"
        
    def _harden_ssh_config(self):
        """Harden SSH service configuration"""
        # In real implementation, this would modify /etc/ssh/sshd_config
        return "SSH configuration hardened"
        
    def _harden_web_services(self):
        """Harden web server configuration"""
        # In real implementation, this would configure Apache/NGINX settings
        return "Web services hardened"
        
    def _harden_database_config(self):
        """Harden database configuration"""
        # In real implementation, this would configure database security settings
        return "Database configuration hardened"
        
    def _configure_default_policy(self):
        """Configure default firewall policy"""
        # In real implementation, this would set default firewall policy
        return "Default firewall policy configured"
        
    def _configure_ipv6(self):
        """Configure IPv6 settings"""
        # In real implementation, this would disable IPv6 if not needed
        return "IPv6 configuration completed"
        
    # ==========================================
    # Notification Methods
    # ==========================================
    def _send_notification(self, notification):
        """Send notification using configured methods"""
        if self.config['notification']['email_recipients']:
            self._send_email_notification(notification)
            
        if self.config['notification']['slack_channels']:
            self._send_slack_notification(notification)
            
        if self.config['notification']['sms_recipients']:
            self._send_sms_notification(notification)
            
    def _send_email_notification(self, notification):
        """Send email notification"""
        self.logger.info("Sending email notification")
        # In real implementation, this would use SMTP to send emails
        
    def _send_slack_notification(self, notification):
        """Send Slack notification"""
        self.logger.info("Sending Slack notification")
        # In real implementation, this would use Slack API
        
    def _send_sms_notification(self, notification):
        """Send SMS notification"""
        self.logger.info("Sending SMS notification")
        # In real implementation, this would use SMS gateway API
        
    # ==========================================
    # Main Configuration Management Workflow
    # ==========================================
    def manage_configuration(self):
        """Complete configuration management workflow"""
        self.logger.info("Starting configuration management workflow")
        
        # Step 1: Harden system
        hardening_results = self.harden_system()
        
        # Step 2: Check baseline
        baseline_results = self.check_baseline()
        
        # Step 3: Detect configuration drift
        drift_results = self.detect_configuration_drift()
        
        # Step 4: Check compliance
        compliance_results = self.check_compliance()
        
        # Step 5: Generate report
        report_file = self.generate_report()
        
        self.logger.info("Configuration management workflow completed")
        
        return report_file
        
    # ==========================================
    # Reporting
    # ==========================================
    def generate_report(self, format='json'):
        """Generate configuration management report"""
        report = {
            'timestamp': datetime.datetime.now().isoformat(),
            'system_info': self._get_system_info(),
            'results': self.results,
            'summary': self._generate_summary(),
            'recommendations': self._generate_recommendations()
        }
        
        filename = os.path.join('reports', f"configuration_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}")
        
        if format == 'json':
            filename += '.json'
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, default=str)
        elif format == 'csv':
            filename += '.csv'
            self._generate_csv_report(report, filename)
        elif format == 'html':
            filename += '.html'
            self._generate_html_report(report, filename)
        else:
            raise ValueError(f"Unknown format: {format}")
            
        return filename
        
    def _get_system_info(self):
        """Get system information"""
        try:
            if sys.platform.startswith('win32'):
                return {
                    'os': 'Windows',
                    'hostname': socket.gethostname(),
                    'architecture': 'x64',
                    'version': 'Windows Server 2019'
                }
            else:
                import platform
                return {
                    'os': 'Linux',
                    'hostname': socket.gethostname(),
                    'architecture': platform.machine(),
                    'version': platform.platform()
                }
        except Exception as e:
            return {
                'os': 'Unknown',
                'hostname': socket.gethostname(),
                'architecture': 'Unknown',
                'version': 'Unknown'
            }
            
    def _generate_summary(self):
        """Generate summary of configuration management results"""
        summary = {
            'total_hardening_steps': len(self.results['hardening']),
            'successful_hardening_steps': sum(1 for step in self.results['hardening'] if step['success']),
            'total_baseline_checks': len(self.results['baseline']),
            'passed_baseline_checks': sum(1 for check in self.results['baseline'] if check['success'] and check['matches']),
            'drift_detected': len(self.results['drift']),
            'total_compliance_rules': len(self.results['compliance']),
            'passed_compliance_rules': sum(1 for rule in self.results['compliance'] if rule['passed'])
        }
        
        return summary
        
    def _generate_recommendations(self):
        """Generate configuration management recommendations"""
        recommendations = []
        
        # Hardening recommendations
        if len([step for step in self.results['hardening'] if not step['success']]) > 0:
            recommendations.append("Re-run failed hardening steps")
            
        # Baseline recommendations
        if len([check for check in self.results['baseline'] if not check['matches']]) > 0:
            recommendations.append("Review configuration changes")
            
        # Drift recommendations
        if len(self.results['drift']) > 0:
            recommendations.append("Investigate configuration drift")
            
        # Compliance recommendations
        if len([rule for rule in self.results['compliance'] if not rule['passed']]) > 0:
            recommendations.append("Fix failed compliance checks")
            
        return recommendations
        
    def _generate_csv_report(self, report, filename):
        """Generate CSV report"""
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=[
                'Category',
                'Type',
                'Name',
                'Success',
                'Result',
                'Timestamp'
            ])
            
            writer.writeheader()
            
            for step in report['results']['hardening']:
                writer.writerow({
                    'Category': 'Hardening',
                    'Type': 'Setting',
                    'Name': step['name'],
                    'Success': step['success'],
                    'Result': step['result'],
                    'Timestamp': step['timestamp']
                })
                
            for check in report['results']['baseline']:
                writer.writerow({
                    'Category': 'Baseline',
                    'Type': check['type'],
                    'Name': check.get('path', check.get('name')),
                    'Success': check['success'] and check['matches'],
                    'Result': 'Match' if check['success'] and check['matches'] else 'Mismatch',
                    'Timestamp': check['timestamp']
                })
                
            for rule in report['results']['compliance']:
                writer.writerow({
                    'Category': 'Compliance',
                    'Type': 'Rule',
                    'Name': rule['rule'],
                    'Success': rule['passed'],
                    'Result': rule['result'],
                    'Timestamp': rule['timestamp']
                })
                
            for drift in report['results']['drift']:
                writer.writerow({
                    'Category': 'Drift',
                    'Type': drift['type'],
                    'Name': drift['path'],
                    'Success': False,
                    'Result': 'Drift Detected',
                    'Timestamp': drift['timestamp']
                })
                
    def _generate_html_report(self, report, filename):
        """Generate HTML report"""
        html = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Configuration Management Report</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    margin: 20px;
                    background-color: #f5f5f5;
                }}
                .report-container {{
                    max-width: 1200px;
                    margin: 0 auto;
                    background-color: white;
                    padding: 20px;
                    border-radius: 8px;
                    box-shadow: 0 0 10px rgba(0,0,0,0.1);
                }}
                .header {{
                    text-align: center;
                    margin-bottom: 30px;
                    padding-bottom: 20px;
                    border-bottom: 1px solid #eee;
                }}
                .section {{
                    margin: 20px 0;
                    padding: 20px;
                    border: 1px solid #eee;
                    border-radius: 5px;
                }}
                .section h3 {{
                    margin-top: 0;
                    color: #333;
                }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin: 10px 0;
                }}
                table, th, td {{
                    border: 1px solid #eee;
                }}
                th, td {{
                    padding: 8px;
                    text-align: left;
                }}
                th {{
                    background-color: #f8f9fa;
                }}
                .success {{
                    color: #28a745;
                    font-weight: bold;
                }}
                .failure {{
                    color: #dc3545;
                    font-weight: bold;
                }}
                .drift {{
                    color: #fd7e14;
                    font-weight: bold;
                }}
            </style>
        </head>
        <body>
            <div class="report-container">
                <div class="header">
                    <h1>Configuration Management Report</h1>
                    <p>Generated: {timestamp}</p>
                    <p>Hostname: {hostname}</p>
                    <p>OS: {os}</p>
                </div>
                
                <div class="section">
                    <h3>Summary</h3>
                    <table>
                        <tr>
                            <th>Metric</th>
                            <th>Value</th>
                            <th>Percentage</th>
                        </tr>
                        <tr>
                            <td>Hardening Steps</td>
                            <td><span class="success">{hardening_success}</span> of {hardening_total}</td>
                            <td>{hardening_percent}%</td>
                        </tr>
                        <tr>
                            <td>Baseline Checks</td>
                            <td><span class="success">{baseline_success}</span> of {baseline_total}</td>
                            <td>{baseline_percent}%</td>
                        </tr>
                        <tr>
                            <td>Compliance Rules</td>
                            <td><span class="success">{compliance_success}</span> of {compliance_total}</td>
                            <td>{compliance_percent}%</td>
                        </tr>
                        <tr>
                            <td>Drift Detected</td>
                            <td><span class="drift">{drift_count}</span> changes</td>
                            <td>-</td>
                        </tr>
                    </table>
                </div>
                
                <div class="section">
                    <h3>Recommendations</h3>
                    <ul>
                        {recommendations}
                    </ul>
                </div>
                
                <div class="section">
                    <h3>Hardening Results</h3>
                    <table>
                        <tr>
                            <th>Name</th>
                            <th>Description</th>
                            <th>Result</th>
                            <th>Success</th>
                            <th>Reboot Required</th>
                        </tr>
                        {hardening_table}
                    </table>
                </div>
                
                <div class="section">
                    <h3>Baseline Checks</h3>
                    <table>
                        <tr>
                            <th>Type</th>
                            <th>Name</th>
                            <th>Result</th>
                            <th>Success</th>
                        </tr>
                        {baseline_table}
                    </table>
                </div>
                
                <div class="section">
                    <h3>Compliance Rules</h3>
                    <table>
                        <tr>
                            <th>Rule</th>
                            <th>Result</th>
                            <th>Passed</th>
                        </tr>
                        {compliance_table}
                    </table>
                </div>
                
                <div class="section">
                    <h3>Configuration Drift</h3>
                    <table>
                        <tr>
                            <th>Type</th>
                            <th>Path</th>
                            <th>Current</th>
                            <th>Expected</th>
                            <th>Time</th>
                        </tr>
                        {drift_table}
                    </table>
                </div>
            </div>
        </body>
        </html>
        """.format(
            timestamp=report['timestamp'],
            hostname=report['system_info']['hostname'],
            os=report['system_info']['os'],
            hardening_total=report['summary']['total_hardening_steps'],
            hardening_success=report['summary']['successful_hardening_steps'],
            hardening_percent=int(report['summary']['successful_hardening_steps'] / report['summary']['total_hardening_steps'] * 100),
            baseline_total=report['summary']['total_baseline_checks'],
            baseline_success=report['summary']['passed_baseline_checks'],
            baseline_percent=int(report['summary']['passed_baseline_checks'] / report['summary']['total_baseline_checks'] * 100),
            compliance_total=report['summary']['total_compliance_rules'],
            compliance_success=report['summary']['passed_compliance_rules'],
            compliance_percent=int(report['summary']['passed_compliance_rules'] / report['summary']['total_compliance_rules'] * 100),
            drift_count=report['summary']['drift_detected'],
            recommendations=''.join(f"<li>{rec}</li>" for rec in report['recommendations']),
            hardening_table=self._generate_hardening_html_table(report['results']['hardening']),
            baseline_table=self._generate_baseline_html_table(report['results']['baseline']),
            compliance_table=self._generate_compliance_html_table(report['results']['compliance']),
            drift_table=self._generate_drift_html_table(report['results']['drift'])
        )
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
            
    def _generate_hardening_html_table(self, results):
        """Generate hardening results table HTML"""
        table_rows = ""
        
        for result in results:
            success_class = 'success' if result['success'] else 'failure'
            reboot_needed = 'Yes' if result['requires_reboot'] else 'No'
            
            table_rows += f"""
            <tr>
                <td>{result['name']}</td>
                <td>{result['description']}</td>
                <td>{result['result']}</td>
                <td class="{success_class}">{result['success']}</td>
                <td>{reboot_needed}</td>
            </tr>
            """
            
        return table_rows
        
    def _generate_baseline_html_table(self, results):
        """Generate baseline checks table HTML"""
        table_rows = ""
        
        for result in results:
            success = result['success'] and result['matches']
            success_class = 'success' if success else 'failure'
            result_text = 'Match' if success else 'Mismatch'
            
            table_rows += f"""
            <tr>
                <td>{result['type']}</td>
                <td>{result.get('path', result.get('name'))}</td>
                <td>{result_text}</td>
                <td class="{success_class}">{success}</td>
            </tr>
            """
            
        return table_rows
        
    def _generate_compliance_html_table(self, results):
        """Generate compliance rules table HTML"""
        table_rows = ""
        
        for result in results:
            success_class = 'success' if result['passed'] else 'failure'
            
            table_rows += f"""
            <tr>
                <td>{result['rule']}</td>
                <td>{result['result']}</td>
                <td class="{success_class}">{result['passed']}</td>
            </tr>
            """
            
        return table_rows
        
    def _generate_drift_html_table(self, results):
        """Generate configuration drift table HTML"""
        table_rows = ""
        
        for result in results:
            table_rows += f"""
            <tr>
                <td>{result['type']}</td>
                <td>{result['path']}</td>
                <td>{result['current']}</td>
                <td>{result['expected']}</td>
                <td>{result['timestamp']}</td>
            </tr>
            """
            
        return table_rows

def main():
    """Main function to demonstrate configuration management"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Configuration Management Automation"
    )
    
    parser.add_argument(
        "-c", "--config",
        default="config/configuration_management.yaml",
        help="Configuration file"
    )
    
    parser.add_argument(
        "-m", "--mode",
        choices=['harden', 'baseline', 'drift', 'compliance', 'complete'],
        default='complete',
        help="Operation mode (default: complete)"
    )
    
    parser.add_argument(
        "-f", "--format",
        choices=['json', 'csv', 'html'],
        default='html',
        help="Report format (default: HTML)"
    )
    
    args = parser.parse_args()
    
    try:
        manager = ConfigurationManager(args.config)
        
        if args.mode == 'complete':
            report_file = manager.manage_configuration()
            print(f"Complete configuration management completed. Report: {report_file}")
            
        elif args.mode == 'harden':
            results = manager.harden_system()
            print(f"System hardening completed. Results: {len(results)} settings applied")
            
        elif args.mode == 'baseline':
            results = manager.check_baseline()
            print(f"Baseline checks completed. Results: {len([r for r in results if r['success'] and r['matches']])} out of {len(results)} passed")
            
        elif args.mode == 'drift':
            results = manager.detect_configuration_drift()
            print(f"Configuration drift detection completed. Drifts found: {len(results)}")
            
        elif args.mode == 'compliance':
            results = manager.check_compliance()
            print(f"Compliance checks completed. Passed: {len([r for r in results if r['passed']])} out of {len(results)}")
            
        # Generate report in requested format
        if args.mode in ['harden', 'baseline', 'drift', 'compliance']:
            report_file = manager.generate_report(args.format)
            print(f"Report generated: {report_file}")
            
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        print(traceback.format_exc())

if __name__ == "__main__":
    main()
