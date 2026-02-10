# Network Automation Projects

This file contains project ideas to enhance your Python network automation skills with practical, hands-on experience. Each project includes learning objectives, key technologies, and implementation guidance.

## Project 1: Network Device Configuration Manager

**Learning Objectives:**

- Understand network device configuration management
- Implement device configuration backup and restore
- Develop configuration compliance checking
- Create configuration change management processes

**Key Technologies:**

- Netmiko for device connectivity
- TextFSM for parsing CLI outputs
- GitPython for configuration version control
- Python's built-in modules for file operations

**Implementation Steps:**

1. **Device Inventory Management:**
   - Create device inventory database with CSV/JSON
   - Include device details: IP address, username, password, device type, location
   - Implement inventory validation checks

2. **Configuration Backup:**
   - Use Netmiko to connect to devices
   - Backup running configuration to files
   - Implement version control with Git
   - Store backups in timestamped directories

3. **Compliance Checking:**
   - Define configuration compliance rules
   - Compare current configurations against baseline
   - Generate compliance reports with details of violations
   - Implement automated remediation for common issues

4. **Configuration Deployment:**
   - Create configuration templates using Jinja2
   - Deploy configurations to devices
   - Implement configuration rollback mechanisms
   - Verify configuration changes

5. **Monitoring and Reporting:**
   - Monitor configuration changes in real-time
   - Generate reports on configuration status
   - Set up alerts for configuration drift
   - Implement audit logging

**Example Code Snippet:**

```python
from netmiko import ConnectHandler

def backup_configuration(device):
    """Backup device configuration"""
    try:
        with ConnectHandler(**device) as conn:
            output = conn.send_command('show running-config')

        # Save configuration to file
        filename = f"backups/{device['host']}_config_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(output)

        return filename

    except Exception as e:
        print(f"Failed to backup {device['host']}: {e}")
        return None
```

## Project 2: Network Topology Discovery Tool

**Learning Objectives:**

- Understand network topology discovery protocols (CDP/LLDP)
- Implement network device discovery and mapping
- Develop network topology visualization
- Analyze network connectivity and reachability

**Key Technologies:**

- Netmiko for device connectivity
- NetworkX for graph representation
- Matplotlib for visualization
- scapy for packet analysis

**Implementation Steps:**

1. **Device Discovery:**
   - Use CDP/LLDP neighbors discovery
   - Implement ping sweeps for network discovery
   - Collect device information from discovered devices

2. **Topology Mapping:**
   - Create device adjacency relationships
   - Build network topology graph using NetworkX
   - Visualize topology with Matplotlib
   - Add device attributes to topology map

3. **Connectivity Analysis:**
   - Analyze network reachability
   - Identify redundant paths and single points of failure
   - Perform path tracing between devices
   - Visualize network traffic patterns

4. **Topology Maintenance:**
   - Implement periodic topology updates
   - Detect device additions and removals
   - Monitor link status changes
   - Send alerts for topology changes

**Example Code Snippet:**

```python
import networkx as nx
import matplotlib.pyplot as plt

def create_topology_map(devices, connections):
    """Create and visualize network topology"""
    G = nx.DiGraph()

    # Add devices to graph
    for device in devices:
        G.add_node(device['hostname'],
                  ip=device['ip'],
                  type=device['type'],
                  location=device['location'])

    # Add connections
    for conn in connections:
        G.add_edge(conn['source'], conn['destination'],
                 interface=conn['interface'],
                 bandwidth=conn['bandwidth'])

    # Visualize topology
    plt.figure(figsize=(12, 8))
    nx.draw(G, with_labels=True, node_color='lightblue',
            node_size=2000, font_size=12)
    plt.savefig('topology_map.png')
    plt.close()

    return G
```

## Project 3: Network Performance Monitoring System

**Learning Objectives:**

- Understand network performance metrics and monitoring
- Implement real-time bandwidth monitoring
- Develop latency and packet loss measurement
- Create network quality of service (QoS) analysis

**Key Technologies:**

- scapy for packet capture
- psutil for system metrics
- matplotlib/seaborn for visualization
- socket programming for network testing

**Implementation Steps:**

1. **Performance Metrics Collection:**
   - Capture network traffic using scapy
   - Calculate bandwidth usage per interface
   - Measure round-trip time (RTT) for devices
   - Detect packet loss and jitter

2. **Network Testing:**
   - Implement ICMP ping sweeps
   - Perform TCP connect scans
   - Test DNS resolution performance
   - Measure web server response times

3. **Data Storage and Analysis:**
   - Store performance data in SQLite database
   - Calculate performance trends over time
   - Identify performance bottlenecks
   - Correlate metrics with network events

4. **Visualization and Reporting:**
   - Create real-time performance dashboards
   - Generate daily/weekly performance reports
   - Visualize bandwidth usage patterns
   - Set up performance alerts

**Example Code Snippet:**

```python
import scapy.all as scapy
import statistics
from collections import deque

class NetworkMonitor:
    def __init__(self, interface):
        self.interface = interface
        self.packets = deque(maxlen=1000)
        self.start_time = time.time()

    def capture_packets(self, packet_count=100):
        """Capture network packets for monitoring"""
        packets = scapy.sniff(iface=self.interface, count=packet_count)

        for pkt in packets:
            self.packets.append({
                'timestamp': pkt.time,
                'size': len(pkt),
                'source': pkt.src,
                'destination': pkt.dst
            })

    def calculate_bandwidth(self):
        """Calculate current bandwidth usage"""
        if len(self.packets) < 2:
            return 0

        total_bytes = sum(pkt['size'] for pkt in self.packets)
        time_window = self.packets[-1]['timestamp'] - self.packets[0]['timestamp']

        if time_window > 0:
            return (total_bytes * 8) / (time_window * 1024 * 1024)  # Mbps

        return 0
```

## Project 4: Network Security Scanner

**Learning Objectives:**

- Understand network security scanning concepts
- Implement port scanning and service detection
- Develop vulnerability scanning
- Create network security reporting

**Key Technologies:**

- socket programming for port scanning
- nmap integration with python-nmap
- requests for HTTP-based scanning
- BeautifulSoup for web content parsing

**Implementation Steps:**

1. **Port Scanning:**
   - Implement TCP connect scanning
   - Perform SYN scanning (stealth scan)
   - Identify open ports and services
   - Detect OS and service versions

2. **Vulnerability Detection:**
   - Check for known vulnerabilities using CVEs
   - Test for weak configurations
   - Detect vulnerable services
   - Identify default credentials

3. **Web Application Scanning:**
   - Crawl websites and identify links
   - Test for common web vulnerabilities
   - Check for outdated software versions
   - Analyze web server headers

4. **Security Reporting:**
   - Generate vulnerability reports
   - Prioritize vulnerabilities by severity
   - Provide remediation recommendations
   - Store scan history

**Example Code Snippet:**

```python
import socket
import concurrent.futures

def scan_port(ip, port):
    """Scan single port on target IP"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        result = sock.connect_ex((ip, port))

        if result == 0:
            service = get_service_name(port)
            version = get_service_version(ip, port)

            return {'port': port, 'status': 'open',
                   'service': service, 'version': version}

        sock.close()

    except Exception as e:
        print(f"Error scanning port {port}: {e}")

    return {'port': port, 'status': 'closed'}

def scan_host(ip, port_range):
    """Scan range of ports on target host"""
    open_ports = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = []

        for port in port_range:
            futures.append(executor.submit(scan_port, ip, port))

        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result['status'] == 'open':
                open_ports.append(result)

    return open_ports
```

## Project 5: Network Access Control System

**Learning Objectives:**

- Understand network access control concepts
- Implement device authentication and authorization
- Develop role-based access control
- Create audit logging for access events

**Key Technologies:**

- Paramiko for SSH access control
- Flask for web interface
- SQLite for user and device database
- Cryptography for secure communication

**Implementation Steps:**

1. **User Management:**
   - Implement user authentication (username/password, multi-factor)
   - Create role-based access control (RBAC) system
   - Manage user sessions and permissions
   - Implement password policies

2. **Device Access Control:**
   - Authenticate devices based on certificates
   - Manage device whitelists/blacklists
   - Control which devices can connect
   - Implement access policies per network segment

3. **Session Management:**
   - Monitor active sessions in real-time
   - Terminate suspicious connections
   - Limit session duration
   - Control concurrent sessions

4. **Audit and Reporting:**
   - Log all access events with details
   - Generate audit reports
   - Set up alerts for security incidents
   - Track changes to access control policies

**Example Code Snippet:**

```python
import sqlite3
import hashlib
from datetime import datetime

def authenticate_user(username, password):
    """Authenticate user credentials"""
    conn = sqlite3.connect('access_control.db')
    cursor = conn.cursor()

    try:
        cursor.execute('''
            SELECT id, username, password_hash, salt, role
            FROM users
            WHERE username = ? AND active = 1
        ''', (username,))

        user = cursor.fetchone()

        if user:
            # Verify password
            salt = user[3]
            stored_hash = user[2]

            hash_object = hashlib.sha256((password + salt).encode())
            password_hash = hash_object.hexdigest()

            if password_hash == stored_hash:
                return {
                    'id': user[0],
                    'username': user[1],
                    'role': user[4]
                }

    except Exception as e:
        print(f"Authentication error: {e}")

    finally:
        conn.close()

    return None

def log_access_event(event_type, username, target_device):
    """Log access events for auditing"""
    conn = sqlite3.connect('access_control.db')
    cursor = conn.cursor()

    try:
        cursor.execute('''
            INSERT INTO access_events (timestamp, event_type, username,
                                   target_device, ip_address)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            datetime.now().isoformat(),
            event_type,
            username,
            target_device,
            '192.168.1.100'  # Replace with actual IP
        ))

        conn.commit()

    except Exception as e:
        print(f"Logging error: {e}")

    finally:
        conn.close()
```

## Project 6: Network Troubleshooting Assistant

**Learning Objectives:**

- Understand network troubleshooting methodologies
- Implement automated network diagnostics
- Develop intelligent network issue identification
- Create troubleshooting workflows

**Key Technologies:**

- scapy for packet analysis
- Netmiko for device commands
- pandas for data analysis
- machine learning for issue classification

**Implementation Steps:**

1. **Network Diagnostics:**
   - Automate common troubleshooting commands
   - Collect device configuration and status
   - Perform connectivity tests
   - Analyze interface statistics

2. **Issue Detection:**
   - Identify common network issues (link failures, routing problems)
   - Detect performance bottlenecks
   - Analyze error logs for patterns
   - Monitor network health metrics

3. **Troubleshooting Workflows:**
   - Create step-by-step troubleshooting guides
   - Implement root cause analysis
   - Suggest possible solutions
   - Track troubleshooting progress

4. **Knowledge Base:**
   - Build network issue knowledge base
   - Store troubleshooting patterns and solutions
   - Implement keyword search functionality
   - Allow for user contributions and updates

**Example Code Snippet:**

```python
def diagnose_network_issue(issue_description):
    """Intelligent network issue diagnosis"""
    # Simple keyword-based classification
    issue_patterns = {
        'latency': ['slow', 'latency', 'delay', 'ping'],
        'connectivity': ['down', 'unreachable', 'connection', 'timeout'],
        'configuration': ['config', 'setting', 'command', 'ssh'],
        'hardware': ['power', 'cable', 'switch', 'router']
    }

    for issue_type, keywords in issue_patterns.items():
        if any(keyword in issue_description.lower() for keyword in keywords):
            return issue_type

    return 'unknown'

def get_troubleshooting_steps(issue_type):
    """Get troubleshooting steps based on issue type"""
    steps = {
        'latency': [
            "Check interface errors and discard counts",
            "Verify routing configuration and metrics",
            "Check for bandwidth utilization on links",
            "Test connectivity with traceroute"
        ],
        'connectivity': [
            "Verify physical link status",
            "Check device configuration and interfaces",
            "Troubleshoot routing and switching issues",
            "Test connectivity with ping and telnet"
        ]
    }

    return steps.get(issue_type, ['Unknown issue type'])
```

## Project 7: Network Configuration Template Engine

**Learning Objectives:**

- Understand network configuration templating
- Implement Jinja2 template rendering
- Develop configuration validation
- Create template management system

**Key Technologies:**

- Jinja2 for template rendering
- JSON/YAML for data storage
- Python's built-in modules for file operations
- NetworkX for graph-based templating

**Implementation Steps:**

1. **Template Management:**
   - Create and store configuration templates
   - Implement template version control
   - Manage template parameters and variables
   - Allow for template sharing and reuse

2. **Data Integration:**
   - Integrate with device inventory
   - Collect device-specific information
   - Handle dynamic variables in templates
   - Validate data before rendering

3. **Configuration Validation:**
   - Validate rendered configurations against device capabilities
   - Check for syntax errors
   - Verify configuration parameters
   - Perform pre-deployment checks

4. **Deployment Automation:**
   - Render configurations from templates
   - Deploy configurations to devices
   - Verify deployment success
   - Implement rollback mechanisms

**Example Code Snippet:**

```python
from jinja2 import Environment, FileSystemLoader
import yaml

def render_configuration_template(template_name, context):
    """Render configuration template with given context"""
    try:
        # Load template from file
        env = Environment(loader=FileSystemLoader('templates'))
        template = env.get_template(template_name)

        # Render template with context
        configuration = template.render(context)

        # Validate rendered configuration
        if validate_configuration(configuration):
            return configuration

    except Exception as e:
        print(f"Error rendering template: {e}")

    return None

def validate_configuration(configuration):
    """Validate network configuration syntax"""
    # Simple validation checks
    required_sections = ['interface', 'router', 'access-list']

    for section in required_sections:
        if section not in configuration:
            print(f"Missing required configuration section: {section}")
            return False

    # Check for syntax errors in specific commands
    invalid_patterns = [
        'interface undefined',
        'ip address invalid',
        'access-list 0'
    ]

    for pattern in invalid_patterns:
        if pattern in configuration:
            print(f"Invalid configuration pattern: {pattern}")
            return False

    return True

def load_device_context(device_id):
    """Load device-specific context data"""
    with open('device_contexts.yaml', 'r', encoding='utf-8') as f:
        contexts = yaml.safe_load(f)

    return contexts.get(device_id, {})
```

## Project 8: Network Traffic Analysis Tool

**Learning Objectives:**

- Understand network traffic analysis
- Implement packet capture and analysis
- Develop network protocol parsing
- Create traffic visualization

**Key Technologies:**

- scapy for packet analysis
- pandas for data analysis
- matplotlib/seaborn for visualization
- socket programming for raw socket access

**Implementation Steps:**

1. **Packet Capture:**
   - Capture network packets using scapy
   - Filter traffic based on protocols, addresses, ports
   - Store packets in pcap format
   - Perform real-time packet analysis

2. **Protocol Analysis:**
   - Parse common network protocols (HTTP, DNS, TCP, UDP)
   - Extract metadata from packets
   - Analyze protocol-specific information
   - Detect anomalies and security threats

3. **Traffic Statistics:**
   - Calculate traffic volume and bandwidth usage
   - Identify top talkers and listeners
   - Analyze communication patterns
   - Detect unusual traffic patterns

4. **Visualization and Reporting:**
   - Create network traffic dashboards
   - Visualize protocol distribution
   - Generate traffic analysis reports
   - Set up alerts for suspicious traffic

**Example Code Snippet:**

```python
from scapy.all import sniff
import pandas as pd
import matplotlib.pyplot as plt

class NetworkTrafficAnalyzer:
    def __init__(self):
        self.packets = []

    def capture_traffic(self, interface, count=1000):
        """Capture network traffic"""
        self.packets = sniff(iface=interface, count=count)
        return len(self.packets)

    def analyze_protocols(self):
        """Analyze protocol distribution"""
        protocol_counts = {}

        for pkt in self.packets:
            protocol = self._get_protocol_name(pkt)

            if protocol in protocol_counts:
                protocol_counts[protocol] += 1
            else:
                protocol_counts[protocol] = 1

        return protocol_counts

    def _get_protocol_name(self, pkt):
        """Determine protocol from packet"""
        if pkt.haslayer('IP'):
            if pkt.haslayer('TCP'):
                return 'TCP'
            elif pkt.haslayer('UDP'):
                return 'UDP'
            elif pkt.haslayer('ICMP'):
                return 'ICMP'
            else:
                return f'IP_{pkt[IP].proto}'
        else:
            return 'Other'

    def plot_protocol_distribution(self, protocol_counts):
        """Plot protocol distribution pie chart"""
        plt.figure(figsize=(8, 8))
        plt.pie(protocol_counts.values(), labels=protocol_counts.keys(),
               autopct='%1.1f%%', startangle=90)
        plt.title('Network Protocol Distribution')
        plt.savefig('protocol_distribution.png')
        plt.close()
```

## Project 9: Network Automation Framework

**Learning Objectives:**

- Understand automation framework design patterns
- Implement modular automation components
- Develop task scheduling and orchestration
- Create robust error handling and logging

**Key Technologies:**

- Celery for task scheduling
- Redis/RabbitMQ for message queuing
- SQLAlchemy for data persistence
- Flask/Django for web interface

**Implementation Steps:**

1. **Framework Architecture:**
   - Design modular framework architecture
   - Implement core automation components
   - Create standard automation interfaces
   - Define automation task structure

2. **Task Management:**
   - Implement task scheduling and execution
   - Create task dependency management
   - Handle task retries and failures
   - Implement task priority system

3. **Device Integration:**
   - Develop device drivers for different vendors
   - Create device communication abstraction layer
   - Handle vendor-specific commands
   - Implement device discovery and enumeration

4. **Monitoring and Control:**
   - Create automation dashboard
   - Monitor automation task status
   - Implement real-time monitoring
   - Provide automation control interface

**Example Code Snippet:**

```python
from celery import Celery
import time

app = Celery('network_automation', broker='redis://localhost:6379/0',
             backend='redis://localhost:6379/0')

@app.task(bind=True, max_retries=3)
def run_automation_task(self, task_name, device, parameters):
    """Execute network automation task"""
    try:
        print(f"Starting task: {task_name} on {device['host']}")

        # Execute task based on task name
        if task_name == 'backup_config':
            result = backup_configuration(device)
        elif task_name == 'deploy_config':
            result = deploy_configuration(device, parameters['config'])
        elif task_name == 'test_connectivity':
            result = test_connectivity(device)
        else:
            raise ValueError(f"Unknown task type: {task_name}")

        print(f"Task completed: {task_name}")
        return result

    except Exception as e:
        print(f"Task failed: {e}")
        self.retry(exc=e, countdown=60)

def schedule_automation_task(task_name, device, parameters, run_at):
    """Schedule automation task for future execution"""
    result = run_automation_task.apply_async(
        args=(task_name, device, parameters),
        eta=run_at
    )

    return result.id

@app.task
def run_periodic_automation():
    """Run periodic automation tasks"""
    # Get list of devices to backup
    devices = get_all_devices()

    for device in devices:
        result = run_automation_task.delay('backup_config', device, {})
        print(f"Backup task scheduled for {device['host']}: {result.id}")
```

## Project 10: Network Automation Testing Framework

**Learning Objectives:**

- Understand software testing methodologies
- Implement network automation testing
- Develop test frameworks and tools
- Create automated test reports

**Key Technologies:**

- pytest/unittest for test frameworks
- mock for testing dependencies
- Netmiko for device interaction
- HTMLTestRunner for reporting

**Implementation Steps:**

1. **Test Framework Setup:**
   - Set up Python testing framework (pytest or unittest)
   - Create test directory structure
   - Implement test fixtures and setup/teardown
   - Handle test dependencies

2. **Network Device Testing:**
   - Write tests for device connectivity
   - Test configuration management
   - Validate network performance metrics
   - Test network security features

3. **Test Infrastructure:**
   - Set up test environments and labs
   - Implement test data management
   - Handle test artifact storage
   - Create test execution environments

4. **Test Execution and Reporting:**
   - Run tests and collect results
   - Generate test reports
   - Analyze test trends
   - Automate test execution

**Example Code Snippet:**

```python
import pytest
from netmiko import ConnectHandler
from unittest.mock import patch, Mock

class TestNetworkAutomation:

    def setup_method(self):
        """Test setup - called before each test method"""
        self.test_device = {
            'device_type': 'cisco_ios',
            'host': '192.168.1.1',
            'username': 'test',
            'password': 'test'
        }

    def test_device_connectivity(self):
        """Test device connectivity"""
        with patch('netmiko.ConnectHandler') as mock_connect:
            mock_connect.return_value = Mock()

            # Attempt to connect
            try:
                with ConnectHandler(**self.test_device):
                    connected = True
            except Exception as e:
                connected = False

            assert connected is True

    @pytest.mark.parametrize("interface, expected_status", [
        ('GigabitEthernet0/1', 'up'),
        ('GigabitEthernet0/2', 'up'),
        ('Serial0/0/0', 'up')
    ])
    def test_interface_status(self, interface, expected_status):
        """Test interface status on device"""
        with patch('netmiko.ConnectHandler') as mock_connect:
            mock_instance = Mock()
            mock_connect.return_value = mock_instance

            # Mock show interface command
            mock_instance.send_command.return_value = (
                f"Interface: {interface}\nStatus: {expected_status}\n"
            )

            # Run interface status check
            with ConnectHandler(**self.test_device) as conn:
                output = conn.send_command(f"show interface {interface} status")

            assert expected_status in output

    def test_configuration_backup(self):
        """Test configuration backup process"""
        # Test backup configuration method
        filename = backup_configuration(self.test_device)

        assert filename is not None
        assert filename.endswith('.txt')
```

## Learning Resources

**Books:**

- "Python Network Programming" by Dr. M. O. Faruque Sarker and Sam Washington
- "Network Programmability and Automation" by Jason Edelman et al.
- "Python for Network Engineers" by David Barroso and Hank Preston

**Online Courses:**

- Coursera: Python for Everybody
- Pluralsight: Python for Network Engineers
- LinkedIn Learning: Network Automation with Python

**Documentation:**

- Netmiko Documentation: https://github.com/ktbyers/netmiko
- NetworkX Documentation: https://networkx.org/documentation
- scapy Documentation: https://scapy.readthedocs.io

**Practice Platforms:**

- Cisco DevNet Sandbox: https://developer.cisco.com/sandbox
- GNS3: https://www.gns3.com
- EVE-NG: https://www.eve-ng.net

Remember, the best way to learn network automation with Python is by doing. Start with simple projects and gradually build complexity as you gain experience.
