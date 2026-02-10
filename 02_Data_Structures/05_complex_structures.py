#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Complex Data Structures in Python for Cybersecurity
This script demonstrates complex data structures with cybersecurity examples.
"""

# ==========================================
# 1. Stacks (Last-In-First-Out)
# ==========================================
print("=== Stacks ===\n")

# Simple stack implementation using list
class PacketStack:
    """Stack for managing network packets"""
    def __init__(self):
        self.packets = []
        
    def push(self, packet):
        """Add packet to stack"""
        self.packets.append(packet)
        
    def pop(self):
        """Remove and return top packet"""
        if not self.is_empty():
            return self.packets.pop()
        return None
        
    def peek(self):
        """Return top packet without removing"""
        if not self.is_empty():
            return self.packets[-1]
        return None
        
    def is_empty(self):
        """Check if stack is empty"""
        return len(self.packets) == 0
        
    def size(self):
        """Return stack size"""
        return len(self.packets)

# Usage example - packet buffer
packet_stack = PacketStack()

# Simulate packet capture
packets = [
    {"id": 1, "src": "192.168.1.100", "dst": "10.0.0.5", "size": 1024},
    {"id": 2, "src": "10.0.0.5", "dst": "192.168.1.100", "size": 512},
    {"id": 3, "src": "172.16.0.10", "dst": "8.8.8.8", "size": 64},
    {"id": 4, "src": "192.168.1.100", "dst": "10.0.0.5", "size": 2048}
]

for packet in packets:
    packet_stack.push(packet)
    print(f"Pushed packet {packet['id']}")

print(f"\nStack size: {packet_stack.size()}")
print(f"Top packet: {packet_stack.peek()['id']}")

print("\nProcessing packets (LIFO):")
while not packet_stack.is_empty():
    packet = packet_stack.pop()
    print(f"Processed packet {packet['id']}")

print()

# ==========================================
# 2. Queues (First-In-First-Out)
# ==========================================
print("=== Queues ===\n")

from collections import deque

class NetworkQueue:
    """Queue for network packet processing"""
    def __init__(self):
        self.queue = deque()
        
    def enqueue(self, packet):
        """Add packet to queue"""
        self.queue.append(packet)
        
    def dequeue(self):
        """Remove and return front packet"""
        if not self.is_empty():
            return self.queue.popleft()
        return None
        
    def front(self):
        """Return front packet without removing"""
        if not self.is_empty():
            return self.queue[0]
        return None
        
    def is_empty(self):
        """Check if queue is empty"""
        return len(self.queue) == 0
        
    def size(self):
        """Return queue size"""
        return len(self.queue)

# Usage example - packet processing pipeline
packet_queue = NetworkQueue()

for packet in packets:
    packet_queue.enqueue(packet)
    print(f"Enqueued packet {packet['id']}")

print(f"\nQueue size: {packet_queue.size()}")
print(f"Front packet: {packet_queue.front()['id']}")

print("\nProcessing packets (FIFO):")
while not packet_queue.is_empty():
    packet = packet_queue.dequeue()
    print(f"Processed packet {packet['id']}")

print()

# ==========================================
# 3. Linked Lists
# ==========================================
print("=== Linked Lists ===\n")

class Node:
    """Node for linked list"""
    def __init__(self, data):
        self.data = data
        self.next = None

class DeviceList:
    """Linked list for connected devices"""
    def __init__(self):
        self.head = None
        
    def add_device(self, device_info):
        """Add device to list"""
        new_node = Node(device_info)
        if not self.head:
            self.head = new_node
        else:
            current = self.head
            while current.next:
                current = current.next
            current.next = new_node
            
    def find_device(self, ip_address):
        """Find device by IP address"""
        current = self.head
        while current:
            if current.data["ip"] == ip_address:
                return current.data
            current = current.next
        return None
        
    def remove_device(self, ip_address):
        """Remove device by IP address"""
        current = self.head
        previous = None
        
        while current:
            if current.data["ip"] == ip_address:
                if previous:
                    previous.next = current.next
                else:
                    self.head = current.next
                return True
            previous, current = current, current.next
            
        return False
        
    def display(self):
        """Display all devices"""
        current = self.head
        devices = []
        while current:
            devices.append(current.data)
            current = current.next
        return devices

# Usage example - connected devices on network
device_list = DeviceList()

devices = [
    {"ip": "192.168.1.100", "mac": "00:11:22:33:44:55", "hostname": "workstation1"},
    {"ip": "192.168.1.101", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "server1"},
    {"ip": "192.168.1.102", "mac": "11:22:33:44:55:66", "hostname": "printer1"},
    {"ip": "192.168.1.103", "mac": "22:33:44:55:66:77", "hostname": "camera1"}
]

for device in devices:
    device_list.add_device(device)

print("Connected devices:")
for device in device_list.display():
    print(f"  {device['hostname']}: {device['ip']} ({device['mac']})")

# Find specific device
target_ip = "192.168.1.101"
found_device = device_list.find_device(target_ip)
if found_device:
    print(f"\nFound device with IP {target_ip}:")
    print(f"  Hostname: {found_device['hostname']}")
    print(f"  MAC: {found_device['mac']}")

# Remove device
remove_ip = "192.168.1.102"
if device_list.remove_device(remove_ip):
    print(f"\nRemoved device with IP {remove_ip}")
else:
    print(f"\nDevice with IP {remove_ip} not found")

print("\nUpdated device list:")
for device in device_list.display():
    print(f"  {device['hostname']}: {device['ip']} ({device['mac']})")

print()

# ==========================================
# 4. Trees and Hierarchies
# ==========================================
print("=== Trees and Hierarchies ===\n")

class TreeNode:
    """Node for tree structure"""
    def __init__(self, data):
        self.data = data
        self.children = []
        
    def add_child(self, child_node):
        """Add child to node"""
        self.children.append(child_node)
        
class NetworkTopology:
    """Tree structure for network topology"""
    def __init__(self, root_data):
        self.root = TreeNode(root_data)
        
    def add_device(self, parent_ip, device_info):
        """Add device to network topology"""
        parent_node = self._find_node(self.root, parent_ip)
        if parent_node:
            new_node = TreeNode(device_info)
            parent_node.add_child(new_node)
            return True
        return False
        
    def _find_node(self, current_node, target_ip):
        """Find node by IP recursively"""
        if current_node.data["ip"] == target_ip:
            return current_node
            
        for child in current_node.children:
            found = self._find_node(child, target_ip)
            if found:
                return found
                
        return None
        
    def display_topology(self, node=None, level=0):
        """Display network topology"""
        if node is None:
            node = self.root
            
        indent = "  " * level
        print(f"{indent}{node.data['hostname']} ({node.data['ip']})")
        
        for child in node.children:
            self.display_topology(child, level + 1)

# Usage example - network topology
network_topology = NetworkTopology({
    "ip": "192.168.1.1",
    "hostname": "router",
    "device_type": "router"
})

# Add devices to topology
network_topology.add_device("192.168.1.1", {
    "ip": "192.168.1.2",
    "hostname": "switch1",
    "device_type": "switch"
})

network_topology.add_device("192.168.1.2", {
    "ip": "192.168.1.100",
    "hostname": "workstation1",
    "device_type": "workstation"
})

network_topology.add_device("192.168.1.2", {
    "ip": "192.168.1.101",
    "hostname": "server1",
    "device_type": "server"
})

network_topology.add_device("192.168.1.2", {
    "ip": "192.168.1.102",
    "hostname": "printer1",
    "device_type": "printer"
})

print("Network Topology:")
network_topology.display_topology()

print()

# ==========================================
# 5. Graphs and Network Connections
# ==========================================
print("=== Graphs and Network Connections ===\n")

class NetworkGraph:
    """Graph representation of network connections"""
    def __init__(self):
        self.graph = {}
        
    def add_node(self, node):
        """Add a node (device) to the graph"""
        if node not in self.graph:
            self.graph[node] = []
            
    def add_edge(self, src, dst, protocol, bandwidth):
        """Add an edge (connection) between two nodes"""
        self.add_node(src)
        self.add_node(dst)
        
        self.graph[src].append((dst, protocol, bandwidth))
        self.graph[dst].append((src, protocol, bandwidth))
        
    def get_neighbors(self, node):
        """Get all neighbors of a node"""
        return self.graph.get(node, [])
        
    def find_path(self, start, end):
        """Find a path between two nodes using BFS"""
        visited = set()
        queue = [[start]]
        
        if start == end:
            return [start]
            
        while queue:
            path = queue.pop(0)
            node = path[-1]
            
            if node not in visited:
                neighbors = self.graph.get(node, [])
                
                for neighbor, _, _ in neighbors:
                    new_path = list(path)
                    new_path.append(neighbor)
                    queue.append(new_path)
                    
                    if neighbor == end:
                        return new_path
                        
                visited.add(node)
                
        return None
        
    def display_graph(self):
        """Display the network graph"""
        for node, connections in self.graph.items():
            print(f"{node} is connected to:")
            for conn in connections:
                dst, protocol, bandwidth = conn
                print(f"  {dst} ({protocol}, {bandwidth} Mbps)")
            print()

# Usage example - network connection graph
network_graph = NetworkGraph()

# Add network connections
connections = [
    ("192.168.1.100", "192.168.1.101", "TCP", 1000),
    ("192.168.1.100", "192.168.1.102", "UDP", 100),
    ("192.168.1.101", "192.168.1.103", "TCP", 1000),
    ("192.168.1.101", "10.0.0.5", "IPSec", 100),
    ("192.168.1.102", "8.8.8.8", "DNS", 10),
    ("10.0.0.5", "8.8.8.8", "DNS", 100)
]

for src, dst, protocol, bandwidth in connections:
    network_graph.add_edge(src, dst, protocol, bandwidth)

print("Network Connections:")
network_graph.display_graph()

# Find path between two devices
src_device = "192.168.1.100"
dst_device = "8.8.8.8"
path = network_graph.find_path(src_device, dst_device)

if path:
    print(f"Path from {src_device} to {dst_device}:")
    for i, node in enumerate(path):
        if i < len(path) - 1:
            print(f"{node} -> ", end="")
        else:
            print(node)
else:
    print(f"No path found between {src_device} and {dst_device}")

print()

# ==========================================
# 6. Heaps and Priority Queues
# ==========================================
print("=== Heaps and Priority Queues ===\n")

import heapq

class VulnerabilityHeap:
    """Min-heap for vulnerability prioritization"""
    def __init__(self):
        self.heap = []
        
    def add_vulnerability(self, cvss_score, cve, description):
        """Add vulnerability to heap (higher CVSS = higher priority)"""
        # Use negative score for min-heap to act as max-heap
        heapq.heappush(self.heap, (-cvss_score, cve, description))
        
    def get_top_vulnerability(self):
        """Get and remove top priority vulnerability"""
        if self.heap:
            neg_score, cve, description = heapq.heappop(self.heap)
            return -neg_score, cve, description
        return None
        
    def peek_top(self):
        """Peek at top priority vulnerability"""
        if self.heap:
            neg_score, cve, description = self.heap[0]
            return -neg_score, cve, description
        return None
        
    def is_empty(self):
        """Check if heap is empty"""
        return len(self.heap) == 0
        
    def size(self):
        """Return heap size"""
        return len(self.heap)

# Usage example - vulnerability management
vuln_heap = VulnerabilityHeap()

vulnerabilities = [
    (9.8, "CVE-2023-1234", "Apache HTTP Server Remote Code Execution"),
    (7.5, "CVE-2023-5678", "OpenSSL Buffer Overflow"),
    (8.8, "CVE-2023-9012", "Windows SMB Remote Code Execution"),
    (5.3, "CVE-2023-3456", "Python Integer Overflow"),
    (9.1, "CVE-2023-7890", "Linux Kernel Privilege Escalation")
]

for score, cve, desc in vulnerabilities:
    vuln_heap.add_vulnerability(score, cve, desc)
    print(f"Added: {cve} (CVSS: {score})")

print(f"\nTotal vulnerabilities: {vuln_heap.size()}")
top_vuln = vuln_heap.peek_top()
print(f"Top priority vulnerability: {top_vuln[1]} (CVSS: {top_vuln[0]})")

print("\nProcessing vulnerabilities by priority:")
while not vuln_heap.is_empty():
    score, cve, desc = vuln_heap.get_top_vulnerability()
    print(f"Processing: {cve} - {desc} (CVSS: {score})")

print()

# ==========================================
# 7. Advanced Dictionary Structures
# ==========================================
print("=== Advanced Dictionary Structures ===\n")

from collections import defaultdict, OrderedDict

# Default dictionary for log analysis
log_counts = defaultdict(int)
web_logs = [
    "192.168.1.100 - GET /index.html",
    "10.0.0.5 - POST /login",
    "192.168.1.100 - GET /about.html",
    "172.16.0.10 - GET /admin",
    "10.0.0.5 - GET /dashboard",
    "192.168.1.100 - GET /contact.html"
]

for log in web_logs:
    ip = log.split()[0]
    log_counts[ip] += 1

print("IP address counts (defaultdict):")
for ip, count in log_counts.items():
    print(f"  {ip}: {count} requests")

print()

# Ordered dictionary for packet sequence
packet_sequence = OrderedDict()
for i in range(5):
    packet_sequence[f"Packet-{i}"] = {
        "id": i,
        "size": 1024 + (i * 256),
        "timestamp": i * 100
    }

print("Packet sequence (ordered):")
for key, value in packet_sequence.items():
    print(f"  {key}: ID={value['id']}, Size={value['size']} bytes")

print()

# ==========================================
# 8. Practical Examples for Cybersecurity
# ==========================================
print("=== Practical Examples ===\n")

# Example 1: Network Traffic Anomaly Detection
print("=== Network Traffic Anomaly Detection ===\n")

class TrafficAnalyzer:
    """Analyze network traffic for anomalies"""
    def __init__(self):
        self.traffic_history = deque(maxlen=50)
        self.anomaly_stack = PacketStack()
        
    def add_traffic(self, packet):
        """Add traffic data and check for anomalies"""
        self.traffic_history.append(packet)
        
        # Check for anomaly: packet size > 10000 bytes
        if packet["size"] > 10000:
            self.anomaly_stack.push(packet)
            print(f"ANOMALY DETECTED: Large packet (size: {packet['size']})")
            
    def get_anomalies(self):
        """Get detected anomalies"""
        anomalies = []
        while not self.anomaly_stack.is_empty():
            anomalies.append(self.anomaly_stack.pop())
        return anomalies
        
    def print_statistics(self):
        """Print traffic statistics"""
        total_traffic = sum(p["size"] for p in self.traffic_history)
        avg_size = total_traffic / len(self.traffic_history)
        
        print(f"Total packets: {len(self.traffic_history)}")
        print(f"Total bytes: {total_traffic}")
        print(f"Average packet size: {avg_size:.2f} bytes")

# Simulate traffic analysis
analyzer = TrafficAnalyzer()

for i in range(50):
    packet = {
        "id": i,
        "size": 512 + (i * 10),
        "timestamp": i * 100
    }
    
    # Inject anomaly every 10th packet
    if i % 10 == 0:
        packet["size"] = 15000
        
    analyzer.add_traffic(packet)

print("\nTraffic Statistics:")
analyzer.print_statistics()

anomalies = analyzer.get_anomalies()
print(f"\nAnomalies detected: {len(anomalies)}")
for anomaly in anomalies:
    print(f"Packet {anomaly['id']}: {anomaly['size']} bytes")

print()

# Example 2: Intrusion Detection System
print("=== Intrusion Detection System ===\n")

class IDS:
    """Intrusion Detection System with state tracking"""
    def __init__(self):
        self.connection_states = {}
        self.suspicious_connections = PacketStack()
        
    def track_connection(self, src_ip, dst_ip, src_port, dst_port, state):
        """Track connection states"""
        key = (src_ip, dst_ip, src_port, dst_port)
        
        if key not in self.connection_states:
            self.connection_states[key] = []
            
        self.connection_states[key].append(state)
        
        # Check for suspicious patterns
        if len(self.connection_states[key]) > 5:
            if all(s == "SYN" for s in self.connection_states[key]):
                self.suspicious_connections.push({
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "states": self.connection_states[key]
                })
                print(f"SYN Flood Detected: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
                
    def get_suspicious_connections(self):
        """Get all suspicious connections"""
        return self.suspicious_connections.packets

# Simulate connection tracking
ids = IDS()

# Normal connections
ids.track_connection("192.168.1.100", "10.0.0.5", 1024, 80, "SYN")
ids.track_connection("192.168.1.100", "10.0.0.5", 1024, 80, "SYN-ACK")
ids.track_connection("192.168.1.100", "10.0.0.5", 1024, 80, "ACK")

# Suspicious connection (SYN flood)
for port in range(1025, 1031):
    ids.track_connection("203.0.113.7", "192.168.1.101", port, 80, "SYN")

suspicious = ids.get_suspicious_connections()
print(f"\nTotal suspicious connections: {len(suspicious)}")
for conn in suspicious:
    print(f"{conn['src_ip']}:{conn['src_port']} -> {conn['dst_ip']}:{conn['dst_port']}")

print()

# Example 3: Malware Analysis
print("=== Malware Analysis ===\n")

class MalwareAnalyzer:
    """Analyze malware behavior using graphs"""
    def __init__(self):
        self.api_graph = NetworkGraph()
        
    def add_api_call(self, process, api_function, parent_process=None):
        """Add API call to behavior graph"""
        if parent_process:
            self.api_graph.add_edge(parent_process, process, "API_CALL", len(api_function))
        self.api_graph.add_node(process)
        
    def analyze_behavior(self, suspicious_apis):
        """Analyze process behavior for suspicious APIs"""
        results = []
        for process in self.api_graph.graph:
            connections = self.api_graph.get_neighbors(process)
            
            for dst, _, _ in connections:
                if dst in suspicious_apis:
                    results.append((process, dst))
                    
        return results

# Simulate malware analysis
malware_analyzer = MalwareAnalyzer()

suspicious_apis = [
    "CreateRemoteThread", "VirtualAllocEx", 
    "WriteProcessMemory", "GetProcAddress"
]

# Malware process behavior
malware_analyzer.add_api_call("malware.exe", "CreateRemoteThread")
malware_analyzer.add_api_call("malware.exe", "VirtualAllocEx")
malware_analyzer.add_api_call("malware.exe", "WriteProcessMemory")
malware_analyzer.add_api_call("svchost.exe", "GetProcAddress", "malware.exe")
malware_analyzer.add_api_call("explorer.exe", "MessageBox", "svchost.exe")

# Analyze suspicious behavior
suspicious_calls = malware_analyzer.analyze_behavior(suspicious_apis)

print("Suspicious API calls detected:")
for process, api in suspicious_calls:
    print(f"  {process} calls {api}")
