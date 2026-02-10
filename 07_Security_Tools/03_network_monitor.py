#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Network Monitor Tool in Python for Cybersecurity
This script implements a network monitoring tool that captures and analyzes
network traffic, detects anomalies, and provides real-time monitoring.
Perfect for beginners!
"""

import socket
import struct
import binascii
import time
import json
from datetime import datetime
from collections import defaultdict, Counter

class NetworkMonitor:
    """Network monitoring and traffic analysis tool"""
    
    def __init__(self, interface='eth0', capture_limit=1000, 
                 verbose=False):
        """
        Initialize network monitor
        
        Args:
            interface: Network interface to monitor
            capture_limit: Maximum number of packets to capture
            verbose: Enable verbose output
        """
        self.interface = interface
        self.capture_limit = capture_limit
        self.verbose = verbose
        self.packets = []
        self.statistics = {
            'total_packets': 0,
            'packet_types': defaultdict(int),
            'source_ips': defaultdict(int),
            'destination_ips': defaultdict(int),
            'source_ports': defaultdict(int),
            'destination_ports': defaultdict(int),
            'protocols': defaultdict(int),
            'packet_sizes': defaultdict(int),
            'flags': defaultdict(int),
            'anomalies': []
        }
        
    def _unpack_ip_header(self, data):
        """Unpack IP header from raw packet data"""
        ip_header = struct.unpack('!BBHHHBBH4s4s', data[:20])
        
        return {
            'version': ip_header[0] >> 4,
            'ihl': ip_header[0] & 0x0F,
            'tos': ip_header[1],
            'total_length': ip_header[2],
            'identification': ip_header[3],
            'flags': ip_header[4] >> 13,
            'fragment_offset': ip_header[4] & 0x1FFF,
            'ttl': ip_header[5],
            'protocol': ip_header[6],
            'checksum': ip_header[7],
            'source_ip': socket.inet_ntoa(ip_header[8]),
            'destination_ip': socket.inet_ntoa(ip_header[9])
        }
        
    def _unpack_tcp_header(self, data):
        """Unpack TCP header from raw packet data"""
        tcp_header = struct.unpack('!HHLLBBHHH', data[:20])
        
        return {
            'source_port': tcp_header[0],
            'destination_port': tcp_header[1],
            'sequence_number': tcp_header[2],
            'acknowledgment_number': tcp_header[3],
            'data_offset': (tcp_header[4] >> 4) * 4,
            'reserved': (tcp_header[4] >> 2) & 0x03,
            'urg': (tcp_header[4] >> 5) & 0x01,
            'ack': (tcp_header[4] >> 4) & 0x01,
            'psh': (tcp_header[4] >> 3) & 0x01,
            'rst': (tcp_header[4] >> 2) & 0x01,
            'syn': (tcp_header[4] >> 1) & 0x01,
            'fin': tcp_header[4] & 0x01,
            'window_size': tcp_header[5],
            'checksum': tcp_header[6],
            'urgent_pointer': tcp_header[7]
        }
        
    def _unpack_udp_header(self, data):
        """Unpack UDP header from raw packet data"""
        udp_header = struct.unpack('!HHHH', data[:8])
        
        return {
            'source_port': udp_header[0],
            'destination_port': udp_header[1],
            'length': udp_header[2],
            'checksum': udp_header[3]
        }
        
    def _get_protocol_name(self, protocol_num):
        """Get protocol name from protocol number"""
        protocols = {
            1: 'ICMP', 6: 'TCP', 17: 'UDP', 41: 'IPv6',
            50: 'ESP', 51: 'AH', 58: 'ICMPv6'
        }
        
        return protocols.get(protocol_num, f'Unknown({protocol_num})')
        
    def _detect_anomalies(self, packet):
        """Detect potential anomalies in packet"""
        anomalies = []
        
        # Check for unusual packet sizes
        if packet['ip_header']['total_length'] > 1500:
            anomalies.append({
                'type': 'large_packet',
                'description': f'Large packet size: {packet["ip_header"]["total_length"]} bytes',
                'severity': 'medium'
            })
            
        elif packet['ip_header']['total_length'] < 40:
            anomalies.append({
                'type': 'small_packet',
                'description': f'Small packet size: {packet["ip_header"]["total_length"]} bytes',
                'severity': 'low'
            })
            
        # Check for unusual TTL values
        if packet['ip_header']['ttl'] < 10 or packet['ip_header']['ttl'] > 250:
            anomalies.append({
                'type': 'unusual_ttl',
                'description': f'Unusual TTL value: {packet["ip_header"]["ttl"]}',
                'severity': 'medium'
            })
            
        return anomalies
        
    def capture_packets(self, duration=60):
        """
        Capture network packets for specified duration
        
        Args:
            duration: Capture duration in seconds
        """
        print(f"{'='*60}")
        print(f"  NETWORK MONITOR - INTERFACE: {self.interface}")
        print(f"{'='*60}")
        print(f"Capture Duration: {duration} seconds")
        print(f"Max Packets: {self.capture_limit}")
        print(f"{'='*60}\n")
        
        start_time = time.time()
        
        try:
            # Create raw socket
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
            
            if self.interface:
                sock.bind((self.interface, 0))
                
            packet_count = 0
            
            while packet_count < self.capture_limit and (time.time() - start_time) < duration:
                try:
                    data, address = sock.recvfrom(65536)
                    packet_count += 1
                    
                    self._parse_packet(data, address)
                    
                    if self.verbose and packet_count % 100 == 0:
                        print(f"  Captured {packet_count} packets...")
                        
                except Exception as e:
                    if self.verbose:
                        print(f"  Error capturing packet: {e}")
                        
        except Exception as e:
            print(f"Error: {e}")
        finally:
            if 'sock' in locals():
                sock.close()
                
        self.statistics['total_packets'] = packet_count
        self._analyze_traffic()
        
        print(f"\nCapture complete: {packet_count} packets captured")
        
    def _parse_packet(self, data, address):
        """Parse raw packet data into structured format"""
        packet = {
            'timestamp': datetime.now().isoformat(),
            'interface': address[0],
            'raw_data': data
        }
        
        # Parse Ethernet header
        eth_header = struct.unpack('!6s6sH', data[:14])
        packet['eth_header'] = {
            'destination_mac': binascii.hexlify(eth_header[0]).decode('utf-8'),
            'source_mac': binascii.hexlify(eth_header[1]).decode('utf-8'),
            'ether_type': socket.ntohs(eth_header[2])
        }
        
        # Parse IP header
        if packet['eth_header']['ether_type'] == 0x0800:
            packet['ip_header'] = self._unpack_ip_header(data[14:])
            self.statistics['protocols'][packet['ip_header']['protocol']] += 1
            
            # Parse transport layer
            protocol = packet['ip_header']['protocol']
            
            if protocol == 6:  # TCP
                packet['tcp_header'] = self._unpack_tcp_header(data[14 + packet['ip_header']['ihl']*4:])
                self.statistics['packet_types']['TCP'] += 1
                self.statistics['source_ports'][packet['tcp_header']['source_port']] += 1
                self.statistics['destination_ports'][packet['tcp_header']['destination_port']] += 1
                
                flags = []
                if packet['tcp_header']['syn']:
                    flags.append('SYN')
                if packet['tcp_header']['ack']:
                    flags.append('ACK')
                if packet['tcp_header']['fin']:
                    flags.append('FIN')
                if packet['tcp_header']['rst']:
                    flags.append('RST')
                    
                if flags:
                    self.statistics['flags'][','.join(flags)] += 1
                    
            elif protocol == 17:  # UDP
                packet['udp_header'] = self._unpack_udp_header(data[14 + packet['ip_header']['ihl']*4:])
                self.statistics['packet_types']['UDP'] += 1
                self.statistics['source_ports'][packet['udp_header']['source_port']] += 1
                self.statistics['destination_ports'][packet['udp_header']['destination_port']] += 1
                
            elif protocol == 1:  # ICMP
                self.statistics['packet_types']['ICMP'] += 1
                
            # Update statistics
            self.statistics['source_ips'][packet['ip_header']['source_ip']] += 1
            self.statistics['destination_ips'][packet['ip_header']['destination_ip']] += 1
            self.statistics['packet_sizes'][packet['ip_header']['total_length']] += 1
            
            # Detect anomalies
            anomalies = self._detect_anomalies(packet)
            if anomalies:
                packet['anomalies'] = anomalies
                self.statistics['anomalies'].extend(anomalies)
                
        elif packet['eth_header']['ether_type'] == 0x0806:  # ARP
            self.statistics['packet_types']['ARP'] += 1
            
        elif packet['eth_header']['ether_type'] == 0x86DD:  # IPv6
            self.statistics['packet_types']['IPv6'] += 1
            
        else:
            self.statistics['packet_types']['Unknown'] += 1
            
        self.packets.append(packet)
        
    def _analyze_traffic(self):
        """Analyze captured traffic and update statistics"""
        print(f"\n{'='*60}")
        print(f"  TRAFFIC ANALYSIS")
        print(f"{'='*60}")
        
        print(f"\nTotal Packets: {self.statistics['total_packets']}")
        
        print(f"\nPacket Types:")
        total = sum(self.statistics['packet_types'].values())
        for ptype, count in sorted(self.statistics['packet_types'].items(), 
                                key=lambda x: x[1], reverse=True):
            percentage = (count / total) * 100
            print(f"  {ptype:8}: {count:5} ({percentage:.1f}%)")
            
        print(f"\nTop Source IPs:")
        for ip, count in Counter(self.statistics['source_ips']).most_common(5):
            print(f"  {ip:15}: {count:5} packets")
            
        print(f"\nTop Destination IPs:")
        for ip, count in Counter(self.statistics['destination_ips']).most_common(5):
            print(f"  {ip:15}: {count:5} packets")
            
        print(f"\nTop Source Ports:")
        for port, count in Counter(self.statistics['source_ports']).most_common(5):
            print(f"  {port:5}: {count:5} packets")
            
        print(f"\nTop Destination Ports:")
        for port, count in Counter(self.statistics['destination_ports']).most_common(5):
            print(f"  {port:5}: {count:5} packets")
            
        print(f"\nTCP Flags:")
        for flags, count in Counter(self.statistics['flags']).items():
            print(f"  {flags:8}: {count:5} packets")
            
        print(f"\nAnomalies Detected: {len(self.statistics['anomalies'])}")
        if self.statistics['anomalies']:
            severity_count = defaultdict(int)
            for anomaly in self.statistics['anomalies']:
                severity_count[anomaly['severity']] += 1
                
            for severity, count in severity_count.items():
                print(f"  {severity.capitalize()}: {count}")
                
    def save_pcap(self, filename):
        """Save captured packets to PCAP file"""
        try:
            with open(filename, 'wb') as f:
                for packet in self.packets:
                    # Write packet header (simplified PCAP format)
                    timestamp = datetime.strptime(packet['timestamp'], 
                                                '%Y-%m-%dT%H:%M:%S.%f')
                    seconds = int(time.mktime(timestamp.timetuple()))
                    microseconds = timestamp.microsecond
                    
                    header = struct.pack('IIII', seconds, microseconds, 
                                       len(packet['raw_data']), 
                                       len(packet['raw_data']))
                    f.write(header)
                    f.write(packet['raw_data'])
                    
            print(f"\nPackets saved to: {filename}")
            
        except Exception as e:
            print(f"\nError saving to PCAP file: {e}")
            
    def save_json(self, filename):
        """Save captured packets to JSON file"""
        try:
            packets_data = []
            
            for packet in self.packets:
                packet_data = packet.copy()
                del packet_data['raw_data']
                packets_data.append(packet_data)
                
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump({
                    'timestamp': datetime.now().isoformat(),
                    'interface': self.interface,
                    'total_packets': self.statistics['total_packets'],
                    'packet_types': dict(self.statistics['packet_types']),
                    'statistics': self.statistics,
                    'packets': packets_data
                }, f, indent=2, default=str)
                
            print(f"\nPackets saved to: {filename}")
            
        except Exception as e:
            print(f"\nError saving to JSON file: {e}")

def main():
    """Main function to run network monitor"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Network Monitor Tool - Capture and analyze network traffic"
    )
    
    parser.add_argument(
        "-i", "--interface",
        default='eth0',
        help="Network interface to monitor (default: eth0)"
    )
    
    parser.add_argument(
        "-d", "--duration",
        type=int,
        default=60,
        help="Capture duration in seconds (default: 60)"
    )
    
    parser.add_argument(
        "-c", "--count",
        type=int,
        default=1000,
        help="Maximum number of packets to capture (default: 1000)"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    parser.add_argument(
        "-o", "--output",
        help="Output file to save captured packets"
    )
    
    parser.add_argument(
        "-f", "--format",
        choices=['json', 'pcap'],
        default='json',
        help="Output format (json or pcap, default: json)"
    )
    
    args = parser.parse_args()
    
    try:
        monitor = NetworkMonitor(
            interface=args.interface,
            capture_limit=args.count,
            verbose=args.verbose
        )
        
        monitor.capture_packets(args.duration)
        
        if args.output:
            if args.format == 'json':
                monitor.save_json(args.output)
            elif args.format == 'pcap':
                monitor.save_pcap(args.output)
                
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
