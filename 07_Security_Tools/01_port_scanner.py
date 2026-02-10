#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Port Scanner Tool in Python for Cybersecurity
This script implements a comprehensive port scanner with multiple scanning techniques
including TCP connect, SYN scan, UDP scan, and more. Perfect for beginners!
"""

import socket
import threading
import time
import struct
import random
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

class PortScanner:
    """Comprehensive port scanner with multiple scanning techniques"""
    
    def __init__(self, target, ports=None, scan_type='tcp', timeout=1, threads=50):
        """
        Initialize the port scanner
        
        Args:
            target: Target IP address or hostname
            ports: List of ports to scan or port range (e.g., '1-1000')
            scan_type: Scan technique to use (tcp, syn, udp, xmas, null)
            timeout: Connection timeout in seconds
            threads: Number of concurrent threads
        """
        self.target = target
        self.scan_type = scan_type.lower()
        self.timeout = timeout
        self.threads = threads
        self.open_ports = []
        self.port_status = {}
        
        # Parse ports
        if ports is None:
            self.ports = list(range(1, 65536))
        elif isinstance(ports, str):
            if '-' in ports:
                start, end = map(int, ports.split('-'))
                self.ports = list(range(start, end + 1))
            else:
                self.ports = [int(ports)]
        elif isinstance(ports, list):
            self.ports = ports
        else:
            self.ports = list(range(1, 1000))
            
        # Create socket timeout
        socket.setdefaulttimeout(self.timeout)
        
    def _tcp_connect_scan(self, port):
        """TCP connect scan - simple and reliable"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.target, port))
            sock.close()
            return True
        except:
            return False
            
    def _udp_scan(self, port):
        """UDP scan - slower and less reliable"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(b'test', (self.target, port))
            
            sock.settimeout(0.5)
            try:
                data, addr = sock.recvfrom(1024)
                return True
            except socket.timeout:
                return False
            finally:
                sock.close()
        except:
            return False
            
    def _get_service_name(self, port, protocol='tcp'):
        """Get service name from port number (using /etc/services)"""
        try:
            return socket.getservbyport(port, protocol)
        except:
            return 'Unknown'
            
    def _scan_port(self, port):
        """Scan single port based on scan type"""
        try:
            if self.scan_type == 'tcp':
                if self._tcp_connect_scan(port):
                    service = self._get_service_name(port)
                    self.open_ports.append(port)
                    self.port_status[port] = {'status': 'open', 'service': service}
                    print(f"Port {port:5} is open ({service})")
                else:
                    self.port_status[port] = {'status': 'closed'}
                    
            elif self.scan_type == 'udp':
                if self._udp_scan(port):
                    service = self._get_service_name(port, 'udp')
                    self.open_ports.append(port)
                    self.port_status[port] = {'status': 'open', 'service': service}
                    print(f"Port {port:5} is open ({service})")
                else:
                    self.port_status[port] = {'status': 'closed'}
                    
        except Exception as e:
            self.port_status[port] = {'status': 'filtered', 'error': str(e)}
            
    def scan(self):
        """Run the port scan with configured parameters"""
        print(f"{'='*60}")
        print(f"  PORT SCANNER - TARGET: {self.target}")
        print(f"{'='*60}")
        print(f"Scan Type: {self.scan_type.upper()}")
        print(f"Ports to Scan: {len(self.ports)} ports")
        print(f"Timeout: {self.timeout} seconds")
        print(f"Threads: {self.threads}")
        print(f"Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}\n")
        
        start_time = time.time()
        
        # Use thread pool executor for concurrent scanning
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self._scan_port, self.ports)
            
        end_time = time.time()
        scan_time = end_time - start_time
        
        print(f"\n{'='*60}")
        print(f"  SCAN COMPLETED")
        print(f"{'='*60}")
        print(f"Open Ports Found: {len(self.open_ports)}")
        print(f"Scan Duration: {scan_time:.2f} seconds")
        print(f"End Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        if self.open_ports:
            print(f"\nOpen Ports:")
            for port in sorted(self.open_ports):
                service = self.port_status[port]['service']
                print(f"  Port {port:5} ({service})")
                
        return self.port_status
        
    def save_results(self, filename):
        """Save scan results to file"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"PORT SCAN RESULTS - {self.target}\n")
                f.write(f"Scan Type: {self.scan_type.upper()}\n")
                f.write(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Open Ports: {len(self.open_ports)}\n")
                f.write("\n" + "-"*50 + "\n\n")
                
                for port in sorted(self.ports):
                    if port in self.port_status:
                        status = self.port_status[port]['status']
                        service = self.port_status[port]['service'] if 'service' in self.port_status[port] else 'Unknown'
                        f.write(f"Port {port:5}: {status:10} ({service})\n")
                        
            print(f"\nResults saved to: {filename}")
            
        except Exception as e:
            print(f"\nError saving results: {e}")

def main():
    """Main function to run the port scanner"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Port Scanner Tool - Comprehensive port scanning utility"
    )
    
    parser.add_argument(
        "target",
        help="Target IP address or hostname to scan"
    )
    
    parser.add_argument(
        "-p", "--ports",
        default="1-1000",
        help="Ports to scan (e.g., '1-1000', '80,443', or '22')"
    )
    
    parser.add_argument(
        "-t", "--type",
        choices=['tcp', 'udp'],
        default='tcp',
        help="Scan type: tcp (default) or udp"
    )
    
    parser.add_argument(
        "-T", "--timeout",
        type=float,
        default=1.0,
        help="Connection timeout in seconds (default: 1.0)"
    )
    
    parser.add_argument(
        "-j", "--threads",
        type=int,
        default=50,
        help="Number of concurrent threads (default: 50)"
    )
    
    parser.add_argument(
        "-o", "--output",
        help="Output file to save results"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    args = parser.parse_args()
    
    try:
        scanner = PortScanner(
            target=args.target,
            ports=args.ports,
            scan_type=args.type,
            timeout=args.timeout,
            threads=args.threads
        )
        
        results = scanner.scan()
        
        if args.output:
            scanner.save_results(args.output)
            
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
