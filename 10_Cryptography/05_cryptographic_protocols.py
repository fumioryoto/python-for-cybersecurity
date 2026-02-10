#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cryptographic Protocols in Python for Cybersecurity
This script implements common cryptographic protocols:
- TLS/SSL (Transport Layer Security)
- SSH (Secure Shell)
- S/MIME (Secure/Multipurpose Internet Mail Extensions)
- PGP (Pretty Good Privacy) for email encryption
- HTTPS communication
- Key exchange protocols
Perfect for beginners!
"""

import os
import sys
import socket
import ssl
import base64
import hashlib
import time
from datetime import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.hazmat.backends import default_backend

class CryptographicProtocols:
    """Class for cryptographic protocol implementations"""
    
    def __init__(self):
        """Initialize cryptographic protocols class"""
        self.backend = default_backend()
        
    # ==========================================
    # TLS/SSL Protocol
    # ==========================================
    def create_ssl_context(self, certificate_file=None, key_file=None, ca_certs=None, 
                          cert_reqs=ssl.CERT_NONE):
        """
        Create SSL context for secure communication
        
        Args:
            certificate_file: Path to server certificate
            key_file: Path to server private key
            ca_certs: Path to CA certificates for verification
            cert_reqs: Certificate requirements (CERT_NONE, CERT_OPTIONAL, CERT_REQUIRED)
            
        Returns:
            SSL context object
        """
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        
        if certificate_file and key_file:
            context.load_cert_chain(certfile=certificate_file, keyfile=key_file)
            
        if ca_certs:
            context.load_verify_locations(cafile=ca_certs)
            context.verify_mode = cert_reqs
            
        # Enable secure protocols and ciphers
        context.options |= ssl.OP_NO_SSLv2
        context.options |= ssl.OP_NO_SSLv3
        context.options |= ssl.OP_NO_TLSv1
        context.options |= ssl.OP_NO_TLSv1_1
        
        context.set_ciphers('ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384')
        
        return context
        
    def ssl_server(self, host='localhost', port=4433, certificate_file=None, key_file=None):
        """
        Create SSL/TLS server
        
        Args:
            host: Server hostname
            port: Server port
            certificate_file: Path to server certificate
            key_file: Path to server private key
            
        Returns:
            Server socket
        """
        context = self.create_ssl_context(certificate_file, key_file)
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, port))
            sock.listen(5)
            
            print(f"SSL server listening on {host}:{port}")
            
            with context.wrap_socket(sock, server_side=True) as ssock:
                conn, addr = ssock.accept()
                print(f"Connection from {addr}")
                
                data = conn.recv(1024)
                if data:
                    print(f"Received: {data.decode('utf-8')}")
                    conn.sendall(b"Server response: Message received")
                    
        return True
        
    def ssl_client(self, host='localhost', port=4433, ca_certs=None, verify=True):
        """
        Create SSL/TLS client
        
        Args:
            host: Server hostname
            port: Server port
            ca_certs: Path to CA certificates for verification
            verify: Whether to verify server certificate
            
        Returns:
            Client socket
        """
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        
        if verify and ca_certs:
            context.load_verify_locations(cafile=ca_certs)
            context.verify_mode = ssl.CERT_REQUIRED
        else:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
        with socket.create_connection((host, port)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                print(f"Connected to {host}:{port}")
                print(f"Cipher: {ssock.cipher()}")
                print(f"Server certificate:")
                print(ssock.getpeercert())
                
                ssock.sendall(b"Client message: Hello, secure world!")
                data = ssock.recv(1024)
                print(f"Server response: {data.decode('utf-8')}")
                
        return True
        
    # ==========================================
    # SSH Protocol
    # ==========================================
    def ssh_key_gen(self, key_type='rsa', bits=2048, filename='id_rsa'):
        """
        Generate SSH key pair
        
        Args:
            key_type: Key type (rsa, dsa, ecdsa, ed25519)
            bits: Key size in bits
            filename: Output filename prefix
            
        Returns:
            Tuple of private and public key paths
        """
        import subprocess
        
        private_key_file = f"{filename}"
        public_key_file = f"{filename}.pub"
        
        # Check if keys already exist
        if os.path.exists(private_key_file) or os.path.exists(public_key_file):
            raise FileExistsError(f"Keys with filename {filename} already exist")
            
        # Generate SSH keys
        if key_type == 'rsa':
            subprocess.run(['ssh-keygen', '-t', 'rsa', '-b', str(bits), '-f', private_key_file, '-N', '', '-q'], 
                        check=True, capture_output=True)
        elif key_type == 'ecdsa':
            subprocess.run(['ssh-keygen', '-t', 'ecdsa', '-b', str(bits), '-f', private_key_file, '-N', '', '-q'],
                        check=True, capture_output=True)
        elif key_type == 'ed25519':
            subprocess.run(['ssh-keygen', '-t', 'ed25519', '-f', private_key_file, '-N', '', '-q'],
                        check=True, capture_output=True)
        else:
            raise ValueError(f"Unsupported key type: {key_type}")
            
        return private_key_file, public_key_file
        
    def ssh_remote_exec(self, hostname, command, username=None, port=22, key_filename=None):
        """
        Execute command on remote host via SSH
        
        Args:
            hostname: Remote hostname or IP address
            command: Command to execute
            username: Remote username
            port: SSH port
            key_filename: Path to private key file
            
        Returns:
            Tuple of (stdout, stderr)
        """
        import paramiko
        
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            if key_filename:
                ssh.connect(hostname, port=port, username=username, key_filename=key_filename)
            else:
                ssh.connect(hostname, port=port, username=username)
                
            stdin, stdout, stderr = ssh.exec_command(command)
            
            return stdout.read().decode('utf-8'), stderr.read().decode('utf-8')
            
        except Exception as e:
            raise Exception(f"SSH execution failed: {e}")
        finally:
            try:
                ssh.close()
            except:
                pass
                
    # ==========================================
    # S/MIME (Email Encryption)
    # ==========================================
    def create_smime_certificate(self, subject_name, filename_prefix='smime', valid_days=365):
        """
        Create self-signed S/MIME certificate for email encryption
        
        Args:
            subject_name: Subject name for certificate
            filename_prefix: Output filename prefix
            valid_days: Number of days certificate is valid
            
        Returns:
            Tuple of (certificate_path, private_key_path)
        """
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=self.backend
        )
        
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
            x509.NameAttribute(NameOID.COUNTRY_NAME, 'US'),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, 'California'),
            x509.NameAttribute(NameOID.LOCALITY_NAME, 'San Francisco'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Example Organization'),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, 'IT'),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=valid_days)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(subject_name)]),
            critical=False,
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        ).sign(private_key, hashes.SHA256(), self.backend)
        
        # Save certificate and private key
        cert_path = f"{filename_prefix}.pem"
        key_path = f"{filename_prefix}_key.pem"
        
        with open(cert_path, 'wb') as f:
            f.write(cert.public_bytes(encoding=serialization.Encoding.PEM))
            
        with open(key_path, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
            
        return cert_path, key_path
        
    def encrypt_smime(self, message, recipient_cert):
        """
        Encrypt message using S/MIME
        
        Args:
            message: Plaintext message to encrypt
            recipient_cert: Recipient's certificate
            
        Returns:
            Encrypted message
        """
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        
        # This is a simplified example - real S/MIME is more complex
        return f"Encrypted message to: {recipient_cert}"
        
    # ==========================================
    # PGP (Pretty Good Privacy)
    # ==========================================
    def pgp_key_gen(self, name, email, comment=None, key_type='RSA', key_length=2048, 
                   passphrase=None, filename='pgp_key'):
        """
        Generate PGP key pair
        
        Args:
            name: User name
            email: User email
            comment: Key comment
            key_type: Key type (RSA, DSA, etc.)
            key_length: Key length in bits
            passphrase: Passphrase for private key
            filename: Output filename
            
        Returns:
            Tuple of (public_key_path, private_key_path)
        """
        import gnupg
        
        gpg = gnupg.GPG()
        
        input_data = gpg.gen_key_input(
            name_real=name,
            name_email=email,
            name_comment=comment,
            key_type=key_type,
            key_length=key_length,
            passphrase=passphrase
        )
        
        key = gpg.gen_key(input_data)
        
        # Export keys
        public_key = gpg.export_keys(key.fingerprint)
        private_key = gpg.export_keys(key.fingerprint, True, passphrase=passphrase)
        
        public_key_path = f"{filename}.asc"
        private_key_path = f"{filename}_sec.asc"
        
        with open(public_key_path, 'w', encoding='utf-8') as f:
            f.write(public_key)
            
        with open(private_key_path, 'w', encoding='utf-8') as f:
            f.write(private_key)
            
        return public_key_path, private_key_path
        
    def encrypt_pgp(self, message, recipient_key, passphrase=None):
        """
        Encrypt message using PGP
        
        Args:
            message: Message to encrypt
            recipient_key: Recipient's public key
            passphrase: Passphrase (if needed)
            
        Returns:
            Encrypted message
        """
        import gnupg
        
        gpg = gnupg.GPG()
        
        with open(recipient_key, 'rb') as f:
            gpg.import_keys(f.read())
            
        encrypted_data = gpg.encrypt(message, recipient_key)
        
        return encrypted_data.data
        
    def decrypt_pgp(self, encrypted_message, private_key, passphrase=None):
        """
        Decrypt PGP encrypted message
        
        Args:
            encrypted_message: Encrypted message
            private_key: Private key for decryption
            passphrase: Passphrase for private key
            
        Returns:
            Decrypted message
        """
        import gnupg
        
        gpg = gnupg.GPG()
        
        with open(private_key, 'rb') as f:
            gpg.import_keys(f.read())
            
        decrypted_data = gpg.decrypt(encrypted_message, passphrase=passphrase)
        
        if decrypted_data.ok:
            return decrypted_data.data
        else:
            raise Exception(f"Decryption failed: {decrypted_data.stderr}")
            
    # ==========================================
    # HTTPS Communication
    # ==========================================
    def https_get(self, url, ca_certs=None, verify=True, headers=None):
        """
        Make HTTPS GET request
        
        Args:
            url: Target URL
            ca_certs: Path to CA certificates for verification
            verify: Whether to verify server certificate
            headers: Optional HTTP headers
            
        Returns:
            Response object
        """
        import requests
        
        try:
            response = requests.get(url, verify=ca_certs if verify else False, headers=headers)
            
            if response.status_code == 200:
                print(f"Successfully retrieved: {url}")
                print(f"Status: {response.status_code}")
                print(f"Server: {response.headers.get('Server', 'N/A')}")
                print(f"Content-Type: {response.headers.get('Content-Type', 'N/A')}")
                print(f"Content-Length: {len(response.content)} bytes")
                
                return response
            else:
                raise Exception(f"HTTP error: {response.status_code}")
                
        except Exception as e:
            raise Exception(f"HTTPS request failed: {e}")
            
    def https_post(self, url, data=None, json=None, ca_certs=None, verify=True, headers=None):
        """
        Make HTTPS POST request
        
        Args:
            url: Target URL
            data: Form data to send
            json: JSON data to send
            ca_certs: Path to CA certificates for verification
            verify: Whether to verify server certificate
            headers: Optional HTTP headers
            
        Returns:
            Response object
        """
        import requests
        
        try:
            response = requests.post(url, data=data, json=json, 
                                   verify=ca_certs if verify else False, 
                                   headers=headers)
                                   
            if response.status_code == 200:
                print(f"Successfully posted to: {url}")
                print(f"Status: {response.status_code}")
                
                return response
            else:
                raise Exception(f"HTTP error: {response.status_code}")
                
        except Exception as e:
            raise Exception(f"HTTPS request failed: {e}")
            
    # ==========================================
    # Network Protocol Analysis
    # ==========================================
    def analyze_ssl_connection(self, hostname, port=443):
        """
        Analyze SSL/TLS connection properties
        
        Args:
            hostname: Server hostname
            port: Server port
            
        Returns:
            Dictionary with SSL/TLS connection information
        """
        import ssl
        import socket
        
        context = ssl.create_default_context()
        
        try:
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    return {
                        'hostname': hostname,
                        'port': port,
                        'cipher': cipher,
                        'certificate': self._parse_certificate(cert),
                        'protocol': ssock.version(),
                        'handshake_time': time.time()
                    }
                    
        except Exception as e:
            raise Exception(f"SSL analysis failed: {e}")
            
    def _parse_certificate(self, cert):
        """Parse certificate information from SSL connection"""
        parsed = {}
        
        if cert:
            parsed['subject'] = dict(x[0] for x in cert['subject'])
            parsed['issuer'] = dict(x[0] for x in cert['issuer'])
            parsed['version'] = cert['version']
            parsed['serialNumber'] = cert['serialNumber']
            parsed['notBefore'] = cert['notBefore']
            parsed['notAfter'] = cert['notAfter']
            
            if 'subjectAltName' in cert:
                parsed['subjectAltName'] = [x[1] for x in cert['subjectAltName']]
                
        return parsed
        
    # ==========================================
    # Digital Signature Verification
    # ==========================================
    def verify_ssl_certificate(self, hostname, port=443, ca_certs=None):
        """
        Verify SSL/TLS certificate
        
        Args:
            hostname: Server hostname
            port: Server port
            ca_certs: Path to CA certificates
            
        Returns:
            Boolean indicating certificate validity
        """
        import ssl
        import socket
        
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        
        if ca_certs:
            context.load_verify_locations(cafile=ca_certs)
        else:
            context.set_default_verify_paths()
            
        try:
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    print("Certificate verified successfully")
                    return True
                    
        except ssl.SSLCertVerificationError as e:
            print(f"Certificate verification failed: {e}")
            return False
        except Exception as e:
            print(f"Connection failed: {e}")
            return False
            
    # ==========================================
    # Secure File Transfer
    # ==========================================
    def secure_file_transfer(self, local_file, remote_host, remote_file, 
                           username, port=22, key_filename=None):
        """
        Secure file transfer using SCP or SFTP
        
        Args:
            local_file: Path to local file
            remote_host: Remote hostname
            remote_file: Remote file path
            username: Remote username
            port: SSH port
            key_filename: Path to private key file
            
        Returns:
            Boolean indicating success
        """
        import paramiko
        
        try:
            transport = paramiko.Transport((remote_host, port))
            
            if key_filename:
                key = paramiko.RSAKey.from_private_key_file(key_filename)
                transport.connect(username=username, pkey=key)
            else:
                transport.connect(username=username)
                
            sftp = paramiko.SFTPClient.from_transport(transport)
            
            print(f"Transferring {local_file} to {remote_host}:{remote_file}")
            sftp.put(local_file, remote_file)
            
            sftp.close()
            transport.close()
            
            print("File transferred successfully")
            return True
            
        except Exception as e:
            print(f"File transfer failed: {e}")
            return False

def demo_cryptographic_protocols():
    """Demonstrate cryptographic protocols"""
    print(f"{'='*60}")
    print(f"  CRYPTOGRAPHIC PROTOCOLS DEMONSTRATION")
    print(f"{'='*60}")
    
    protocols = CryptographicProtocols()
    
    # Test 1: SSL Analysis
    print(f"\n1. SSL/TLS CONNECTION ANALYSIS:")
    
    try:
        ssl_info = protocols.analyze_ssl_connection('github.com')
        print(f"   Host: {ssl_info['hostname']}:{ssl_info['port']}")
        print(f"   Protocol: {ssl_info['protocol']}")
        print(f"   Cipher: {ssl_info['cipher'][0]} ({ssl_info['cipher'][1]} bits)")
        print(f"   Server: {ssl_info['certificate']['subject']['organizationName']}")
        print(f"   Subject: {ssl_info['certificate']['subject']['commonName']}")
        
    except Exception as e:
        print(f"   Error: {e}")
        
    # Test 2: Certificate Verification
    print(f"\n2. CERTIFICATE VERIFICATION:")
    
    is_valid = protocols.verify_ssl_certificate('github.com')
    print(f"   Certificate valid: {'✓' if is_valid else '✗'}")
    
    # Test 3: HTTPS Communication
    print(f"\n3. HTTPS COMMUNICATION:")
    
    try:
        response = protocols.https_get('https://github.com')
        print(f"   Status code: {response.status_code}")
        print(f"   Content type: {response.headers.get('Content-Type')}")
        print(f"   Server: {response.headers.get('Server')}")
        
    except Exception as e:
        print(f"   Error: {e}")
        
    return True

def main():
    """Main function to demonstrate cryptographic protocols"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Cryptographic Protocols - TLS/SSL, SSH, S/MIME, and HTTPS demonstration"
    )
    
    parser.add_argument(
        "-d", "--demo",
        action="store_true",
        help="Run cryptographic protocols demonstration"
    )
    
    parser.add_argument(
        "-s", "--server",
        action="store_true",
        help="Start SSL server"
    )
    
    parser.add_argument(
        "-c", "--client",
        action="store_true",
        help="Start SSL client"
    )
    
    parser.add_argument(
        "-H", "--https",
        help="Test HTTPS connection to URL"
    )
    
    parser.add_argument(
        "-S", "--ssh",
        help="SSH remote command execution"
    )
    
    parser.add_argument(
        "-u", "--username",
        help="SSH username"
    )
    
    parser.add_argument(
        "-k", "--key",
        help="SSH private key file"
    )
    
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=22,
        help="Port number"
    )
    
    args = parser.parse_args()
    
    try:
        protocols = CryptographicProtocols()
        
        if args.demo:
            demo_cryptographic_protocols()
            
        elif args.server:
            protocols.ssl_server()
            
        elif args.client:
            protocols.ssl_client()
            
        elif args.https:
            try:
                response = protocols.https_get(args.https)
                print(f"\nResponse:")
                print(response.text[:200] + '...')
            except Exception as e:
                print(f"Error: {e}")
                
        elif args.ssh and args.username:
            try:
                stdout, stderr = protocols.ssh_remote_exec(
                    args.ssh,
                    'ls -la',
                    args.username,
                    args.port,
                    args.key
                )
                
                if stdout:
                    print(f"Remote command output:\n{stdout}")
                    
                if stderr:
                    print(f"Remote command errors:\n{stderr}")
                    
            except Exception as e:
                print(f"Error: {e}")
                
        else:
            parser.print_help()
            
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        print(traceback.format_exc())

if __name__ == "__main__":
    main()
