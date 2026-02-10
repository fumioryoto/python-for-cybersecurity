#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Static Analysis Techniques in Python for Cybersecurity
This script implements static analysis methods:
- File type detection and validation
- PE/ELF/Mach-O file analysis
- Strings extraction and analysis
- Import/Export analysis
- Code disassembly
- Control flow analysis
- Data flow analysis
Perfect for beginners!
"""

import os
import sys
import struct
import pefile
import lief
import capstone
import magic
import hashlib
import re
import binascii
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass
from enum import Enum

class FileType(Enum):
    """File type enumeration"""
    UNKNOWN = 0
    PE = 1
    ELF = 2
    MACH_O = 3
    APK = 4
    DEX = 5
    JAR = 6
    PDF = 7
    ZIP = 8
    RAR = 9

@dataclass
class FileAnalysisResult:
    """File analysis result structure"""
    file_path: str
    file_name: str
    file_size: int
    file_type: FileType
    magic_number: str
    hashes: Dict[str, str]
    entropy: float
    strings: List[str]
    suspicious_strings: List[str]
    pe_info: Dict[str, Any]
    elf_info: Dict[str, Any]
    sections: List[Dict[str, Any]]
    imports: List[str]
    suspicious_imports: List[str]
    exports: List[str]
    resources: List[Dict[str, Any]]

class StaticAnalyzer:
    """Class for static analysis operations"""
    
    def __init__(self):
        """Initialize static analyzer"""
        self.suspicious_imports = [
            'CreateProcess', 'CreateRemoteThread', 'VirtualAlloc',
            'VirtualProtect', 'WriteProcessMemory', 'ReadProcessMemory',
            'RegCreateKey', 'RegSetValue', 'RegDeleteKey',
            'Connect', 'send', 'recv', 'GetAdaptersAddresses',
            'GetHostByName', 'URLDownloadToFile', 'ShellExecute'
        ]
        
        self.suspicious_strings = [
            r'http://[^\s]*', r'https://[^\s]*', r'\\system32\\',
            r'\\Windows\\', r'\\Temp\\', r'\\AppData\\', r'shellcode',
            r'payload', r'virus', r'malware', r'password',
            r'credit card', r'steal', r'encrypt', r'decrypt',
            r'botnet', r'C2', r'command and control'
        ]
        
        self.packers = {
            'UPX': ['UPX!', 'UPX0', 'UPX1'],
            'ASPack': ['ASPACK'],
            'FSG': ['FSG!'],
            'Themida': ['Themida'],
            'VMProtect': ['VMProtect'],
            'Armadillo': ['Armadillo']
        }
        
        self.file_magic = {
            b'MZ': FileType.PE,
            b'\x7fELF': FileType.ELF,
            b'\xca\xfe\xba\xbe': FileType.MACH_O,
            b'\x50\x4b\x03\x04': FileType.ZIP,
            b'\x52\x61\x72\x21': FileType.RAR,
            b'%PDF': FileType.PDF
        }
        
    def detect_file_type(self, file_path: str) -> FileType:
        """
        Detect file type from magic number
        
        Args:
            file_path: File to analyze
            
        Returns:
            File type enumeration
        """
        try:
            with open(file_path, 'rb') as f:
                magic_bytes = f.read(4)
                
            for magic_number, file_type in self.file_magic.items():
                if magic_bytes.startswith(magic_number):
                    return file_type
                    
        except Exception as e:
            print(f"Error detecting file type: {e}")
            
        return FileType.UNKNOWN
        
    def calculate_hashes(self, file_path: str) -> Dict[str, str]:
        """
        Calculate MD5, SHA-1, and SHA-256 hashes
        
        Args:
            file_path: File to hash
            
        Returns:
            Dictionary of hash values
        """
        hashes = {'md5': '', 'sha1': '', 'sha256': ''}
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                
            hashes['md5'] = hashlib.md5(data).hexdigest()
            hashes['sha1'] = hashlib.sha1(data).hexdigest()
            hashes['sha256'] = hashlib.sha256(data).hexdigest()
            
        except Exception as e:
            print(f"Error calculating hashes: {e}")
            
        return hashes
        
    def calculate_entropy(self, file_path: str) -> float:
        """
        Calculate file entropy
        
        Args:
            file_path: File to analyze
            
        Returns:
            Entropy value (0-8)
        """
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                
            byte_counts = [0] * 256
            
            for byte in data:
                byte_counts[byte] += 1
                
            file_size = len(data)
            entropy = 0.0
            
            for count in byte_counts:
                if count > 0:
                    probability = count / file_size
                    entropy -= probability * (probability.bit_length() if probability else 0)
                    
            return entropy
            
        except Exception as e:
            print(f"Error calculating entropy: {e}")
            return 0.0
            
    def extract_strings(self, file_path: str, min_length: int = 4) -> List[str]:
        """
        Extract printable strings from binary file
        
        Args:
            file_path: File to analyze
            min_length: Minimum string length
            
        Returns:
            List of extracted strings
        """
        import string
        
        strings = []
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                
            current_string = b''
            
            for byte in data:
                if byte in string.printable.encode('utf-8'):
                    current_string += bytes([byte])
                else:
                    if len(current_string) >= min_length:
                        try:
                            strings.append(current_string.decode('utf-8'))
                        except:
                            pass
                    current_string = b''
                    
            if len(current_string) >= min_length:
                try:
                    strings.append(current_string.decode('utf-8'))
                except:
                    pass
                    
        except Exception as e:
            print(f"Error extracting strings: {e}")
            
        return list(set(strings))
        
    def analyze_strings(self, strings: List[str]) -> List[str]:
        """
        Analyze strings for suspicious content
        
        Args:
            strings: List of strings to analyze
            
        Returns:
            List of suspicious strings
        """
        suspicious = []
        
        for string in strings:
            for pattern in self.suspicious_strings:
                if re.search(pattern, string, re.IGNORECASE):
                    suspicious.append(string)
                    break
                    
        return suspicious
        
    def analyze_pe_file(self, file_path: str) -> Dict[str, Any]:
        """
        Analyze PE file
        
        Args:
            file_path: PE file to analyze
            
        Returns:
            Dictionary containing PE information
        """
        pe_info = {
            'imphash': '',
            'file_info': {},
            'sections': [],
            'imports': [],
            'exports': [],
            'resources': [],
            'is_packed': False,
            'detected_packer': '',
            'digital_signature': False,
            'subsystem': '',
            'machine_type': '',
            'compiler_version': '',
            'image_version': '',
            'os_version': '',
            'checksum': 0
        }
        
        try:
            pe = pefile.PE(file_path)
            
            # Get imphash
            pe_info['imphash'] = pe.get_imphash()
            
            # File info
            if hasattr(pe, 'VS_FIXEDFILEINFO'):
                pe_info['file_info'] = {
                    'product_version': f"{pe.VS_FIXEDFILEINFO.ProductVersionMS >> 16}.{pe.VS_FIXEDFILEINFO.ProductVersionMS & 0xFFFF}.{pe.VS_FIXEDFILEINFO.ProductVersionLS >> 16}.{pe.VS_FIXEDFILEINFO.ProductVersionLS & 0xFFFF}",
                    'file_version': f"{pe.VS_FIXEDFILEINFO.FileVersionMS >> 16}.{pe.VS_FIXEDFILEINFO.FileVersionMS & 0xFFFF}.{pe.VS_FIXEDFILEINFO.FileVersionLS >> 16}.{pe.VS_FIXEDFILEINFO.FileVersionLS & 0xFFFF}"
                }
                
            # Sections
            for section in pe.sections:
                section_info = {
                    'name': section.Name.decode().strip(),
                    'virtual_address': section.VirtualAddress,
                    'virtual_size': section.Misc_VirtualSize,
                    'raw_size': section.SizeOfRawData,
                    'entropy': self.calculate_entropy_from_bytes(section.get_data())
                }
                
                pe_info['sections'].append(section_info)
                
            # Imports
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    pe_info['imports'].append(entry.dll.decode())
                    
                    for imp in entry.imports:
                        if imp.name:
                            imp_name = imp.name.decode()
                            pe_info['imports'].append(imp_name)
                            
            # Exports
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    pe_info['exports'].append(exp.name.decode())
                    
            # Resources
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                pe_info['resources'] = self._enumerate_resources(pe.DIRECTORY_ENTRY_RESOURCE)
                
            # Check for digital signature
            if hasattr(pe, 'OPTIONAL_HEADER') and hasattr(pe.OPTIONAL_HEADER, 'DataDirectory'):
                data_dir = pe.OPTIONAL_HEADER.DataDirectory[4]
                if data_dir.VirtualAddress > 0 and data_dir.Size > 0:
                    pe_info['digital_signature'] = True
                    
            pe.close()
            
            # Check for packers
            pe_info['detected_packer'] = self._detect_packer(file_path)
            pe_info['is_packed'] = len(pe_info['detected_packer']) > 0
            
        except Exception as e:
            print(f"PE analysis error: {e}")
            
        return pe_info
        
    def _detect_packer(self, file_path: str) -> str:
        """Detect packer from file content"""
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
                
            for packer, signatures in self.packers.items():
                for signature in signatures:
                    if signature.encode('utf-8') in content:
                        return packer
                        
        except Exception as e:
            print(f"Packer detection error: {e}")
            
        return ''
        
    def _enumerate_resources(self, resource_dir) -> List[Dict[str, Any]]:
        """Enumerate PE resources"""
        resources = []
        
        for entry in resource_dir.entries:
            if entry.struct.NameIsString:
                name = entry.struct.Name.decode()
            else:
                name = hex(entry.struct.Id)
                
            if hasattr(entry, 'directory'):
                for subentry in entry.directory.entries:
                    resource_info = {
                        'name': name,
                        'id': subentry.struct.Id,
                        'language': subentry.struct.Language,
                        'sub_language': subentry.struct.SubLanguage
                    }
                    
                    resources.append(resource_info)
                    
        return resources
        
    def calculate_entropy_from_bytes(self, data: bytes) -> float:
        """Calculate entropy from byte data"""
        byte_counts = [0] * 256
        
        for byte in data:
            byte_counts[byte] += 1
            
        data_length = len(data)
        entropy = 0.0
        
        for count in byte_counts:
            if count > 0:
                probability = count / data_length
                entropy -= probability * (probability.bit_length() if probability else 0)
                
        return entropy
        
    def analyze_elf_file(self, file_path: str) -> Dict[str, Any]:
        """
        Analyze ELF file
        
        Args:
            file_path: ELF file to analyze
            
        Returns:
            Dictionary containing ELF information
        """
        elf_info = {
            'type': '',
            'machine': '',
            'version': '',
            'entry_point': 0,
            'program_headers': [],
            'sections': [],
            'dynamic_symbols': [],
            'relocations': [],
            'hash_info': {}
        }
        
        try:
            elf = lief.parse(file_path)
            
            elf_info['type'] = str(elf.header.file_type)
            elf_info['machine'] = str(elf.header.machine_type)
            elf_info['version'] = str(elf.header.identity_version)
            elf_info['entry_point'] = elf.header.entrypoint
            
            # Program headers
            for segment in elf.segments:
                elf_info['program_headers'].append({
                    'type': str(segment.type),
                    'virtual_address': segment.virtual_address,
                    'virtual_size': segment.virtual_size,
                    'offset': segment.file_offset,
                    'size': segment.physical_size
                })
                
            # Sections
            for section in elf.sections:
                elf_info['sections'].append({
                    'name': section.name,
                    'type': str(section.type),
                    'size': section.size,
                    'virtual_address': section.virtual_address,
                    'offset': section.file_offset,
                    'entropy': self.calculate_entropy_from_bytes(section.content)
                })
                
            # Dynamic symbols
            if hasattr(elf, 'dynamic_symbols'):
                for symbol in elf.dynamic_symbols:
                    elf_info['dynamic_symbols'].append({
                        'name': symbol.name,
                        'value': symbol.value,
                        'size': symbol.size,
                        'binding': str(symbol.binding),
                        'type': str(symbol.type)
                    })
                    
        except Exception as e:
            print(f"ELF analysis error: {e}")
            
        return elf_info
        
    def disassemble_code(self, file_path: str, offset: int = 0, size: int = 64) -> List[Dict[str, Any]]:
        """
        Disassemble code from file
        
        Args:
            file_path: File to disassemble
            offset: Offset from beginning of file
            size: Number of bytes to disassemble
            
        Returns:
            List of disassembled instructions
        """
        instructions = []
        
        try:
            with open(file_path, 'rb') as f:
                f.seek(offset)
                data = f.read(size)
                
            # Determine architecture
            cs_arch, cs_mode = self._detect_architecture(file_path)
            
            md = capstone.Cs(cs_arch, cs_mode)
            md.detail = True
            
            for instruction in md.disasm(data, offset):
                instructions.append({
                    'address': instruction.address,
                    'mnemonic': instruction.mnemonic,
                    'op_str': instruction.op_str,
                    'bytes': binascii.hexlify(instruction.bytes).decode()
                })
                
        except Exception as e:
            print(f"Disassembly error: {e}")
            
        return instructions
        
    def _detect_architecture(self, file_path: str) -> Tuple[int, int]:
        """Detect architecture from file"""
        file_type = self.detect_file_type(file_path)
        
        if file_type == FileType.PE:
            try:
                pe = pefile.PE(file_path)
                
                if pe.FILE_HEADER.Machine == 0x8664:
                    pe.close()
                    return capstone.CS_ARCH_X86, capstone.CS_MODE_64
                elif pe.FILE_HEADER.Machine == 0x14C:
                    pe.close()
                    return capstone.CS_ARCH_X86, capstone.CS_MODE_32
                    
            except Exception as e:
                print(f"Architecture detection error: {e}")
                
        elif file_type == FileType.ELF:
            try:
                elf = lief.parse(file_path)
                
                if elf.header.machine_type == lief.ELF.EM_X86_64:
                    return capstone.CS_ARCH_X86, capstone.CS_MODE_64
                elif elf.header.machine_type == lief.ELF.EM_386:
                    return capstone.CS_ARCH_X86, capstone.CS_MODE_32
                    
            except Exception as e:
                print(f"Architecture detection error: {e}")
                
        return capstone.CS_ARCH_X86, capstone.CS_MODE_32
        
    def run_analysis(self, file_path: str) -> FileAnalysisResult:
        """
        Run complete static analysis
        
        Args:
            file_path: File to analyze
            
        Returns:
            FileAnalysisResult object
        """
        print(f"{'='*60}")
        print(f"  STATIC ANALYSIS")
        print(f"{'='*60}")
        
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        
        file_type = self.detect_file_type(file_path)
        hashes = self.calculate_hashes(file_path)
        entropy = self.calculate_entropy(file_path)
        strings = self.extract_strings(file_path)
        suspicious_strings = self.analyze_strings(strings)
        
        pe_info = {}
        elf_info = {}
        sections = []
        imports = []
        suspicious_imports = []
        exports = []
        resources = []
        
        if file_type == FileType.PE:
            pe_info = self.analyze_pe_file(file_path)
            imports = pe_info.get('imports', [])
            exports = pe_info.get('exports', [])
            resources = pe_info.get('resources', [])
            
            # Filter out DLL names from imports for suspicious import detection
            filtered_imports = []
            
            for import_name in imports:
                if import_name.endswith('.dll'):
                    continue
                    
                if import_name in self.suspicious_imports:
                    suspicious_imports.append(import_name)
                    
                filtered_imports.append(import_name)
                
        elif file_type == FileType.ELF:
            elf_info = self.analyze_elf_file(file_path)
            imports = elf_info.get('dynamic_symbols', [])
            sections = elf_info.get('sections', [])
            
        return FileAnalysisResult(
            file_path=file_path,
            file_name=file_name,
            file_size=file_size,
            file_type=file_type,
            magic_number=self._get_magic_number(file_path),
            hashes=hashes,
            entropy=entropy,
            strings=strings,
            suspicious_strings=suspicious_strings,
            pe_info=pe_info,
            elf_info=elf_info,
            sections=sections,
            imports=imports,
            suspicious_imports=suspicious_imports,
            exports=exports,
            resources=resources
        )
        
    def _get_magic_number(self, file_path: str) -> str:
        """Get magic number string"""
        try:
            with open(file_path, 'rb') as f:
                magic_bytes = f.read(4)
                
            return magic_bytes.hex()
            
        except Exception as e:
            print(f"Error getting magic number: {e}")
            return ''
            
    def generate_report(self, result: FileAnalysisResult) -> str:
        """
        Generate analysis report
        
        Args:
            result: FileAnalysisResult object
            
        Returns:
            Formatted report string
        """
        report = f"""
{'='*60}
STATIC ANALYSIS REPORT
{'='*60}

FILE INFORMATION
----------------
File Path: {result.file_path}
File Name: {result.file_name}
File Size: {result.file_size:,} bytes
File Type: {result.file_type.name}
Magic Number: {result.magic_number}

HASH VALUES
-----------
MD5: {result.hashes['md5']}
SHA-1: {result.hashes['sha1']}
SHA-256: {result.hashes['sha256']}

ENTROPY
-------
{result.entropy:.2f} bits per byte
{'(Suspiciously high - packed/compressed)' if result.entropy > 7.5 else '(Normal range)'}

STRINGS ANALYSIS
----------------
Total strings: {len(result.strings)}
Suspicious strings: {len(result.suspicious_strings)}

{'='*60}
Report generated: {time.ctime()}
{'='*60}
"""
        
        if result.suspicious_strings:
            report += f"""

SUSPICIOUS STRINGS ({len(result.suspicious_strings)})
------------------
{chr(10).join(result.suspicious_strings)}
"""
            
        if result.suspicious_imports:
            report += f"""

SUSPICIOUS IMPORTS ({len(result.suspicious_imports)})
------------------
{chr(10).join(result.suspicious_imports)}
"""
            
        if result.file_type == FileType.PE and result.pe_info.get('is_packed'):
            report += f"""

PACKER DETECTION
----------------
Packer: {result.pe_info['detected_packer']}
"""
            
        return report
        
    def save_report(self, report: str, file_path: str):
        """
        Save report to file
        
        Args:
            report: Report content
            file_path: Output file path
        """
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(report)
                
            print(f"Report saved to: {file_path}")
            
        except Exception as e:
            print(f"Error saving report: {e}")
            
    def scan_directory(self, directory: str) -> List[FileAnalysisResult]:
        """
        Scan directory for files
        
        Args:
            directory: Directory to scan
            
        Returns:
            List of FileAnalysisResult objects
        """
        results = []
        
        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                
                if os.path.isfile(file_path) and os.path.getsize(file_path) > 0:
                    try:
                        print(f"Analyzing: {file_path}")
                        result = self.run_analysis(file_path)
                        results.append(result)
                        
                    except Exception as e:
                        print(f"Error analyzing {file_path}: {e}")
                        
        return results

def main():
    """Main function to demonstrate static analysis"""
    import argparse
    import time
    
    parser = argparse.ArgumentParser(
        description="Static Analyzer - Analyze files for malware indicators"
    )
    
    parser.add_argument(
        "target",
        help="File or directory to analyze"
    )
    
    parser.add_argument(
        "-r", "--recursive",
        action="store_true",
        help="Scan directory recursively"
    )
    
    parser.add_argument(
        "-o", "--output",
        help="Output report file"
    )
    
    parser.add_argument(
        "-d", "--disassemble",
        type=int,
        help="Disassemble code at offset"
    )
    
    parser.add_argument(
        "-s", "--strings",
        action="store_true",
        help="Extract and analyze strings"
    )
    
    parser.add_argument(
        "-m", "--malware",
        action="store_true",
        help="Show malware detection results"
    )
    
    args = parser.parse_args()
    
    analyzer = StaticAnalyzer()
    
    try:
        if os.path.isdir(args.target):
            print(f"Scanning directory: {args.target}")
            results = analyzer.scan_directory(args.target)
        else:
            print(f"Analyzing file: {args.target}")
            results = [analyzer.run_analysis(args.target)]
            
        if args.malware:
            print(f"{'='*60}")
            print(f"  MALWARE DETECTION RESULTS")
            print(f"{'='*60}")
            
            for result in results:
                threat_score = 0
                
                if result.entropy > 7.5:
                    threat_score += 3
                
                if result.suspicious_imports:
                    threat_score += len(result.suspicious_imports) * 0.5
                    
                if result.suspicious_strings:
                    threat_score += len(result.suspicious_strings) * 0.3
                    
                if result.file_type == FileType.PE and result.pe_info.get('is_packed'):
                    threat_score += 4
                    
                threat_score = min(10, threat_score)
                
                print(f"{result.file_name}")
                print(f"  Threat Score: {threat_score:.1f}/10")
                print(f"  Suspicious Imports: {len(result.suspicious_imports)}")
                print(f"  Suspicious Strings: {len(result.suspicious_strings)}")
                
                if threat_score > 5:
                    print(f"  Status: SUSPICIOUS")
                else:
                    print(f"  Status: CLEAN")
                    
                print()
                
        if args.strings:
            for result in results:
                print(f"{'='*60}")
                print(f"  STRINGS ANALYSIS: {result.file_name}")
                print(f"{'='*60}")
                
                if result.suspicious_strings:
                    print(f"Suspicious strings ({len(result.suspicious_strings)}):")
                    for string in result.suspicious_strings:
                        print(f"  {string}")
                        
        if args.disassemble is not None:
            for result in results:
                if os.path.isfile(result.file_path):
                    print(f"{'='*60}")
                    print(f"  DISASSEMBLY: {result.file_name}")
                    print(f"{'='*60}")
                    
                    instructions = analyzer.disassemble_code(
                        result.file_path,
                        args.disassemble,
                        64
                    )
                    
                    for instr in instructions:
                        print(f"0x{instr['address']:08x}: {instr['bytes']:20} {instr['mnemonic']} {instr['op_str']}")
                        
        if args.output:
            all_reports = []
            
            for result in results:
                all_reports.append(analyzer.generate_report(result))
                
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write('\n'.join(all_reports))
                
            print(f"Reports saved to: {args.output}")
            
        if not any([args.malware, args.strings, args.disassemble, args.output]):
            for result in results:
                print(analyzer.generate_report(result))
                
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        print(traceback.format_exc())

if __name__ == "__main__":
    main()
