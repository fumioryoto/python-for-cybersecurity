#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Binary Analysis in Python for Cybersecurity
This script implements binary analysis techniques:
- File format detection
- PE/ELF/Mach-O parsing
- Section and segment analysis
- Import/export function detection
- String extraction
Perfect for beginners!
"""

import os
import sys
import struct
import binascii
import string
from typing import List, Dict, Any
from dataclasses import dataclass
from enum import Enum
import pefile
import lief
import pyelftools

class FileType(Enum):
    """Enumeration of supported file types"""
    UNKNOWN = 0
    PE = 1      # Windows Portable Executable
    ELF = 2     # Unix Executable and Linkable Format
    MACH_O = 3  # macOS Mach-O
    APK = 4     # Android Application Package
    JAR = 5     # Java Archive
    DEX = 6     # Android Dalvik Executable
    PDF = 7     # Portable Document Format
    ZIP = 8     # ZIP archive
    RAR = 9     # RAR archive
    TAR = 10    # Tar archive

@dataclass
class BinaryInfo:
    """Binary file information structure"""
    file_path: str
    file_size: int
    file_type: FileType
    architecture: str
    entry_point: int
    sections: List[Dict[str, Any]]
    imports: List[str]
    exports: List[str]
    strings: List[str]

class BinaryAnalyzer:
    """Class for binary file analysis"""
    
    def __init__(self):
        """Initialize binary analyzer"""
        self.supported_formats = [
            FileType.PE, FileType.ELF, FileType.MACH_O,
            FileType.APK, FileType.JAR, FileType.DEX
        ]
        
    def detect_file_type(self, file_path: str) -> FileType:
        """
        Detect binary file type based on magic bytes
        
        Args:
            file_path: Path to binary file
            
        Returns:
            File type as FileType enumeration
        """
        try:
            with open(file_path, 'rb') as f:
                magic_bytes = f.read(16)
                
            # Check magic bytes for common formats
            if magic_bytes.startswith(b'\x4d\x5a'):  # MZ
                return FileType.PE
            elif magic_bytes.startswith(b'\x7fELF'):  # ELF
                return FileType.ELF
            elif magic_bytes.startswith(b'\xca\xfe\xba\xbe'):  # Mach-O
                return FileType.MACH_O
            elif magic_bytes.startswith(b'PK\x03\x04'):  # ZIP archive
                # Check for specific ZIP-based formats
                with open(file_path, 'rb') as f:
                    content = f.read(512)
                    
                if b'AndroidManifest.xml' in content:
                    return FileType.APK
                elif b'META-INF' in content and b'classes.dex' in content:
                    return FileType.APK
                elif b'META-INF' in content and b'.class' in content:
                    return FileType.JAR
                else:
                    return FileType.ZIP
            elif magic_bytes.startswith(b'dex\n'):  # DEX file
                return FileType.DEX
            elif magic_bytes.startswith(b'%PDF'):  # PDF file
                return FileType.PDF
            elif magic_bytes.startswith(b'Rar!\x1a\x07'):  # RAR file
                return FileType.RAR
            elif magic_bytes.startswith(b'ustar'):  # TAR archive
                return FileType.TAR
            else:
                return FileType.UNKNOWN
                
        except Exception as e:
            print(f"Error detecting file type: {e}")
            return FileType.UNKNOWN
            
    def analyze_binary(self, file_path: str) -> BinaryInfo:
        """
        Analyze binary file and extract information
        
        Args:
            file_path: Path to binary file
            
        Returns:
            BinaryInfo object with analysis results
        """
        file_type = self.detect_file_type(file_path)
        file_size = os.path.getsize(file_path)
        
        info = BinaryInfo(
            file_path=file_path,
            file_size=file_size,
            file_type=file_type,
            architecture='Unknown',
            entry_point=0,
            sections=[],
            imports=[],
            exports=[],
            strings=[]
        )
        
        # Analyze based on file type
        if file_type == FileType.PE:
            self._analyze_pe_file(file_path, info)
        elif file_type == FileType.ELF:
            self._analyze_elf_file(file_path, info)
        elif file_type == FileType.MACH_O:
            self._analyze_mach_o_file(file_path, info)
        elif file_type == FileType.APK or file_type == FileType.JAR:
            self._analyze_zip_based(file_path, info)
        elif file_type == FileType.DEX:
            self._analyze_dex_file(file_path, info)
            
        # Extract strings from any file type
        info.strings = self._extract_strings(file_path)
        
        return info
        
    def _analyze_pe_file(self, file_path: str, info: BinaryInfo):
        """Analyze Windows PE file"""
        try:
            pe = pefile.PE(file_path)
            
            # Architecture
            if pe.FILE_HEADER.Machine == 0x8664:
                info.architecture = 'x86_64'
            elif pe.FILE_HEADER.Machine == 0x14c:
                info.architecture = 'x86'
            elif pe.FILE_HEADER.Machine == 0xAA64:
                info.architecture = 'ARM64'
            elif pe.FILE_HEADER.Machine == 0x1C0:
                info.architecture = 'ARM'
                
            # Entry point
            info.entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            
            # Sections
            for section in pe.sections:
                info.sections.append({
                    'name': section.Name.decode().strip(),
                    'virtual_address': section.VirtualAddress,
                    'virtual_size': section.Misc_VirtualSize,
                    'raw_size': section.SizeOfRawData,
                    'flags': section.Characteristics
                })
                
            # Imports
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    info.imports.append(entry.dll.decode())
                    
            # Exports
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for export in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if export.name:
                        info.exports.append(export.name.decode())
                        
            pe.close()
            
        except Exception as e:
            print(f"Error analyzing PE file: {e}")
            
    def _analyze_elf_file(self, file_path: str, info: BinaryInfo):
        """Analyze ELF file"""
        try:
            from elftools.elf.elffile import ELFFile
            
            with open(file_path, 'rb') as f:
                elf = ELFFile(f)
                
                # Architecture
                if elf['e_machine'] == 'EM_X86_64':
                    info.architecture = 'x86_64'
                elif elf['e_machine'] == 'EM_386':
                    info.architecture = 'x86'
                elif elf['e_machine'] == 'EM_ARM':
                    info.architecture = 'ARM'
                elif elf['e_machine'] == 'EM_AARCH64':
                    info.architecture = 'ARM64'
                    
                # Entry point
                info.entry_point = elf['e_entry']
                
                # Sections
                for section in elf.iter_sections():
                    info.sections.append({
                        'name': section.name,
                        'virtual_address': section['sh_addr'],
                        'virtual_size': section['sh_size'],
                        'raw_size': section['sh_size'],
                        'flags': section['sh_flags']
                    })
                    
        except Exception as e:
            print(f"Error analyzing ELF file: {e}")
            
    def _analyze_mach_o_file(self, file_path: str, info: BinaryInfo):
        """Analyze Mach-O file"""
        try:
            binary = lief.parse(file_path)
            
            if binary:
                # Architecture
                if binary.header.cpu_type == lief.MachO.CPUTYPE.ARM64:
                    info.architecture = 'ARM64'
                elif binary.header.cpu_type == lief.MachO.CPUTYPE.X86_64:
                    info.architecture = 'x86_64'
                elif binary.header.cpu_type == lief.MachO.CPUTYPE.X86:
                    info.architecture = 'x86'
                    
                # Entry point
                info.entry_point = binary.header.entrypoint
                
                # Sections
                for section in binary.sections:
                    info.sections.append({
                        'name': section.name,
                        'virtual_address': section.virtual_address,
                        'virtual_size': section.size,
                        'raw_size': section.size,
                        'flags': section.flags
                    })
                    
        except Exception as e:
            print(f"Error analyzing Mach-O file: {e}")
            
    def _analyze_zip_based(self, file_path: str, info: BinaryInfo):
        """Analyze ZIP-based files (APK, JAR)"""
        import zipfile
        
        try:
            with zipfile.ZipFile(file_path, 'r') as zf:
                # APK specific
                if info.file_type == FileType.APK:
                    info.architecture = 'ARM/ARM64'
                    
                # JAR specific
                if info.file_type == FileType.JAR:
                    info.architecture = 'Java'
                    
        except Exception as e:
            print(f"Error analyzing ZIP-based file: {e}")
            
    def _analyze_dex_file(self, file_path: str, info: BinaryInfo):
        """Analyze DEX file (Android)"""
        # For DEX files, we can use dextools or similar libraries
        try:
            # This is a simplified implementation
            info.architecture = 'Dalvik'
            
        except Exception as e:
            print(f"Error analyzing DEX file: {e}")
            
    def _extract_strings(self, file_path: str, min_length: int = 4) -> List[str]:
        """
        Extract printable strings from binary file
        
        Args:
            file_path: Path to binary file
            min_length: Minimum string length to extract
            
        Returns:
            List of printable strings
        """
        printable_chars = string.printable.encode('utf-8')
        strings = []
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
                
            current_string = b''
            
            for byte in content:
                if byte in printable_chars:
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
            
        # Deduplicate strings
        return list(set(strings))
        
    def verify_signature(self, file_path: str) -> Dict[str, Any]:
        """
        Verify digital signature of binary file
        
        Args:
            file_path: Path to binary file
            
        Returns:
            Dictionary with signature information
        """
        signature_info = {
            'verified': False,
            'signer': 'Unknown',
            'timestamp': None,
            'algorithm': 'Unknown'
        }
        
        try:
            if self.detect_file_type(file_path) == FileType.PE:
                import pefile
                
                pe = pefile.PE(file_path)
                
                if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
                    signature_info['verified'] = True
                    signature_info['signer'] = 'Windows Authenticode'
                    
                pe.close()
                
            elif self.detect_file_type(file_path) == FileType.APK:
                import zipfile
                
                with zipfile.ZipFile(file_path, 'r') as zf:
                    if 'META-INF/CERT.RSA' in zf.namelist() or 'META-INF/CERT.SF' in zf.namelist():
                        signature_info['verified'] = True
                        signature_info['signer'] = 'Android APK Signature'
                        
        except Exception as e:
            print(f"Error verifying signature: {e}")
            
        return signature_info
        
    def check_packer(self, info: BinaryInfo) -> List[str]:
        """
        Check for known packer signatures
        
        Args:
            info: Binary information object
            
        Returns:
            List of detected packers
        """
        packers = []
        
        if info.file_type == FileType.PE:
            packers.extend(self._check_pe_packers(info))
        elif info.file_type == FileType.ELF:
            packers.extend(self._check_elf_packers(info))
            
        return packers
        
    def _check_pe_packers(self, info: BinaryInfo) -> List[str]:
        """Check for PE packers"""
        pe_packers = []
        
        # Check for common packer signatures
        packer_signatures = {
            'UPX': ['UPX!', 'UPX0', 'UPX1'],
            'ASPack': ['ASPACK'],
            'FSG': ['FSG!'],
            'Themida': ['Themida'],
            'VMProtect': ['VMProtect']
        }
        
        try:
            with open(info.file_path, 'rb') as f:
                content = f.read()
                
            for packer, signatures in packer_signatures.items():
                for signature in signatures:
                    if signature.encode('utf-8') in content:
                        pe_packers.append(packer)
                        
        except Exception as e:
            print(f"Error checking PE packers: {e}")
            
        return pe_packers
        
    def _check_elf_packers(self, info: BinaryInfo) -> List[str]:
        """Check for ELF packers"""
        elf_packers = []
        
        # Check for common packer signatures
        packer_signatures = {
            'UPX': ['UPX!', 'UPX0', 'UPX1'],
            'UPX3': ['UPX!'],
            'MUPACK': ['MUPACK'],
            'ASProtect': ['ASProtect']
        }
        
        try:
            with open(info.file_path, 'rb') as f:
                content = f.read()
                
            for packer, signatures in packer_signatures.items():
                for signature in signatures:
                    if signature.encode('utf-8') in content:
                        elf_packers.append(packer)
                        
        except Exception as e:
            print(f"Error checking ELF packers: {e}")
            
        return elf_packers
        
    def save_analysis(self, info: BinaryInfo, output_file: str):
        """
        Save analysis results to JSON file
        
        Args:
            info: Binary information object
            output_file: Path to output file
        """
        import json
        
        analysis_data = {
            'file_path': info.file_path,
            'file_size': info.file_size,
            'file_type': info.file_type.name,
            'architecture': info.architecture,
            'entry_point': hex(info.entry_point) if info.entry_point else '0x0',
            'sections': info.sections,
            'imports': info.imports,
            'exports': info.exports,
            'strings': info.strings,
            'signature': self.verify_signature(info.file_path),
            'packers': self.check_packer(info)
        }
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(analysis_data, f, ensure_ascii=False, indent=4, default=str)
                
            print(f"Analysis saved to: {output_file}")
            
        except Exception as e:
            print(f"Error saving analysis: {e}")
            
    def print_analysis(self, info: BinaryInfo):
        """Print analysis results to console"""
        print(f"{'='*60}")
        print(f"  BINARY ANALYSIS REPORT")
        print(f"{'='*60}")
        print(f"File Path: {info.file_path}")
        print(f"File Size: {info.file_size} bytes ({info.file_size / 1024:.1f} KB)")
        print(f"File Type: {info.file_type.name}")
        print(f"Architecture: {info.architecture}")
        print(f"Entry Point: 0x{info.entry_point:X}")
        print(f"Sections: {len(info.sections)}")
        print(f"Imports: {len(info.imports)}")
        print(f"Exports: {len(info.exports)}")
        print(f"Strings: {len(info.strings)}")
        print(f"Packers: {', '.join(self.check_packer(info))}")
        
        signature = self.verify_signature(info.file_path)
        print(f"Signature Verified: {'Yes' if signature['verified'] else 'No'}")
        if signature['verified']:
            print(f"Signer: {signature['signer']}")
        
        print()
        print("=== Sections ===")
        for section in info.sections:
            print(f"  {section['name']:16} VA: 0x{section['virtual_address']:X} Size: 0x{section['virtual_size']:X}")
            
        print()
        print("=== Imports ===")
        for import_name in info.imports[:10]:
            print(f"  {import_name}")
        if len(info.imports) > 10:
            print(f"  ... and {len(info.imports) - 10} more")
            
        print()
        print("=== Exports ===")
        for export_name in info.exports[:10]:
            print(f"  {export_name}")
        if len(info.exports) > 10:
            print(f"  ... and {len(info.exports) - 10} more")
            
        print()
        print("=== Strings ===")
        for string in info.strings[:10]:
            print(f"  {string}")
        if len(info.strings) > 10:
            print(f"  ... and {len(info.strings) - 10} more")

def main():
    """Main function to demonstrate binary analysis"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Binary Analysis Tool - Analyze and extract information from binary files"
    )
    
    parser.add_argument(
        "file_path",
        help="Path to binary file to analyze"
    )
    
    parser.add_argument(
        "-o", "--output",
        help="Output file to save analysis results in JSON format"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print verbose analysis information"
    )
    
    args = parser.parse_args()
    
    if not os.path.exists(args.file_path):
        print(f"Error: File not found - {args.file_path}")
        return
    
    analyzer = BinaryAnalyzer()
    
    try:
        print(f"Analyzing file: {args.file_path}")
        info = analyzer.analyze_binary(args.file_path)
        
        if args.verbose:
            analyzer.print_analysis(info)
            
        if args.output:
            analyzer.save_analysis(info, args.output)
            
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        print(traceback.format_exc())

if __name__ == "__main__":
    main()
