#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Disassembly and Decompilation in Python for Cybersecurity
This script implements disassembly and decompilation techniques:
- X86/X64 disassembly using Capstone
- ARM/ARM64 disassembly
- Control flow graph analysis
- Function detection
- Decompilation techniques
Perfect for beginners!
"""

import os
import sys
import struct
import binascii
import pefile
import lief
import capstone
import unicorn
import hexdump
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass

@dataclass
class Instruction:
    """Disassembled instruction structure"""
    address: int
    bytes: bytes
    mnemonic: str
    operands: str
    size: int

@dataclass
class Function:
    """Function information structure"""
    address: int
    name: str
    instructions: List[Instruction]
    calls: List[int]
    references: List[int]

class Disassembler:
    """Class for code disassembly and decompilation"""
    
    def __init__(self, arch: str = 'x86_64'):
        """
        Initialize disassembler
        
        Args:
            arch: Target architecture (x86, x86_64, ARM, ARM64)
        """
        self.arch = arch
        self.cs = self._create_capstone(arch)
        
    def _create_capstone(self, arch: str):
        """Create Capstone disassembler instance"""
        if arch == 'x86_64':
            return capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        elif arch == 'x86':
            return capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        elif arch == 'ARM':
            return capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
        elif arch == 'ARM64':
            return capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        else:
            raise ValueError(f"Unsupported architecture: {arch}")
            
    def disassemble(self, data: bytes, base_address: int = 0x00401000, max_instructions: int = None) -> List[Instruction]:
        """
        Disassemble binary data
        
        Args:
            data: Binary data to disassemble
            base_address: Base address for disassembly
            max_instructions: Maximum number of instructions to disassemble
            
        Returns:
            List of Instruction objects
        """
        instructions = []
        
        try:
            for i in self.cs.disasm(data, base_address):
                if max_instructions and len(instructions) >= max_instructions:
                    break
                    
                instructions.append(Instruction(
                    address=i.address,
                    bytes=i.bytes,
                    mnemonic=i.mnemonic,
                    operands=i.op_str,
                    size=i.size
                ))
                
        except Exception as e:
            print(f"Disassembly error: {e}")
            
        return instructions
        
    def disassemble_file(self, file_path: str, section: str = None, offset: int = 0, 
                        length: int = None, max_instructions: int = None) -> List[Instruction]:
        """
        Disassemble section of binary file
        
        Args:
            file_path: Path to binary file
            section: Section name to disassemble
            offset: Offset within file
            length: Length of data to disassemble
            max_instructions: Maximum number of instructions to disassemble
            
        Returns:
            List of Instruction objects
        """
        try:
            # Determine file type
            with open(file_path, 'rb') as f:
                magic = f.read(4)
                
            if magic.startswith(b'MZ'):
                return self._disassemble_pe_file(file_path, section, offset, length, max_instructions)
            elif magic.startswith(b'\x7fELF'):
                return self._disassemble_elf_file(file_path, section, offset, length, max_instructions)
            elif magic.startswith(b'CAFEBABE') or magic.startswith(b'\xca\xfe\xba\xbe'):
                return self._disassemble_mach_o_file(file_path, section, offset, length, max_instructions)
            else:
                # Treat as raw binary
                with open(file_path, 'rb') as f:
                    if offset > 0:
                        f.seek(offset)
                        
                    if length:
                        data = f.read(length)
                    else:
                        data = f.read()
                        
                return self.disassemble(data, offset, max_instructions)
                
        except Exception as e:
            print(f"File disassembly error: {e}")
            return []
            
    def _disassemble_pe_file(self, file_path: str, section: str = None, offset: int = 0, 
                            length: int = None, max_instructions: int = None) -> List[Instruction]:
        """Disassemble PE file sections"""
        try:
            pe = pefile.PE(file_path)
            
            if section:
                # Find section by name
                for sec in pe.sections:
                    sec_name = sec.Name.decode().strip()
                    if sec_name == section:
                        # Disassemble section data
                        data = sec.get_data()
                        base_addr = pe.OPTIONAL_HEADER.ImageBase + sec.VirtualAddress
                        
                        return self.disassemble(data, base_addr, max_instructions)
                        
                print(f"Section '{section}' not found")
                return []
                
            else:
                # Disassemble from entry point
                entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
                base_addr = pe.OPTIONAL_HEADER.ImageBase + entry_point
                
                # Read code section
                code_section = None
                
                for sec in pe.sections:
                    sec_name = sec.Name.decode().strip()
                    if sec_name == '.text' or sec.Characteristics & 0x20000000:  # Execute flag
                        code_section = sec
                        break
                        
                if code_section:
                    data = code_section.get_data()
                    return self.disassemble(data, base_addr, max_instructions)
                    
            pe.close()
            
        except Exception as e:
            print(f"PE file disassembly error: {e}")
            
        return []
        
    def _disassemble_elf_file(self, file_path: str, section: str = None, offset: int = 0, 
                            length: int = None, max_instructions: int = None) -> List[Instruction]:
        """Disassemble ELF file sections"""
        try:
            from elftools.elf.elffile import ELFFile
            
            with open(file_path, 'rb') as f:
                elf = ELFFile(f)
                
                if section:
                    for sec in elf.iter_sections():
                        if sec.name == section:
                            data = sec.data()
                            base_addr = sec['sh_addr']
                            
                            return self.disassemble(data, base_addr, max_instructions)
                            
                    print(f"Section '{section}' not found")
                    return []
                    
                else:
                    # Disassemble from entry point
                    entry_point = elf['e_entry']
                   
                    for sec in elf.iter_sections():
                        if sec['sh_addr'] <= entry_point < sec['sh_addr'] + sec['sh_size']:
                            data = sec.data()
                            offset_within_section = entry_point - sec['sh_addr']
                            data_to_disassemble = data[offset_within_section:]
                            
                            return self.disassemble(data_to_disassemble, entry_point, max_instructions)
                            
        except Exception as e:
            print(f"ELF file disassembly error: {e}")
            
        return []
        
    def _disassemble_mach_o_file(self, file_path: str, section: str = None, offset: int = 0, 
                                length: int = None, max_instructions: int = None) -> List[Instruction]:
        """Disassemble Mach-O file sections"""
        try:
            binary = lief.parse(file_path)
            
            if binary:
                if section:
                    for sec in binary.sections:
                        if sec.name == section:
                            data = sec.content
                            base_addr = sec.virtual_address
                            
                            return self.disassemble(data, base_addr, max_instructions)
                            
                    print(f"Section '{section}' not found")
                    return []
                    
                else:
                    # Disassemble from entry point
                    entry_point = binary.header.entrypoint
                    
                    for sec in binary.sections:
                        if sec.virtual_address <= entry_point < sec.virtual_address + sec.size:
                            data = sec.content
                            offset_within_section = entry_point - sec.virtual_address
                            data_to_disassemble = data[offset_within_section:]
                            
                            return self.disassemble(data_to_disassemble, entry_point, max_instructions)
                            
        except Exception as e:
            print(f"Mach-O file disassembly error: {e}")
            
        return []
        
    def find_functions(self, instructions: List[Instruction]) -> List[Function]:
        """
        Detect functions in disassembled code
        
        Args:
            instructions: List of disassembled instructions
            
        Returns:
            List of Function objects
        """
        functions = []
        function_start = None
        
        for i, instr in enumerate(instructions):
            # Function detection heuristic - look for prologue patterns
            if self._is_function_prologue(instr):
                if function_start is not None:
                    # End previous function
                    function = Function(
                        address=function_start,
                        name=f"sub_{function_start:08x}",
                        instructions=instructions[function_start_idx:i],
                        calls=[],
                        references=[]
                    )
                    functions.append(function)
                    
                function_start = instr.address
                function_start_idx = i
                
            # Check for function calls
            if self._is_call_instruction(instr):
                # Extract call target
                call_target = self._extract_call_target(instr)
                if call_target and function_start:
                    functions[-1].calls.append(call_target)
                    
        # Add last function
        if function_start is not None:
            function = Function(
                address=function_start,
                name=f"sub_{function_start:08x}",
                instructions=instructions[function_start_idx:],
                calls=[],
                references=[]
            )
            functions.append(function)
            
        return functions
        
    def _is_function_prologue(self, instr: Instruction) -> bool:
        """Check if instruction is function prologue"""
        if self.arch in ['x86', 'x86_64']:
            return (instr.mnemonic == 'push' and instr.operands == 'rbp') or \
                   (instr.mnemonic == 'mov' and 'rbp' in instr.operands and 'rsp' in instr.operands)
                   
        elif self.arch == 'ARM':
            return (instr.mnemonic == 'push' and 'lr' in instr.operands) or \
                   (instr.mnemonic == 'stmdb' and 'sp!' in instr.operands)
                   
        elif self.arch == 'ARM64':
            return (instr.mnemonic == 'stp' and 'x29' in instr.operands and 'sp' in instr.operands)
                   
        return False
        
    def _is_call_instruction(self, instr: Instruction) -> bool:
        """Check if instruction is function call"""
        if self.arch in ['x86', 'x86_64']:
            return instr.mnemonic == 'call'
            
        elif self.arch == 'ARM':
            return instr.mnemonic in ['bl', 'bx']
            
        elif self.arch == 'ARM64':
            return instr.mnemonic == 'bl'
            
        return False
        
    def _extract_call_target(self, instr: Instruction) -> int:
        """Extract call target address from instruction"""
        if self.arch in ['x86', 'x86_64']:
            if instr.operands.startswith('0x'):
                return int(instr.operands, 16)
            elif '+' in instr.operands:
                parts = instr.operands.split('+')
                if len(parts) > 1 and parts[1].startswith('0x'):
                    return int(parts[1], 16)
                    
        return None
        
    def generate_control_flow_graph(self, instructions: List[Instruction]) -> Dict[int, List[int]]:
        """
        Generate control flow graph
        
        Args:
            instructions: List of disassembled instructions
            
        Returns:
            Control flow graph as dictionary of {source: [destinations]}
        """
        cfg = {}
        
        for i, instr in enumerate(instructions):
            src = instr.address
            
            if src not in cfg:
                cfg[src] = []
                
            # Check for control flow instructions
            if self._is_control_flow_instruction(instr):
                targets = self._get_instruction_targets(instr, instructions, i)
                
                for target in targets:
                    cfg[src].append(target)
                    
            # Fallthrough
            if i + 1 < len(instructions):
                next_instr = instructions[i + 1]
                if self._is_fallthrough(instr):
                    cfg[src].append(next_instr.address)
                    
            cfg[src] = list(set(cfg[src]))
            
        return cfg
        
    def _is_control_flow_instruction(self, instr: Instruction) -> bool:
        """Check if instruction affects control flow"""
        if self.arch in ['x86', 'x86_64']:
            return instr.mnemonic in ['jmp', 'je', 'jne', 'jl', 'jg', 'ja', 'jb', 'jbe', 'jae', 'jle', 'jge', 'call', 'ret']
            
        elif self.arch == 'ARM':
            return instr.mnemonic in ['b', 'bl', 'bx', 'beq', 'bne', 'blt', 'bgt', 'ble', 'bge']
            
        elif self.arch == 'ARM64':
            return instr.mnemonic in ['b', 'bl', 'cbz', 'cbnz', 'tbz', 'tbnz']
            
        return False
        
    def _get_instruction_targets(self, instr: Instruction, instructions: List[Instruction], index: int) -> List[int]:
        """Get instruction targets from control flow instruction"""
        targets = []
        
        if self._is_call_instruction(instr):
            target = self._extract_call_target(instr)
            if target:
                targets.append(target)
                
        elif self._is_unconditional_jump(instr):
            if instr.operands.startswith('0x'):
                targets.append(int(instr.operands, 16))
            elif self._is_relative_jump(instr):
                # Calculate absolute address from relative offset
                pass
                
        elif self._is_conditional_jump(instr):
            if instr.operands.startswith('0x'):
                targets.append(int(instr.operands, 16))
                
        elif self._is_return(instr):
            # Return instructions have no targets
            pass
            
        return targets
        
    def _is_unconditional_jump(self, instr: Instruction) -> bool:
        if self.arch in ['x86', 'x86_64']:
            return instr.mnemonic == 'jmp'
            
        elif self.arch in ['ARM', 'ARM64']:
            return instr.mnemonic == 'b'
            
        return False
        
    def _is_conditional_jump(self, instr: Instruction) -> bool:
        if self.arch in ['x86', 'x86_64']:
            return len(instr.mnemonic) > 1 and instr.mnemonic.startswith('j') and not self._is_unconditional_jump(instr)
            
        elif self.arch == 'ARM':
            return len(instr.mnemonic) > 1 and (instr.mnemonic.startswith('b') and instr.mnemonic[1] not in ['l', 'x'])
            
        elif self.arch == 'ARM64':
            return instr.mnemonic in ['cbz', 'cbnz', 'tbz', 'tbnz']
            
        return False
        
    def _is_return(self, instr: Instruction) -> bool:
        if self.arch in ['x86', 'x86_64']:
            return instr.mnemonic == 'ret'
            
        elif self.arch == 'ARM':
            return instr.mnemonic in ['bx', 'pop'] and 'pc' in instr.operands
            
        elif self.arch == 'ARM64':
            return instr.mnemonic in ['ret', 'bx']
            
        return False
        
    def _is_fallthrough(self, instr: Instruction) -> bool:
        return not self._is_unconditional_jump(instr) and not self._is_return(instr)
        
    def print_disassembly(self, instructions: List[Instruction], columns: int = 4):
        """Print disassembly to console with syntax highlighting"""
        print(f"{'='*60}")
        print(f"  DISASSEMBLY")
        print(f"{'='*60}")
        
        format_str = "{:08x}: {:16} {:10} {:20}"
        
        for i, instr in enumerate(instructions):
            hex_str = binascii.hexlify(instr.bytes).decode('utf-8')
            hex_str = ' '.join([hex_str[j:j+2] for j in range(0, len(hex_str), 2)])
            
            # Syntax highlighting
            mnemonic = instr.mnemonic
            if mnemonic in ['push', 'pop', 'call', 'ret']:
                mnemonic = f"\033[92m{mnemonic}\033[0m"
            elif mnemonic.startswith('j'):
                mnemonic = f"\033[93m{mnemonic}\033[0m"
            elif mnemonic in ['mov', 'add', 'sub', 'xor', 'and', 'or']:
                mnemonic = f"\033[96m{mnemonic}\033[0m"
                
            print(format_str.format(instr.address, hex_str.ljust(16), mnemonic, instr.operands))
            
            if (i + 1) % columns == 0:
                print()
                
        print()
        
    def generate_asm_file(self, instructions: List[Instruction], output_file: str):
        """Generate assembly file from disassembly"""
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(f"; Generated by Python Disassembler\n")
                f.write(f"; Architecture: {self.arch}\n")
                f.write(f"; Instructions: {len(instructions)}\n\n")
                
                for instr in instructions:
                    hex_str = binascii.hexlify(instr.bytes).decode('utf-8')
                    hex_str = ' '.join([hex_str[j:j+2] for j in range(0, len(hex_str), 2)])
                    
                    f.write(f"{instr.address:08x}: {hex_str.ljust(16)} {instr.mnemonic:10} {instr.operands}\n")
                    
            print(f"Assembly file saved to: {output_file}")
            
        except Exception as e:
            print(f"Error saving assembly file: {e}")
            
    def analyze_function_calls(self, functions: List[Function]) -> Dict[int, List[int]]:
        """Analyze function call graph"""
        call_graph = {}
        
        for function in functions:
            if function.address not in call_graph:
                call_graph[function.address] = []
                
            for call_target in function.calls:
                if call_target not in call_graph[function.address]:
                    call_graph[function.address].append(call_target)
                    
                if call_target not in call_graph:
                    call_graph[call_target] = []
                    
        return call_graph

def demo_disassembler():
    """Demonstrate disassembler functionality"""
    print(f"{'='*60}")
    print(f"  DISASSEMBLER DEMONSTRATION")
    print(f"{'='*60}")
    
    # Test 1: Disassemble simple shellcode
    print(f"\n1. Disassemble x86_64 Shellcode:")
    shellcode = b"\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x48\x31\xc9\xb0\x02\x0f\x05"
    
    disassembler = Disassembler('x86_64')
    instructions = disassembler.disassemble(shellcode, 0x401000)
    
    disassembler.print_disassembly(instructions, 2)
    
    # Test 2: Function detection
    print(f"\n2. Function Detection:")
    functions = disassembler.find_functions(instructions)
    print(f"Found {len(functions)} functions")
    
    for function in functions:
        print(f"Function {function.name} at 0x{function.address:08x}")
        print(f"  Instructions: {len(function.instructions)}")
        print(f"  Calls: {len(function.calls)}")
        
    # Test 3: Control flow graph
    print(f"\n3. Control Flow Graph:")
    cfg = disassembler.generate_control_flow_graph(instructions)
    print(f"Nodes: {len(cfg)}")
    print(f"Edges: {sum(len(edges) for edges in cfg.values())}")
    
    for src, dests in cfg.items():
        print(f"0x{src:08x} -> {[f'0x{dest:08x}' for dest in dests]}")
        
    # Test 4: Generate assembly file
    disassembler.generate_asm_file(instructions, 'disassembly.asm')
    
    return True

def main():
    """Main function to demonstrate disassembly"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Disassembler - Disassemble binary files"
    )
    
    parser.add_argument(
        "file_path",
        help="Path to binary file to disassemble"
    )
    
    parser.add_argument(
        "-a", "--arch",
        choices=['x86', 'x86_64', 'ARM', 'ARM64'],
        default='x86_64',
        help="Target architecture (default: x86_64)"
    )
    
    parser.add_argument(
        "-s", "--section",
        help="Section to disassemble"
    )
    
    parser.add_argument(
        "-o", "--offset",
        type=int,
        default=0,
        help="Offset within file"
    )
    
    parser.add_argument(
        "-l", "--length",
        type=int,
        help="Length of data to disassemble"
    )
    
    parser.add_argument(
        "-i", "--instructions",
        type=int,
        help="Maximum number of instructions to disassemble"
    )
    
    parser.add_argument(
        "-c", "--columns",
        type=int,
        default=4,
        help="Number of columns per line"
    )
    
    parser.add_argument(
        "-A", "--asm-file",
        help="Output assembly file"
    )
    
    parser.add_argument(
        "-d", "--demo",
        action="store_true",
        help="Run demonstration"
    )
    
    args = parser.parse_args()
    
    if args.demo:
        demo_disassembler()
        return
    
    if not os.path.exists(args.file_path):
        print(f"Error: File not found - {args.file_path}")
        return
    
    disassembler = Disassembler(args.arch)
    
    try:
        print(f"Disassembling file: {args.file_path}")
        
        instructions = disassembler.disassemble_file(
            args.file_path,
            args.section,
            args.offset,
            args.length,
            args.instructions
        )
        
        print(f"Disassembled {len(instructions)} instructions")
        
        disassembler.print_disassembly(instructions, args.columns)
        
        if args.asm_file:
            disassembler.generate_asm_file(instructions, args.asm_file)
            
        # Function detection
        functions = disassembler.find_functions(instructions)
        print(f"\nFound {len(functions)} functions")
        
        for function in functions:
            print(f"Function {function.name} at 0x{function.address:08x}")
            print(f"  Instructions: {len(function.instructions)}")
            print(f"  Calls: {len(function.calls)}")
            
        # Control flow graph
        cfg = disassembler.generate_control_flow_graph(instructions)
        print(f"\nControl Flow Graph: {len(cfg)} nodes, {sum(len(edges) for edges in cfg.values())} edges")
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        print(traceback.format_exc())

if __name__ == "__main__":
    main()
