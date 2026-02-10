#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Debugging and Instrumentation in Python for Cybersecurity
This script implements debugging and instrumentation techniques:
- Runtime debugging using GDB and WinDbg
- Memory debugging and monitoring
- API hooking and interception
- Code injection techniques
- Runtime instrumentation
Perfect for beginners!
"""

import os
import sys
import time
import struct
import ctypes
import subprocess
import socket
import threading
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass

@dataclass
class Breakpoint:
    """Breakpoint information structure"""
    address: int
    original_bytes: bytes
    active: bool = True
    hit_count: int = 0

@dataclass
class MemoryRegion:
    """Memory region information structure"""
    address: int
    size: int
    permissions: str
    region_type: str
    state: str
    protection: str

@dataclass
class ProcessInfo:
    """Process information structure"""
    pid: int
    name: str
    path: str
    arguments: str
    parent_pid: int
    priority: int
    memory_info: Dict[str, int]
    cpu_usage: float

class Debugger:
    """Class for debugging operations"""
    
    def __init__(self, target: str = None):
        """
        Initialize debugger
        
        Args:
            target: Target process name or PID
        """
        self.target = target
        self.pid = None
        self.process_handle = None
        self.breakpoints: Dict[int, Breakpoint] = {}
        self.debug_events = []
        
        if sys.platform == 'win32':
            self._init_windows()
        elif sys.platform == 'linux':
            self._init_linux()
        else:
            raise NotImplementedError(f"Debugging not implemented for {sys.platform}")
            
    def _init_windows(self):
        """Initialize Windows debugging API"""
        import win32api
        import win32process
        import win32security
        import pywintypes
        
        self.win32api = win32api
        self.win32process = win32process
        self.win32security = win32security
        self.pywintypes = pywintypes
        
    def _init_linux(self):
        """Initialize Linux debugging API"""
        pass
        
    def attach(self, pid: int = None) -> bool:
        """
        Attach debugger to process
        
        Args:
            pid: Process ID to attach to
            
        Returns:
            True if attachment successful, False otherwise
        """
        if sys.platform == 'win32':
            return self._attach_windows(pid)
        elif sys.platform == 'linux':
            return self._attach_linux(pid)
        else:
            return False
            
    def _attach_windows(self, pid: int) -> bool:
        """Attach to Windows process"""
        try:
            import win32api
            import win32process
            import win32security
            
            # Open process with debugging privileges
            self.process_handle = win32api.OpenProcess(
                win32process.PROCESS_ALL_ACCESS,
                False,
                pid
            )
            
            self.pid = pid
            
            print(f"Successfully attached to process {pid}")
            return True
            
        except Exception as e:
            print(f"Failed to attach to process {pid}: {e}")
            return False
            
    def _attach_linux(self, pid: int) -> bool:
        """Attach to Linux process"""
        try:
            # Use ptrace to attach
            import ctypes
            libc = ctypes.CDLL('libc.so.6')
            
            # Send PTRACE_ATTACH signal
            libc.ptrace(16, pid, 0, 0)  # PTRACE_ATTACH
            
            # Wait for process to stop
            import os
            _, status = os.waitpid(pid, 0)
            
            self.pid = pid
            print(f"Successfully attached to process {pid}")
            return True
            
        except Exception as e:
            print(f"Failed to attach to process {pid}: {e}")
            return False
            
    def create_process(self, command: str) -> int:
        """
        Create new process and attach debugger
        
        Args:
            command: Command to execute
            
        Returns:
            Process ID of created process
        """
        if sys.platform == 'win32':
            return self._create_process_windows(command)
        elif sys.platform == 'linux':
            return self._create_process_linux(command)
        else:
            raise NotImplementedError
            
    def _create_process_windows(self, command: str) -> int:
        """Create process on Windows"""
        try:
            import win32api
            import win32process
            import win32security
            
            # Create process suspended
            startup_info = win32process.STARTUPINFO()
            process_info = win32process.CreateProcess(
                None,
                command,
                None,
                None,
                0,
                win32process.CREATE_NEW_CONSOLE | win32process.CREATE_SUSPENDED,
                None,
                None,
                startup_info
            )
            
            self.pid = process_info[2]
            self.process_handle = process_info[0]
            
            print(f"Created process {self.pid} with command: {command}")
            
            return self.pid
            
        except Exception as e:
            print(f"Failed to create process: {e}")
            return -1
            
    def _create_process_linux(self, command: str) -> int:
        """Create process on Linux"""
        try:
            # Use subprocess with preexec_fn to create process
            import subprocess
            
            process = subprocess.Popen(
                command,
                shell=True,
                preexec_fn=lambda: self._linux_child_callback(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            self.pid = process.pid
            print(f"Created process {self.pid} with command: {command}")
            
            return self.pid
            
        except Exception as e:
            print(f"Failed to create process: {e}")
            return -1
            
    def _linux_child_callback(self):
        """Callback function for Linux process creation"""
        import ctypes
        import signal
        
        libc = ctypes.CDLL('libc.so.6')
        
        # Stop child process to allow debugger to attach
        libc.ptrace(0, 0, 0, 0)  # PTRACE_TRACEME
        os.kill(os.getpid(), signal.SIGSTOP)
        
    def read_memory(self, address: int, size: int) -> bytes:
        """
        Read process memory
        
        Args:
            address: Memory address to read from
            size: Number of bytes to read
            
        Returns:
            Bytes read from memory
        """
        if sys.platform == 'win32':
            return self._read_memory_windows(address, size)
        elif sys.platform == 'linux':
            return self._read_memory_linux(address, size)
        else:
            raise NotImplementedError
            
    def _read_memory_windows(self, address: int, size: int) -> bytes:
        """Read memory on Windows"""
        try:
            import win32api
            import win32process
            
            buffer = win32process.ReadProcessMemory(
                self.process_handle,
                address,
                size
            )
            
            return buffer
            
        except Exception as e:
            print(f"Error reading memory: {e}")
            return b''
            
    def _read_memory_linux(self, address: int, size: int) -> bytes:
        """Read memory on Linux"""
        try:
            import ctypes
            import os
            
            libc = ctypes.CDLL('libc.so.6')
            
            # Use process_vm_readv for direct memory reading
            buf = ctypes.create_string_buffer(size)
            bytes_read = ctypes.c_size_t()
            
            ret = libc.process_vm_readv(
                self.pid,
                [(ctypes.c_ulonglong(address), ctypes.c_size_t(size))],
                1,
                [(ctypes.addressof(buf), ctypes.c_size_t(size))],
                1,
                0,
                ctypes.byref(bytes_read),
                None
            )
            
            if ret == 0:
                return buf.raw[:bytes_read.value]
            else:
                return b''
                
        except Exception as e:
            print(f"Error reading memory: {e}")
            return b''
            
    def write_memory(self, address: int, data: bytes) -> bool:
        """
        Write to process memory
        
        Args:
            address: Memory address to write to
            data: Bytes to write
            
        Returns:
            True if write successful, False otherwise
        """
        if sys.platform == 'win32':
            return self._write_memory_windows(address, data)
        elif sys.platform == 'linux':
            return self._write_memory_linux(address, data)
        else:
            raise NotImplementedError
            
    def _write_memory_windows(self, address: int, data: bytes) -> bool:
        """Write memory on Windows"""
        try:
            import win32api
            import win32process
            
            win32process.WriteProcessMemory(
                self.process_handle,
                address,
                data
            )
            
            return True
            
        except Exception as e:
            print(f"Error writing memory: {e}")
            return False
            
    def _write_memory_linux(self, address: int, data: bytes) -> bool:
        """Write memory on Linux"""
        try:
            import ctypes
            import os
            
            libc = ctypes.CDLL('libc.so.6')
            
            buf = ctypes.create_string_buffer(data)
            
            ret = libc.process_vm_writev(
                self.pid,
                [(ctypes.addressof(buf), ctypes.c_size_t(len(data)))],
                1,
                [(ctypes.c_ulonglong(address), ctypes.c_size_t(len(data)))],
                1,
                0,
                None,
                None
            )
            
            return ret == len(data)
            
        except Exception as e:
            print(f"Error writing memory: {e}")
            return False
            
    def set_breakpoint(self, address: int, size: int = 1) -> Breakpoint:
        """
        Set breakpoint at specified address
        
        Args:
            address: Memory address to break at
            size: Size of instruction to replace
            
        Returns:
            Breakpoint information object
        """
        if address in self.breakpoints:
            return self.breakpoints[address]
            
        try:
            original_bytes = self.read_memory(address, size)
            
            if not original_bytes:
                raise Exception(f"Could not read memory at 0x{address:08x}")
                
            # Replace with software breakpoint (int3 on x86/x64)
            breakpoint_byte = b'\xcc' * size  # 0xCC = INT3 instruction
            
            if not self.write_memory(address, breakpoint_byte):
                raise Exception(f"Could not write breakpoint")
                
            breakpoint = Breakpoint(
                address=address,
                original_bytes=original_bytes,
                active=True,
                hit_count=0
            )
            
            self.breakpoints[address] = breakpoint
            print(f"Breakpoint set at 0x{address:08x}")
            
            return breakpoint
            
        except Exception as e:
            print(f"Error setting breakpoint: {e}")
            return None
            
    def remove_breakpoint(self, address: int) -> bool:
        """
        Remove breakpoint
        
        Args:
            address: Address of breakpoint to remove
            
        Returns:
            True if removal successful
        """
        if address not in self.breakpoints:
            print("Breakpoint not found")
            return False
            
        try:
            breakpoint = self.breakpoints[address]
            
            if not self.write_memory(breakpoint.address, breakpoint.original_bytes):
                raise Exception(f"Could not restore original bytes")
                
            del self.breakpoints[address]
            print(f"Breakpoint removed at 0x{address:08x}")
            
            return True
            
        except Exception as e:
            print(f"Error removing breakpoint: {e}")
            return False
            
    def continue_process(self):
        """Continue process execution from breakpoint"""
        if sys.platform == 'win32':
            return self._continue_windows()
        elif sys.platform == 'linux':
            return self._continue_linux()
        else:
            raise NotImplementedError
            
    def _continue_windows(self):
        """Continue process on Windows"""
        try:
            import win32api
            import win32process
            
            win32process.ResumeThread(self.process_handle)
            
        except Exception as e:
            print(f"Error continuing process: {e}")
            
    def _continue_linux(self):
        """Continue process on Linux"""
        try:
            import ctypes
            import os
            
            libc = ctypes.CDLL('libc.so.6')
            libc.ptrace(7, self.pid, 0, 0)  # PTRACE_CONTINUE
            
        except Exception as e:
            print(f"Error continuing process: {e}")
            
    def single_step(self):
        """Single step execution"""
        if sys.platform == 'win32':
            return self._single_step_windows()
        elif sys.platform == 'linux':
            return self._single_step_linux()
        else:
            raise NotImplementedError
            
    def _single_step_windows(self):
        """Single step on Windows"""
        try:
            import win32api
            import win32process
            
            import ctypes
            import ctypes.wintypes
            
            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            
            context = ctypes.create_string_buffer(0x2c0)
            context[0:4] = struct.pack('i', 0x10000)  # CONTEXT_FULL
            
            res = kernel32.GetThreadContext(
                self.process_handle,
                ctypes.byref(context)
            )
            
            if res:
                # Set trace flag
                context[0x164:0x168] = struct.pack('i', 0x100)  # EFLAGS
                context[0x160:0x164] = struct.pack('i', context[0x160] | 0x100)  # Set TF flag
                
                kernel32.SetThreadContext(self.process_handle, ctypes.byref(context))
                
                kernel32.ResumeThread(self.process_handle)
                
        except Exception as e:
            print(f"Error single-stepping: {e}")
            
    def _single_step_linux(self):
        """Single step on Linux"""
        try:
            import ctypes
            import os
            
            libc = ctypes.CDLL('libc.so.6')
            libc.ptrace(9, self.pid, 0, 0)  # PTRACE_SINGLESTEP
            
        except Exception as e:
            print(f"Error single-stepping: {e}")
            
    def get_process_info(self) -> ProcessInfo:
        """Get process information"""
        if sys.platform == 'win32':
            return self._get_process_info_windows()
        elif sys.platform == 'linux':
            return self._get_process_info_linux()
        else:
            raise NotImplementedError
            
    def _get_process_info_windows(self) -> ProcessInfo:
        """Get process information on Windows"""
        try:
            import win32api
            import win32process
            
            import ctypes
            import ctypes.wintypes
            
            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            
            # Get process memory info
            class PROCESS_MEMORY_COUNTERS_EX(ctypes.Structure):
                _fields_ = [
                    ("cb", ctypes.c_ulong),
                    ("PageFaultCount", ctypes.c_ulong),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t),
                    ("PrivateUsage", ctypes.c_size_t),
                ]
                
            mem_counters = PROCESS_MEMORY_COUNTERS_EX()
            mem_counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS_EX)
            
            kernel32.GetProcessMemoryInfo(
                self.process_handle,
                ctypes.byref(mem_counters),
                mem_counters.cb
            )
            
            memory_info = {
                'WorkingSetSize': mem_counters.WorkingSetSize,
                'PrivateUsage': mem_counters.PrivateUsage,
                'PagefileUsage': mem_counters.PagefileUsage
            }
            
            # Get process basic info
            import psutil
            
            process = psutil.Process(self.pid)
            
            return ProcessInfo(
                pid=self.pid,
                name=process.name(),
                path=process.exe(),
                arguments=' '.join(process.cmdline()),
                parent_pid=process.ppid(),
                priority=process.nice(),
                memory_info=memory_info,
                cpu_usage=process.cpu_percent(interval=0.1)
            )
            
        except Exception as e:
            print(f"Error getting process info: {e}")
            return None
            
    def _get_process_info_linux(self) -> ProcessInfo:
        """Get process information on Linux"""
        try:
            import psutil
            
            process = psutil.Process(self.pid)
            
            memory_info = {
                'WorkingSetSize': process.memory_info().rss,
                'PrivateUsage': process.memory_info().vms,
                'PagefileUsage': process.memory_info().vms
            }
            
            return ProcessInfo(
                pid=self.pid,
                name=process.name(),
                path=process.exe(),
                arguments=' '.join(process.cmdline()),
                parent_pid=process.ppid(),
                priority=process.nice(),
                memory_info=memory_info,
                cpu_usage=process.cpu_percent(interval=0.1)
            )
            
        except Exception as e:
            print(f"Error getting process info: {e}")
            return None
            
    def enumerate_modules(self) -> List[Dict[str, Any]]:
        """Enumerate loaded modules"""
        if sys.platform == 'win32':
            return self._enumerate_modules_windows()
        elif sys.platform == 'linux':
            return self._enumerate_modules_linux()
        else:
            raise NotImplementedError
            
    def _enumerate_modules_windows(self) -> List[Dict[str, Any]]:
        """Enumerate modules on Windows"""
        try:
            import win32api
            import win32process
            import win32security
            import ctypes
            import ctypes.wintypes
            
            modules = []
            
            # Use CreateToolhelp32Snapshot to enumerate modules
            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            
            TH32CS_SNAPMODULE = 0x00000008
            hSnapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, self.pid)
            
            if hSnapshot != -1:
                class MODULEENTRY32(ctypes.Structure):
                    _fields_ = [
                        ("dwSize", ctypes.c_ulong),
                        ("th32ModuleID", ctypes.c_ulong),
                        ("th32ProcessID", ctypes.c_ulong),
                        ("GlblcntUsage", ctypes.c_ulong),
                        ("ProccntUsage", ctypes.c_ulong),
                        ("modBaseAddr", ctypes.c_ulonglong),
                        ("modBaseSize", ctypes.c_ulong),
                        ("hModule", ctypes.c_ulong),
                        ("szModule", ctypes.c_char * 256),
                        ("szExePath", ctypes.c_char * 260),
                    ]
                    
                module_entry = MODULEENTRY32()
                module_entry.dwSize = ctypes.sizeof(MODULEENTRY32)
                
                if kernel32.Module32First(hSnapshot, ctypes.byref(module_entry)):
                    while True:
                        modules.append({
                            'name': module_entry.szModule.decode(),
                            'base_address': module_entry.modBaseAddr,
                            'size': module_entry.modBaseSize,
                            'path': module_entry.szExePath.decode()
                        })
                        
                        if not kernel32.Module32Next(hSnapshot, ctypes.byref(module_entry)):
                            break
                            
                kernel32.CloseHandle(hSnapshot)
                
            return modules
            
        except Exception as e:
            print(f"Error enumerating modules: {e}")
            return []
            
    def _enumerate_modules_linux(self) -> List[Dict[str, Any]]:
        """Enumerate modules on Linux"""
        try:
            with open(f"/proc/{self.pid}/maps", 'r') as f:
                lines = f.readlines()
                
            modules = []
            
            for line in lines:
                parts = line.strip().split()
                
                if len(parts) > 5 and parts[5].startswith('[') and parts[5].endswith(']'):
                    continue
                    
                if len(parts) > 5:
                    modules.append({
                        'name': parts[5],
                        'base_address': int(parts[0].split('-')[0], 16),
                        'size': int(parts[0].split('-')[1], 16) - int(parts[0].split('-')[0], 16),
                        'path': parts[5]
                    })
                    
            return modules
            
        except Exception as e:
            print(f"Error enumerating modules: {e}")
            return []

def main():
    """Main function to demonstrate debugging"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Debugger - Runtime debugging and instrumentation"
    )
    
    parser.add_argument(
        "-a", "--attach",
        type=int,
        help="PID of process to attach to"
    )
    
    parser.add_argument(
        "-c", "--command",
        help="Command to execute and attach to"
    )
    
    parser.add_argument(
        "-r", "--read",
        type=int,
        help="Address to read memory from"
    )
    
    parser.add_argument(
        "-w", "--write",
        nargs=2,
        help="Address and hex data to write"
    )
    
    parser.add_argument(
        "-b", "--breakpoint",
        type=int,
        help="Address to set breakpoint"
    )
    
    parser.add_argument(
        "-i", "--info",
        action="store_true",
        help="Show process information"
    )
    
    parser.add_argument(
        "-m", "--modules",
        action="store_true",
        help="Show loaded modules"
    )
    
    args = parser.parse_args()
    
    # Create debugger instance
    debugger = None
    
    try:
        if args.attach:
            debugger = Debugger()
            debugger.attach(args.attach)
            
        elif args.command:
            debugger = Debugger()
            debugger.create_process(args.command)
            
        else:
            print("Error: Either -a/--attach or -c/--command must be specified")
            parser.print_help()
            return
            
        if args.info:
            info = debugger.get_process_info()
            if info:
                print(f"{'='*60}")
                print(f"  PROCESS INFORMATION")
                print(f"{'='*60}")
                print(f"PID: {info.pid}")
                print(f"Name: {info.name}")
                print(f"Path: {info.path}")
                print(f"Arguments: {info.arguments}")
                print(f"Parent PID: {info.parent_pid}")
                print(f"Priority: {info.priority}")
                print(f"CPU Usage: {info.cpu_usage:.1f}%")
                print(f"Memory Usage:")
                for key, value in info.memory_info.items():
                    print(f"  {key}: {value:,} bytes ({value/1024:.1f} KB)")
                    
        if args.modules:
            modules = debugger.enumerate_modules()
            print(f"\n{'='*60}")
            print(f"  LOADED MODULES ({len(modules)})")
            print(f"{'='*60}")
            
            for module in modules:
                print(f"  {module['name']}")
                print(f"    Base Address: 0x{module['base_address']:08x}")
                print(f"    Size: {module['size']:,} bytes")
                print(f"    Path: {module['path']}")
                print()
                
        if args.read:
            data = debugger.read_memory(args.read, 16)
            print(f"\n{'='*60}")
            print(f"  MEMORY READ (0x{args.read:08x})")
            print(f"{'='*60}")
            print(data.hex())
            
        if args.write:
            address = int(args.write[0], 16)
            data = bytes.fromhex(args.write[1])
            
            if debugger.write_memory(address, data):
                print(f"\n{'='*60}")
                print(f"  MEMORY WRITE (0x{address:08x})")
                print(f"{'='*60}")
                print(f"Successfully wrote {len(data)} bytes")
            else:
                print(f"Failed to write memory")
                
        if args.breakpoint:
            breakpoint = debugger.set_breakpoint(args.breakpoint)
            if breakpoint:
                print(f"\n{'='*60}")
                print(f"  BREAKPOINT SET")
                print(f"{'='*60}")
                print(f"Address: 0x{breakpoint.address:08x}")
                print(f"Original bytes: {breakpoint.original_bytes.hex()}")
                print(f"Active: {breakpoint.active}")
                
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        print(traceback.format_exc())
        
    finally:
        if debugger:
            pass  # Cleanup resources

if __name__ == "__main__":
    main()
