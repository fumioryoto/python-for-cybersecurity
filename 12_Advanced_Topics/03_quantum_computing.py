#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Quantum Computing for Cybersecurity in Python
This script implements quantum computing concepts and applications:
- Quantum gates and circuits
- Quantum algorithms (Deutsch-Jozsa, Shor's, Grover's)
- Quantum cryptography
- Post-quantum cryptography
- Quantum key distribution
- Quantum computing threats
Perfect for beginners!
"""

import os
import sys
import time
import random
import math
import numpy as np
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass
from enum import Enum

class QuantumGate(Enum):
    """Quantum gate enumeration"""
    HADAMARD = 0
    PAULI_X = 1
    PAULI_Y = 2
    PAULI_Z = 3
    CNOT = 4
    T = 5
    S = 6

@dataclass
class QuantumState:
    """Quantum state representation"""
    qubits: int
    amplitudes: np.ndarray

@dataclass
class QuantumGateOperation:
    """Quantum gate operation"""
    gate: QuantumGate
    qubits: List[int]

@dataclass
class QuantumCircuit:
    """Quantum circuit structure"""
    qubits: int
    gates: List[QuantumGateOperation]
    measurements: List[int]

class QuantumComputer:
    """Quantum computer simulator"""
    
    def __init__(self, qubits: int = 5):
        """
        Initialize quantum computer
        
        Args:
            qubits: Number of qubits
        """
        self.qubits = qubits
        self.state = QuantumState(
            qubits=qubits,
            amplitudes=np.zeros(2 ** qubits, dtype=np.complex128)
        )
        
        # Initialize to |000...0> state
        self.state.amplitudes[0] = 1.0
        
    def apply_gate(self, gate: QuantumGate, qubits: List[int]) -> bool:
        """
        Apply quantum gate to specified qubits
        
        Args:
            gate: Quantum gate to apply
            qubits: Target qubits
            
        Returns:
            True if operation successful, False otherwise
        """
        try:
            if gate == QuantumGate.HADAMARD:
                return self._apply_hadamard(qubits)
            elif gate == QuantumGate.PAULI_X:
                return self._apply_pauli_x(qubits)
            elif gate == QuantumGate.PAULI_Y:
                return self._apply_pauli_y(qubits)
            elif gate == QuantumGate.PAULI_Z:
                return self._apply_pauli_z(qubits)
            elif gate == QuantumGate.CNOT:
                return self._apply_cnot(qubits)
            elif gate == QuantumGate.T:
                return self._apply_t(qubits)
            elif gate == QuantumGate.S:
                return self._apply_s(qubits)
                
            return False
            
        except Exception as e:
            print(f"Error applying gate: {e}")
            return False
            
    def _apply_hadamard(self, qubits: List[int]) -> bool:
        """Apply Hadamard gate"""
        H = (1 / math.sqrt(2)) * np.array([[1, 1], [1, -1]])
        
        for qubit in qubits:
            self._apply_single_qubit_gate(H, qubit)
            
        return True
            
    def _apply_pauli_x(self, qubits: List[int]) -> bool:
        """Apply Pauli-X (NOT) gate"""
        X = np.array([[0, 1], [1, 0]])
        
        for qubit in qubits:
            self._apply_single_qubit_gate(X, qubit)
            
        return True
            
    def _apply_pauli_y(self, qubits: List[int]) -> bool:
        """Apply Pauli-Y gate"""
        Y = np.array([[0, -1j], [1j, 0]])
        
        for qubit in qubits:
            self._apply_single_qubit_gate(Y, qubit)
            
        return True
            
    def _apply_pauli_z(self, qubits: List[int]) -> bool:
        """Apply Pauli-Z gate"""
        Z = np.array([[1, 0], [0, -1]])
        
        for qubit in qubits:
            self._apply_single_qubit_gate(Z, qubit)
            
        return True
            
    def _apply_t(self, qubits: List[int]) -> bool:
        """Apply T gate"""
        T = np.array([[1, 0], [0, math.e ** (1j * math.pi / 4)]])
        
        for qubit in qubits:
            self._apply_single_qubit_gate(T, qubit)
            
        return True
            
    def _apply_s(self, qubits: List[int]) -> bool:
        """Apply S gate"""
        S = np.array([[1, 0], [0, 1j]])
        
        for qubit in qubits:
            self._apply_single_qubit_gate(S, qubit)
            
        return True
            
    def _apply_cnot(self, qubits: List[int]) -> bool:
        """Apply CNOT gate (control, target)"""
        if len(qubits) != 2:
            return False
            
        control, target = qubits
        
        # CNOT matrix in computational basis
        cnot = np.eye(2 ** self.qubits)
        
        for i in range(2 ** self.qubits):
            if (i >> control) & 1:  # Control qubit is 1
                target_mask = 1 << target
                j = i ^ target_mask
                cnot[i, i] = 0
                cnot[i, j] = 1
                
        self.state.amplitudes = np.dot(cnot, self.state.amplitudes)
        
        return True
            
    def _apply_single_qubit_gate(self, gate_matrix: np.ndarray, qubit: int):
        """Apply single qubit gate to state"""
        # Kronecker product to create multi-qubit gate
        gate = np.eye(1)
        
        for i in range(self.qubits):
            if i == qubit:
                gate = np.kron(gate, gate_matrix)
            else:
                gate = np.kron(gate, np.eye(2))
                
        self.state.amplitudes = np.dot(gate, self.state.amplitudes)
        
    def measure(self, qubits: List[int] = None) -> Tuple[List[int], float]:
        """
        Measure quantum state
        
        Args:
            qubits: Qubits to measure
            
        Returns:
            Tuple of (measurement_result, probability)
        """
        try:
            if qubits is None:
                qubits = list(range(self.qubits))
                
            # Calculate probabilities
            probabilities = np.abs(self.state.amplitudes) ** 2
            
            # Randomly select a result based on probabilities
            result = np.random.choice(len(probabilities), p=probabilities)
            
            # Convert to binary string with leading zeros
            bin_result = format(result, f'0{self.qubits}b')
            
            # Extract measured bits
            measurement = [int(bin_result[q]) for q in qubits]
            
            # Calculate probability of this measurement
            probability = probabilities[result]
            
            # Collapse state
            self._collapse_state(result)
            
            return measurement, probability
            
        except Exception as e:
            print(f"Error measuring: {e}")
            return [], 0.0
            
    def _collapse_state(self, result: int):
        """Collapse state to measurement result"""
        # Set all amplitudes to 0 except the measured state
        new_amplitudes = np.zeros_like(self.state.amplitudes)
        new_amplitudes[result] = 1.0
        self.state.amplitudes = new_amplitudes
        
    def run_circuit(self, circuit: QuantumCircuit) -> List[Tuple[List[int], float]]:
        """
        Run quantum circuit
        
        Args:
            circuit: QuantumCircuit to execute
            
        Returns:
            List of measurement results with probabilities
        """
        results = []
        
        for gate_op in circuit.gates:
            self.apply_gate(gate_op.gate, gate_op.qubits)
            
        for _ in range(10):  # Run 10 shots
            measurement, probability = self.measure(circuit.measurements)
            results.append((measurement, probability))
            
        return results
        
    def get_state_vector(self) -> np.ndarray:
        """
        Get current state vector
        
        Returns:
            State vector
        """
        return self.state.amplitudes
        
    def print_state(self):
        """Print current quantum state"""
        print(f"{'='*60}")
        print(f"  QUANTUM STATE")
        print(f"{'='*60}")
        
        for i, amp in enumerate(self.state.amplitudes):
            if amp != 0:
                state_str = format(i, f'0{self.qubits}b')
                probability = np.abs(amp) ** 2
                print(f"|{state_str}> : {amp:.3f} ({probability:.1%})")
                
    def reset(self):
        """Reset quantum computer to initial state"""
        self.state.amplitudes = np.zeros(2 ** self.qubits, dtype=np.complex128)
        self.state.amplitudes[0] = 1.0

class QuantumAlgorithm:
    """Collection of quantum algorithms"""
    
    @staticmethod
    def deutsch_jozsa(oracle: callable, qubits: int = 3) -> bool:
        """
        Deutsch-Jozsa algorithm for balanced vs constant functions
        
        Args:
            oracle: Quantum oracle function
            qubits: Number of qubits
            
        Returns:
            True if function is balanced, False if constant
        """
        qc = QuantumComputer(qubits)
        
        # Initialize state
        for i in range(qubits - 1):
            qc.apply_gate(QuantumGate.HADAMARD, [i])
            
        qc.apply_gate(QuantumGate.PAULI_X, [qubits - 1])
        qc.apply_gate(QuantumGate.HADAMARD, [qubits - 1])
        
        # Apply oracle
        oracle(qc)
        
        # Apply Hadamard gates again
        for i in range(qubits - 1):
            qc.apply_gate(QuantumGate.HADAMARD, [i])
            
        # Measure
        measurement, _ = qc.measure(list(range(qubits - 1)))
        
        # Check result
        return any(bit == 1 for bit in measurement)
        
    @staticmethod
    def grovers_algorithm(target_state: str, qubits: int = 4) -> Tuple[str, float]:
        """
        Grover's algorithm for search
        
        Args:
            target_state: Target state to find
            qubits: Number of qubits
            
        Returns:
            Tuple of (found_state, probability)
        """
        qc = QuantumComputer(qubits)
        
        # Initialize superposition
        for i in range(qubits):
            qc.apply_gate(QuantumGate.HADAMARD, [i])
            
        # Number of iterations
        iterations = int(math.sqrt(2 ** qubits) * math.pi / 4)
        
        for _ in range(iterations):
            # Oracle phase shift
            target_idx = int(target_state, 2)
            
            qc._apply_single_qubit_gate(np.array([[1, 0], [0, -1]]), 0)
            
            # Diffusion operator
            for i in range(qubits):
                qc.apply_gate(QuantumGate.HADAMARD, [i])
                
            for i in range(qubits):
                qc.apply_gate(QuantumGate.PAULI_X, [i])
                
            # Apply multi-CNOT gate
            for i in range(qubits - 1):
                qc.apply_gate(QuantumGate.CNOT, [i, qubits - 1])
                
            for i in range(qubits):
                qc.apply_gate(QuantumGate.PAULI_X, [i])
                
            for i in range(qubits):
                qc.apply_gate(QuantumGate.HADAMARD, [i])
                
        # Measure
        measurement, probability = qc.measure()
        
        found_state = ''.join(map(str, measurement))
        
        return found_state, probability
        
    @staticmethod
    def shors_algorithm(small_primes: bool = True) -> Tuple[int, int]:
        """
        Simplified version of Shor's algorithm for factoring
        
        Args:
            small_primes: Use small primes for demo
            
        Returns:
            Tuple of factors
        """
        if small_primes:
            # Demo with small number
            n = 15
            
            # Find random a coprime to n
            a = random.randint(2, n - 1)
            while math.gcd(a, n) != 1:
                a = random.randint(2, n - 1)
                
            # Find period r such that a^r ≡ 1 mod n
            r = 4  # Known period for demo
            
            if r % 2 == 0:
                factor1 = math.gcd(a^(r/2) - 1, n)
                factor2 = math.gcd(a^(r/2) + 1, n)
                
                if factor1 > 1 and factor2 > 1 and factor1 * factor2 == n:
                    return factor1, factor2
                    
        return None, None

class QuantumCryptography:
    """Quantum cryptography operations"""
    
    @staticmethod
    def quantum_key_distribution(num_bits: int = 128) -> Tuple[List[int], List[int]]:
        """
        Quantum Key Distribution (BB84 protocol)
        
        Args:
            num_bits: Number of bits to distribute
            
        Returns:
            Tuple of (alice_bits, bob_bits)
        """
        alice_bits = []
        bob_bits = []
        alice_bases = []
        bob_bases = []
        
        for _ in range(num_bits):
            # Alice sends qubits
            bit = random.randint(0, 1)
            base = random.randint(0, 1)
            
            alice_bits.append(bit)
            alice_bases.append(base)
            
            # Bob measures
            measure_base = random.randint(0, 1)
            bob_bases.append(measure_base)
            
            # If bases match, get bit
            if base == measure_base:
                bob_bits.append(bit)
                
        return alice_bits, bob_bits
        
    @staticmethod
    def post_quantum_encrypt(plaintext: str, key: str) -> bytes:
        """
        Post-quantum encryption using NTRU lattice-based cryptography
        
        Args:
            plaintext: Text to encrypt
            key: Encryption key
            
        Returns:
            Encrypted bytes
        """
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import ntru
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.hkdf import HKDF
            
            # Generate NTRU keys (in real scenario, use proper key exchange)
            private_key = ntru.NTRUPrimeParameters.bits_2048.to_private_key()
            public_key = private_key.public_key()
            
            # Encrypt using hybrid encryption
            ciphertext = public_key.encrypt(
                plaintext.encode('utf-8'),
                ntru.NTRUEncryptionParameters.bits_2048
            )
            
            return ciphertext
            
        except Exception as e:
            print(f"Post-quantum encryption error: {e}")
            return b''
            
    @staticmethod
    def quantum_resistant_signature(data: bytes) -> Tuple[bytes, bytes]:
        """
        Quantum-resistant digital signature using Dilithium
        
        Args:
            data: Data to sign
            
        Returns:
            Tuple of (signature, public_key)
        """
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import dilithium
            
            # Generate Dilithium keys
            private_key = dilithium.DilithiumParameters.bytes_2048.to_private_key()
            public_key = private_key.public_key()
            
            # Sign data
            signature = private_key.sign(data)
            
            return signature, public_key
            
        except Exception as e:
            print(f"Quantum-resistant signature error: {e}")
            return b'', b''

class QuantumThreatSimulator:
    """Simulator for quantum computing threats to classical cryptography"""
    
    def __init__(self, threat_level: str = 'medium'):
        """
        Initialize threat simulator
        
        Args:
            threat_level: Threat severity level (low, medium, high)
        """
        self.threat_level = threat_level
        
    def simulate_shor_factoring(self, key_size: int) -> Tuple[float, bool]:
        """
        Simulate Shor's algorithm factoring time
        
        Args:
            key_size: RSA key size in bits
            
        Returns:
            Tuple of (time_in_seconds, successful)
        """
        try:
            # Simplified factoring time estimation
            if self.threat_level == 'low':
                time_scale = 1000000
            elif self.threat_level == 'medium':
                time_scale = 1000
            else:
                time_scale = 1
                
            time_sec = (key_size ** 3) * time_scale
            
            successful = time_sec < 31536000  # 1 year
            
            return time_sec, successful
            
        except Exception as e:
            print(f"Simulation error: {e}")
            return 0, False
            
    def estimate_security_level(self, algorithm: str) -> Tuple[int, str]:
        """
        Estimate post-quantum security level
        
        Args:
            algorithm: Cryptographic algorithm
            
        Returns:
            Tuple of (security_level, recommendation)
        """
        security_ratings = {
            'rsa-1024': (0, 'Compromised - Replace immediately'),
            'rsa-2048': (2, 'At risk in 10-20 years'),
            'rsa-4096': (4, 'Medium security'),
            'ntru': (8, 'High security'),
            'dilithium': (10, 'Excellent security'),
            'lattice': (9, 'High security'),
            'hash-based': (10, 'Excellent security')
        }
        
        return security_ratings.get(algorithm.lower(), (1, 'Unknown algorithm'))

def main():
    """Main function to demonstrate quantum computing concepts"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Quantum Computing for Cybersecurity - Demonstration of quantum concepts"
    )
    
    parser.add_argument(
        "-q", "--qubits",
        type=int,
        default=3,
        help="Number of qubits for quantum computer"
    )
    
    parser.add_argument(
        "-a", "--algorithm",
        choices=["deutsch-jozsa", "grovers", "shors", "bb84"],
        help="Quantum algorithm to demonstrate"
    )
    
    parser.add_argument(
        "-c", "--circuit",
        action="store_true",
        help="Show quantum circuit demo"
    )
    
    parser.add_argument(
        "-t", "--threat",
        type=int,
        metavar="KEY_SIZE",
        help="Simulate quantum threat to RSA key"
    )
    
    parser.add_argument(
        "-p", "--post-quantum",
        help="Demonstrate post-quantum encryption"
    )
    
    parser.add_argument(
        "-s", "--signature",
        help="Demonstrate quantum-resistant signatures"
    )
    
    args = parser.parse_args()
    
    try:
        if args.algorithm:
            if args.algorithm == "deutsch-jozsa":
                # Constant oracle (always returns 0)
                def constant_oracle(qc):
                    pass
                    
                # Balanced oracle (flips every qubit)
                def balanced_oracle(qc):
                    for i in range(qc.qubits - 1):
                        qc.apply_gate(QuantumGate.CNOT, [i, qc.qubits - 1])
                        
                print(f"{'='*60}")
                print(f"  DEUTSCH-JOZSA ALGORITHM")
                print(f"{'='*60}")
                
                result_constant = QuantumAlgorithm.deutsch_jozsa(constant_oracle)
                result_balanced = QuantumAlgorithm.deutsch_jozsa(balanced_oracle)
                
                print(f"Constant function: {result_constant}")
                print(f"Balanced function: {result_balanced}")
                print(f"{'='*60}")
                
            elif args.algorithm == "grovers":
                target_state = "1010"
                result, probability = QuantumAlgorithm.grovers_algorithm(target_state)
                
                print(f"{'='*60}")
                print(f"  GROVER'S ALGORITHM")
                print(f"{'='*60}")
                print(f"Target state: {target_state}")
                print(f"Found state: {result}")
                print(f"Probability: {probability:.1%}")
                
            elif args.algorithm == "shors":
                factor1, factor2 = QuantumAlgorithm.shors_algorithm()
                
                if factor1 and factor2:
                    print(f"{'='*60}")
                    print(f"  SHOR'S ALGORITHM")
                    print(f"{'='*60}")
                    print(f"Factors of 15: {factor1} and {factor2}")
                    
            elif args.algorithm == "bb84":
                alice_bits, bob_bits = QuantumCryptography.quantum_key_distribution()
                
                print(f"{'='*60}")
                print(f"  BB84 QUANTUM KEY DISTRIBUTION")
                print(f"{'='*60}")
                print(f"Alice's bits: {alice_bits}")
                print(f"Bob's bits: {bob_bits}")
                print(f"Bits matched: {len(bob_bits)}/{len(alice_bits)}")
                
        elif args.circuit:
            qc = QuantumComputer(args.qubits)
            
            print(f"{'='*60}")
            print(f"  QUANTUM COMPUTER DEMO")
            print(f"{'='*60}")
            print(f"Initial state:")
            qc.print_state()
            
            # Apply Hadamard gate to all qubits
            for i in range(qc.qubits):
                qc.apply_gate(QuantumGate.HADAMARD, [i])
                
            print(f"\nAfter Hadamard gates:")
            qc.print_state()
            
            # Measure
            measurement, probability = qc.measure()
            
            print(f"\nMeasurement: {''.join(map(str, measurement))}")
            print(f"Probability: {probability:.1%}")
            
        elif args.threat:
            simulator = QuantumThreatSimulator(threat_level='medium')
            time_sec, successful = simulator.simulate_shor_factoring(args.threat)
            
            print(f"{'='*60}")
            print(f"  QUANTUM THREAT SIMULATION")
            print(f"{'='*60}")
            print(f"RSA Key Size: {args.threat} bits")
            print(f"Estimated Factoring Time:")
            
            if time_sec < 60:
                print(f"{time_sec:.1f} seconds")
            elif time_sec < 3600:
                print(f"{time_sec/60:.1f} minutes")
            elif time_sec < 86400:
                print(f"{time_sec/3600:.1f} hours")
            elif time_sec < 31536000:
                print(f"{time_sec/86400:.1f} days")
            else:
                print(f"{time_sec/31536000:.1f} years")
                
            print(f"Attack Successful: {successful}")
            
        elif args.post_quantum:
            ciphertext = QuantumCryptography.post_quantum_encrypt(args.post_quantum, 'testkey')
            
            if ciphertext:
                print(f"{'='*60}")
                print(f"  POST-QUANTUM ENCRYPTION")
                print(f"{'='*60}")
                print(f"Plaintext: {args.post_quantum}")
                print(f"Ciphertext: {ciphertext.hex()}")
                
        elif args.signature:
            signature, public_key = QuantumCryptography.quantum_resistant_signature(args.signature.encode('utf-8'))
            
            if signature:
                print(f"{'='*60}")
                print(f"  QUANTUM-RESISTANT SIGNATURE")
                print(f"{'='*60}")
                print(f"Data to sign: {args.signature}")
                print(f"Signature: {signature.hex()}")
                
        else:
            parser.print_help()
            
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        print(traceback.format_exc())

if __name__ == "__main__":
    main()
