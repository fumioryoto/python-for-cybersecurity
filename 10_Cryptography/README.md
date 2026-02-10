# Cryptography Basics in Python

This folder contains Python implementations of fundamental cryptographic concepts and algorithms for cybersecurity professionals and students.

## What is Cryptography?

Cryptography is the practice and study of techniques for secure communication in the presence of third parties called adversaries. It involves:

- **Encryption**: Converting plaintext into ciphertext (unintelligible format)
- **Decryption**: Converting ciphertext back into plaintext
- **Hash Functions**: Creating fixed-size output from variable-size input (one-way function)
- **Digital Signatures**: Verifying authenticity and integrity of data
- **Key Exchange**: Securely exchanging cryptographic keys

## Topics Covered

### 1. Symmetric Encryption

- AES (Advanced Encryption Standard)
- DES (Data Encryption Standard) - Legacy, not recommended
- 3DES (Triple DES) - Legacy, not recommended
- ChaCha20-Poly1305

### 2. Asymmetric Encryption

- RSA (Rivest-Shamir-Adleman)
- ECC (Elliptic Curve Cryptography) - RSA alternative with smaller keys

### 3. Hash Functions

- MD5 - Legacy, not collision resistant
- SHA-1 - Legacy, not collision resistant
- SHA-256, SHA-384, SHA-512 (SHA-2 family)
- SHA3 (Keccak) - NIST standard from 2015
- BLAKE2 - Fast secure hash

### 4. Digital Signatures

- RSA signatures
- ECC signatures (ECDSA)
- EdDSA (Edwards-curve Digital Signature Algorithm)

### 5. Key Management

- Key generation
- Key exchange (Diffie-Hellman, ECDH)
- Key derivation (PBKDF2, scrypt, Argon2)
- Key storage and protection

### 6. Cryptographic Protocols

- TLS/SSL (Secure Socket Layer)
- SSH (Secure Shell)
- S/MIME (Secure/Multipurpose Internet Mail Extensions)
- PGP (Pretty Good Privacy)

## Prerequisites

To understand and implement cryptographic concepts, you should have:

1. Basic Python programming skills
2. Understanding of numbers and modular arithmetic
3. Knowledge of binary and hexadecimal representation
4. Familiarity with basic networking concepts

## Files in this Directory

### [01_symmetric_encryption.py](01_symmetric_encryption.py)

Implementations of symmetric encryption algorithms (AES, DES, 3DES) with block modes (ECB, CBC, CFB, OFB, CTR)

### [02_asymmetric_encryption.py](02_asymmetric_encryption.py)

Implementations of asymmetric encryption (RSA, ECC) and digital signatures

### [03_hash_functions.py](03_hash_functions.py)

Cryptographic hash functions (MD5, SHA-1, SHA-2, SHA-3, BLAKE2) and applications

### [04_key_management.py](04_key_management.py)

Key generation, exchange, derivation, and management

### [05_cryptographic_protocols.py](05_cryptographic_protocols.py)

Implementations of common cryptographic protocols (TLS, SSH, S/MIME)

### [06_elliptic_curves.py](06_elliptic_curves.py)

Elliptic Curve Cryptography (ECC) fundamentals and implementations

### [07_crypto_math.py](07_crypto_math.py)

Mathematical foundations of cryptography (modular arithmetic, finite fields, number theory)

### [08_cryptanalysis.py](08_cryptanalysis.py)

Basics of cryptanalysis and attacks on cryptographic systems

### [projects.md](projects.md)

Hands-on cryptography projects for practice

## Recommended Learning Path

1. **Math Foundations**: Learn modular arithmetic, number theory, finite fields
2. **Hash Functions**: Understand one-way functions and their properties
3. **Symmetric Encryption**: Master block ciphers and modes of operation
4. **Asymmetric Encryption**: Learn public-key cryptography and digital signatures
5. **Key Management**: Understand key generation, exchange, and protection
6. **Protocols**: Study TLS/SSL, SSH, and other cryptographic protocols
7. **Cryptanalysis**: Learn how cryptographic systems are attacked

## Tools for Cryptography

- **Crypto Libraries**: cryptography, pycryptodome, oscrypto
- **Key Management**: AWS KMS, HashiCorp Vault, GPG
- **Protocol Analyzers**: Wireshark, tcpdump
- **Code Analysis**: static analyzers, vulnerability scanners

## Resources for Further Learning

- **Books**:
  - "Applied Cryptography" by Bruce Schneier
  - "Cryptography Engineering" by Niels Ferguson, Bruce Schneier, Tadayoshi Kohno
  - "Understanding Cryptography" by Christof Paar and Jan Pelzl
- **Online Courses**:
  - Coursera: Cryptography I and Cryptography II (Stanford)
  - edX: Applied Cryptography (University of Maryland)
  - Khan Academy: Cryptography
- **Documentation**:
  - Python Cryptography Library: https://cryptography.io/en/latest/
  - NIST Cryptography Standards: https://csrc.nist.gov/publications
  - OWASP Cryptography Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cryptography_Cheat_Sheet.html

## Legal and Ethical Notes

**⚠️ IMPORTANT:** Cryptography is a powerful tool, but it must be used responsibly. In some countries, the use of strong cryptography may be restricted or regulated. Always ensure you comply with local laws and regulations.

## Getting Started

1. Install required packages:

   ```bash
   pip install cryptography
   pip install pycryptodome
   pip install python-gnupg
   ```

2. Explore the files in order of increasing complexity
3. Run the examples and modify them to understand behavior
4. Complete the projects in `projects.md` to apply your knowledge

Remember: The best way to learn cryptography is by doing. Start with simple examples and gradually tackle more complex algorithms and protocols.
