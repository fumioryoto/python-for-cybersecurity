#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
YARA Rule Development in Python for Cybersecurity
This script implements YARA rule creation and scanning:
- YARA rule language basics
- Rule compilation and validation
- File and memory scanning
- YARA rule development best practices
- Integration with malware analysis
Perfect for beginners!
"""

import os
import sys
import time
import yara
import magic
import pefile
import lief
import hashlib
import requests
import json
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass
from enum import Enum

class DetectionType(Enum):
    """Detection type enumeration"""
    STRING = 0
    BYTE = 1
    REGEX = 2
    META = 3

@dataclass
class DetectionSignature:
    """Detection signature structure"""
    signature_type: DetectionType
    value: str
    name: str
    description: str
    offset: int = 0
    size: int = 0

@dataclass
class YARARule:
    """YARA rule structure"""
    name: str
    description: str
    author: str
    version: str
    references: List[str]
    tags: List[str]
    strings: Dict[str, Any]
    conditions: str
    metadata: Dict[str, Any]
    detections: List[DetectionSignature]

class YARARuleManager:
    """Class for managing YARA rules"""
    
    def __init__(self):
        """Initialize rule manager"""
        self.rules: Dict[str, YARARule] = {}
        self.compiled_rules = None
        
    def create_rule(self, name: str, description: str, author: str = None,
                   version: str = '1.0', tags: List[str] = None) -> YARARule:
        """
        Create new YARA rule
        
        Args:
            name: Rule name
            description: Rule description
            author: Rule author
            version: Rule version
            tags: Rule tags
            
        Returns:
            New YARARule object
        """
        rule = YARARule(
            name=name,
            description=description,
            author=author or 'Unknown',
            version=version,
            references=[],
            tags=tags or [],
            strings={},
            conditions='',
            metadata={},
            detections=[]
        )
        
        self.rules[name] = rule
        return rule
        
    def add_string_signature(self, rule: YARARule, signature: str, name: str,
                           case_sensitive: bool = False, ascii: bool = True) -> str:
        """
        Add string signature to rule
        
        Args:
            rule: YARARule object
            signature: String signature
            name: Signature name
            case_sensitive: Case sensitivity flag
            ascii: ASCII encoding flag
            
        Returns:
            Signature identifier
        """
        identifier = f'$s{len(rule.strings) + 1}'
        
        modifiers = []
        if case_sensitive:
            modifiers.append('ascii')
        else:
            modifiers.append('nocase')
            
        if ascii:
            modifiers.append('ascii')
        else:
            modifiers.append('wide')
            
        rule.strings[identifier] = (f'"{signature}"', ' '.join(modifiers))
        
        rule.detections.append(DetectionSignature(
            signature_type=DetectionType.STRING,
            value=signature,
            name=name,
            description=f"String signature {name}"
        ))
        
        return identifier
        
    def add_byte_signature(self, rule: YARARule, signature: str, name: str,
                          offset: int = None) -> str:
        """
        Add byte signature to rule
        
        Args:
            rule: YARARule object
            signature: Byte signature (hex string)
            name: Signature name
            offset: Offset from beginning of file
            
        Returns:
            Signature identifier
        """
        identifier = f'$b{len(rule.strings) + 1}'
        
        rule.strings[identifier] = (f'{{ {signature} }}',)
        
        rule.detections.append(DetectionSignature(
            signature_type=DetectionType.BYTE,
            value=signature,
            name=name,
            description=f"Byte signature {name}"
        ))
        
        return identifier
        
    def add_regex_signature(self, rule: YARARule, pattern: str, name: str) -> str:
        """
        Add regex signature to rule
        
        Args:
            rule: YARARule object
            pattern: Regular expression pattern
            name: Signature name
            
        Returns:
            Signature identifier
        """
        identifier = f'$r{len(rule.strings) + 1}'
        
        rule.strings[identifier] = (f'/{pattern}/', 'ascii')
        
        rule.detections.append(DetectionSignature(
            signature_type=DetectionType.REGEX,
            value=pattern,
            name=name,
            description=f"Regex signature {name}"
        ))
        
        return identifier
        
    def set_condition(self, rule: YARARule, condition: str):
        """
        Set rule condition
        
        Args:
            rule: YARARule object
            condition: Condition expression
        """
        rule.conditions = condition
        
    def add_metadata(self, rule: YARARule, key: str, value: str):
        """
        Add metadata to rule
        
        Args:
            rule: YARARule object
            key: Metadata key
            value: Metadata value
        """
        rule.metadata[key] = value
        
    def add_reference(self, rule: YARARule, reference: str):
        """
        Add reference to rule
        
        Args:
            rule: YARARule object
            reference: Reference URL or description
        """
        rule.references.append(reference)
        
    def compile_rules(self) -> yara.Rules:
        """Compile all rules"""
        try:
            rule_sources = []
            
            for rule in self.rules.values():
                rule_sources.append(self._generate_rule_source(rule))
                
            self.compiled_rules = yara.compile(source='\n'.join(rule_sources))
            
            return self.compiled_rules
            
        except Exception as e:
            print(f"Error compiling rules: {e}")
            return None
            
    def _generate_rule_source(self, rule: YARARule) -> str:
        """Generate YARA rule source from YARARule object"""
        source = f'rule {rule.name} {{\n'
        
        if rule.tags:
            source += f'  tags = [{", ".join([f"\'{tag}\'" for tag in rule.tags])}]\n'
            
        if rule.description:
            source += f'  description = "{rule.description}"\n'
            
        if rule.author:
            source += f'  author = "{rule.author}"\n'
            
        if rule.version:
            source += f'  version = "{rule.version}"\n'
            
        if rule.references:
            refs = ", ".join([f"\'{ref}\'" for ref in rule.references])
            source += f'  references = [{refs}]\n'
            
        if rule.metadata:
            for key, value in rule.metadata.items():
                source += f'  {key} = "{value}"\n'
            
        if rule.strings:
            source += '  strings:\n'
            for identifier, string in rule.strings.items():
                if isinstance(string, tuple) and len(string) > 1:
                    source += f'    {identifier} = {string[0]} {string[1]}\n'
                else:
                    source += f'    {identifier} = {string}\n'
                    
        if rule.conditions:
            source += f'  condition:\n    {rule.conditions}\n'
            
        source += '}\n'
        
        return source
        
    def scan_file(self, file_path: str, fast: bool = True) -> List[Dict[str, Any]]:
        """
        Scan file with YARA rules
        
        Args:
            file_path: File to scan
            fast: Use fast scan method
            
        Returns:
            List of matches
        """
        if self.compiled_rules is None:
            print("Rules not compiled")
            return []
            
        try:
            matches = self.compiled_rules.match(file_path, fast=fast)
            
            results = []
            
            for match in matches:
                result = {
                    'rule': match.rule,
                    'tags': match.tags,
                    'strings': [],
                    'meta': match.meta
                }
                
                for string in match.strings:
                    identifier = string[0]
                    offset = string[1]
                    data = string[2]
                    
                    try:
                        data_str = data.decode('utf-8')
                    except:
                        data_str = repr(data)
                        
                    result['strings'].append({
                        'identifier': identifier,
                        'offset': offset,
                        'data': data_str
                    })
                    
                results.append(result)
                
            return results
            
        except Exception as e:
            print(f"Error scanning file {file_path}: {e}")
            return []
            
    def scan_directory(self, directory: str, recursive: bool = True,
                     extensions: List[str] = None) -> Dict[str, List[Dict[str, Any]]]:
        """
        Scan directory with YARA rules
        
        Args:
            directory: Directory to scan
            recursive: Scan recursively
            extensions: File extensions to scan
            
        Returns:
            Dictionary of matches per file
        """
        results = {}
        
        for root, dirs, files in os.walk(directory):
            for file in files:
                if extensions and not any(file.lower().endswith(ext) for ext in extensions):
                    continue
                    
                file_path = os.path.join(root, file)
                
                try:
                    matches = self.scan_file(file_path)
                    
                    if matches:
                        results[file_path] = matches
                        
                except Exception as e:
                    print(f"Error scanning {file_path}: {e}")
                    
            if not recursive:
                break
                
        return results
        
    def validate_rule(self, rule_source: str) -> Tuple[bool, List[str]]:
        """
        Validate YARA rule
        
        Args:
            rule_source: Rule source to validate
            
        Returns:
            Tuple of success and error messages
        """
        errors = []
        
        try:
            yara.compile(source=rule_source)
            return True, []
            
        except Exception as e:
            errors.append(str(e))
            
            return False, errors
            
    def load_rules_from_file(self, file_path: str) -> List[YARARule]:
        """
        Load rules from YARA file
        
        Args:
            file_path: YARA file path
            
        Returns:
            List of YARARule objects
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            compiled_rules = yara.compile(source=content)
            
            rules = []
            
            for rule in compiled_rules.rules:
                yararule = YARARule(
                    name=rule.identifier,
                    description='',
                    author='',
                    version='1.0',
                    references=[],
                    tags=[],
                    strings={},
                    conditions='',
                    metadata={},
                    detections=[]
                )
                
                if hasattr(rule, 'tags'):
                    yararule.tags = rule.tags
                    
                if hasattr(rule, 'meta'):
                    for key, value in rule.meta.items():
                        if key == 'description':
                            yararule.description = value
                        elif key == 'author':
                            yararule.author = value
                        elif key == 'version':
                            yararule.version = value
                        elif key == 'references':
                            yararule.references = value
                        else:
                            yararule.metadata[key] = value
                            
                if hasattr(rule, 'strings'):
                    for string in rule.strings:
                        yararule.strings[string[0]] = string[1]
                        
                if hasattr(rule, 'condition'):
                    yararule.conditions = rule.condition
                    
                rules.append(yararule)
                
            return rules
            
        except Exception as e:
            print(f"Error loading rules from file: {e}")
            return []
            
    def save_rules_to_file(self, file_path: str, rules: List[YARARule] = None):
        """
        Save rules to YARA file
        
        Args:
            file_path: Output file path
            rules: Specific rules to save
        """
        if rules is None:
            rules = list(self.rules.values())
            
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                for rule in rules:
                    f.write(self._generate_rule_source(rule))
                    f.write('\n')
                    
            print(f"Rules saved to {file_path}")
            
        except Exception as e:
            print(f"Error saving rules to file: {e}")
            
    def export_rules_to_json(self, file_path: str, rules: List[YARARule] = None):
        """
        Export rules to JSON
        
        Args:
            file_path: Output file path
            rules: Specific rules to export
        """
        if rules is None:
            rules = list(self.rules.values())
            
        rule_data = []
        
        for rule in rules:
            rule_info = {
                'name': rule.name,
                'description': rule.description,
                'author': rule.author,
                'version': rule.version,
                'references': rule.references,
                'tags': rule.tags,
                'strings': list(rule.strings.items()),
                'conditions': rule.conditions,
                'metadata': rule.metadata,
                'detections': [
                    {
                        'signature_type': d.signature_type.value,
                        'value': d.value,
                        'name': d.name,
                        'description': d.description,
                        'offset': d.offset,
                        'size': d.size
                    }
                    for d in rule.detections
                ]
            }
            
            rule_data.append(rule_info)
            
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(rule_data, f, indent=2, default=str)
                
            print(f"Rules exported to {file_path}")
            
        except Exception as e:
            print(f"Error exporting rules to JSON: {e}")

class YARAGenerator:
    """Class for generating common YARA rules"""
    
    def __init__(self, manager: YARARuleManager):
        """
        Initialize rule generator
        
        Args:
            manager: YARARuleManager instance
        """
        self.manager = manager
        
    def generate_malware_rule(self, malware_name: str, strings: List[str],
                            file_types: List[str], author: str = None,
                            tags: List[str] = None) -> YARARule:
        """
        Generate malware rule
        
        Args:
            malware_name: Malware name
            strings: List of string signatures
            file_types: Target file types
            author: Rule author
            tags: Rule tags
            
        Returns:
            Generated YARARule object
        """
        rule_name = f"malware_{malware_name.lower().replace(' ', '_')}"
        description = f"Detects {malware_name} malware"
        
        rule = self.manager.create_rule(
            name=rule_name,
            description=description,
            author=author,
            tags=tags
        )
        
        # Add string signatures
        for i, string in enumerate(strings):
            self.manager.add_string_signature(
                rule,
                string,
                f"signature_{i+1}",
                case_sensitive=False
            )
            
        # Add file type conditions
        if file_types:
            conditions = []
            
            for file_type in file_types:
                if file_type.lower() == 'pe':
                    conditions.append("pe.is_dll or pe.is_exe")
                elif file_type.lower() == 'elf':
                    conditions.append("elf.e_machine == ELF.EM_X86_64")
                elif file_type.lower() == 'pdf':
                    conditions.append("uint32(0) == 0x25504446")
                    
            if conditions:
                rule.conditions = f"any of them and ({' or '.join(conditions)})"
            else:
                rule.conditions = "any of them"
        else:
            rule.conditions = "any of them"
            
        return rule
        
    def generate_packer_rule(self, packer_name: str, signatures: List[str],
                          author: str = None) -> YARARule:
        """
        Generate packer rule
        
        Args:
            packer_name: Packer name
            signatures: Packer signatures
            author: Rule author
            
        Returns:
            Generated YARARule object
        """
        rule_name = f"packer_{packer_name.lower().replace(' ', '_')}"
        description = f"Detects {packer_name} packer"
        
        rule = self.manager.create_rule(
            name=rule_name,
            description=description,
            author=author,
            tags=['packer', 'compression']
        )
        
        for i, signature in enumerate(signatures):
            self.manager.add_string_signature(
                rule,
                signature,
                f"signature_{i+1}",
                case_sensitive=True
            )
            
        rule.conditions = "any of them"
        return rule
        
    def generate_exploit_rule(self, exploit_name: str, exploit_type: str,
                           signatures: List[str], author: str = None) -> YARARule:
        """
        Generate exploit rule
        
        Args:
            exploit_name: Exploit name
            exploit_type: Exploit type
            signatures: Exploit signatures
            author: Rule author
            
        Returns:
            Generated YARARule object
        """
        rule_name = f"exploit_{exploit_name.lower().replace(' ', '_')}"
        description = f"Detects {exploit_name} exploit"
        
        rule = self.manager.create_rule(
            name=rule_name,
            description=description,
            author=author,
            tags=['exploit', exploit_type.lower()]
        )
        
        for i, signature in enumerate(signatures):
            self.manager.add_string_signature(
                rule,
                signature,
                f"signature_{i+1}",
                case_sensitive=False
            )
            
        rule.conditions = "any of them"
        return rule
        
    def generate_vulnerability_rule(self, cve_id: str, description: str,
                                  signatures: List[str], author: str = None) -> YARARule:
        """
        Generate vulnerability rule
        
        Args:
            cve_id: CVE identifier
            description: Vulnerability description
            signatures: Vulnerability signatures
            author: Rule author
            
        Returns:
            Generated YARARule object
        """
        rule_name = f"cve_{cve_id.lower().replace('-', '_')}"
        description = f"Detects {description} (CVE-{cve_id})"
        
        rule = self.manager.create_rule(
            name=rule_name,
            description=description,
            author=author,
            tags=['vulnerability', 'cve']
        )
        
        for i, signature in enumerate(signatures):
            self.manager.add_string_signature(
                rule,
                signature,
                f"signature_{i+1}",
                case_sensitive=True
            )
            
        rule.conditions = "any of them"
        self.manager.add_metadata(rule, 'cve_id', cve_id)
        
        return rule

def main():
    """Main function to demonstrate YARA rule functionality"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="YARA Rule Manager - Create and manage YARA rules"
    )
    
    parser.add_argument(
        "-c", "--create-rule",
        nargs=2,
        metavar=("RULE_NAME", "DESCRIPTION"),
        help="Create new rule with given name and description"
    )
    
    parser.add_argument(
        "-a", "--add-string",
        nargs=3,
        metavar=("RULE_NAME", "STRING", "NAME"),
        help="Add string signature to rule"
    )
    
    parser.add_argument(
        "-b", "--add-byte",
        nargs=3,
        metavar=("RULE_NAME", "BYTE", "NAME"),
        help="Add byte signature to rule"
    )
    
    parser.add_argument(
        "-r", "--add-regex",
        nargs=3,
        metavar=("RULE_NAME", "REGEX", "NAME"),
        help="Add regex signature to rule"
    )
    
    parser.add_argument(
        "-C", "--compile",
        action="store_true",
        help="Compile and validate rules"
    )
    
    parser.add_argument(
        "-s", "--scan",
        help="Scan file or directory with compiled rules"
    )
    
    parser.add_argument(
        "-d", "--directory",
        help="Scan directory recursively"
    )
    
    parser.add_argument(
        "-o", "--output",
        help="Output file for rule generation"
    )
    
    parser.add_argument(
        "-l", "--list",
        action="store_true",
        help="List all loaded rules"
    )
    
    parser.add_argument(
        "-g", "--generate",
        help="Generate rules from known patterns"
    )
    
    parser.add_argument(
        "-V", "--validate",
        help="Validate YARA rule file"
    )
    
    args = parser.parse_args()
    
    manager = YARARuleManager()
    generator = YARAGenerator(manager)
    
    try:
        if args.create_rule:
            rule = manager.create_rule(
                name=args.create_rule[0],
                description=args.create_rule[1],
                author="Your Name",
                tags=["test"]
            )
            print(f"Rule '{rule.name}' created successfully")
            
        if args.add_string and len(args.add_string) >= 3:
            if args.add_string[0] not in manager.rules:
                print(f"Rule '{args.add_string[0]}' not found")
            else:
                rule = manager.rules[args.add_string[0]]
                manager.add_string_signature(
                    rule,
                    args.add_string[1],
                    args.add_string[2],
                    case_sensitive=False
                )
                print(f"String signature added to rule '{rule.name}'")
                
        if args.add_byte and len(args.add_byte) >= 3:
            if args.add_byte[0] not in manager.rules:
                print(f"Rule '{args.add_byte[0]}' not found")
            else:
                rule = manager.rules[args.add_byte[0]]
                manager.add_byte_signature(
                    rule,
                    args.add_byte[1],
                    args.add_byte[2]
                )
                print(f"Byte signature added to rule '{rule.name}'")
                
        if args.add_regex and len(args.add_regex) >= 3:
            if args.add_regex[0] not in manager.rules:
                print(f"Rule '{args.add_regex[0]}' not found")
            else:
                rule = manager.rules[args.add_regex[0]]
                manager.add_regex_signature(
                    rule,
                    args.add_regex[1],
                    args.add_regex[2]
                )
                print(f"Regex signature added to rule '{rule.name}'")
                
        if args.compile:
            if manager.compile_rules():
                print("Rules compiled successfully")
            else:
                print("Failed to compile rules")
                
        if args.scan:
            if manager.compiled_rules is None:
                print("Rules not compiled")
            else:
                matches = manager.scan_file(args.scan)
                if matches:
                    print(f"{'='*60}")
                    print(f"  DETECTIONS in {args.scan}")
                    print(f"{'='*60}")
                    
                    for match in matches:
                        print(f"\nRule: {match['rule']}")
                        print(f"Tags: {', '.join(match['tags'])}")
                        
                        for string in match['strings']:
                            print(f"String: {string['identifier']}")
                            print(f"Offset: 0x{string['offset']:08x}")
                            print(f"Data: {string['data']}")
                else:
                    print("No detections found")
                    
        if args.directory:
            if manager.compiled_rules is None:
                print("Rules not compiled")
            else:
                results = manager.scan_directory(args.directory, recursive=True)
                
                if results:
                    print(f"{'='*60}")
                    print(f"  SCAN RESULTS")
                    print(f"{'='*60}")
                    
                    for file_path, matches in results.items():
                        print(f"\nFile: {file_path}")
                        
                        for match in matches:
                            print(f"Rule: {match['rule']}")
                            print(f"Tags: {', '.join(match['tags'])}")
                else:
                    print("No detections found")
                    
        if args.list:
            print(f"{'='*60}")
            print(f"  LOADED RULES ({len(manager.rules)})")
            print(f"{'='*60}")
            
            for name, rule in manager.rules.items():
                print(f"\nRule: {rule.name}")
                print(f"Description: {rule.description}")
                print(f"Author: {rule.author}")
                print(f"Version: {rule.version}")
                print(f"Tags: {', '.join(rule.tags)}")
                print(f"Strings: {len(rule.strings)}")
                print(f"Detections: {len(rule.detections)}")
                
                if rule.references:
                    print(f"References: {', '.join(rule.references)}")
                    
        if args.generate:
            print(f"Generating rules for {args.generate}...")
            
            if args.generate == "packers":
                generator.generate_packer_rule(
                    "UPX",
                    ["UPX!", "UPX0", "UPX1"],
                    "Your Name"
                )
                
                generator.generate_packer_rule(
                    "ASPack",
                    ["ASPACK"],
                    "Your Name"
                )
                
                generator.generate_packer_rule(
                    "VMProtect",
                    ["VMProtect"],
                    "Your Name"
                )
                
            elif args.generate == "malware":
                generator.generate_malware_rule(
                    "Ransomware",
                    ["ransom", "encrypt", "decrypt", "C2", "botnet"],
                    ["PE", "ELF"],
                    "Your Name",
                    ["malware", "ransomware"]
                )
                
            print(f"Rules generated successfully")
            
        if args.validate:
            with open(args.validate, 'r', encoding='utf-8') as f:
                rule_content = f.read()
                
            valid, errors = manager.validate_rule(rule_content)
            
            if valid:
                print("Rule is valid")
            else:
                print(f"Rule is invalid:")
                for error in errors:
                    print(f"  {error}")
                    
        if args.output:
            manager.save_rules_to_file(args.output)
            
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        print(traceback.format_exc())

if __name__ == "__main__":
    main()
