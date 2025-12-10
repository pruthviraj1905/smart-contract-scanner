#!/usr/bin/env python3
"""
Advanced Storage-Level Vulnerability Analysis Module
Detects uninitialized storage, storage collisions, and non-privileged storage exploits
"""

import requests
import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

class StorageVulnerabilityType(Enum):
    UNINITIALIZED_STORAGE = "Uninitialized Storage Slot"
    UNPROTECTED_STORAGE_WRITE = "Unprotected Storage Write"
    STORAGE_COLLISION = "Storage Layout Collision"
    CRITICAL_SLOT_EXPOSURE = "Critical Storage Slot Exposed"
    STORAGE_OVERWRITE = "Storage Slot Overwrite Vulnerability"
    DELEGATECALL_STORAGE_HIJACK = "Delegatecall Storage Hijacking"
    ARRAY_LENGTH_MANIPULATION = "Array Length Manipulation"
    MAPPING_KEY_COLLISION = "Mapping Key Collision"
    SLOT_PACKING_OVERFLOW = "Storage Slot Packing Overflow"

@dataclass
class StorageSlot:
    slot_number: int
    slot_hex: str
    value: str
    is_initialized: bool
    data_type: str
    variable_name: str = ""
    is_critical: bool = False
    is_writable: bool = True
    access_pattern: str = ""

@dataclass
class StorageVulnerability:
    vuln_type: StorageVulnerabilityType
    affected_slots: List[int]
    severity: str
    description: str
    exploit_path: str
    impact: str
    recommendation: str
    confidence: float
    proof_of_concept: str = ""

class StorageAnalyzer:
    def __init__(self, api_key: str = None, chain_config: Dict = None, api_free_fetcher=None):
        self.api_key = api_key
        self.api_free_fetcher = api_free_fetcher
        self.use_api_free = api_free_fetcher is not None

        self.chain_config = chain_config or {
            'chain_id': '1',
            'chain': 'ethereum',
            'name': 'Ethereum'
        }

        # Critical storage slots for common patterns
        self.CRITICAL_SLOTS = {
            0: "owner/admin address",
            1: "implementation address", 
            2: "pause state/emergency flag",
            3: "total supply/balance",
            4: "fee recipient",
            5: "treasury address"
        }
        
        # EIP-1967 proxy slots
        self.PROXY_SLOTS = {
            '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc': 'EIP-1967 Implementation',
            '0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103': 'EIP-1967 Admin',
            '0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50': 'EIP-1967 Beacon'
        }
        
        # Storage patterns for vulnerability detection
        self.STORAGE_PATTERNS = {
            'unprotected_storage_write': [
                r'assembly\s*\{\s*sstore\s*\([^)]*\)\s*\}(?![^}]*require)',
                r'\.slot\s*:=\s*[^;]*(?![^;]*onlyOwner)',
                r'StorageSlot\.getAddressSlot\([^)]*\)\.value\s*=(?![^;]*require)'
            ],
            'delegatecall_storage_risk': [
                r'delegatecall\([^)]*\)(?![^;]*require\([^}]*storage)',
                r'assembly\s*\{[^}]*delegatecall\([^)]*\)(?![^}]*check)'
            ],
            'array_manipulation': [
                r'\.length\s*=\s*[^;]*(?![^;]*require)',
                r'array\.pop\(\)(?![^;]*require)',
                r'delete\s+\w+\[.*\](?![^;]*onlyOwner)'
            ]
        }

    def analyze_storage(self, contract_address: str, source_code: str = None,
                       max_slots: int = 50) -> List[StorageVulnerability]:
        """
        Comprehensive storage analysis for vulnerabilities
        """
        # Skip storage analysis for zero address or undeployed contracts
        if not contract_address or contract_address == '0x' + '0' * 40:
            print(f"⚠️ Skipping storage analysis for zero address")
            return []

        print(f"🔍 Starting comprehensive storage analysis for {contract_address}")

        vulnerabilities = []

        # Phase 1: Read and analyze storage slots (with timeout)
        print(f"[+] Phase 1: Storage slot enumeration (0-{max_slots}) - Quick mode")
        try:
            # Reduce max_slots for faster scanning (only critical slots)
            quick_slots = min(max_slots, 10)  # Only check first 10 slots
            storage_slots = self._read_storage_slots(contract_address, quick_slots)
        except Exception as e:
            print(f"⚠️ Storage read timeout/error: {e}")
            storage_slots = []
        
        # Phase 2: Identify uninitialized critical storage (with timeout)
        print(f"[+] Phase 2: Uninitialized storage detection")
        try:
            uninit_vulns = self._detect_uninitialized_storage(storage_slots)
            vulnerabilities.extend(uninit_vulns)
        except Exception as e:
            print(f"⚠️ Phase 2 error: {e}")
        
        # Phase 3: Source code storage analysis (with timeout)
        if source_code:
            try:
                print(f"[+] Phase 3: Source code storage pattern analysis")
                source_vulns = self._analyze_source_storage_patterns(source_code, contract_address)
                vulnerabilities.extend(source_vulns)
            except Exception as e:
                print(f"⚠️ Phase 3 error: {e}")

            # Phase 4: Storage layout analysis (with timeout)
            try:
                print(f"[+] Phase 4: Storage layout vulnerability analysis")
                layout_vulns = self._analyze_storage_layout(source_code, storage_slots)
                vulnerabilities.extend(layout_vulns)
            except Exception as e:
                print(f"⚠️ Phase 4 error: {e}")

        # Phase 5: Critical slot exposure analysis (with timeout)
        try:
            print(f"[+] Phase 5: Critical storage slot exposure analysis")
            critical_vulns = self._analyze_critical_slot_exposure(storage_slots)
            vulnerabilities.extend(critical_vulns)
        except Exception as e:
            print(f"⚠️ Phase 5 error: {e}")

        # Phase 6: Storage collision detection (with timeout)
        try:
            print(f"[+] Phase 6: Storage collision analysis")
            collision_vulns = self._detect_storage_collisions(storage_slots, source_code)
            vulnerabilities.extend(collision_vulns)
        except Exception as e:
            print(f"⚠️ Phase 6 error: {e}")
        
        print(f"📊 Storage analysis complete: {len(vulnerabilities)} vulnerabilities found")
        return vulnerabilities

    def _read_storage_slots(self, contract_address: str, max_slots: int) -> List[StorageSlot]:
        """Read storage slots from blockchain (with timeout protection)"""
        import time
        storage_slots = []
        start_time = time.time()
        timeout = 10  # 10 second timeout for storage reading

        for slot in range(max_slots):
            # Check timeout
            if time.time() - start_time > timeout:
                print(f"⚠️ Storage read timeout after {slot} slots")
                break

            slot_hex = f"0x{slot:x}"
            try:
                value = self._read_storage_slot(contract_address, slot_hex)

                if value:
                    is_initialized = value != "0x" + "0" * 64
                    is_critical = slot in self.CRITICAL_SLOTS

                    storage_slot = StorageSlot(
                        slot_number=slot,
                        slot_hex=slot_hex,
                        value=value,
                        is_initialized=is_initialized,
                        data_type=self._infer_data_type(value),
                        variable_name=self.CRITICAL_SLOTS.get(slot, f"slot_{slot}"),
                        is_critical=is_critical
                    )
                    storage_slots.append(storage_slot)
            except Exception as e:
                print(f"⚠️ Error reading slot {slot}: {e}")
                continue
        
        # Also check EIP-1967 proxy slots
        for proxy_slot_hex, description in self.PROXY_SLOTS.items():
            value = self._read_storage_slot(contract_address, proxy_slot_hex)
            if value and value != "0x" + "0" * 64:
                storage_slot = StorageSlot(
                    slot_number=int(proxy_slot_hex, 16),
                    slot_hex=proxy_slot_hex,
                    value=value,
                    is_initialized=True,
                    data_type="address",
                    variable_name=description,
                    is_critical=True
                )
                storage_slots.append(storage_slot)
        
        return storage_slots

    def _detect_uninitialized_storage(self, storage_slots: List[StorageSlot]) -> List[StorageVulnerability]:
        """Detect uninitialized critical storage slots (fast mode)"""
        vulnerabilities = []

        # Check critical slots that should be initialized
        critical_uninitialized = [slot for slot in storage_slots
                                 if slot.is_critical and not slot.is_initialized]

        for slot in critical_uninitialized:
            vuln = StorageVulnerability(
                vuln_type=StorageVulnerabilityType.UNINITIALIZED_STORAGE,
                affected_slots=[slot.slot_number],
                severity="HIGH",
                description=f"Critical storage slot {slot.slot_number} ({slot.variable_name}) is uninitialized",
                exploit_path="1. Contract deployed without proper initialization\n2. Critical variables remain zero\n3. Exploit uninitialized state",
                impact="Uninitialized critical variables can lead to unauthorized access or fund loss",
                recommendation=f"Initialize {slot.variable_name} in constructor or initializer function",
                confidence=0.9,
                proof_of_concept=f"Storage slot {slot.slot_number} contains: {slot.value}"
            )
            vulnerabilities.append(vuln)

        # REMOVED: Gap detection was causing 2+ minute hangs
        # Only check the first 10 slots we scanned, not all slots up to max
        # This prevents expensive loops when contracts have high slot numbers

        return vulnerabilities

    def _analyze_source_storage_patterns(self, source_code: str, contract_address: str) -> List[StorageVulnerability]:
        """Analyze source code for storage-related vulnerability patterns"""
        vulnerabilities = []
        
        # Detect unprotected storage writes
        for pattern in self.STORAGE_PATTERNS['unprotected_storage_write']:
            matches = list(re.finditer(pattern, source_code, re.MULTILINE | re.IGNORECASE))
            for match in matches:
                vuln = StorageVulnerability(
                    vuln_type=StorageVulnerabilityType.UNPROTECTED_STORAGE_WRITE,
                    affected_slots=[], # Would need more analysis to determine exact slots
                    severity="CRITICAL",
                    description="Direct storage write without access control protection",
                    exploit_path="1. Call function with unprotected storage write\n2. Overwrite critical contract state\n3. Gain unauthorized control",
                    impact="Direct storage manipulation can lead to complete contract compromise",
                    recommendation="Add proper access control (require, onlyOwner) to storage write operations",
                    confidence=0.85,
                    proof_of_concept=match.group(0)
                )
                vulnerabilities.append(vuln)
        
        # Detect delegatecall storage risks
        for pattern in self.STORAGE_PATTERNS['delegatecall_storage_risk']:
            matches = list(re.finditer(pattern, source_code, re.MULTILINE | re.IGNORECASE))
            for match in matches:
                vuln = StorageVulnerability(
                    vuln_type=StorageVulnerabilityType.DELEGATECALL_STORAGE_HIJACK,
                    affected_slots=[],
                    severity="CRITICAL",
                    description="Unprotected delegatecall can hijack contract storage",
                    exploit_path="1. Call delegatecall with malicious contract\n2. Malicious contract overwrites storage\n3. Complete storage hijacking",
                    impact="Delegatecall can completely overwrite contract storage leading to total compromise",
                    recommendation="Add strict validation for delegatecall targets and implement storage protection",
                    confidence=0.9,
                    proof_of_concept=match.group(0)
                )
                vulnerabilities.append(vuln)
        
        # Detect array length manipulation
        for pattern in self.STORAGE_PATTERNS['array_manipulation']:
            matches = list(re.finditer(pattern, source_code, re.MULTILINE | re.IGNORECASE))
            for match in matches:
                vuln = StorageVulnerability(
                    vuln_type=StorageVulnerabilityType.ARRAY_LENGTH_MANIPULATION,
                    affected_slots=[],
                    severity="HIGH",
                    description="Unprotected array length manipulation vulnerability",
                    exploit_path="1. Call function that manipulates array length\n2. Cause storage corruption\n3. Exploit corrupted state",
                    impact="Array length manipulation can corrupt storage and lead to unexpected behavior",
                    recommendation="Add access control to array manipulation functions",
                    confidence=0.75,
                    proof_of_concept=match.group(0)
                )
                vulnerabilities.append(vuln)
        
        # Detect constructor vs initializer pattern misuse
        if 'constructor(' in source_code and 'proxy' in source_code.lower():
            if 'initialize(' not in source_code:
                vuln = StorageVulnerability(
                    vuln_type=StorageVulnerabilityType.UNINITIALIZED_STORAGE,
                    affected_slots=[0, 1, 2], # Common critical slots
                    severity="HIGH",
                    description="Proxy contract uses constructor instead of initializer",
                    exploit_path="1. Deploy proxy with this implementation\n2. Constructor never executes\n3. Critical storage remains uninitialized",
                    impact="Storage initialization skipped in proxy context, leading to uninitialized critical variables",
                    recommendation="Replace constructor with initialize() function for proxy compatibility",
                    confidence=0.85,
                    proof_of_concept="Constructor found in proxy-compatible contract without initializer"
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities

    def _analyze_storage_layout(self, source_code: str, storage_slots: List[StorageSlot]) -> List[StorageVulnerability]:
        """Analyze storage layout for vulnerabilities"""
        vulnerabilities = []
        
        # Detect potential storage slot packing issues
        struct_matches = re.findall(r'struct\s+\w+\s*\{([^}]+)\}', source_code, re.MULTILINE | re.IGNORECASE)
        
        for struct_content in struct_matches:
            # Look for potentially dangerous packing patterns
            lines = [line.strip() for line in struct_content.split(';') if line.strip()]
            
            # Check for uint8/bool followed by address (packing issue)
            for i in range(len(lines) - 1):
                if ('uint8' in lines[i] or 'bool' in lines[i]) and 'address' in lines[i + 1]:
                    vuln = StorageVulnerability(
                        vuln_type=StorageVulnerabilityType.SLOT_PACKING_OVERFLOW,
                        affected_slots=[],
                        severity="MEDIUM", 
                        description="Potential storage slot packing vulnerability in struct",
                        exploit_path="1. Exploit packing boundaries\n2. Overflow into adjacent slot\n3. Corrupt critical data",
                        impact="Storage packing issues can lead to data corruption",
                        recommendation="Review struct packing and use explicit slot assignments",
                        confidence=0.6,
                        proof_of_concept=f"Struct packing: {lines[i]} -> {lines[i+1]}"
                    )
                    vulnerabilities.append(vuln)
        
        # Detect mapping key collision risks
        mapping_patterns = re.findall(r'mapping\s*\([^)]+\s*=>\s*[^)]+\)\s*\w+', source_code)
        if len(mapping_patterns) > 5:  # Many mappings increase collision risk
            vuln = StorageVulnerability(
                vuln_type=StorageVulnerabilityType.MAPPING_KEY_COLLISION,
                affected_slots=[],
                severity="LOW",
                description=f"Contract has {len(mapping_patterns)} mappings, increasing storage collision risk",
                exploit_path="1. Calculate storage slot collisions\n2. Find overlapping mapping keys\n3. Exploit storage conflicts",
                impact="Multiple mappings can lead to storage slot collisions",
                recommendation="Use explicit storage slots or reduce mapping count",
                confidence=0.4
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities

    def _analyze_critical_slot_exposure(self, storage_slots: List[StorageSlot]) -> List[StorageVulnerability]:
        """Analyze exposure of critical storage slots"""
        vulnerabilities = []
        
        # Check if critical slots contain sensitive data
        for slot in storage_slots:
            if slot.is_critical and slot.is_initialized:
                # Check if it's an address that might be externally readable
                if slot.data_type == "address":
                    address_value = "0x" + slot.value[-40:] if len(slot.value) >= 42 else slot.value
                    
                    # Check for zero address in critical slot
                    if address_value == "0x" + "0" * 40:
                        vuln = StorageVulnerability(
                            vuln_type=StorageVulnerabilityType.CRITICAL_SLOT_EXPOSURE,
                            affected_slots=[slot.slot_number],
                            severity="HIGH",
                            description=f"Critical slot {slot.slot_number} ({slot.variable_name}) contains zero address",
                            exploit_path="1. Critical address is zero\n2. Functions relying on this address fail\n3. Potential for unauthorized access",
                            impact="Zero addresses in critical slots can break access control",
                            recommendation=f"Set proper address for {slot.variable_name}",
                            confidence=0.9,
                            proof_of_concept=f"Slot {slot.slot_number}: {address_value}"
                        )
                        vulnerabilities.append(vuln)
                
                # Check for externally readable critical data
                vuln = StorageVulnerability(
                    vuln_type=StorageVulnerabilityType.CRITICAL_SLOT_EXPOSURE,
                    affected_slots=[slot.slot_number],
                    severity="MEDIUM",
                    description=f"Critical storage slot {slot.slot_number} is readable by anyone",
                    exploit_path="1. Read critical storage slot\n2. Extract sensitive information\n3. Use for targeted attacks",
                    impact="Critical storage data exposure can aid in targeted attacks",
                    recommendation="Consider if critical data should be stored privately or encrypted",
                    confidence=0.5
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities

    def _detect_storage_collisions(self, storage_slots: List[StorageSlot], 
                                 source_code: str = None) -> List[StorageVulnerability]:
        """Detect potential storage slot collisions"""
        vulnerabilities = []
        
        # Check for duplicate values in different slots (potential collision)
        value_to_slots = {}
        for slot in storage_slots:
            if slot.is_initialized and slot.value != "0x" + "0" * 64:
                if slot.value in value_to_slots:
                    value_to_slots[slot.value].append(slot.slot_number)
                else:
                    value_to_slots[slot.value] = [slot.slot_number]
        
        for value, slots in value_to_slots.items():
            if len(slots) > 1:
                vuln = StorageVulnerability(
                    vuln_type=StorageVulnerabilityType.STORAGE_COLLISION,
                    affected_slots=slots,
                    severity="MEDIUM",
                    description=f"Multiple storage slots contain identical value: {value[:10]}...",
                    exploit_path="1. Identify storage collision\n2. Exploit conflicting storage layout\n3. Cause state corruption",
                    impact="Storage collisions can lead to unexpected behavior and state corruption",
                    recommendation="Review storage layout to ensure unique slot usage",
                    confidence=0.6,
                    proof_of_concept=f"Slots {slots} contain identical value: {value}"
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities

    def _read_storage_slot(self, address: str, slot: str) -> Optional[str]:
        """Read storage slot from blockchain - API-free mode preferred"""
        # Try API-free mode first (RPC)
        if self.use_api_free and self.api_free_fetcher:
            try:
                result = self.api_free_fetcher.get_storage_at(address, slot)
                if result:
                    return result
            except Exception as e:
                print(f"[-] API-free storage read failed: {e}")

        # Fallback to API mode
        if self.api_key:
            try:
                url = self.chain_config.get('api_base', 'https://api.etherscan.io/api')
                params = {
                    'module': 'proxy',
                    'action': 'eth_getStorageAt',
                    'address': address,
                    'position': slot,
                    'tag': 'latest',
                    'apikey': self.api_key
                }

                if 'v2' in url:
                    params['chainid'] = self.chain_config['chain_id']

                response = requests.get(url, params=params)
                data = response.json()

                return data.get('result')

            except Exception as e:
                print(f"[-] API storage read failed: {e}")

        return None

    def _infer_data_type(self, value: str) -> str:
        """Infer data type from storage value"""
        if not value or value == "0x" + "0" * 64:
            return "uninitialized"
        
        # Check if it looks like an address (last 20 bytes non-zero)
        if len(value) >= 42 and value[-40:] != "0" * 40:
            return "address"
        
        # Check if it's a boolean (0 or 1)
        if value == "0x" + "0" * 63 + "1":
            return "bool"
        
        # Check if it's a small number
        try:
            num_value = int(value, 16)
            if num_value < 2**32:
                return "uint32"
            elif num_value < 2**64:
                return "uint64"
            else:
                return "uint256"
        except:
            return "bytes32"

    def generate_storage_report(self, vulnerabilities: List[StorageVulnerability], 
                              storage_slots: List[StorageSlot]) -> str:
        """Generate comprehensive storage analysis report"""
        
        report = "# COMPREHENSIVE STORAGE ANALYSIS REPORT\n\n"
        
        # Summary
        report += "## EXECUTIVE SUMMARY\n"
        report += f"- **Storage Slots Analyzed**: {len(storage_slots)}\n"
        report += f"- **Vulnerabilities Found**: {len(vulnerabilities)}\n"
        
        critical = len([v for v in vulnerabilities if v.severity == "CRITICAL"])
        high = len([v for v in vulnerabilities if v.severity == "HIGH"])
        medium = len([v for v in vulnerabilities if v.severity == "MEDIUM"])
        low = len([v for v in vulnerabilities if v.severity == "LOW"])
        
        report += f"- **Critical**: {critical}\n"
        report += f"- **High**: {high}\n"
        report += f"- **Medium**: {medium}\n"
        report += f"- **Low**: {low}\n\n"
        
        # Storage slot overview
        report += "## STORAGE SLOT OVERVIEW\n\n"
        initialized = len([s for s in storage_slots if s.is_initialized])
        critical_slots = len([s for s in storage_slots if s.is_critical])
        
        report += f"- **Initialized Slots**: {initialized}/{len(storage_slots)}\n"
        report += f"- **Critical Slots**: {critical_slots}\n\n"
        
        # Detailed vulnerabilities
        if vulnerabilities:
            report += "## DETAILED VULNERABILITY ANALYSIS\n\n"
            
            for i, vuln in enumerate(vulnerabilities, 1):
                report += f"### {i}. {vuln.vuln_type.value} ({vuln.severity})\n\n"
                report += f"**Description**: {vuln.description}\n\n"
                report += f"**Affected Slots**: {vuln.affected_slots}\n\n"
                report += f"**Impact**: {vuln.impact}\n\n"
                report += f"**Exploit Path**:\n{vuln.exploit_path}\n\n"
                report += f"**Recommendation**: {vuln.recommendation}\n\n"
                report += f"**Confidence**: {vuln.confidence:.0%}\n\n"
                if vuln.proof_of_concept:
                    report += f"**Proof of Concept**:\n```\n{vuln.proof_of_concept}\n```\n\n"
                report += "---\n\n"
        
        return report