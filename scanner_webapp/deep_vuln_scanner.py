#!/usr/bin/env python3
"""
Deep Smart Contract Vulnerability Scanner
Focuses on non-privileged fund drain exploits

Author: Rovo Dev
Target: Critical fund drain vulnerabilities for bug bounty submission
"""

import re
import json
import requests
import os
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from enum import Enum
from bytecode_analyzer import BytecodeAnalyzer
from pattern_engine import AdvancedPatternEngine

class VulnSeverity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

@dataclass
class Vulnerability:
    title: str
    severity: VulnSeverity
    description: str
    location: str
    exploit_path: str
    impact: str
    proof_of_concept: str
    recommendation: str
    confidence: float  # 0.0 to 1.0

class DeepContractScanner:
    def __init__(self, etherscan_api_key: str = None):
        self.api_key = etherscan_api_key
        self.vulnerabilities = []
        self.bytecode_analyzer = BytecodeAnalyzer()
        self.pattern_engine = AdvancedPatternEngine()
        
        # Critical vulnerability patterns for fund drain
        self.critical_patterns = {
            'unauthorized_transfer': [
                r'function\s+\w*[Tt]ransfer\w*\s*\([^)]*\)\s*public.*\{(?![^}]*require\([^}]*msg\.sender)',
                r'\.transfer\s*\([^)]*\)\s*;(?![^;]*require)',
                r'\.transferFrom\s*\([^)]*\)\s*;(?![^;]*require)',
            ],
            'unprotected_withdraw': [
                r'function\s+\w*[Ww]ithdraw\w*\s*\([^)]*\)\s*public.*\{(?![^}]*require\([^}]*msg\.sender)',
                r'payable\(.*\)\.transfer\s*\(',
                r'\.call\{value:\s*.*\}\s*\(',
            ],
            'approval_manipulation': [
                r'_approve\s*\([^,]*,\s*[^,]*,\s*type\s*\(\s*uint256\s*\)\.max\)',
                r'\.approve\s*\([^,]*,\s*type\s*\(\s*uint256\s*\)\.max\)',
                r'_allowances\[.*\]\[.*\]\s*=\s*type\s*\(\s*uint256\s*\)\.max',
            ],
            'reentrancy_vulnerable': [
                r'\.transfer\s*\([^)]*\).*\{[^}]*external\s+call',
                r'external\s+call.*\.transfer\s*\(',
                r'\.call\s*\([^)]*\).*state\s*=',
            ],
            'access_control_bypass': [
                r'require\s*\(\s*false\s*,',  # Always failing require
                r'if\s*\(\s*false\s*\)',      # Always false condition
                r'onlyOwner.*\{\s*$',         # Empty modifier implementation
            ],
            'integer_overflow': [
                r'[^-]\+[^=\+]',  # Addition without SafeMath
                r'[^-]\*[^=\*]',  # Multiplication without SafeMath
                r'\*\*\s*\d+',    # Exponentiation
            ],
            'price_manipulation': [
                r'getReserves\s*\(\s*\)',
                r'reserve[01]\s*[*/]\s*reserve[01]',
                r'\.price\s*=',
                r'currentPrice\s*=.*getReserves',
            ]
        }
        
        # Decompiled bytecode patterns (for unverified contracts)
        self.bytecode_patterns = {
            'unauthorized_balance_access': [
                r'balanceOf\(this\)\.gas\(msg\.gas\)',
                r'\.transfer\(msg\.sender,\s*v\d+\)\.gas\(msg\.gas\)',
            ],
            'missing_auth_checks': [
                r'function.*public.*nonPayable.*\{(?!.*require\(.*msg\.sender)',
                r'require\(msg\.data\.length.*\>=.*\)(?!.*require\(.*authorized)',
            ],
            'storage_manipulation': [
                r'STORAGE\[0x[0-9a-fA-F]+\]\s*=',
                r'mapping.*\[msg\.sender\](?!.*require)',
            ]
        }

    def scan_contract(self, contract_address: str, source_code: str = None, 
                     decompiled_code: str = None, bytecode: str = None) -> List[Vulnerability]:
        """
        Main scanning function - analyzes contract for vulnerabilities
        """
        self.vulnerabilities = []
        
        print(f"[+] Starting deep scan of contract: {contract_address}")
        
        # Get contract info from Etherscan if available
        contract_info = self._fetch_contract_info(contract_address)
        
        if source_code:
            print("[+] Analyzing verified Solidity source code...")
            self._analyze_solidity_source(source_code, contract_address)
            # Also run pattern analysis
            print("[+] Running pattern analysis on source code...")
            pattern_vulns = self.pattern_engine.scan_for_patterns(source_code, "solidity")
            self._convert_pattern_vulns_to_vulnerabilities(pattern_vulns, contract_address)
            
        elif decompiled_code:
            print("[+] Analyzing decompiled bytecode...")
            self._analyze_decompiled_code(decompiled_code, contract_address)
            # Run specialized decompiled pattern analysis
            print("[+] Running decompiled pattern analysis...")
            decompiled_vulns = self.pattern_engine.analyze_decompiled_patterns(decompiled_code)
            self._convert_pattern_vulns_to_vulnerabilities(decompiled_vulns, contract_address)
            
        elif bytecode:
            print("[+] Analyzing raw bytecode...")
            self._analyze_raw_bytecode(bytecode, contract_address)
            # Run bytecode analysis
            print("[+] Running deep bytecode analysis...")
            bytecode_results = self.bytecode_analyzer.analyze_bytecode(bytecode)
            self._convert_bytecode_vulns_to_vulnerabilities(bytecode_results, contract_address)
            
        else:
            # Try to fetch from Etherscan
            source = self._fetch_contract_source(contract_address)
            if source:
                self._analyze_solidity_source(source, contract_address)
                pattern_vulns = self.pattern_engine.scan_for_patterns(source, "solidity")
                self._convert_pattern_vulns_to_vulnerabilities(pattern_vulns, contract_address)
            else:
                print("[-] No source code available and none provided")
                
        # Additional analysis
        self._analyze_storage_layout(contract_address)
        self._analyze_function_selectors(contract_address)
        self._check_constructor_flaws(contract_address)
        
        return self._rank_vulnerabilities()

    def _analyze_solidity_source(self, source_code: str, contract_address: str):
        """Analyze verified Solidity source code for vulnerabilities"""
        
        # 1. Check for unauthorized transfer functions
        self._check_unauthorized_transfers(source_code, contract_address)
        
        # 2. Check for reentrancy vulnerabilities
        self._check_reentrancy_patterns(source_code, contract_address)
        
        # 3. Check for access control issues
        self._check_access_control(source_code, contract_address)
        
        # 4. Check for approval manipulation
        self._check_approval_manipulation(source_code, contract_address)
        
        # 5. Check for price manipulation vulnerabilities
        self._check_price_manipulation(source_code, contract_address)
        
        # 6. Check for integer overflow/underflow
        self._check_integer_issues(source_code, contract_address)
        
        # 7. Check for withdrawal patterns
        self._check_withdrawal_patterns(source_code, contract_address)

    def _check_unauthorized_transfers(self, code: str, address: str):
        """Check for transfer functions without proper authorization"""
        
        # Look for public transfer functions without access control
        pattern = r'function\s+(\w*[Tt]ransfer\w*)\s*\([^)]*\)\s*(public|external)([^{]*)\{([^}]*)\}'
        matches = re.finditer(pattern, code, re.MULTILINE | re.DOTALL)
        
        for match in matches:
            func_name = match.group(1)
            func_body = match.group(4)
            
            # Check if function has proper authorization
            has_auth = any(auth in func_body for auth in [
                'require(', 'onlyOwner', 'msg.sender', 'authorized', 'admin'
            ])
            
            # Check if it actually transfers funds
            has_transfer = any(transfer in func_body for transfer in [
                '.transfer(', '.transferFrom(', '.send(', '.call{value:'
            ])
            
            if has_transfer and not has_auth:
                vuln = Vulnerability(
                    title=f"Unauthorized Fund Transfer in {func_name}()",
                    severity=VulnSeverity.CRITICAL,
                    description=f"Function {func_name}() allows unauthorized token/ETH transfers",
                    location=f"Contract: {address}, Function: {func_name}",
                    exploit_path="1. Call function directly\n2. Specify target address\n3. Drain funds",
                    impact="Complete loss of contract funds and user deposits",
                    proof_of_concept=f"await contract.{func_name}(victimToken, drainAmount);",
                    recommendation="Add proper access control: require(authorized[msg.sender], 'Not authorized');",
                    confidence=0.9
                )
                self.vulnerabilities.append(vuln)

    def _check_reentrancy_patterns(self, code: str, address: str):
        """Check for reentrancy vulnerabilities in state-changing functions"""
        
        # Look for external calls before state updates
        external_call_pattern = r'(\.\w*call\w*\([^)]*\)|\.transfer\([^)]*\)|\.send\([^)]*\))'
        state_change_pattern = r'(\w+\s*=\s*[^;]+;|\w+\[.*\]\s*=|\w+\s*\+=|\w+\s*-=)'
        
        lines = code.split('\n')
        for i, line in enumerate(lines):
            if re.search(external_call_pattern, line):
                # Check if state is modified after this external call
                for j in range(i+1, min(i+10, len(lines))):  # Check next 10 lines
                    if re.search(state_change_pattern, lines[j]):
                        vuln = Vulnerability(
                            title="Potential Reentrancy Vulnerability",
                            severity=VulnSeverity.HIGH,
                            description="External call followed by state modification creates reentrancy risk",
                            location=f"Contract: {address}, Line: {i+1}",
                            exploit_path="1. Call function\n2. In callback, call same function\n3. Manipulate state",
                            impact="State manipulation, potential fund drain through recursive calls",
                            proof_of_concept="// Malicious contract calls back during transfer",
                            recommendation="Use ReentrancyGuard modifier or Checks-Effects-Interactions pattern",
                            confidence=0.7
                        )
                        self.vulnerabilities.append(vuln)
                        break

    def _check_access_control(self, code: str, address: str):
        """Check for access control bypass vulnerabilities"""
        
        # Look for circular dependency in access control
        admin_functions = re.findall(r'function\s+(\w*[Aa]dmin\w*)\s*\([^)]*\)\s*[^{]*\{([^}]*)\}', code, re.DOTALL)
        
        for func_name, func_body in admin_functions:
            # Check if setAdmin function requires admin privileges (circular dependency)
            if 'setAdmin' in func_name or 'addAdmin' in func_name:
                if 'require(' in func_body and 'admin' in func_body.lower():
                    vuln = Vulnerability(
                        title="Circular Dependency in Access Control",
                        severity=VulnSeverity.CRITICAL,
                        description="Admin functions require admin access but no initial admin is set",
                        location=f"Contract: {address}, Function: {func_name}",
                        exploit_path="1. Check if admin mapping is empty\n2. Identify broken initialization\n3. All admin functions inaccessible",
                        impact="All admin functions permanently inaccessible, contract broken",
                        proof_of_concept="// No way to set initial admin, contract in broken state",
                        recommendation="Set initial admin in constructor or provide initialization function",
                        confidence=0.8
                    )
                    self.vulnerabilities.append(vuln)

    def _analyze_decompiled_code(self, decompiled_code: str, address: str):
        """Analyze decompiled bytecode for vulnerabilities"""
        
        # Check for functions without authorization that manipulate balances
        self._check_decompiled_unauthorized_access(decompiled_code, address)
        
        # Check for storage manipulation without checks
        self._check_decompiled_storage_issues(decompiled_code, address)
        
        # Check for missing initialization
        self._check_decompiled_initialization(decompiled_code, address)

    def _check_decompiled_unauthorized_access(self, code: str, address: str):
        """Check decompiled code for unauthorized fund access"""
        
        # Look for transfer functions in decompiled code
        transfer_pattern = r'function\s+(\w+)\s*\([^)]*\)\s*public\s*nonPayable\s*\{[^}]*\.transfer\(msg\.sender'
        matches = re.finditer(transfer_pattern, code)
        
        for match in matches:
            func_name = match.group(1)
            
            # Check if there's an authorization check
            func_content = match.group(0)
            has_auth_check = 'require(' in func_content and ('authorized' in func_content or 'admin' in func_content)
            
            if not has_auth_check:
                vuln = Vulnerability(
                    title=f"Unauthorized Transfer Function: {func_name}",
                    severity=VulnSeverity.CRITICAL,
                    description=f"Decompiled function {func_name} transfers funds without authorization",
                    location=f"Contract: {address}, Function: {func_name}",
                    exploit_path="1. Call function with token address\n2. Receive all contract's token balance",
                    impact="Complete drainage of contract token balances",
                    proof_of_concept=f"contract.{func_name}(tokenAddress, amount)",
                    recommendation="Verify if authorization mapping is properly initialized",
                    confidence=0.85
                )
                self.vulnerabilities.append(vuln)

    def _fetch_contract_info(self, address: str) -> Dict:
        """Fetch contract information from Etherscan"""
        if not self.api_key:
            return {}
            
        try:
            url = f"https://api.etherscan.io/v2/api"
            params = {
                'chainid': '1',
                'module': 'account',
                'action': 'balance',
                'address': address,
                'tag': 'latest',
                'apikey': self.api_key
            }
            response = requests.get(url, params=params)
            return response.json()
        except Exception as e:
            print(f"[-] Error fetching contract info: {e}")
            return {}

    def _analyze_storage_layout(self, address: str):
        """Analyze contract storage for initialization issues"""
        if not self.api_key:
            return
            
        # Check critical storage slots
        critical_slots = ['0x0', '0x1', '0x2']  # Common admin/owner slots
        
        for slot in critical_slots:
            try:
                url = f"https://api.etherscan.io/v2/api"
                params = {
                    'chainid': '1',
                    'module': 'proxy',
                    'action': 'eth_getStorageAt',
                    'address': address,
                    'position': slot,
                    'tag': 'latest',
                    'apikey': self.api_key
                }
                response = requests.get(url, params=params)
                data = response.json()
                
                if data.get('result') == '0x0000000000000000000000000000000000000000000000000000000000000000':
                    vuln = Vulnerability(
                        title=f"Uninitialized Critical Storage Slot {slot}",
                        severity=VulnSeverity.HIGH,
                        description=f"Storage slot {slot} is empty, may indicate broken initialization",
                        location=f"Contract: {address}, Storage slot: {slot}",
                        exploit_path="1. Verify storage is uninitialized\n2. Check if admin functions are accessible\n3. Contract may be in broken state",
                        impact="Admin functions may be permanently inaccessible",
                        proof_of_concept=f"eth_getStorageAt({address}, {slot}) returns 0x0",
                        recommendation="Verify contract initialization and admin setup",
                        confidence=0.6
                    )
                    self.vulnerabilities.append(vuln)
                    
            except Exception as e:
                print(f"[-] Error checking storage slot {slot}: {e}")

    def _rank_vulnerabilities(self) -> List[Vulnerability]:
        """Rank vulnerabilities by severity and confidence"""
        severity_weights = {
            VulnSeverity.CRITICAL: 4,
            VulnSeverity.HIGH: 3,
            VulnSeverity.MEDIUM: 2,
            VulnSeverity.LOW: 1,
            VulnSeverity.INFO: 0
        }
        
        return sorted(self.vulnerabilities, 
                     key=lambda v: (severity_weights[v.severity], v.confidence), 
                     reverse=True)

    def generate_report(self, contract_address: str, output_file: str = None):
        """Generate detailed vulnerability report"""
        
        if not self.vulnerabilities:
            print("[-] No vulnerabilities found")
            return
            
        report = f"""
# Smart Contract Security Report
## Contract: {contract_address}
## Scan Date: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Executive Summary
Found {len(self.vulnerabilities)} potential vulnerabilities:
"""
        
        # Count by severity
        severity_counts = {}
        for vuln in self.vulnerabilities:
            severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1
            
        for severity, count in severity_counts.items():
            report += f"- {severity.value}: {count}\n"
        
        report += "\n## Detailed Findings\n\n"
        
        for i, vuln in enumerate(self.vulnerabilities, 1):
            report += f"""
### {i}. {vuln.title}
- **Severity**: {vuln.severity.value}
- **Confidence**: {vuln.confidence:.0%}
- **Location**: {vuln.location}

**Description:**
{vuln.description}

**Exploit Path:**
{vuln.exploit_path}

**Impact:**
{vuln.impact}

**Proof of Concept:**
```solidity
{vuln.proof_of_concept}
```

**Recommendation:**
{vuln.recommendation}

---
"""
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(report)
            print(f"[+] Report saved to {output_file}")
        else:
            print(report)

    # Additional analysis methods
    def _check_approval_manipulation(self, code: str, address: str):
        """Check for approval manipulation vulnerabilities"""
        patterns = self.critical_patterns['approval_manipulation']
        for pattern in patterns:
            matches = re.finditer(pattern, code)
            for match in matches:
                # Extract context
                start = max(0, match.start() - 200)
                end = min(len(code), match.end() + 200)
                context = code[start:end]
                
                # Check if it's in a public function without proper auth
                if 'public' in context and 'require(' not in context:
                    vuln = Vulnerability(
                        title="Unauthorized Approval Manipulation",
                        severity=VulnSeverity.CRITICAL,
                        description="Unlimited approval can be set without proper authorization",
                        location=f"Contract: {address}",
                        exploit_path="1. Call approval function\n2. Set unlimited approval\n3. Drain funds via transferFrom",
                        impact="Complete fund drainage via approval exploitation",
                        proof_of_concept=match.group(0),
                        recommendation="Add proper access control to approval functions",
                        confidence=0.9
                    )
                    self.vulnerabilities.append(vuln)

    def _check_price_manipulation(self, code: str, address: str):
        """Check for price manipulation vulnerabilities"""
        if 'getReserves()' in code and 'currentPrice' in code:
            vuln = Vulnerability(
                title="Price Manipulation Vulnerability",
                severity=VulnSeverity.HIGH,
                description="Price calculation depends on manipulable DEX reserves",
                location=f"Contract: {address}",
                exploit_path="1. Manipulate DEX liquidity\n2. Trigger price-dependent functions\n3. Exploit price discrepancy",
                impact="Economic exploitation through price manipulation",
                proof_of_concept="// Flash loan attack on DEX reserves",
                recommendation="Use time-weighted average price (TWAP) or price oracles",
                confidence=0.7
            )
            self.vulnerabilities.append(vuln)

    def _check_integer_issues(self, code: str, address: str):
        """Check for integer overflow/underflow issues"""
        if 'pragma solidity' in code:
            version_match = re.search(r'pragma solidity\s*[\^><=\s]*(\d+\.\d+)', code)
            if version_match:
                version = float(version_match.group(1))
                if version < 0.8:  # Before Solidity 0.8, no automatic overflow protection
                    math_operations = re.findall(r'(\w+\s*[\+\-\*\/]\s*\w+)', code)
                    if math_operations and 'SafeMath' not in code:
                        vuln = Vulnerability(
                            title="Integer Overflow/Underflow Risk",
                            severity=VulnSeverity.MEDIUM,
                            description="Arithmetic operations without SafeMath in pre-0.8 Solidity",
                            location=f"Contract: {address}",
                            exploit_path="1. Find arithmetic operation\n2. Provide values causing overflow\n3. Exploit incorrect calculation",
                            impact="Financial loss through arithmetic manipulation",
                            proof_of_concept="// Provide max values to cause overflow",
                            recommendation="Use SafeMath library or upgrade to Solidity 0.8+",
                            confidence=0.6
                        )
                        self.vulnerabilities.append(vuln)

    def _check_withdrawal_patterns(self, code: str, address: str):
        """Check withdrawal function patterns"""
        withdraw_pattern = r'function\s+(\w*[Ww]ithdraw\w*)\s*\([^)]*\)\s*(public|external)([^{]*)\{([^}]*)\}'
        matches = re.finditer(withdraw_pattern, code, re.MULTILINE | re.DOTALL)
        
        for match in matches:
            func_name = match.group(1)
            func_body = match.group(4)
            
            # Check for proper access control
            has_auth = any(auth in func_body for auth in [
                'require(', 'onlyOwner', 'msg.sender', 'authorized'
            ])
            
            # Check if it sends ETH or tokens
            sends_value = any(send in func_body for send in [
                '.transfer(', '.send(', '.call{value:'
            ])
            
            if sends_value and not has_auth:
                vuln = Vulnerability(
                    title=f"Unprotected Withdrawal Function: {func_name}",
                    severity=VulnSeverity.CRITICAL,
                    description=f"Function {func_name}() allows unauthorized withdrawals",
                    location=f"Contract: {address}, Function: {func_name}",
                    exploit_path="1. Call withdrawal function\n2. Specify own address\n3. Drain contract balance",
                    impact="Complete drainage of contract ETH/token balance",
                    proof_of_concept=f"await contract.{func_name}();",
                    recommendation="Add proper access control to withdrawal functions",
                    confidence=0.95
                )
                self.vulnerabilities.append(vuln)

    def _check_decompiled_storage_issues(self, code: str, address: str):
        """Check decompiled code for storage manipulation issues"""
        # Look for direct storage manipulation without checks
        storage_writes = re.findall(r'([a-zA-Z_]\w*)\[([^\]]+)\]\s*=\s*([^;]+);', code)
        
        for storage_var, key, value in storage_writes:
            if 'msg.sender' in key and 'require(' not in code[:code.find(f'{storage_var}[{key}]')]:
                vuln = Vulnerability(
                    title="Unchecked Storage Manipulation",
                    severity=VulnSeverity.HIGH,
                    description=f"Direct manipulation of {storage_var} mapping without authorization",
                    location=f"Contract: {address}",
                    exploit_path="1. Call function that modifies storage\n2. Set arbitrary values\n3. Bypass access controls",
                    impact="Access control bypass through storage manipulation",
                    proof_of_concept=f"{storage_var}[{key}] = {value};",
                    recommendation="Add proper authorization checks before storage modifications",
                    confidence=0.7
                )
                self.vulnerabilities.append(vuln)

    def _check_decompiled_initialization(self, code: str, address: str):
        """Check for initialization issues in decompiled code"""
        # Look for mapping declarations that might be uninitialized
        mappings = re.findall(r'mapping\s*\([^)]+\)\s*(\w+);', code)
        
        for mapping_name in mappings:
            if any(keyword in mapping_name.lower() for keyword in ['admin', 'owner', 'auth']):
                vuln = Vulnerability(
                    title=f"Potentially Uninitialized Access Control Mapping: {mapping_name}",
                    severity=VulnSeverity.MEDIUM,
                    description=f"Access control mapping {mapping_name} may not be properly initialized",
                    location=f"Contract: {address}",
                    exploit_path="1. Verify mapping is empty\n2. Check if admin functions are accessible\n3. Contract may be in broken state",
                    impact="Admin functions may be permanently inaccessible due to initialization failure",
                    proof_of_concept=f"// Check if {mapping_name}[address] is empty for all addresses",
                    recommendation="Verify proper initialization in constructor or initialization function",
                    confidence=0.5
                )
                self.vulnerabilities.append(vuln)

    def _analyze_function_selectors(self, address: str):
        """Analyze function selectors for suspicious patterns"""
        # This would require more advanced bytecode analysis
        # For now, we'll implement basic checks
        pass

    def _check_constructor_flaws(self, address: str):
        """Check for constructor implementation flaws"""
        # This would analyze constructor code for initialization issues
        pass

    def _convert_pattern_vulns_to_vulnerabilities(self, pattern_vulns: List[Dict], address: str):
        """Convert pattern engine results to Vulnerability objects"""
        for pv in pattern_vulns:
            severity = getattr(VulnSeverity, pv.get('severity', 'MEDIUM'))
            
            vuln = Vulnerability(
                title=pv.get('title', 'Pattern-based vulnerability'),
                severity=severity,
                description=pv.get('description', 'Vulnerability detected by pattern analysis'),
                location=f"Contract: {address}, {pv.get('location', 'Unknown location')}",
                exploit_path=self._format_exploit_conditions(pv.get('exploit_conditions', [])),
                impact=self._determine_impact(severity),
                proof_of_concept=pv.get('matched_text', 'Pattern matched'),
                recommendation="Review and fix the identified pattern",
                confidence=pv.get('confidence', 0.7)
            )
            self.vulnerabilities.append(vuln)

    def _convert_bytecode_vulns_to_vulnerabilities(self, bytecode_results: Dict, address: str):
        """Convert bytecode analyzer results to Vulnerability objects"""
        for bv in bytecode_results.get('vulnerabilities', []):
            severity_map = {
                'CRITICAL': VulnSeverity.CRITICAL,
                'HIGH': VulnSeverity.HIGH,
                'MEDIUM': VulnSeverity.MEDIUM,
                'LOW': VulnSeverity.LOW
            }
            severity = severity_map.get(bv.get('severity', 'MEDIUM'), VulnSeverity.MEDIUM)
            
            vuln = Vulnerability(
                title=bv.get('type', 'Bytecode vulnerability').replace('_', ' ').title(),
                severity=severity,
                description=bv.get('description', 'Vulnerability detected in bytecode analysis'),
                location=f"Contract: {address}, Function: {bv.get('function', 'Unknown')}",
                exploit_path="Bytecode-level vulnerability detected",
                impact=self._determine_impact(severity),
                proof_of_concept=bv.get('pattern', 'Bytecode pattern matched'),
                recommendation="Review bytecode implementation and fix identified issues",
                confidence=bv.get('confidence', 0.6)
            )
            self.vulnerabilities.append(vuln)

    def _format_exploit_conditions(self, conditions: List[str]) -> str:
        """Format exploit conditions into a readable string"""
        if not conditions:
            return "No specific exploit conditions identified"
        
        formatted = "Exploit Conditions:\n"
        for i, condition in enumerate(conditions, 1):
            formatted += f"{i}. {condition}\n"
        return formatted

    def _determine_impact(self, severity: VulnSeverity) -> str:
        """Determine impact description based on severity"""
        impact_map = {
            VulnSeverity.CRITICAL: "Complete loss of funds, contract compromise, or unauthorized access to all assets",
            VulnSeverity.HIGH: "Significant financial loss, unauthorized access to user funds, or major functionality bypass", 
            VulnSeverity.MEDIUM: "Moderate financial loss, limited unauthorized access, or functionality disruption",
            VulnSeverity.LOW: "Minor financial loss or functionality issues",
            VulnSeverity.INFO: "Information disclosure or best practice violations"
        }
        return impact_map.get(severity, "Unknown impact level")

    def _analyze_raw_bytecode(self, bytecode: str, address: str):
        """Analyze raw bytecode for vulnerabilities"""
        # Basic bytecode analysis
        if len(bytecode) < 100:
            vuln = Vulnerability(
                title="Suspiciously Small Bytecode",
                severity=VulnSeverity.MEDIUM,
                description="Contract bytecode is unusually small, may be a proxy or have limited functionality",
                location=f"Contract: {address}",
                exploit_path="1. Analyze proxy pattern\n2. Check for upgrade mechanisms\n3. Look for implementation vulnerabilities",
                impact="Potential proxy vulnerabilities or incomplete implementation",
                proof_of_concept=f"Bytecode length: {len(bytecode)} bytes",
                recommendation="Verify contract implementation and proxy patterns",
                confidence=0.4
            )
            self.vulnerabilities.append(vuln)

    def _fetch_contract_source(self, address: str) -> Optional[str]:
        """Fetch verified contract source code from Etherscan"""
        if not self.api_key:
            return None
            
        try:
            url = f"https://api.etherscan.io/v2/api"
            params = {
                'chainid': '1',
                'module': 'contract',
                'action': 'getsourcecode',
                'address': address,
                'apikey': self.api_key
            }
            response = requests.get(url, params=params)
            data = response.json()
            
            if data.get('status') == '1' and data.get('result'):
                return data['result'][0].get('SourceCode', '')
        except Exception as e:
            print(f"[-] Error fetching source code: {e}")
        
        return None


def main():
    """Main function to demonstrate scanner usage"""
    
    # Load API key from environment or config
    api_key = os.getenv('ETHERSCAN_API_KEY', 'FSN464PWAV4HJQ8NC8X67DFF6FN9ZIV899')
    
    scanner = DeepContractScanner(api_key)
    
    print("=== Deep Smart Contract Vulnerability Scanner ===")
    print("Focus: Non-privileged fund drain exploits")
    print()
    
    # Example usage
    contract_address = "0x4bccA4a0Bfa325dc00E9c498A62EA271aA31Cf4D"
    
    # Read decompiled code if available
    decompiled_file = "bsc/decomplie.txt"
    if os.path.exists(decompiled_file):
        with open(decompiled_file, 'r') as f:
            decompiled_code = f.read()
        
        vulnerabilities = scanner.scan_contract(
            contract_address=contract_address,
            decompiled_code=decompiled_code
        )
        
        if vulnerabilities:
            print(f"[+] Found {len(vulnerabilities)} potential vulnerabilities!")
            scanner.generate_report(contract_address, f"vulnerability_report_{contract_address}.md")
        else:
            print("[-] No critical vulnerabilities found")
    else:
        print("[-] No decompiled code file found")
        print("[*] Usage: python deep_vuln_scanner.py")
        print("[*] Ensure bsc/decomplie.txt exists or provide source code")

if __name__ == "__main__":
    main()