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
from ultra_strict_validator import UltraStrictValidator
from proxy_detector import ProxyDetector, ProxyInfo, ProxyType
from storage_analyzer import StorageAnalyzer, StorageVulnerability, StorageVulnerabilityType
from enhanced_vulnerability_patterns import EnhancedVulnerabilityPatterns, EnhancedVulnPattern
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

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
    def __init__(self, etherscan_api_key: str = None, chain_config: Dict = None, enable_ai_validation: bool = True):
        # Load API keys from environment
        self.api_key = etherscan_api_key or os.getenv('ETHERSCAN_API_KEY')
        self.vulnerabilities = []
        self.bytecode_analyzer = BytecodeAnalyzer()
        self.pattern_engine = AdvancedPatternEngine()
        self.ultra_strict_validator = UltraStrictValidator()
        self.proxy_detector = ProxyDetector(api_key=self.api_key, chain_config=chain_config)
        self.storage_analyzer = StorageAnalyzer(api_key=self.api_key, chain_config=chain_config)
        self.enhanced_patterns = EnhancedVulnerabilityPatterns()
        
        # Progress tracking for CLI output
        self.current_progress = 0
        self.scan_phases = [
            "🔍 Initializing vulnerability scanner",
            "🔍 Proxy detection analysis", 
            "🔍 Enhanced critical pattern analysis",
            "🔍 Storage-level vulnerability analysis",
            "🔍 Reentrancy detection",
            "🔍 Access control analysis", 
            "🔍 Arithmetic vulnerability detection",
            "🔍 ERC20 handling analysis",
            "🔍 Reward distribution logic",
            "🔍 Signature replay detection",
            "🔍 Privilege escalation patterns",
            "🔍 Oracle manipulation analysis",
            "🔍 Flash loan exploit detection",
            "🔍 Cross-function reentrancy",
            "🔍 Storage collision analysis",
            "✅ Finalizing vulnerability report"
        ]
        
        # Chain configuration with unified Etherscan API v2
        # All chains use the same API endpoint with different chain IDs
        self.chain_config = chain_config or {
            'chain_id': '1', 
            'api_base': 'https://api.etherscan.io/v2/api',
            'name': 'Ethereum'
        }
        
        # AI validation setup
        self.enable_ai_validation = enable_ai_validation and os.getenv('ENABLE_AI_VALIDATION', 'true').lower() == 'true'
        
        if self.enable_ai_validation:
            try:
                from ai_validator import AIVulnerabilityValidator
                self.ai_validator = AIVulnerabilityValidator()
                if self.ai_validator.enabled:
                    print("🤖 AI-powered false positive detection enabled")
                else:
                    self.enable_ai_validation = False
            except ImportError:
                print("⚠️  AI validator not available")
                self.enable_ai_validation = False
        
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
            'privilege_escalation': [
                # NEW: Advanced privilege escalation patterns
                r'function\s+\w*[Ss]etOwner\w*\s*\([^)]*\)\s*(?:public|external)(?![^{]*onlyOwner)',  # Unprotected setOwner
                r'function\s+\w*[Aa]ddAdmin\w*\s*\([^)]*\)\s*(?:public|external)(?![^{]*require\([^}]*msg\.sender)',  # Unprotected addAdmin
                r'function\s+\w*[Gg]rantRole\w*\s*\([^)]*\)\s*(?:public|external)(?![^{]*hasRole)',  # Unprotected grantRole
                r'function\s+\w*[Uu]pgrade\w*\s*\([^)]*\)\s*(?:public|external)(?![^{]*onlyOwner)',  # Unprotected upgrade
                r'delegatecall\s*\([^)]*\)(?![^;]*require\([^}]*owner)',  # Unprotected delegatecall
                r'assembly\s*\{[^}]*sstore\s*\([^)]*\)(?![^}]*require)',  # Direct storage manipulation
                r'_setImplementation\s*\([^)]*\)(?![^;]*onlyOwner)',  # Unprotected implementation change
                r'modifier\s+onlyOwner\s*\([^)]*\)\s*\{\s*_\s*;\s*\}',  # Empty onlyOwner modifier
                r'require\s*\(\s*msg\.sender\s*==\s*0x0+\s*\)',  # Impossible owner check
            ],
            'role_manipulation': [
                # NEW: Role-based access control bypasses
                r'hasRole\s*\([^,]*,\s*msg\.sender\s*\)\s*\|\|\s*true',  # Always true role check
                r'_roles\[.*\]\[.*\]\s*=\s*true(?![^;]*require)',  # Direct role assignment
                r'function\s+\w*[Rr]enounceRole\w*.*\{(?![^}]*require\([^}]*msg\.sender)',  # Unprotected role renouncement
                r'DEFAULT_ADMIN_ROLE\s*=\s*0x0+(?![^;]*private)',  # Public admin role constant
                r'_setupRole\s*\([^,]*,\s*[^)]*\)(?![^;]*require)',  # Unprotected role setup
            ],
            'proxy_manipulation': [
                # NEW: Proxy contract privilege escalation
                r'function\s+\w*[Uu]pgradeTo\w*\s*\([^)]*\)\s*(?:public|external)(?![^{]*onlyAdmin)',  # Unprotected proxy upgrade
                r'_setImplementation\s*\([^)]*\)(?![^;]*_authorizeUpgrade)',  # Missing upgrade authorization
                r'function\s+initialize\s*\([^)]*\)\s*public(?![^{]*initializer)',  # Re-initializable function
                r'assembly\s*\{[^}]*delegatecall\s*\([^)]*\)(?![^}]*auth)',  # Unprotected assembly delegatecall
                r'StorageSlot\.getAddressSlot\s*\([^)]*\)\.value\s*=(?![^;]*onlyOwner)',  # Direct storage slot manipulation
            ],
            'function_selector_collision': [
                # NEW: Function selector collision attacks
                r'function\s+\w+\s*\([^)]*\)\s*(?:public|external).*fallback',  # Function shadowing fallback
                r'bytes4\s*selector\s*=\s*this\.\w+\.selector(?![^;]*require)',  # Manipulated selector
                r'function\s+0x[a-fA-F0-9]{8}\s*\(',  # Direct function selector definition
                r'msg\.sig\s*==\s*0x[a-fA-F0-9]{8}(?![^&]*owner)',  # Hardcoded selector check without auth
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
            ],
            'signature_replay': [
                # NEW: Signature replay and manipulation
                r'ecrecover\s*\([^)]*\)(?![^;]*nonce)',  # ecrecover without nonce protection
                r'function\s+\w*[Pp]ermit\w*.*(?![^{]*deadline)',  # Permit without deadline
                r'_nonces\[.*\](?!\+\+)',  # Nonce not incremented
                r'bytes32\s+digest\s*=.*(?![^;]*block\.timestamp)',  # Missing timestamp in digest
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
                     decompiled_code: str = None, bytecode: str = None, 
                     combine_sources: bool = False) -> List[Vulnerability]:
        """
        Main scanning function - analyzes contract for vulnerabilities
        """
        self.vulnerabilities = []
        
        print(f"🚀 STARTING DEEP VULNERABILITY SCAN")
        print(f"📊 Contract: {contract_address}")
        print(f"🌐 Blockchain: {self.chain_config.get('name', 'Ethereum')} (Chain ID: {self.chain_config.get('chain_id', '1')})")
        print(f"🔍 Analysis Mode: {'Source Code' if source_code else 'Decompiled' if decompiled_code else 'Bytecode'}")
        print("=" * 80)
        
        # 🆕 PHASE 1: Detect if contract is a proxy
        self._emit_progress("🔍 Phase 1: Proxy Detection Analysis", 5)
        proxy_info = self.proxy_detector.detect_proxy(contract_address, source_code, bytecode)
        
        if proxy_info.proxy_type != ProxyType.NOT_PROXY:
            self._emit_progress(f"✅ PROXY DETECTED: {proxy_info.proxy_type.value}", 10)
            print(f"    🎯 Confidence: {proxy_info.confidence:.0%}")
            print(f"    🔧 Detection Method: {proxy_info.detection_method}")
            
            if proxy_info.implementation_address:
                print(f"    📍 Implementation: {proxy_info.implementation_address}")
            if proxy_info.admin_address:
                print(f"    👤 Admin: {proxy_info.admin_address}")
            if proxy_info.facets:
                print(f"    💎 Facets: {len(proxy_info.facets)} contracts")
            
            # Scan all relevant contracts (proxy + implementation + facets)
            all_addresses = self.proxy_detector.get_all_implementation_addresses(proxy_info)
            self._emit_progress(f"🔍 Scanning {len(all_addresses)} related contracts", 15)
            
            # Enhanced proxy-specific vulnerability patterns
            self._add_proxy_specific_vulnerabilities(proxy_info)
            
            return self._scan_proxy_architecture(all_addresses, proxy_info, source_code, decompiled_code, bytecode, combine_sources)
        else:
            self._emit_progress("ℹ️ Regular contract detected (not a proxy)", 10)
        
        # Get contract info from blockchain API
        contract_info = self._fetch_contract_info(contract_address)
        
        # Combined analysis mode
        if combine_sources:
            print("[+] Combined analysis mode enabled - analyzing all available sources")
            return self._combined_analysis(contract_address, source_code, decompiled_code, bytecode)
        
        if source_code:
            self._emit_progress("🔍 Analyzing verified Solidity source code", 20)
            self._analyze_solidity_source(source_code, contract_address)
            
            self._emit_progress("🔍 Advanced pattern matching on source", 35)
            pattern_vulns = self.pattern_engine.scan_for_patterns(source_code, "solidity")
            self._convert_pattern_vulns_to_vulnerabilities(pattern_vulns, contract_address)
            
        elif decompiled_code:
            self._emit_progress("🔍 Analyzing decompiled bytecode", 20)
            self._analyze_decompiled_code(decompiled_code, contract_address)
            
            self._emit_progress("🔍 Decompiled pattern analysis", 35)
            decompiled_vulns = self.pattern_engine.analyze_decompiled_patterns(decompiled_code)
            self._convert_pattern_vulns_to_vulnerabilities(decompiled_vulns, contract_address)
            
        elif bytecode:
            self._emit_progress("🔍 Analyzing raw bytecode", 20)
            self._analyze_raw_bytecode(bytecode, contract_address)
            
            self._emit_progress("🔍 Deep bytecode analysis", 35)
            bytecode_results = self.bytecode_analyzer.analyze_bytecode(bytecode)
            self._convert_bytecode_vulns_to_vulnerabilities(bytecode_results, contract_address)
            
        else:
            # Try to fetch from blockchain
            self._emit_progress("🔍 Fetching contract from blockchain", 15)
            source = self._fetch_contract_source(contract_address)
            if source:
                self._emit_progress("🔍 Analyzing blockchain source code", 25)
                self._analyze_solidity_source(source, contract_address)
                pattern_vulns = self.pattern_engine.scan_for_patterns(source, "solidity")
                self._convert_pattern_vulns_to_vulnerabilities(pattern_vulns, contract_address)
            else:
                self._emit_progress("❌ No source code available", 25)
                
        # Additional analysis phases
        self._emit_progress("🔍 Storage layout analysis", 45)
        self._analyze_storage_layout(contract_address)
        
        self._emit_progress("🔍 Function selector analysis", 50)
        self._analyze_function_selectors(contract_address)
        
        self._emit_progress("🔍 Constructor vulnerability check", 55)
        self._check_constructor_flaws(contract_address)
        
        # 🆕 PHASE 6: Enhanced Critical Vulnerability Pattern Analysis  
        self._emit_progress("🔍 Enhanced critical pattern analysis", 60)
        self._perform_enhanced_pattern_analysis(contract_address, source_code, decompiled_code)
        
        # 🆕 PHASE 7: Comprehensive Storage Analysis
        self._emit_progress("🔍 Comprehensive storage analysis", 70)
        self._perform_comprehensive_storage_analysis([contract_address], source_code, decompiled_code)
        
        # Ultra-strict non-privileged validation (always applied)
        if self.vulnerabilities:
            self._emit_progress("🤖 Ultra-strict fund drain validation", 80)
            initial_count = len(self.vulnerabilities)
            self.vulnerabilities = self.ultra_strict_validator.ultra_strict_validate(self.vulnerabilities)
            filtered_count = len(self.vulnerabilities)
            print(f"      🎯 Filtered: {initial_count} → {filtered_count} vulnerabilities")
        
        # AI validation of findings (additional layer)
        if self.enable_ai_validation and self.vulnerabilities:
            self._emit_progress("🧠 AI validation for false positive elimination", 90)
            self.vulnerabilities = self.ai_validator.validate_vulnerabilities(self.vulnerabilities)
            print(f"      🎯 AI validated: {len(self.vulnerabilities)} final vulnerabilities")
        
        # Final ranking and report generation
        self._emit_progress("✅ Finalizing vulnerability report", 95)
        ranked_vulns = self._rank_vulnerabilities()
        
        self._emit_progress("🎯 Scan complete!", 100)
        print("=" * 80)
        print(f"🎉 SCAN COMPLETED SUCCESSFULLY!")
        print(f"📊 Total vulnerabilities found: {len(ranked_vulns)}")
        if ranked_vulns:
            critical_count = len([v for v in ranked_vulns if v.severity == VulnSeverity.CRITICAL])
            high_count = len([v for v in ranked_vulns if v.severity == VulnSeverity.HIGH])
            print(f"🔴 Critical: {critical_count} | 🟠 High: {high_count}")
        print("=" * 80)
        
        return ranked_vulns

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
        
        # 8. NEW: Check for privilege escalation patterns
        self._check_privilege_escalation_patterns(source_code, contract_address)
        
        # 9. NEW: Check for role manipulation patterns
        self._check_role_manipulation_patterns(source_code, contract_address)
        
        # 10. NEW: Check for signature replay patterns
        self._check_signature_replay_patterns(source_code, contract_address)
        
        # Emit progress for web UI
        self._emit_progress("✅ Solidity analysis complete", 95)

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
        """Fetch contract information from blockchain API"""
        if not self.api_key:
            return {}
            
        try:
            url = self.chain_config['api_base']
            params = {
                'module': 'account',
                'action': 'balance', 
                'address': address,
                'tag': 'latest',
                'apikey': self.api_key
            }
            
            # Add chainid for v2 APIs
            if 'v2' in url:
                params['chainid'] = self.chain_config['chain_id']
                
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
                url = self.chain_config['api_base']
                params = {
                    'module': 'proxy',
                    'action': 'eth_getStorageAt',
                    'address': address,
                    'position': slot,
                    'tag': 'latest',
                    'apikey': self.api_key
                }
                
                # Add chainid for v2 APIs
                if 'v2' in url:
                    params['chainid'] = self.chain_config['chain_id']
                
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

    def generate_report(self, contract_address: str, output_file: str = None, scan_params: dict = None):
        """Generate detailed vulnerability report with enhanced naming"""
        
        if not self.vulnerabilities:
            print("[-] No vulnerabilities found")
            return None
            
        # Generate smart filename if not provided
        if not output_file:
            output_file = self._generate_report_filename(contract_address, scan_params or {})
        
        report = f"""
# Smart Contract Security Report
## Contract: {contract_address}
## Scan Date: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
## Scan Parameters: {self._format_scan_params(scan_params or {})}

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
            return output_file
        else:
            print(report)
            return None

    def _generate_report_filename(self, contract_address: str, scan_params: dict) -> str:
        """Generate smart filename based on contract address with versioning"""
        import os
        from datetime import datetime
        
        # Clean contract address for filename
        if contract_address and contract_address != '0x0000000000000000000000000000000000000000':
            base_name = contract_address.replace('0x', '')[:16]  # Use first 16 chars after 0x
        else:
            # For non-deployed contracts, use timestamp
            base_name = f"contract_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Add scan type suffix
        scan_suffix = []
        if scan_params.get('non_privileged_only'):
            scan_suffix.append('nonpriv')
        if scan_params.get('enable_ai'):
            scan_suffix.append('ai')
        if scan_params.get('severity'):
            scan_suffix.append(scan_params['severity'].lower())
        
        suffix_str = '_' + '_'.join(scan_suffix) if scan_suffix else ''
        
        # Check for existing reports and add version number
        reports_dir = 'reports'
        os.makedirs(reports_dir, exist_ok=True)
        
        base_filename = f"{base_name}{suffix_str}"
        version = 1
        
        while True:
            if version == 1:
                filename = f"{reports_dir}/{base_filename}.md"
            else:
                filename = f"{reports_dir}/{base_filename}-{version}.md"
            
            if not os.path.exists(filename):
                return filename
            version += 1

    def _format_scan_params(self, scan_params: dict) -> str:
        """Format scan parameters for report"""
        params = []
        if scan_params.get('chain'):
            params.append(f"Chain: {scan_params['chain']}")
        if scan_params.get('non_privileged_only'):
            params.append("Non-Privileged Only: ✅")
        if scan_params.get('enable_ai'):
            params.append("AI Validation: ✅")
        if scan_params.get('severity'):
            params.append(f"Min Severity: {scan_params['severity']}")
        if scan_params.get('source_type'):
            params.append(f"Source: {scan_params['source_type']}")
        
        return ' | '.join(params) if params else 'Default settings'

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

    def _combined_analysis(self, contract_address: str, source_code: str = None, 
                          decompiled_code: str = None, bytecode: str = None) -> List[Vulnerability]:
        """Perform combined analysis using multiple source types simultaneously"""
        
        print("[+] Starting comprehensive multi-source analysis...")
        
        # Track analysis results from each source
        analysis_results = {
            'source_patterns': [],
            'decompiled_patterns': [], 
            'bytecode_results': [],
            'cross_validation': []
        }
        
        # 1. Analyze verified source code if available
        if source_code and source_code.strip():
            print("[+] Analyzing verified Solidity source...")
            self._analyze_solidity_source(source_code, contract_address)
            pattern_vulns = self.pattern_engine.scan_for_patterns(source_code, "solidity")
            self._convert_pattern_vulns_to_vulnerabilities(pattern_vulns, contract_address)
            analysis_results['source_patterns'] = pattern_vulns
            print(f"    ✅ Found {len(pattern_vulns)} patterns in source code")
        
        # 2. Analyze decompiled code if available
        if decompiled_code and decompiled_code.strip():
            print("[+] Analyzing decompiled code...")
            self._analyze_decompiled_code(decompiled_code, contract_address)
            decompiled_vulns = self.pattern_engine.analyze_decompiled_patterns(decompiled_code)
            self._convert_pattern_vulns_to_vulnerabilities(decompiled_vulns, contract_address)
            analysis_results['decompiled_patterns'] = decompiled_vulns
            print(f"    ✅ Found {len(decompiled_vulns)} patterns in decompiled code")
        
        # 3. Analyze bytecode if available
        if bytecode and bytecode.strip():
            print("[+] Analyzing raw bytecode...")
            self._analyze_raw_bytecode(bytecode, contract_address)
            bytecode_results = self.bytecode_analyzer.analyze_bytecode(bytecode)
            self._convert_bytecode_vulns_to_vulnerabilities(bytecode_results, contract_address)
            analysis_results['bytecode_results'] = bytecode_results
            print(f"    ✅ Found {len(bytecode_results.get('vulnerabilities', []))} bytecode vulnerabilities")
        
        # 4. Cross-validation: Compare findings across sources
        print("[+] Performing cross-validation...")
        cross_validated = self._cross_validate_findings(analysis_results)
        
        # 5. Additional analysis
        self._analyze_storage_layout(contract_address)
        self._analyze_function_selectors(contract_address)
        self._check_constructor_flaws(contract_address)
        
        print(f"[+] Combined analysis complete: {len(self.vulnerabilities)} total vulnerabilities found")
        print(f"[+] Cross-validated findings: {len(cross_validated)} high-confidence vulnerabilities")
        
        return self._rank_vulnerabilities()

    def _cross_validate_findings(self, analysis_results: Dict) -> List[Dict]:
        """Cross-validate findings across different source types"""
        
        validated_findings = []
        
        # Compare source code and decompiled patterns
        source_patterns = analysis_results.get('source_patterns', [])
        decompiled_patterns = analysis_results.get('decompiled_patterns', [])
        
        for source_vuln in source_patterns:
            for decompiled_vuln in decompiled_patterns:
                # Check if vulnerabilities are similar
                if self._are_similar_vulnerabilities(source_vuln, decompiled_vuln):
                    validated_findings.append({
                        'title': f"Cross-Validated: {source_vuln.get('title', 'Unknown')}",
                        'confidence': 0.95,  # High confidence due to cross-validation
                        'sources': ['source_code', 'decompiled'],
                        'description': f"Vulnerability confirmed in both source and decompiled analysis: {source_vuln.get('description', '')}",
                        'severity': 'CRITICAL'
                    })
        
        # Look for bytecode-specific vulnerabilities that confirm source findings
        bytecode_results = analysis_results.get('bytecode_results', {})
        bytecode_vulns = bytecode_results.get('vulnerabilities', [])
        
        for bytecode_vuln in bytecode_vulns:
            if bytecode_vuln.get('type') == 'unauthorized_transfer':
                validated_findings.append({
                    'title': f"Bytecode-Confirmed: {bytecode_vuln.get('description', 'Unauthorized Transfer')}",
                    'confidence': 0.9,
                    'sources': ['bytecode'],
                    'description': f"Bytecode analysis confirms unauthorized transfer capability",
                    'severity': 'CRITICAL'
                })
        
        return validated_findings

    def _are_similar_vulnerabilities(self, vuln1: Dict, vuln2: Dict) -> bool:
        """Check if two vulnerabilities are describing the same issue"""
        
        # Extract titles and descriptions
        title1 = vuln1.get('title', '').lower()
        title2 = vuln2.get('title', '').lower()
        desc1 = vuln1.get('description', '').lower()
        desc2 = vuln2.get('description', '').lower()
        
        # Look for common keywords
        common_keywords = [
            'transfer', 'unauthorized', 'approval', 'drain', 'funds',
            'reentrancy', 'access control', 'admin', 'owner'
        ]
        
        # Check if they share similar vulnerability types
        shared_keywords = 0
        for keyword in common_keywords:
            if (keyword in title1 or keyword in desc1) and (keyword in title2 or keyword in desc2):
                shared_keywords += 1
        
        return shared_keywords >= 2

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
        """Fetch verified contract source code from blockchain API"""
        if not self.api_key:
            return None
            
        try:
            url = self.chain_config['api_base']
            params = {
                'module': 'contract',
                'action': 'getsourcecode',
                'address': address,
                'apikey': self.api_key
            }
            
            # Add chainid for v2 APIs
            if 'v2' in url:
                params['chainid'] = self.chain_config['chain_id']
                
            response = requests.get(url, params=params)
            data = response.json()
            
            if data.get('status') == '1' and data.get('result'):
                return data['result'][0].get('SourceCode', '')
        except Exception as e:
            print(f"[-] Error fetching source code: {e}")
        
        return None

    def _check_privilege_escalation_patterns(self, code: str, address: str):
        """Check for privilege escalation vulnerabilities using new patterns"""
        patterns = self.critical_patterns['privilege_escalation']
        
        for pattern in patterns:
            matches = re.finditer(pattern, code, re.MULTILINE | re.DOTALL)
            for match in matches:
                matched_text = match.group(0)
                
                # Determine specific vulnerability type
                if 'setOwner' in matched_text.lower():
                    title = "Unprotected setOwner Function"
                    description = "Function allows anyone to change contract ownership without authorization"
                    exploit_path = "1. Call setOwner() with attacker address\n2. Gain full contract control\n3. Access all privileged functions"
                elif 'addAdmin' in matched_text.lower():
                    title = "Unprotected addAdmin Function" 
                    description = "Function allows anyone to grant admin privileges without authorization"
                    exploit_path = "1. Call addAdmin() with attacker address\n2. Gain admin privileges\n3. Access admin-only functions"
                elif 'grantRole' in matched_text.lower():
                    title = "Unprotected grantRole Function"
                    description = "Function allows anyone to grant roles without proper access control"
                    exploit_path = "1. Call grantRole() with desired role\n2. Grant role to attacker\n3. Access role-protected functions"
                elif 'delegatecall' in matched_text.lower():
                    title = "Unprotected delegatecall"
                    description = "Function allows arbitrary delegatecall without authorization checks"
                    exploit_path = "1. Deploy malicious contract\n2. Call delegatecall with malicious address\n3. Execute arbitrary code in contract context"
                else:
                    title = "Privilege Escalation Vulnerability"
                    description = "Function allows unauthorized privilege escalation"
                    exploit_path = "1. Identify unprotected function\n2. Call function to escalate privileges\n3. Access protected functionality"
                
                vuln = Vulnerability(
                    title=title,
                    severity=VulnSeverity.CRITICAL,
                    description=description,
                    location=f"Contract: {address}, Code: {matched_text[:100]}...",
                    exploit_path=exploit_path,
                    impact="Complete contract takeover and unauthorized access to all functions",
                    proof_of_concept=matched_text,
                    recommendation="Add proper access control (onlyOwner, require checks, or role-based access)",
                    confidence=0.95
                )
                self.vulnerabilities.append(vuln)

    def _check_role_manipulation_patterns(self, code: str, address: str):
        """Check for role manipulation vulnerabilities using new patterns"""
        patterns = self.critical_patterns['role_manipulation']
        
        for pattern in patterns:
            matches = re.finditer(pattern, code, re.MULTILINE | re.DOTALL)
            for match in matches:
                matched_text = match.group(0)
                
                vuln = Vulnerability(
                    title="Role-Based Access Control Bypass",
                    severity=VulnSeverity.HIGH,
                    description="Role-based access control can be bypassed or manipulated without proper authorization",
                    location=f"Contract: {address}, Code: {matched_text[:100]}...",
                    exploit_path="1. Identify role manipulation vulnerability\n2. Bypass role checks or grant unauthorized roles\n3. Access role-protected functions",
                    impact="Unauthorized access to role-protected functions and potential privilege escalation",
                    proof_of_concept=matched_text,
                    recommendation="Implement proper role validation and secure role assignment mechanisms",
                    confidence=0.9
                )
                self.vulnerabilities.append(vuln)

    def _check_signature_replay_patterns(self, code: str, address: str):
        """Check for signature replay vulnerabilities using new patterns"""
        patterns = self.critical_patterns['signature_replay']
        
        for pattern in patterns:
            matches = re.finditer(pattern, code, re.MULTILINE | re.DOTALL)
            for match in matches:
                matched_text = match.group(0)
                
                # Determine specific vulnerability type
                if 'ecrecover' in matched_text.lower() and 'nonce' not in matched_text.lower():
                    title = "Signature Replay via ecrecover"
                    description = "ecrecover implementation lacks nonce protection, allowing signature replay attacks"
                    exploit_path = "1. Capture valid signature\n2. Replay signature multiple times\n3. Execute unauthorized transactions"
                elif 'permit' in matched_text.lower():
                    title = "Vulnerable Permit Implementation"
                    description = "Permit function lacks deadline or nonce protection"
                    exploit_path = "1. Obtain permit signature\n2. Replay signature after intended use\n3. Unauthorized token approvals"
                else:
                    title = "Signature Replay Vulnerability"
                    description = "Implementation allows signature replay attacks"
                    exploit_path = "1. Capture signature\n2. Replay in different context\n3. Unauthorized operations"
                
                vuln = Vulnerability(
                    title=title,
                    severity=VulnSeverity.HIGH,
                    description=description,
                    location=f"Contract: {address}, Code: {matched_text[:100]}...",
                    exploit_path=exploit_path,
                    impact="Unauthorized transactions through signature replay, potential fund theft",
                    proof_of_concept=matched_text,
                    recommendation="Implement nonce tracking, deadline checks, and proper signature validation",
                    confidence=0.85
                )
                self.vulnerabilities.append(vuln)

    def _add_proxy_specific_vulnerabilities(self, proxy_info: ProxyInfo):
        """Add proxy-specific vulnerabilities based on detected proxy type"""
        
        if proxy_info.proxy_type == ProxyType.EIP1967_TRANSPARENT:
            if proxy_info.admin_address and proxy_info.admin_address == '0x0000000000000000000000000000000000000000':
                vuln = Vulnerability(
                    title="Transparent Proxy with Zero Admin Address",
                    severity=VulnSeverity.CRITICAL,
                    description="EIP-1967 transparent proxy has zero admin address, making upgrades impossible",
                    location=f"Proxy: {proxy_info.proxy_address}",
                    exploit_path="1. Verify admin slot is zero\n2. All upgrade functions fail\n3. Proxy cannot be upgraded",
                    impact="Proxy is permanently locked, no upgrades possible, potential permanent bugs",
                    proof_of_concept="eth_getStorageAt(proxyAddress, adminSlot) returns 0x0",
                    recommendation="Set proper admin address or use UUPS pattern",
                    confidence=0.95
                )
                self.vulnerabilities.append(vuln)
        
        elif proxy_info.proxy_type == ProxyType.EIP1967_UUPS:
            if not proxy_info.implementation_address:
                vuln = Vulnerability(
                    title="UUPS Proxy with Invalid Implementation",
                    severity=VulnSeverity.HIGH,
                    description="UUPS proxy implementation address is invalid or zero",
                    location=f"Proxy: {proxy_info.proxy_address}",
                    exploit_path="1. Check implementation slot\n2. Implementation is zero or invalid\n3. All calls fail",
                    impact="Proxy is non-functional, all function calls will fail",
                    proof_of_concept="eth_getStorageAt(proxyAddress, implementationSlot) invalid",
                    recommendation="Set valid implementation address",
                    confidence=0.9
                )
                self.vulnerabilities.append(vuln)
        
        elif proxy_info.proxy_type == ProxyType.EIP2535_DIAMOND:
            if proxy_info.facets and len(proxy_info.facets) > 10:
                vuln = Vulnerability(
                    title="Diamond Proxy with Excessive Facets",
                    severity=VulnSeverity.MEDIUM,
                    description=f"Diamond proxy has {len(proxy_info.facets)} facets, increasing complexity and attack surface",
                    location=f"Proxy: {proxy_info.proxy_address}",
                    exploit_path="1. Analyze large number of facets\n2. Look for inconsistencies\n3. Exploit facet interactions",
                    impact="Increased attack surface, potential for facet conflicts and vulnerabilities",
                    proof_of_concept=f"Diamond has {len(proxy_info.facets)} facets - high complexity",
                    recommendation="Minimize facet count and ensure proper access control across all facets",
                    confidence=0.7
                )
                self.vulnerabilities.append(vuln)
        
        elif proxy_info.proxy_type == ProxyType.MINIMAL_PROXY:
            if proxy_info.implementation_address:
                vuln = Vulnerability(
                    title="Minimal Proxy Implementation Risk",
                    severity=VulnSeverity.MEDIUM,
                    description="Minimal proxy (EIP-1167) is immutable - implementation vulnerabilities cannot be fixed",
                    location=f"Proxy: {proxy_info.proxy_address}, Implementation: {proxy_info.implementation_address}",
                    exploit_path="1. Find vulnerabilities in implementation\n2. Exploit affects all clones\n3. Cannot upgrade to fix",
                    impact="Vulnerabilities in implementation affect all proxy clones permanently",
                    proof_of_concept="All minimal proxy clones share same immutable implementation",
                    recommendation="Thoroughly audit implementation before deploying minimal proxies",
                    confidence=0.8
                )
                self.vulnerabilities.append(vuln)

    def _scan_proxy_architecture(self, addresses: List[str], proxy_info: ProxyInfo, 
                                source_code: str = None, decompiled_code: str = None, 
                                bytecode: str = None, combine_sources: bool = False) -> List[Vulnerability]:
        """Scan complete proxy architecture including all related contracts"""
        
        print(f"[+] Comprehensive proxy architecture scan...")
        
        # Track which addresses we've analyzed
        analyzed_contracts = {}
        
        for address in addresses:
            print(f"[+] Analyzing contract: {address}")
            
            if address == proxy_info.proxy_address:
                print("    📋 Proxy Contract Analysis")
                contract_type = "proxy"
            elif address == proxy_info.implementation_address:
                print("    🔧 Implementation Contract Analysis")
                contract_type = "implementation"
            elif proxy_info.facets and address in proxy_info.facets:
                print(f"    💎 Diamond Facet Analysis")
                contract_type = "facet"
            else:
                print("    📋 Related Contract Analysis")
                contract_type = "related"
            
            # Try to get source code for this specific address
            contract_source = source_code if address == proxy_info.proxy_address else self._fetch_contract_source(address)
            contract_decompiled = decompiled_code if address == proxy_info.proxy_address else None
            
            # Analyze this specific contract
            if contract_source:
                print(f"    ✅ Analyzing verified source code...")
                self._analyze_solidity_source(contract_source, address)
                pattern_vulns = self.pattern_engine.scan_for_patterns(contract_source, "solidity")
                self._convert_pattern_vulns_to_vulnerabilities(pattern_vulns, address)
                
                # Add proxy-specific pattern analysis
                self._analyze_proxy_implementation_patterns(contract_source, address, contract_type, proxy_info)
                
            elif contract_decompiled or address == proxy_info.proxy_address:
                print(f"    ⚙️ Analyzing decompiled code...")
                code_to_analyze = contract_decompiled or self._fetch_and_decompile_contract(address)
                if code_to_analyze:
                    self._analyze_decompiled_code(code_to_analyze, address)
            else:
                print(f"    🔍 Analyzing bytecode patterns...")
                contract_bytecode = self._fetch_contract_bytecode(address)
                if contract_bytecode:
                    self._analyze_raw_bytecode(contract_bytecode, address)
            
            analyzed_contracts[address] = {
                'type': contract_type,
                'analyzed': True,
                'vulnerabilities_count': len([v for v in self.vulnerabilities if address in v.location])
            }
        
        # Cross-contract analysis for proxy-specific vulnerabilities
        print(f"[+] Cross-contract proxy vulnerability analysis...")
        self._analyze_proxy_cross_contract_vulnerabilities(proxy_info, analyzed_contracts)
        
        # Storage collision analysis
        if proxy_info.implementation_address:
            print(f"[+] Storage collision analysis...")
            self._analyze_storage_collisions(proxy_info)
        
        # 🆕 PHASE 7: Enhanced Critical Vulnerability Pattern Analysis
        print(f"[+] Phase 7: Enhanced critical vulnerability pattern analysis...")
        for address in addresses:
            contract_source = source_code if address == proxy_info.proxy_address else None
            contract_decompiled = decompiled_code if address == proxy_info.proxy_address else None
            self._perform_enhanced_pattern_analysis(address, contract_source, contract_decompiled)
        
        # 🆕 PHASE 8: Comprehensive Storage Analysis
        print(f"[+] Phase 8: Comprehensive storage-level analysis...")
        self._perform_comprehensive_storage_analysis(addresses)
        
        return self._rank_vulnerabilities()

    def _analyze_proxy_implementation_patterns(self, source_code: str, address: str, 
                                            contract_type: str, proxy_info: ProxyInfo):
        """Analyze proxy implementation for specific vulnerability patterns"""
        
        if contract_type == "implementation":
            # Check for constructor usage in implementation (should use initializer)
            if 'constructor(' in source_code and 'initializer' not in source_code:
                vuln = Vulnerability(
                    title="Implementation Uses Constructor Instead of Initializer",
                    severity=VulnSeverity.HIGH,
                    description="Implementation contract uses constructor which won't execute in proxy context",
                    location=f"Implementation: {address}",
                    exploit_path="1. Deploy proxy with this implementation\n2. Constructor code never executes\n3. Uninitialized state",
                    impact="Critical state variables remain uninitialized, potential for unauthorized access",
                    proof_of_concept="Constructor code in implementation is ignored by proxy",
                    recommendation="Replace constructor with initializer function and use initializer modifier",
                    confidence=0.9
                )
                self.vulnerabilities.append(vuln)
            
            # Check for self-destruct in implementation
            if 'selfdestruct(' in source_code or 'suicide(' in source_code:
                vuln = Vulnerability(
                    title="Self-Destruct in Proxy Implementation",
                    severity=VulnSeverity.CRITICAL,
                    description="Implementation contract contains self-destruct, could brick all proxies",
                    location=f"Implementation: {address}",
                    exploit_path="1. Call self-destruct function\n2. Implementation contract destroyed\n3. All proxies become non-functional",
                    impact="Complete failure of all proxy contracts using this implementation",
                    proof_of_concept="selfdestruct() call in implementation affects all proxies",
                    recommendation="Remove self-destruct from implementation or add strict access controls",
                    confidence=0.95
                )
                self.vulnerabilities.append(vuln)
                
        elif contract_type == "proxy":
            # Check for function selector collisions
            proxy_functions = re.findall(r'function\s+(\w+)\s*\(', source_code)
            implementation_source = self._fetch_contract_source(proxy_info.implementation_address) if proxy_info.implementation_address else None
            
            if implementation_source:
                impl_functions = re.findall(r'function\s+(\w+)\s*\(', implementation_source)
                collisions = set(proxy_functions) & set(impl_functions)
                
                if collisions:
                    vuln = Vulnerability(
                        title="Function Selector Collision Between Proxy and Implementation",
                        severity=VulnSeverity.HIGH,
                        description=f"Functions {', '.join(collisions)} exist in both proxy and implementation",
                        location=f"Proxy: {address}, Implementation: {proxy_info.implementation_address}",
                        exploit_path="1. Call ambiguous function\n2. Proxy function executes instead of implementation\n3. Bypass intended logic",
                        impact="Function calls may execute unintended code, potential access control bypass",
                        proof_of_concept=f"Colliding functions: {', '.join(collisions)}",
                        recommendation="Rename functions to avoid selector collisions",
                        confidence=0.8
                    )
                    self.vulnerabilities.append(vuln)

    def _analyze_proxy_cross_contract_vulnerabilities(self, proxy_info: ProxyInfo, analyzed_contracts: Dict):
        """Analyze vulnerabilities that span across proxy and implementation contracts"""
        
        # Check for admin key compromise scenarios
        if proxy_info.admin_address:
            vuln = Vulnerability(
                title="Centralized Proxy Admin Control",
                severity=VulnSeverity.MEDIUM,
                description="Single admin address controls proxy upgrades, creating centralization risk",
                location=f"Proxy: {proxy_info.proxy_address}, Admin: {proxy_info.admin_address}",
                exploit_path="1. Compromise admin private key\n2. Deploy malicious implementation\n3. Upgrade proxy to malicious code",
                impact="Complete compromise of proxy and user funds through admin key compromise",
                proof_of_concept="Admin can unilaterally upgrade to malicious implementation",
                recommendation="Use multisig or timelock for admin functions",
                confidence=0.7
            )
            self.vulnerabilities.append(vuln)
        
        # Check for upgrade frontrunning possibilities
        if proxy_info.proxy_type in [ProxyType.EIP1967_TRANSPARENT, ProxyType.EIP1967_UUPS]:
            vuln = Vulnerability(
                title="Proxy Upgrade Frontrunning Risk",
                severity=VulnSeverity.MEDIUM,
                description="Proxy upgrades can be frontrun to extract value before security fixes",
                location=f"Proxy: {proxy_info.proxy_address}",
                exploit_path="1. Monitor mempool for upgrade transactions\n2. Frontrun with exploit transaction\n3. Extract value before fix is applied",
                impact="Attackers can exploit known vulnerabilities before upgrades fix them",
                proof_of_concept="Mempool monitoring + MEV for upgrade frontrunning",
                recommendation="Use commit-reveal scheme or timelock for upgrades",
                confidence=0.6
            )
            self.vulnerabilities.append(vuln)

    def _analyze_storage_collisions(self, proxy_info: ProxyInfo):
        """Analyze potential storage slot collisions between proxy and implementation"""
        
        if not proxy_info.implementation_address:
            return
            
        # This would require more sophisticated analysis of storage layouts
        # For now, we provide a general warning about storage collision risks
        vuln = Vulnerability(
            title="Potential Storage Layout Collision Risk",
            severity=VulnSeverity.LOW,
            description="Proxy and implementation may have conflicting storage layouts",
            location=f"Proxy: {proxy_info.proxy_address}, Implementation: {proxy_info.implementation_address}",
            exploit_path="1. Analyze storage layouts\n2. Find overlapping slots\n3. Exploit storage conflicts",
            impact="Data corruption or unexpected behavior due to storage conflicts",
            proof_of_concept="Manual analysis required for storage layout verification",
            recommendation="Use OpenZeppelin upgradeable contracts pattern with storage gaps",
            confidence=0.4
        )
        self.vulnerabilities.append(vuln)

    def _fetch_contract_source(self, address: str) -> Optional[str]:
        """Fetch contract source code from blockchain explorer"""
        if not self.api_key:
            return None
            
        try:
            url = self.chain_config['api_base']
            params = {
                'module': 'contract',
                'action': 'getsourcecode',
                'address': address,
                'apikey': self.api_key
            }
            
            if 'v2' in url:
                params['chainid'] = self.chain_config['chain_id']
            
            response = requests.get(url, params=params)
            data = response.json()
            
            if data.get('result') and len(data['result']) > 0:
                return data['result'][0].get('SourceCode')
            return None
            
        except Exception as e:
            print(f"[-] Error fetching source for {address}: {e}")
            return None

    def _fetch_contract_bytecode(self, address: str) -> Optional[str]:
        """Fetch contract bytecode"""
        if not self.api_key:
            return None
            
        try:
            url = self.chain_config['api_base']
            params = {
                'module': 'proxy',
                'action': 'eth_getCode',
                'address': address,
                'tag': 'latest',
                'apikey': self.api_key
            }
            
            if 'v2' in url:
                params['chainid'] = self.chain_config['chain_id']
            
            response = requests.get(url, params=params)
            data = response.json()
            
            return data.get('result')
            
        except Exception as e:
            print(f"[-] Error fetching bytecode for {address}: {e}")
            return None

    def _fetch_and_decompile_contract(self, address: str) -> Optional[str]:
        """Fetch and decompile contract (placeholder - would integrate with decompiler)"""
        # This would integrate with a decompiler service
        # For now, return None
        return None

    def _perform_comprehensive_storage_analysis(self, addresses: List[str], 
                                              source_code: str = None, decompiled_code: str = None):
        """Perform comprehensive storage-level vulnerability analysis"""
        
        for address in addresses:
            print(f"🔍 Storage analysis for {address}")
            
            try:
                # Run comprehensive storage analysis
                storage_vulnerabilities = self.storage_analyzer.analyze_storage(
                    contract_address=address,
                    source_code=source_code if address == addresses[0] else None,
                    max_slots=100  # Analyze first 100 storage slots
                )
                
                # Convert storage vulnerabilities to our Vulnerability format
                self._convert_storage_vulns_to_vulnerabilities(storage_vulnerabilities, address)
                
                if storage_vulnerabilities:
                    print(f"    ✅ Found {len(storage_vulnerabilities)} storage-level vulnerabilities")
                    
                    # Log storage vulnerability summary
                    critical_storage = len([v for v in storage_vulnerabilities if v.severity == "CRITICAL"])
                    high_storage = len([v for v in storage_vulnerabilities if v.severity == "HIGH"])
                    medium_storage = len([v for v in storage_vulnerabilities if v.severity == "MEDIUM"])
                    
                    print(f"    📊 Storage vulnerabilities: {critical_storage} Critical, {high_storage} High, {medium_storage} Medium")
                else:
                    print(f"    ✅ No storage-level vulnerabilities found")
                    
            except Exception as e:
                print(f"    ❌ Storage analysis failed for {address}: {e}")

    def _convert_storage_vulns_to_vulnerabilities(self, storage_vulns: List[StorageVulnerability], address: str):
        """Convert storage vulnerability objects to our standard Vulnerability format"""
        
        severity_mapping = {
            "CRITICAL": VulnSeverity.CRITICAL,
            "HIGH": VulnSeverity.HIGH,
            "MEDIUM": VulnSeverity.MEDIUM,
            "LOW": VulnSeverity.LOW
        }
        
        for storage_vuln in storage_vulns:
            # Map storage vulnerability to our standard format
            severity = severity_mapping.get(storage_vuln.severity, VulnSeverity.MEDIUM)
            
            # Create enhanced title based on vulnerability type
            enhanced_titles = {
                StorageVulnerabilityType.UNINITIALIZED_STORAGE: "🔴 Uninitialized Critical Storage",
                StorageVulnerabilityType.UNPROTECTED_STORAGE_WRITE: "🔴 Unprotected Storage Manipulation", 
                StorageVulnerabilityType.STORAGE_COLLISION: "🟡 Storage Layout Collision",
                StorageVulnerabilityType.CRITICAL_SLOT_EXPOSURE: "🟠 Critical Storage Exposure",
                StorageVulnerabilityType.STORAGE_OVERWRITE: "🔴 Storage Overwrite Vulnerability",
                StorageVulnerabilityType.DELEGATECALL_STORAGE_HIJACK: "🔴 Delegatecall Storage Hijacking",
                StorageVulnerabilityType.ARRAY_LENGTH_MANIPULATION: "🟠 Array Length Manipulation",
                StorageVulnerabilityType.MAPPING_KEY_COLLISION: "🟡 Mapping Key Collision",
                StorageVulnerabilityType.SLOT_PACKING_OVERFLOW: "🟡 Storage Packing Overflow"
            }
            
            enhanced_title = enhanced_titles.get(storage_vuln.vuln_type, storage_vuln.vuln_type.value)
            
            # Enhanced location information
            if storage_vuln.affected_slots:
                slots_info = f"Affected slots: {storage_vuln.affected_slots}"
                location = f"Contract: {address}, {slots_info}"
            else:
                location = f"Contract: {address}, Storage analysis"
            
            # Create vulnerability object
            vuln = Vulnerability(
                title=enhanced_title,
                severity=severity,
                description=storage_vuln.description,
                location=location,
                exploit_path=storage_vuln.exploit_path,
                impact=storage_vuln.impact,
                proof_of_concept=storage_vuln.proof_of_concept,
                recommendation=storage_vuln.recommendation,
                confidence=storage_vuln.confidence
            )
            
            self.vulnerabilities.append(vuln)

    def _emit_progress(self, message: str, progress: int):
        """Emit progress update for real-time CLI output"""
        self.current_progress = progress
        print(f"[{progress:3d}%] {message}")
        
        # Add visual progress bar for better UX
        bar_length = 40
        filled_length = int(bar_length * progress // 100)
        bar = '█' * filled_length + '░' * (bar_length - filled_length)
        print(f"      [{bar}] {progress}%")
        print()

    def _perform_enhanced_pattern_analysis(self, contract_address: str, 
                                         source_code: str = None, decompiled_code: str = None):
        """Perform enhanced critical vulnerability pattern analysis"""
        
        print(f"🔍 Enhanced pattern analysis for {contract_address}")
        
        try:
            # Get all enhanced patterns
            all_patterns = self.enhanced_patterns.get_all_patterns()
            critical_patterns = self.enhanced_patterns.get_critical_patterns()
            
            print(f"    📊 Analyzing {len(all_patterns)} enhanced patterns ({len(critical_patterns)} critical)")
            
            found_vulnerabilities = 0
            
            # Analyze source code if available
            if source_code:
                print(f"    📄 Analyzing Solidity source code...")
                source_vulns = self._analyze_enhanced_patterns_in_code(
                    all_patterns, source_code, contract_address, is_decompiled=False
                )
                found_vulnerabilities += len(source_vulns)
                
            # Analyze decompiled code if available  
            if decompiled_code:
                print(f"    🔍 Analyzing decompiled bytecode...")
                decompiled_vulns = self._analyze_enhanced_patterns_in_code(
                    all_patterns, decompiled_code, contract_address, is_decompiled=True
                )
                found_vulnerabilities += len(decompiled_vulns)
            
            # If no source code, try to fetch and analyze
            elif not source_code and not decompiled_code:
                print(f"    🔍 No source provided, attempting bytecode analysis...")
                contract_bytecode = self._fetch_contract_bytecode(contract_address)
                if contract_bytecode:
                    # Basic bytecode pattern analysis
                    bytecode_vulns = self._analyze_enhanced_patterns_in_code(
                        all_patterns, contract_bytecode, contract_address, is_decompiled=True
                    )
                    found_vulnerabilities += len(bytecode_vulns)
            
            if found_vulnerabilities > 0:
                print(f"    ✅ Found {found_vulnerabilities} enhanced pattern vulnerabilities")
                
                # Log critical findings
                critical_found = len([v for v in self.vulnerabilities 
                                    if v.severity == VulnSeverity.CRITICAL and 
                                    'Enhanced Pattern' in v.title])
                
                if critical_found > 0:
                    print(f"    🚨 CRITICAL: {critical_found} critical fund-drain vulnerabilities detected!")
            else:
                print(f"    ✅ No enhanced pattern vulnerabilities detected")
                
        except Exception as e:
            print(f"    ❌ Enhanced pattern analysis failed: {e}")

    def _analyze_enhanced_patterns_in_code(self, patterns: List[EnhancedVulnPattern], 
                                         code: str, contract_address: str, 
                                         is_decompiled: bool = False) -> List[str]:
        """Analyze code for enhanced vulnerability patterns"""
        
        found_vulns = []
        
        for pattern in patterns:
            # Check pattern matches
            matches = self.enhanced_patterns.check_pattern_match(pattern, code, is_decompiled)
            
            if matches:
                # Create vulnerability for each match
                for match_text, line_num in matches:
                    
                    # Map pattern severity to our enum
                    severity_map = {
                        "CRITICAL": VulnSeverity.CRITICAL,
                        "HIGH": VulnSeverity.HIGH,
                        "MEDIUM": VulnSeverity.MEDIUM,
                        "LOW": VulnSeverity.LOW
                    }
                    severity = severity_map.get(pattern.severity, VulnSeverity.MEDIUM)
                    
                    # Enhanced title with category
                    analysis_type = "Decompiled" if is_decompiled else "Source"
                    title = f"🔥 Enhanced Pattern: {pattern.name} ({analysis_type})"
                    
                    # Enhanced location with line number
                    location = f"Contract: {contract_address}, Line {line_num}: {match_text[:80]}..."
                    
                    # Create comprehensive vulnerability
                    vuln = Vulnerability(
                        title=title,
                        severity=severity,
                        description=f"[{pattern.category.upper()}] {pattern.description}",
                        location=location,
                        exploit_path=pattern.exploit_path,
                        impact=pattern.impact,
                        proof_of_concept=f"Matched pattern at line {line_num}: {match_text}",
                        recommendation=pattern.recommendation,
                        confidence=pattern.confidence
                    )
                    
                    self.vulnerabilities.append(vuln)
                    found_vulns.append(pattern.name)
                    
                    # Log critical findings immediately
                    if pattern.severity == "CRITICAL":
                        print(f"        🚨 CRITICAL: {pattern.name}")
                        print(f"           Line {line_num}: {match_text[:100]}...")
        
        return found_vulns


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