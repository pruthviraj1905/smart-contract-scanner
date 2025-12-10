#!/usr/bin/env python3
"""
Advanced Pattern Detection Engine
Specialized patterns for non-privileged fund drain detection
"""

import re
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from enum import Enum

class PatternCategory(Enum):
    FUND_DRAIN = "fund_drain"
    ACCESS_CONTROL = "access_control"
    REENTRANCY = "reentrancy"
    LOGIC_FLAW = "logic_flaw"
    PRICE_MANIPULATION = "price_manipulation"
    INITIALIZATION = "initialization"

@dataclass
class VulnPattern:
    name: str
    category: PatternCategory
    patterns: List[str]
    description: str
    severity: str
    exploit_conditions: List[str]
    false_positive_checks: List[str]
    confidence_modifier: float = 1.0

class AdvancedPatternEngine:
    def __init__(self):
        self.vulnerability_patterns = self._initialize_patterns()
        
    def _initialize_patterns(self) -> Dict[str, VulnPattern]:
        """Initialize comprehensive vulnerability patterns"""
        
        patterns = {}
        
        # === FUND DRAIN PATTERNS ===
        patterns["unauthorized_transfer_basic"] = VulnPattern(
            name="Unauthorized Transfer Function",
            category=PatternCategory.FUND_DRAIN,
            patterns=[
                r'function\s+\w*[Tt]ransfer[^(]*\([^)]*\)\s*(public|external)[^{]*\{(?![^}]*require\([^}]*(msg\.sender|authorized|owner|admin))',
                r'function\s+\w*[Ww]ithdraw[^(]*\([^)]*\)\s*(public|external)[^{]*\{(?![^}]*require\([^}]*(msg\.sender|authorized|owner|admin))',
                r'function\s+\w*[Dd]rain[^(]*\([^)]*\)\s*(public|external)[^{]*\{(?![^}]*require\([^}]*(msg\.sender|authorized|owner|admin))',
            ],
            description="Public function that transfers funds without proper authorization checks",
            severity="CRITICAL",
            exploit_conditions=[
                "Function is public or external",
                "Function transfers tokens or ETH", 
                "No authorization checks present",
                "Contract holds transferable assets"
            ],
            false_positive_checks=[
                r'require\s*\([^)]*msg\.sender',
                r'onlyOwner',
                r'onlyAdmin',
                r'authorized\[msg\.sender\]',
                r'_msgSender\(\)',
            ]
        )
        
        patterns["decompiled_unauthorized_transfer"] = VulnPattern(
            name="Decompiled Unauthorized Transfer", 
            category=PatternCategory.FUND_DRAIN,
            patterns=[
                r'function\s+transferToken\s*\([^)]*\)\s*public\s*nonPayable\s*\{[^}]*require\(_setV3Factory\[msg\.sender\]',
                r'function\s+\w+\s*\([^)]*\)\s*public\s*nonPayable\s*\{[^}]*\.transfer\(msg\.sender[^}]*\}',
                r'\.balanceOf\(this\)\.gas\(msg\.gas\)[^}]*\.transfer\(msg\.sender',
            ],
            description="Decompiled function that transfers all token balance to caller",
            severity="CRITICAL", 
            exploit_conditions=[
                "Function transfers contract's token balance",
                "Transfers to msg.sender", 
                "Authorization mapping may be empty",
                "Contract holds tokens"
            ],
            false_positive_checks=[
                r'require\([^)]*authorized',
                r'require\([^)]*owner',
                r'require\([^)]*admin',
            ]
        )
        
        patterns["unlimited_approval"] = VulnPattern(
            name="Unlimited Approval Manipulation",
            category=PatternCategory.FUND_DRAIN,
            patterns=[
                r'function\s+\w*[Aa]pprove\w*\s*\([^)]*\)\s*(public|external)[^{]*\{[^}]*_approve\([^,]*,\s*[^,]*,\s*type\s*\(\s*uint256\s*\)\.max\)',
                r'_approve\s*\(\s*[^,]+,\s*[^,]+,\s*type\s*\(\s*uint256\s*\)\.max\s*\)',
                r'IERC20\([^)]*\)\.approve\([^,]*,\s*type\s*\(\s*uint256\s*\)\.max\)',
            ],
            description="Function allows setting unlimited token approvals for arbitrary addresses",
            severity="CRITICAL",
            exploit_conditions=[
                "Function can approve unlimited amounts",
                "Approval can be set for any address",
                "No proper authorization checks",
                "Contract holds valuable tokens"
            ],
            false_positive_checks=[
                r'require\s*\([^)]*onlyOwner',
                r'require\s*\([^)]*msg\.sender\s*==\s*owner',
                r'modifier\s+onlyOwner',
            ]
        )
        
        # === ACCESS CONTROL PATTERNS ===
        patterns["circular_admin_dependency"] = VulnPattern(
            name="Circular Admin Dependency",
            category=PatternCategory.ACCESS_CONTROL,
            patterns=[
                r'function\s+setAdmin\s*\([^)]*\)\s*(public|external)[^{]*\{[^}]*require\s*\([^)]*admin[^}]*\)',
                r'function\s+addAdmin\s*\([^)]*\)\s*(public|external)[^{]*\{[^}]*require\s*\([^)]*admin[^}]*\)',
                r'function\s+grantRole\s*\([^)]*\)\s*(public|external)[^{]*\{[^}]*require\s*\([^)]*hasRole[^}]*\)',
            ],
            description="Admin functions require admin privileges but no initial admin is set",
            severity="CRITICAL",
            exploit_conditions=[
                "setAdmin function requires admin privileges",
                "No constructor sets initial admin",
                "Admin mapping is empty", 
                "All admin functions become inaccessible"
            ],
            false_positive_checks=[
                r'constructor[^}]*admin',
                r'initialize[^}]*admin',
                r'_setupRole',
                r'_grantRole\s*\([^,]*,\s*msg\.sender\)',
            ]
        )
        
        patterns["broken_modifier"] = VulnPattern(
            name="Broken Access Modifier",
            category=PatternCategory.ACCESS_CONTROL,
            patterns=[
                r'modifier\s+onlyOwner\s*\(\s*\)\s*\{\s*_;\s*\}',  # Empty modifier
                r'modifier\s+onlyAdmin\s*\(\s*\)\s*\{\s*_;\s*\}',
                r'require\s*\(\s*true\s*,',  # Always true require
                r'require\s*\(\s*false\s*,', # Always false require  
            ],
            description="Access control modifier is broken or bypassed",
            severity="CRITICAL",
            exploit_conditions=[
                "Modifier does not perform actual checks",
                "Functions rely on broken modifier",
                "Critical functions become publicly accessible"
            ],
            false_positive_checks=[
                r'require\s*\([^)]*msg\.sender',
                r'require\s*\([^)]*owner',
                r'_checkRole\(',
            ]
        )
        
        # === REENTRANCY PATTERNS ===
        patterns["reentrancy_external_call"] = VulnPattern(
            name="Reentrancy via External Call",
            category=PatternCategory.REENTRANCY,
            patterns=[
                r'\.call\s*\{[^}]*value\s*:[^}]*\}[^;]*;[^}]*\w+\s*=\s*[^;]+;',
                r'\.transfer\s*\([^)]*\)[^;]*;[^}]*\w+\s*=\s*[^;]+;',
                r'\.send\s*\([^)]*\)[^;]*;[^}]*\w+\s*=\s*[^;]+;',
                r'\.\w+\(\)[^;]*;[^}]*balances\[',
            ],
            description="External call followed by state modification creates reentrancy vulnerability",
            severity="HIGH",
            exploit_conditions=[
                "External call to untrusted contract",
                "State modification after external call",
                "No reentrancy guard present",
                "Function can be called recursively"
            ],
            false_positive_checks=[
                r'nonReentrant',
                r'ReentrancyGuard',
                r'_status\s*=\s*_ENTERED',
                r'require\s*\([^)]*_status\s*!=\s*_ENTERED',
            ]
        )
        
        # === LOGIC FLAWS ===
        patterns["integer_overflow"] = VulnPattern(
            name="Integer Overflow/Underflow",
            category=PatternCategory.LOGIC_FLAW,
            patterns=[
                r'pragma\s+solidity\s*[\^<>=\s]*0\.[0-7]\.', # Solidity < 0.8
                r'\b\w+\s*\+\s*\w+(?!\s*;[^}]*require)',     # Addition without checks
                r'\b\w+\s*\*\s*\w+(?!\s*;[^}]*require)',     # Multiplication without checks
                r'\b\w+\s*-\s*\w+(?!\s*;[^}]*require)',      # Subtraction without checks
            ],
            description="Arithmetic operations without overflow protection in vulnerable Solidity version",
            severity="MEDIUM",
            exploit_conditions=[
                "Solidity version < 0.8.0",
                "No SafeMath library used",
                "Arithmetic operations on user input",
                "No manual overflow checks"
            ],
            false_positive_checks=[
                r'SafeMath',
                r'\.add\(',
                r'\.sub\(',
                r'\.mul\(',
                r'\.div\(',
                r'pragma\s+solidity\s*[\^>=\s]*0\.[8-9]',
            ]
        )
        
        patterns["incorrect_profit_calculation"] = VulnPattern(
            name="Incorrect Profit Calculation",
            category=PatternCategory.LOGIC_FLAW,
            patterns=[
                r'profit\s*=\s*profit\s*\+\s*sellAmount\s*;',
                r'profit\s*\+=\s*sellAmount\s*;',
                r'return\s+sellAmount\s*;.*\/\/.*profit',
            ],
            description="Incorrect profit calculation treats all sales as 100% profit",
            severity="HIGH",
            exploit_conditions=[
                "Profit calculation logic is flawed",
                "Fees based on incorrect profit calculations",
                "Economic model can be exploited"
            ],
            false_positive_checks=[
                r'costBasis',
                r'averagePrice',
                r'purchasePrice',
                r'if\s*\([^)]*profit\s*>\s*0\)',
            ]
        )
        
        # === PRICE MANIPULATION ===
        patterns["price_manipulation"] = VulnPattern(
            name="Price Manipulation Vulnerability", 
            category=PatternCategory.PRICE_MANIPULATION,
            patterns=[
                r'getReserves\(\)[^}]*currentPrice\s*=',
                r'reserve[01]\s*/\s*reserve[01]',
                r'\.getAmountsOut\([^)]*\)[^}]*price',
                r'currentPrice\s*=\s*0.*return\s+0',
            ],
            description="Price calculation vulnerable to manipulation via liquidity changes",
            severity="HIGH", 
            exploit_conditions=[
                "Price depends on DEX reserves",
                "No price validation or bounds",
                "Single source of price data",
                "Price can be manipulated by large trades"
            ],
            false_positive_checks=[
                r'TWAP',
                r'oracle',
                r'chainlink',
                r'timeWeighted',
                r'require\s*\([^)]*price\s*[><=]',
            ]
        )
        
        # === INITIALIZATION PATTERNS ===
        patterns["missing_initialization"] = VulnPattern(
            name="Missing Initialization",
            category=PatternCategory.INITIALIZATION,
            patterns=[
                r'mapping\s*\([^)]*\)\s+(\w*admin\w*|\w*owner\w*|\w*authorized\w*);(?![^}]*constructor)',
                r'address\s+(admin|owner|authorized)\s*;(?![^}]*constructor[^}]*=)',
                r'bool\s+(initialized|setup)\s*;(?![^}]*constructor[^}]*=\s*true)',
            ],
            description="Critical variables not initialized in constructor",
            severity="HIGH",
            exploit_conditions=[
                "Critical access control variables uninitialized",
                "No initialization function called",
                "Default values allow unauthorized access",
                "Contract deployed without proper setup"
            ],
            false_positive_checks=[
                r'constructor[^}]*\1\s*=',
                r'initialize[^}]*\1\s*=',
                r'_setupRole',
                r'_grantRole',
            ]
        )
        
        return patterns
    
    def scan_for_patterns(self, code: str, code_type: str = "solidity") -> List[Dict]:
        """
        Scan code for vulnerability patterns
        """
        found_vulnerabilities = []
        
        for pattern_name, vuln_pattern in self.vulnerability_patterns.items():
            matches = self._check_pattern(code, vuln_pattern)
            
            for match in matches:
                # Check for false positives
                if self._is_false_positive(code, match, vuln_pattern):
                    continue
                
                vulnerability = {
                    'pattern_name': pattern_name,
                    'title': vuln_pattern.name,
                    'category': vuln_pattern.category.value,
                    'severity': vuln_pattern.severity,
                    'description': vuln_pattern.description,
                    'location': f"Line {self._get_line_number(code, match['start'])}",
                    'matched_text': match['text'],
                    'confidence': self._calculate_confidence(code, match, vuln_pattern),
                    'exploit_conditions': vuln_pattern.exploit_conditions,
                    'context': self._extract_context(code, match['start'], match['end'])
                }
                
                found_vulnerabilities.append(vulnerability)
        
        return found_vulnerabilities
    
    def _check_pattern(self, code: str, vuln_pattern: VulnPattern) -> List[Dict]:
        """Check for specific pattern matches"""
        matches = []
        
        for pattern in vuln_pattern.patterns:
            for match in re.finditer(pattern, code, re.MULTILINE | re.DOTALL | re.IGNORECASE):
                matches.append({
                    'pattern': pattern,
                    'start': match.start(),
                    'end': match.end(),
                    'text': match.group(0)
                })
        
        return matches
    
    def _is_false_positive(self, code: str, match: Dict, vuln_pattern: VulnPattern) -> bool:
        """Check if match is likely a false positive"""
        
        # Extract context around the match
        context_start = max(0, match['start'] - 500)
        context_end = min(len(code), match['end'] + 500)
        context = code[context_start:context_end]
        
        # Check false positive patterns
        for fp_pattern in vuln_pattern.false_positive_checks:
            if re.search(fp_pattern, context, re.IGNORECASE):
                return True
        
        return False
    
    def _calculate_confidence(self, code: str, match: Dict, vuln_pattern: VulnPattern) -> float:
        """Calculate confidence score for the match"""
        
        base_confidence = 0.7
        confidence_modifier = vuln_pattern.confidence_modifier
        
        # Extract function context
        context = self._extract_context(code, match['start'], match['end'])
        
        # Increase confidence if:
        # 1. Function is public/external
        if re.search(r'\b(public|external)\b', context):
            confidence_modifier += 0.1
        
        # 2. No obvious authorization checks
        auth_patterns = ['require(', 'onlyOwner', 'onlyAdmin', 'authorized[']
        if not any(pattern in context for pattern in auth_patterns):
            confidence_modifier += 0.15
        
        # 3. Contains fund transfer operations
        transfer_patterns = ['.transfer(', '.send(', '.call{value:', 'transferFrom(']
        if any(pattern in context for pattern in transfer_patterns):
            confidence_modifier += 0.1
        
        # 4. Multiple suspicious patterns in same function
        suspicious_count = sum(1 for pattern in ['uint256.max', 'balanceOf(this)', 'msg.sender'] 
                              if pattern in context)
        confidence_modifier += suspicious_count * 0.05
        
        final_confidence = min(1.0, base_confidence * confidence_modifier)
        return round(final_confidence, 2)
    
    def _get_line_number(self, code: str, position: int) -> int:
        """Get line number for a position in code"""
        return code[:position].count('\n') + 1
    
    def _extract_context(self, code: str, start: int, end: int, context_size: int = 300) -> str:
        """Extract context around a match"""
        context_start = max(0, start - context_size)
        context_end = min(len(code), end + context_size)
        return code[context_start:context_end]
    
    def analyze_decompiled_patterns(self, decompiled_code: str) -> List[Dict]:
        """
        Specialized analysis for decompiled bytecode patterns
        """
        decompiled_patterns = [
            {
                'name': 'Decompiled Transfer Without Auth',
                'pattern': r'function\s+transferToken\s*\([^)]*\)\s*public\s*nonPayable\s*\{[^}]*require\(_setV3Factory\[msg\.sender\]',
                'severity': 'CRITICAL',
                'description': 'Decompiled transferToken function depends on potentially empty authorization mapping'
            },
            {
                'name': 'Circular Authorization Dependency',
                'pattern': r'function\s+setAdmin\s*\([^)]*\)\s*public\s*nonPayable\s*\{[^}]*require\(_setV3Factory\[msg\.sender\]',
                'severity': 'CRITICAL', 
                'description': 'setAdmin function requires authorization but mapping may be empty'
            },
            {
                'name': 'Balance Extraction Pattern',
                'pattern': r'\.balanceOf\(this\)\.gas\(msg\.gas\)[^}]*\.transfer\(msg\.sender',
                'severity': 'HIGH',
                'description': 'Function extracts full contract balance and transfers to caller'
            },
            {
                'name': 'Missing Authorization Mapping Check',
                'pattern': r'mapping\s*\([^)]*\)\s*_setV3Factory.*STORAGE\[0x1\]',
                'severity': 'MEDIUM',
                'description': 'Authorization mapping may not be properly initialized'
            }
        ]
        
        found_patterns = []
        
        for pattern_info in decompiled_patterns:
            matches = re.finditer(pattern_info['pattern'], decompiled_code, re.MULTILINE | re.DOTALL)
            
            for match in matches:
                found_patterns.append({
                    'title': pattern_info['name'],
                    'severity': pattern_info['severity'],
                    'description': pattern_info['description'],
                    'location': f"Line {self._get_line_number(decompiled_code, match.start())}",
                    'matched_text': match.group(0),
                    'confidence': 0.8,
                    'context': self._extract_context(decompiled_code, match.start(), match.end())
                })
        
        return found_patterns
    
    def generate_pattern_report(self, vulnerabilities: List[Dict]) -> str:
        """Generate detailed pattern analysis report"""
        
        if not vulnerabilities:
            return "No vulnerability patterns detected.\n"
        
        report = "# Pattern Analysis Report\n\n"
        
        # Group by category
        categories = {}
        for vuln in vulnerabilities:
            cat = vuln.get('category', 'unknown')
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(vuln)
        
        # Summary
        report += f"## Summary\n\n"
        report += f"Total patterns detected: {len(vulnerabilities)}\n\n"
        
        for category, vulns in categories.items():
            report += f"- **{category.replace('_', ' ').title()}**: {len(vulns)}\n"
        
        report += "\n"
        
        # Detailed findings
        for category, vulns in categories.items():
            report += f"## {category.replace('_', ' ').title()} Patterns\n\n"
            
            for vuln in vulns:
                report += f"### {vuln['title']}\n"
                report += f"- **Severity**: {vuln['severity']}\n"
                report += f"- **Confidence**: {vuln['confidence']:.0%}\n"
                report += f"- **Location**: {vuln['location']}\n"
                report += f"- **Description**: {vuln['description']}\n\n"
                
                if 'exploit_conditions' in vuln:
                    report += "**Exploit Conditions:**\n"
                    for condition in vuln['exploit_conditions']:
                        report += f"- {condition}\n"
                    report += "\n"
                
                if len(vuln.get('matched_text', '')) < 200:
                    report += f"**Matched Pattern:**\n```\n{vuln['matched_text']}\n```\n\n"
                
                report += "---\n\n"
        
        return report


def main():
    """Test pattern engine"""
    engine = AdvancedPatternEngine()
    
    # Test with sample vulnerable code
    test_code = """
    function transferToken(address account, uint256 amount) public nonPayable { 
        require(msg.data.length - 4 >= 64);
        require(_setV3Factory[msg.sender], Error('Not authorized'));
        v0, v1 = account.balanceOf(this).gas(msg.gas);
        v2, v3 = account.transfer(msg.sender, v1).gas(msg.gas);
        require(v3, Error('Token transfer failed'));
    }
    """
    
    vulnerabilities = engine.scan_for_patterns(test_code, "decompiled")
    report = engine.generate_pattern_report(vulnerabilities)
    print(report)


if __name__ == "__main__":
    main()