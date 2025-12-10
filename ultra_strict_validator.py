#!/usr/bin/env python3
"""
Ultra-Strict Non-Privileged Fund Drain Validator
Specifically designed for bug bounty validation
"""

import re
from typing import List, Dict, Tuple
from dataclasses import dataclass
from enum import Enum

# Avoid circular import - redefine classes locally
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
    confidence: float

class UltraStrictValidator:
    def __init__(self):
        # Keywords that IMMEDIATELY disqualify a vulnerability
        self.disqualifying_keywords = [
            'onlyowner', 'only owner', 'onlyadmin', 'only admin',
            'require(msg.sender', 'require(_msgSender', 'require(owner',
            'require(admin', 'authorized[msg.sender]', 'hasRole(',
            '_checkRole(', 'AccessControl', 'malicious owner',
            'governance', 'multisig', 'timelock', 'modifier onlyOwner'
        ]
        
        # Keywords that indicate real fund drain
        self.fund_drain_keywords = [
            '.transfer(', '.send(', '.call{value:', 'transferFrom(',
            'drain', 'steal', 'extract', 'withdraw', 'balance'
        ]
        
        # Keywords that indicate external access
        self.external_access_keywords = [
            'public', 'external', 'anyone can call', 'no authorization',
            'without permission', 'unrestricted'
        ]
    
    def ultra_strict_validate(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Apply ultra-strict validation for non-privileged fund drain"""
        
        print("🔒 Applying ULTRA-STRICT non-privileged fund drain validation...")
        
        validated = []
        
        for vuln in vulnerabilities:
            print(f"   🔍 Analyzing: {vuln.title}")
            
            # Step 1: Check for immediate disqualifiers
            if self._has_disqualifying_keywords(vuln):
                print(f"      ❌ REJECTED: Contains privileged access requirements")
                continue
            
            # Step 2: Verify fund drain capability
            if not self._confirms_fund_drain(vuln):
                print(f"      ❌ REJECTED: No confirmed fund drain capability")
                continue
            
            # Step 3: Verify external access
            if not self._confirms_external_access(vuln):
                print(f"      ❌ REJECTED: No confirmed external access")
                continue
            
            # Step 4: Verify practical exploitability
            if not self._is_practically_exploitable(vuln):
                print(f"      ❌ REJECTED: Not practically exploitable")
                continue
            
            # If it passes all checks, it's a real vulnerability
            print(f"      ✅ VALIDATED: Confirmed non-privileged fund drain vulnerability")
            validated.append(vuln)
        
        print(f"🔒 Ultra-strict validation complete: {len(validated)}/{len(vulnerabilities)} vulnerabilities confirmed")
        return validated
    
    def _has_disqualifying_keywords(self, vuln: Vulnerability) -> bool:
        """Check if vulnerability contains any disqualifying keywords"""

        # Combine all text fields
        full_text = f"{vuln.title} {vuln.description} {vuln.proof_of_concept} {vuln.exploit_path}".lower()

        # IMPROVED: More precise detection with context
        # Only disqualify if access control is ACTUALLY enforced
        for keyword in self.disqualifying_keywords:
            keyword_lower = keyword.lower()

            # Skip if keyword appears in negative context (e.g., "missing onlyOwner")
            if keyword_lower in full_text:
                # Check if it's mentioned as MISSING or BROKEN
                context_window = 50
                keyword_pos = full_text.find(keyword_lower)

                if keyword_pos > 0:
                    before = full_text[max(0, keyword_pos-context_window):keyword_pos]
                    after = full_text[keyword_pos:keyword_pos+context_window]

                    # If mentioned as missing/broken/bypass, don't disqualify
                    negative_context = ['missing', 'broken', 'bypass', 'unprotected', 'no ', 'without', 'lack', 'absent']
                    if any(neg in before or neg in after for neg in negative_context):
                        continue  # Don't disqualify

                    # If it's actually enforced, disqualify
                    return True

        return False
    
    def _confirms_fund_drain(self, vuln: Vulnerability) -> bool:
        """Verify that vulnerability actually enables fund drain"""
        
        full_text = f"{vuln.title} {vuln.description} {vuln.proof_of_concept} {vuln.impact}".lower()
        
        # Must explicitly mention fund movement
        fund_indicators = [
            'transfer', 'withdraw', 'send', 'call{value:', 'drain', 'steal',
            'ierc20', 'token', 'balance', 'funds', 'ether', 'eth', 'erc20',
            'emergencytokenwithdraw', 'withdrawether', 'payable', 'msg.sender'
        ]
        
        has_fund_indicators = any(indicator in full_text for indicator in fund_indicators)
        
        # Check for critical patterns that indicate fund movement
        critical_patterns = [
            'transfer(msg.sender', 'call{value:', '.transfer(', '.send(',
            'emergencytokenwithdraw', 'ierc20(', 'payable(msg.sender)'
        ]
        
        has_critical_patterns = any(pattern in full_text for pattern in critical_patterns)
        
        return has_fund_indicators or has_critical_patterns
    
    def _confirms_external_access(self, vuln: Vulnerability) -> bool:
        """Verify that vulnerability is accessible by external users"""
        
        full_text = f"{vuln.title} {vuln.description} {vuln.proof_of_concept} {vuln.exploit_path}".lower()
        
        # Must be public/external OR be explicitly identified as public drain
        access_indicators = [
            'public function', 'external function', 'anyone can call', 
            'no authorization', 'without permission', 'unrestricted access',
            'public token drain', 'public', 'external'
        ]
        
        has_access_indicators = any(indicator in full_text for indicator in access_indicators)
        
        # Special case: if it's clearly a drain function, assume external access
        is_drain_function = any(keyword in full_text for keyword in [
            'drain', 'emergencytokenwithdraw', 'public token drain'
        ])
        
        # Must NOT have authorization requirements (but allow some emergency checks)
        no_auth_required = not any(auth in full_text for auth in [
            'onlyowner', 'onlyadmin', 'require(msg.sender ==', 'authorized[msg.sender]'
        ])
        
        return (has_access_indicators or is_drain_function) and no_auth_required
    
    def _is_practically_exploitable(self, vuln: Vulnerability) -> bool:
        """Check if vulnerability is practically exploitable"""

        exploit_text = vuln.exploit_path.lower()
        full_text = f"{vuln.title} {vuln.description} {exploit_text}".lower()

        # Must have clear exploit steps
        has_clear_steps = any(indicator in exploit_text for indicator in [
            '1.', 'step 1', 'first', 'call function', 'execute', 'invoke', 'call'
        ])

        # Allow flash loans and market manipulation as they're common attack vectors
        # IMPROVED: Don't reject flash loan attacks
        requires_impossible_setup = any(complex_indicator in exploit_text for complex_indicator in [
            'requires governance vote', 'requires multisig approval',
            'depends on admin', 'owner must'
        ])

        # Must result in fund gain
        fund_gain = any(gain in full_text for gain in [
            'receive tokens', 'gain funds', 'extract', 'drain', 'profit',
            'withdraw', 'transfer', 'steal', 'take', 'claim'
        ])

        return has_clear_steps and not requires_impossible_setup and fund_gain

def test_ultra_strict_validator():
    """Test the ultra-strict validator with sample vulnerabilities"""
    
    validator = UltraStrictValidator()
    
    # Create test cases
    test_vulns = [
        # False positive - requires owner
        Vulnerability(
            title="Owner Can Approve Unlimited Tokens",
            severity=VulnSeverity.CRITICAL,
            description="Function allows owner to approve unlimited tokens",
            location="Test",
            exploit_path="1. Owner calls function 2. Sets unlimited approval",
            impact="Owner can steal funds",
            proof_of_concept="function approve() public onlyOwner { ... }",
            recommendation="Fix",
            confidence=0.9
        ),
        
        # True positive - external fund drain
        Vulnerability(
            title="Public Function Drains Contract Balance",
            severity=VulnSeverity.CRITICAL,
            description="Anyone can call drain() function to transfer all contract funds to themselves",
            location="Test",
            exploit_path="1. Call drain() function 2. Receive all contract ETH 3. Profit",
            impact="Complete loss of funds - anyone can steal all ETH",
            proof_of_concept="function drain() public { payable(msg.sender).transfer(address(this).balance); }",
            recommendation="Add authorization",
            confidence=0.9
        ),
        
        # False positive - logic error
        Vulnerability(
            title="Incorrect Fee Calculation",
            severity=VulnSeverity.HIGH,
            description="Fee calculation logic has rounding errors",
            location="Test",
            exploit_path="1. Exploit rounding 2. Save on fees",
            impact="Economic model issues",
            proof_of_concept="fee = amount / 100; // loses precision",
            recommendation="Fix calculation",
            confidence=0.7
        )
    ]
    
    validated = validator.ultra_strict_validate(test_vulns)
    
    print(f"\n📊 Test Results:")
    print(f"   Original: {len(test_vulns)} vulnerabilities")
    print(f"   Validated: {len(validated)} vulnerabilities")
    print(f"   Expected: 1 vulnerability (public drain function)")
    
    for vuln in validated:
        print(f"   ✅ {vuln.title}")

if __name__ == "__main__":
    test_ultra_strict_validator()