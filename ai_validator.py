#!/usr/bin/env python3
"""
OpenAI-powered vulnerability validation
Reduces false positives using AI analysis
"""

import os
import json
import time
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import requests
from deep_vuln_scanner import Vulnerability, VulnSeverity

@dataclass
class AIValidationResult:
    is_valid: bool
    confidence: float
    reasoning: str
    severity_adjustment: Optional[str] = None
    exploitability_score: float = 0.0
    recommendation: str = ""

class AIVulnerabilityValidator:
    def __init__(self, openai_api_key: str = None, model: str = "gpt-4"):
        self.api_key = openai_api_key or os.getenv('OPENAI_API_KEY')
        self.model = model or os.getenv('OPENAI_MODEL', 'gpt-4')
        self.api_url = "https://api.openai.com/v1/chat/completions"
        
        if not self.api_key:
            print("⚠️  OpenAI API key not found. AI validation disabled.")
            self.enabled = False
        else:
            print(f"🤖 AI Validation enabled with {self.model}")
            self.enabled = True

    def validate_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Validate a list of vulnerabilities using AI"""
        if not self.enabled:
            return vulnerabilities
        
        print(f"🤖 Starting AI validation for {len(vulnerabilities)} vulnerabilities...")
        validated_vulns = []
        
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"[{i}/{len(vulnerabilities)}] Validating: {vuln.title}")
            
            try:
                validation_result = self._validate_single_vulnerability(vuln)
                
                if validation_result.is_valid:
                    # Update vulnerability with AI insights
                    updated_vuln = self._enhance_vulnerability_with_ai(vuln, validation_result)
                    validated_vulns.append(updated_vuln)
                    print(f"    ✅ Valid (confidence: {validation_result.confidence:.0%})")
                else:
                    print(f"    ❌ False positive: {validation_result.reasoning}")
                
                # Rate limiting
                time.sleep(0.5)
                
            except Exception as e:
                print(f"    ⚠️  AI validation error: {e}")
                # Keep original vulnerability if AI fails
                validated_vulns.append(vuln)
        
        print(f"🤖 AI validation complete: {len(validated_vulns)}/{len(vulnerabilities)} vulnerabilities confirmed")
        return validated_vulns

    def _validate_single_vulnerability(self, vuln: Vulnerability) -> AIValidationResult:
        """Validate a single vulnerability using OpenAI"""
        
        prompt = self._create_validation_prompt(vuln)
        
        try:
            response = requests.post(
                self.api_url,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": self.model,
                    "messages": [
                        {
                            "role": "system", 
                            "content": """You are a world-class smart contract security auditor with expertise in identifying EXPLOITABLE vulnerabilities that can lead to fund drain.

CRITICAL FOCUS: Only validate vulnerabilities that meet ALL these criteria:
1. Can be exploited by external users (non-privileged attackers)
2. Can result in direct fund extraction or unauthorized token transfers
3. Have a clear exploit path without requiring admin privileges
4. Are not protected by proper access controls

ENHANCED DETECTION for privilege escalation:
- Look for unprotected functions that can change ownership or roles
- Identify missing authorization checks in critical functions
- Detect proxy upgrade vulnerabilities without proper protection
- Check for role manipulation without proper validation
- Analyze function selector collisions that bypass access controls

SEVERITY GUIDELINES:
- CRITICAL: Direct fund drain possible by any user
- HIGH: Privilege escalation leading to potential fund access
- MEDIUM: Authorization bypass with limited impact
- LOW: Minor access control issues"""
                        },
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ],
                    "temperature": 0.1,
                    "max_tokens": 1000
                }
            )
            
            if response.status_code != 200:
                raise Exception(f"OpenAI API error: {response.status_code}")
            
            ai_response = response.json()
            content = ai_response['choices'][0]['message']['content']
            
            return self._parse_ai_response(content)
            
        except Exception as e:
            raise Exception(f"AI validation failed: {e}")

    def _create_validation_prompt(self, vuln: Vulnerability) -> str:
        """Create a ultra-strict prompt for non-privileged fund drain validation"""
        
        return f"""
You are a SENIOR SMART CONTRACT AUDITOR specializing in BUG BOUNTY VALIDATION. Your job is to be EXTREMELY STRICT about what constitutes a valid non-privileged fund drain vulnerability.

**VULNERABILITY TO ANALYZE:**
Title: {vuln.title}
Severity: {vuln.severity.value}
Description: {vuln.description}
Location: {vuln.location}
Exploit Path: {vuln.exploit_path}
Impact: {vuln.impact}
Proof of Concept: {vuln.proof_of_concept}
Scanner Confidence: {vuln.confidence:.0%}

**STRICT VALIDATION RULES:**
For bug bounty submission, vulnerability MUST meet ALL criteria:

1. **NON-PRIVILEGED ACCESS REQUIRED**
   - Any external user can call the vulnerable function
   - NO onlyOwner, onlyAdmin, or access control modifiers
   - NO require() statements checking msg.sender permissions
   - NO authorization mappings or role checks

2. **DIRECT FUND THEFT CAPABILITY**
   - Allows stealing ETH/tokens from contract OR other users
   - NOT just economic manipulation or fee bypassing
   - NOT just logic errors or calculation mistakes
   - MUST result in attacker gaining funds they shouldn't have

3. **PRACTICAL EXPLOIT PATH**
   - Clear step-by-step attack vector
   - No complex multi-transaction setups
   - No dependency on external market conditions
   - Reproducible exploit that works consistently

4. **IMMEDIATE IMPACT**
   - Funds can be drained in single transaction or simple sequence
   - No need for admin cooperation or special circumstances
   - Direct financial loss to users or protocol

**AUTOMATIC FALSE POSITIVE INDICATORS:**
❌ Contains "onlyOwner" or "onlyAdmin" in function signature
❌ Contains "require(authorized[msg.sender]" or similar auth checks
❌ Requires specific roles or permissions
❌ Only affects fee calculations without allowing theft
❌ Describes logic errors without direct fund access
❌ Mentions "malicious owner" scenarios
❌ Deployment/initialization issues
❌ Economic model critiques
❌ Best practice violations

**TRANSFER FUNCTION ANALYSIS:**
If this involves transfer functions, verify:
- Is the function public/external WITHOUT access modifiers?
- Can ANY address call it to transfer ANY tokens/ETH?
- Does it transfer FROM the contract or other users TO the attacker?
- Is there NO authorization check whatsoever?

**ULTRA-STRICT QUESTIONS:**
1. Can a random person with no special access drain funds RIGHT NOW?
2. Would this work on mainnet TODAY without any special setup?
3. Is this a direct "steal money" vulnerability or just a logic issue?
4. Could an attacker profit financially from this exploit immediately?

**RESPONSE FORMAT (JSON):**
{{
    "is_valid": true/false,
    "confidence": 0.0-1.0,
    "reasoning": "DETAILED explanation focusing on fund drain capability and access control",
    "fund_drain_confirmed": true/false,
    "severity_adjustment": "CRITICAL/HIGH/MEDIUM/LOW",
    "exploitability_score": 0.0-1.0,
    "attack_vector": "Step-by-step exploit path",
    "recommendation": "Enhanced mitigation strategy"
}}
    "external_access_confirmed": true/false,
    "exploitability_score": 0-10,
    "severity_adjustment": "CRITICAL/HIGH/MEDIUM/LOW" or null,
    "recommendation": "specific recommendation"
}}

BE EXTREMELY STRICT. If there's ANY doubt about direct fund theft by external users, mark as FALSE POSITIVE.

ANALYZE:
"""

    def _parse_ai_response(self, response: str) -> AIValidationResult:
        """Parse AI response with enhanced validation"""
        
        try:
            # Try to extract JSON from response
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            
            if json_start != -1 and json_end != -1:
                json_str = response[json_start:json_end]
                data = json.loads(json_str)
                
                # Enhanced validation - require BOTH fund drain AND external access
                is_valid = data.get('is_valid', False)
                fund_drain = data.get('fund_drain_confirmed', False)
                external_access = data.get('external_access_confirmed', False)
                
                # Ultra-strict validation: must confirm BOTH aspects
                final_validity = is_valid and fund_drain and external_access
                
                return AIValidationResult(
                    is_valid=final_validity,
                    confidence=float(data.get('confidence', 0.0)),
                    reasoning=f"STRICT VALIDATION - Fund Drain: {fund_drain}, External Access: {external_access}, Reasoning: {data.get('reasoning', 'No reasoning provided')}",
                    severity_adjustment=data.get('severity_adjustment'),
                    exploitability_score=float(data.get('exploitability_score', 0.0)),
                    recommendation=data.get('recommendation', '')
                )
            else:
                # Ultra-strict fallback - look for explicit confirmation
                response_lower = response.lower()
                
                # Must explicitly confirm both fund drain AND external access
                fund_drain_confirmed = any(phrase in response_lower for phrase in [
                    'fund drain confirmed', 'can steal funds', 'direct theft', 'drain contract'
                ])
                
                external_access_confirmed = any(phrase in response_lower for phrase in [
                    'external access confirmed', 'no authorization', 'anyone can call', 'public function'
                ]) and 'onlyowner' not in response_lower and 'require(' not in response_lower
                
                is_valid = fund_drain_confirmed and external_access_confirmed
                confidence = 0.7 if is_valid else 0.1
                
                return AIValidationResult(
                    is_valid=is_valid,
                    confidence=confidence,
                    reasoning=f"FALLBACK ANALYSIS - Fund Drain: {fund_drain_confirmed}, External Access: {external_access_confirmed}"
                )
                
        except Exception as e:
            # Ultra-conservative fallback - mark as invalid
            return AIValidationResult(
                is_valid=False,
                confidence=0.0,
                reasoning=f"PARSING ERROR - Marked as invalid for safety: {e}"
            )

    def _enhance_vulnerability_with_ai(self, vuln: Vulnerability, ai_result: AIValidationResult) -> Vulnerability:
        """Enhance vulnerability with AI insights"""
        
        # Update confidence score
        ai_confidence_boost = float(os.getenv('AI_CONFIDENCE_BOOST', '0.1'))
        new_confidence = min(1.0, vuln.confidence + ai_confidence_boost)
        
        # Update severity if AI suggests adjustment
        new_severity = vuln.severity
        if ai_result.severity_adjustment:
            try:
                new_severity = VulnSeverity(ai_result.severity_adjustment)
            except ValueError:
                pass  # Keep original severity if invalid
        
        # Enhanced description with AI reasoning
        enhanced_description = f"{vuln.description}\n\n🤖 AI Validation: {ai_result.reasoning}"
        
        # Enhanced recommendation
        enhanced_recommendation = vuln.recommendation
        if ai_result.recommendation:
            enhanced_recommendation += f"\n\n🤖 AI Recommendation: {ai_result.recommendation}"
        
        return Vulnerability(
            title=f"🤖 AI-Validated: {vuln.title}",
            severity=new_severity,
            description=enhanced_description,
            location=vuln.location,
            exploit_path=vuln.exploit_path,
            impact=f"{vuln.impact}\n\n🤖 Exploitability Score: {ai_result.exploitability_score}/10",
            proof_of_concept=vuln.proof_of_concept,
            recommendation=enhanced_recommendation,
            confidence=new_confidence
        )

    def quick_validate(self, vuln_title: str, vuln_description: str, proof_of_concept: str = "") -> bool:
        """Quick validation for a single vulnerability during scanning"""
        if not self.enabled:
            return True  # Default to valid if AI disabled
        
        prompt = f"""
Quick validation: Is this a real exploitable vulnerability or false positive?

Title: {vuln_title}
Description: {vuln_description}
PoC: {proof_of_concept}

Answer with just: VALID or FALSE_POSITIVE and brief reason.
"""
        
        try:
            response = requests.post(
                self.api_url,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": "gpt-3.5-turbo",  # Use faster model for quick validation
                    "messages": [
                        {"role": "system", "content": "You are a smart contract security expert. Quickly identify real vulnerabilities vs false positives."},
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": 0.1,
                    "max_tokens": 100
                }
            )
            
            if response.status_code == 200:
                ai_response = response.json()
                content = ai_response['choices'][0]['message']['content'].upper()
                return 'VALID' in content and 'FALSE_POSITIVE' not in content
            else:
                return True  # Default to valid on API error
                
        except Exception:
            return True  # Default to valid on error

def main():
    """Test AI validator"""
    validator = AIVulnerabilityValidator()
    
    # Test vulnerability
    test_vuln = Vulnerability(
        title="Unauthorized Token Approval",
        severity=VulnSeverity.CRITICAL,
        description="Function approveDOKMax allows owner to approve unlimited tokens from any address",
        location="DOK.sol:291",
        exploit_path="1. Owner calls approveDOKMax\n2. Drains user funds",
        impact="Complete loss of user funds",
        proof_of_concept="function approveDOKMax(address owner, address spender) public onlyOwner",
        recommendation="Remove this function",
        confidence=0.9
    )
    
    validated = validator.validate_vulnerabilities([test_vuln])
    print(f"\nValidation result: {len(validated)} vulnerabilities confirmed")

if __name__ == "__main__":
    main()