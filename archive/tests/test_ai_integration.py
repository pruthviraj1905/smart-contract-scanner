#!/usr/bin/env python3
"""
Test AI integration with sample vulnerabilities
"""

import os
from ai_validator import AIVulnerabilityValidator
from deep_vuln_scanner import Vulnerability, VulnSeverity

def test_ai_validation():
    """Test AI validation with sample vulnerabilities"""
    
    print("🧪 Testing AI-powered vulnerability validation")
    print("=" * 50)
    
    # Check if OpenAI API key is available
    if not os.getenv('OPENAI_API_KEY'):
        print("⚠️  OpenAI API key not found in .env file")
        print("💡 Add OPENAI_API_KEY=your_key_here to .env file to test AI validation")
        return
    
    # Initialize AI validator
    validator = AIVulnerabilityValidator()
    
    if not validator.enabled:
        print("❌ AI validator not enabled")
        return
    
    # Create test vulnerabilities (including false positives)
    test_vulnerabilities = [
        Vulnerability(
            title="Unauthorized Token Approval",
            severity=VulnSeverity.CRITICAL,
            description="Function approveDOKMax allows owner to approve unlimited tokens from any address",
            location="DOK.sol:291",
            exploit_path="1. Owner calls approveDOKMax\n2. Sets unlimited approval\n3. Drains user tokens",
            impact="Complete loss of user funds",
            proof_of_concept="function approveDOKMax(address owner, address spender) public onlyOwner { _approve(owner, spender, type(uint256).max); }",
            recommendation="Remove this function or add proper access controls",
            confidence=0.9
        ),
        Vulnerability(
            title="Public Transfer Function Without Authorization",
            severity=VulnSeverity.CRITICAL,
            description="Function allows anyone to transfer tokens from contract",
            location="Contract.sol:42",
            exploit_path="1. Call transferToken()\n2. Specify token address\n3. Drain contract balance",
            impact="Complete drainage of contract token balances",
            proof_of_concept="function transferToken(address token, uint256 amount) public { IERC20(token).transfer(msg.sender, amount); }",
            recommendation="Add authorization checks",
            confidence=0.95
        ),
        Vulnerability(
            title="Profit Calculation Logic Error", 
            severity=VulnSeverity.HIGH,
            description="Incorrect profit calculation treats all sales as 100% profit",
            location="Contract.sol:150",
            exploit_path="1. Economic model manipulation\n2. Incorrect fee calculations",
            impact="Economic model breakdown",
            proof_of_concept="profit = profit + sellAmount; // Incorrect calculation",
            recommendation="Fix profit calculation logic",
            confidence=0.7
        )
    ]
    
    print(f"📝 Testing {len(test_vulnerabilities)} sample vulnerabilities...")
    print()
    
    # Run AI validation
    validated = validator.validate_vulnerabilities(test_vulnerabilities)
    
    # Display results
    print("\n📊 AI Validation Results:")
    print("=" * 50)
    print(f"Original vulnerabilities: {len(test_vulnerabilities)}")
    print(f"AI-validated vulnerabilities: {len(validated)}")
    print(f"False positives eliminated: {len(test_vulnerabilities) - len(validated)}")
    
    print("\n🤖 AI-Validated Vulnerabilities:")
    for i, vuln in enumerate(validated, 1):
        print(f"\n{i}. {vuln.title}")
        print(f"   Confidence: {vuln.confidence:.0%}")
        print(f"   Severity: {vuln.severity.value}")
        
        # Extract AI reasoning if present
        if "🤖 AI Validation:" in vuln.description:
            ai_reasoning = vuln.description.split("🤖 AI Validation:")[1].strip()
            print(f"   AI Reasoning: {ai_reasoning[:100]}...")

def test_quick_validation():
    """Test quick validation feature"""
    
    print("\n🚀 Testing Quick AI Validation")
    print("=" * 30)
    
    validator = AIVulnerabilityValidator()
    
    if not validator.enabled:
        print("⚠️  AI validation not available")
        return
    
    test_cases = [
        {
            "title": "onlyOwner Function Vulnerability",
            "description": "Function requires owner privileges but allows unlimited approvals",
            "poc": "function approve() public onlyOwner { ... }",
            "expected": False  # Should be false positive
        },
        {
            "title": "Public Drain Function", 
            "description": "Anyone can call this function to drain contract funds",
            "poc": "function drain() public { payable(msg.sender).transfer(address(this).balance); }",
            "expected": True  # Should be valid
        }
    ]
    
    for i, test in enumerate(test_cases, 1):
        print(f"\n{i}. Testing: {test['title']}")
        result = validator.quick_validate(test['title'], test['description'], test['poc'])
        status = "✅ VALID" if result else "❌ FALSE POSITIVE"
        expected = "✅ CORRECT" if result == test['expected'] else "❌ INCORRECT"
        print(f"   Result: {status} ({expected})")

if __name__ == "__main__":
    test_ai_validation()
    test_quick_validation()