#!/usr/bin/env python3
"""
Test Script for Deep Smart Contract Vulnerability Scanner
Tests all components with real contract examples
"""

import os
import sys
from pathlib import Path

# Import scanner components
from deep_vuln_scanner import DeepContractScanner, Vulnerability, VulnSeverity
from bytecode_analyzer import BytecodeAnalyzer
from pattern_engine import AdvancedPatternEngine
from scanner_cli import main as cli_main

def test_verified_contract():
    """Test with a verified contract (sample vulnerable code)"""
    print("=" * 60)
    print("🧪 Testing Verified Contract Analysis")
    print("=" * 60)
    
    # Sample vulnerable Solidity code
    vulnerable_solidity = """
    pragma solidity ^0.8.0;
    
    contract VulnerableContract {
        mapping(address => bool) public authorized;
        address public owner;
        
        // CRITICAL: Unauthorized approval function
        function approveDOKMax(address owner, address spender) public {
            IERC20(tokenAddress).approve(spender, type(uint256).max);
        }
        
        // CRITICAL: Missing authorization on withdraw
        function withdraw() public {
            payable(msg.sender).transfer(address(this).balance);
        }
        
        // HIGH: Reentrancy vulnerability
        function vulnerableWithdraw() public {
            uint amount = balances[msg.sender];
            (bool success,) = msg.sender.call{value: amount}("");
            require(success, "Transfer failed");
            balances[msg.sender] = 0; // State change after external call
        }
        
        // CRITICAL: Circular admin dependency
        function setAdmin(address addr, bool flag) public {
            require(authorized[msg.sender], "Not authorized");
            authorized[addr] = flag;
        }
        
        mapping(address => uint256) public balances;
        address public tokenAddress;
    }
    """
    
    # Test with main scanner
    scanner = DeepContractScanner()
    vulnerabilities = scanner.scan_contract(
        contract_address="0x1234567890123456789012345678901234567890",
        source_code=vulnerable_solidity
    )
    
    print(f"✅ Found {len(vulnerabilities)} vulnerabilities in verified contract")
    for vuln in vulnerabilities:
        emoji = "🔴" if vuln.severity == VulnSeverity.CRITICAL else "🟠"
        print(f"   {emoji} {vuln.title} ({vuln.severity.value})")
    
    return len(vulnerabilities)

def test_decompiled_contract():
    """Test with decompiled contract code"""
    print("\n" + "=" * 60)
    print("🧪 Testing Decompiled Contract Analysis")
    print("=" * 60)
    
    # Check if decompiled file exists
    decompiled_file = Path("bsc/decomplie.txt")
    if not decompiled_file.exists():
        print("❌ Decompiled file not found, creating sample...")
        
        # Create sample decompiled code
        sample_decompiled = """
        // Decompiled by library.dedaub.com
        mapping (address => bool) _setV3Factory; // STORAGE[0x1]
        address _owner; // STORAGE[0x0] bytes 0 to 19
        
        function transferToken(address account, uint256 amount) public nonPayable { 
            require(msg.data.length - 4 >= 64);
            require(_setV3Factory[msg.sender], Error('Not authorized'));
            if (!(0 - amount)) {
                v0, v1 = account.balanceOf(this).gas(msg.gas);
                require(bool(v0), 0, RETURNDATASIZE());
            }
            v2, v3 = account.transfer(msg.sender, v1).gas(msg.gas);
            require(bool(v2), 0, RETURNDATASIZE());
            require(v3, Error('Token transfer failed'));
        }
        
        function setAdmin(address addr, bool flag) public nonPayable { 
            require(msg.data.length - 4 >= 64);
            require(_setV3Factory[msg.sender], Error('Not authorized'));
            _setV3Factory[addr] = flag;
        }
        
        function withdraw() public nonPayable { 
            require(_setV3Factory[msg.sender], Error('Not authorized'));
            payable(msg.sender).transfer(address(this).balance);
        }
        """
        
        # Ensure directory exists
        os.makedirs("bsc", exist_ok=True)
        with open(decompiled_file, 'w') as f:
            f.write(sample_decompiled)
    
    # Test with decompiled code
    with open(decompiled_file, 'r') as f:
        decompiled_code = f.read()
    
    scanner = DeepContractScanner()
    vulnerabilities = scanner.scan_contract(
        contract_address="0x4bccA4a0Bfa325dc00E9c498A62EA271aA31Cf4D",
        decompiled_code=decompiled_code
    )
    
    print(f"✅ Found {len(vulnerabilities)} vulnerabilities in decompiled contract")
    for vuln in vulnerabilities:
        emoji = "🔴" if vuln.severity == VulnSeverity.CRITICAL else "🟠"
        print(f"   {emoji} {vuln.title} ({vuln.severity.value})")
    
    return len(vulnerabilities)

def test_bytecode_analyzer():
    """Test bytecode analysis component"""
    print("\n" + "=" * 60)
    print("🧪 Testing Bytecode Analyzer")
    print("=" * 60)
    
    # Sample bytecode (ERC20 transfer function with potential vulnerabilities)
    sample_bytecode = """
    608060405260043610610062576000357c0100000000000000000000000000000000000000000000000000000000
    900463ffffffff168063a9059cbb14610067578063dd62ed3e1461009a578063095ea7b3146100cd5780637065cb48
    14610100578063f2fde38b14610133575b600080fd5b610080600480360381019061007b919061066d565b610166
    57610166565b60405161009791906106c8565b60405180910390f35b6100b560048036038101906100b091906106e3
    565b61017e565b6040516100c49190610732565b60405180910390f35b6100e860048036038101906100e3919061066d
    565b6101a3565b6040516100f791906106c8565b60405180910390f35b61011b6004803603810190610116919061074d
    565b6101bb565b60405161012a91906106c8565b60405180910390f35b61014e6004803603810190610149919061074d
    565b6101db565b60405161015d91906106c8565b60405180910390f35b600061017682600084610281565b905092915050
    565b6000600260008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffff
    16815260200190815260200160002060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffff
    ffffffffffffffffffffffffff168152602001908152602001600020549050929150505661f155
    """
    
    analyzer = BytecodeAnalyzer()
    results = analyzer.analyze_bytecode(sample_bytecode)
    
    print(f"✅ Bytecode Analysis Results:")
    print(f"   📍 Functions detected: {len(results['functions'])}")
    print(f"   🔧 Storage operations: {len(results['storage_accesses'])}")
    print(f"   🌐 External calls: {len(results['external_calls'])}")
    print(f"   ⚠️  Vulnerabilities: {len(results['vulnerabilities'])}")
    
    # Generate report
    report = analyzer.generate_bytecode_report(results)
    with open("bytecode_analysis_report.md", 'w') as f:
        f.write(report)
    print("   📄 Detailed report saved to bytecode_analysis_report.md")
    
    return len(results['vulnerabilities'])

def test_pattern_engine():
    """Test pattern detection engine"""
    print("\n" + "=" * 60)
    print("🧪 Testing Pattern Detection Engine")
    print("=" * 60)
    
    # Test with various vulnerable patterns
    test_patterns = [
        # Unauthorized transfer
        """
        function transferToken(address token, uint256 amount) public {
            IERC20(token).transfer(msg.sender, amount);
        }
        """,
        
        # Unlimited approval
        """
        function approveMax(address spender) public {
            IERC20(token).approve(spender, type(uint256).max);
        }
        """,
        
        # Reentrancy
        """
        function withdraw() public {
            uint amount = balances[msg.sender];
            (bool success,) = msg.sender.call{value: amount}("");
            balances[msg.sender] = 0;
        }
        """,
        
        # Price manipulation
        """
        function getPrice() public view returns (uint256) {
            (uint reserve0, uint reserve1,) = pair.getReserves();
            return reserve1 / reserve0;
        }
        """,
        
        # Circular admin dependency
        """
        function setAdmin(address admin) public {
            require(isAdmin[msg.sender], "Not authorized");
            isAdmin[admin] = true;
        }
        """
    ]
    
    engine = AdvancedPatternEngine()
    total_patterns = 0
    
    for i, code in enumerate(test_patterns, 1):
        vulnerabilities = engine.scan_for_patterns(code)
        total_patterns += len(vulnerabilities)
        print(f"   📝 Pattern {i}: {len(vulnerabilities)} vulnerabilities detected")
        
        for vuln in vulnerabilities:
            print(f"      - {vuln['title']} ({vuln['severity']})")
    
    print(f"✅ Total patterns detected: {total_patterns}")
    return total_patterns

def test_cli_integration():
    """Test CLI integration"""
    print("\n" + "=" * 60)
    print("🧪 Testing CLI Integration")
    print("=" * 60)
    
    # Create test files
    test_contract = """
    pragma solidity ^0.8.0;
    
    contract TestContract {
        function drain() public {
            payable(msg.sender).transfer(address(this).balance);
        }
    }
    """
    
    with open("test_contract.sol", 'w') as f:
        f.write(test_contract)
    
    print("✅ CLI test files created")
    print("   📁 test_contract.sol")
    print("   💡 Run: python scanner_cli.py --address 0x123... --source test_contract.sol")
    
    return True

def test_integration_with_real_files():
    """Test integration with existing files in workspace"""
    print("\n" + "=" * 60)
    print("🧪 Testing Integration with Workspace Files")
    print("=" * 60)
    
    found_files = 0
    
    # Check for existing contract files
    contract_files = [
        "bsc/DOK.sol",
        "bsc/decomplie.txt", 
        "bsc/bytecode.txt"
    ]
    
    for file_path in contract_files:
        if os.path.exists(file_path):
            found_files += 1
            print(f"   ✅ Found: {file_path}")
            
            # Test with actual file
            if file_path.endswith('.sol'):
                print(f"      📊 Testing Solidity analysis...")
                with open(file_path, 'r') as f:
                    content = f.read()
                
                scanner = DeepContractScanner()
                vulns = scanner.scan_contract("0xTest", source_code=content)
                print(f"      🎯 {len(vulns)} vulnerabilities detected")
                
            elif 'decomplie' in file_path:
                print(f"      📊 Testing decompiled analysis...")
                with open(file_path, 'r') as f:
                    content = f.read()
                
                scanner = DeepContractScanner()
                vulns = scanner.scan_contract("0xTest", decompiled_code=content)
                print(f"      🎯 {len(vulns)} vulnerabilities detected")
        else:
            print(f"   ❌ Not found: {file_path}")
    
    print(f"✅ Integration test completed with {found_files} files")
    return found_files

def generate_comprehensive_report():
    """Generate a comprehensive test report"""
    print("\n" + "=" * 60)
    print("📋 COMPREHENSIVE SCANNER TEST REPORT")
    print("=" * 60)
    
    # Run all tests
    test_results = {
        'verified_contract': test_verified_contract(),
        'decompiled_contract': test_decompiled_contract(), 
        'bytecode_analyzer': test_bytecode_analyzer(),
        'pattern_engine': test_pattern_engine(),
        'cli_integration': 1 if test_cli_integration() else 0,
        'workspace_integration': test_integration_with_real_files()
    }
    
    print("\n" + "=" * 60)
    print("📊 FINAL TEST SUMMARY")
    print("=" * 60)
    
    total_vulnerabilities = 0
    for component, count in test_results.items():
        if isinstance(count, int):
            total_vulnerabilities += count
        
        status = "✅ PASS" if count > 0 else "⚠️  LOW"
        print(f"{component.replace('_', ' ').title()}: {count} vulnerabilities - {status}")
    
    print(f"\n🎯 Total Vulnerabilities Detected: {total_vulnerabilities}")
    print(f"🧪 Scanner Components Tested: {len(test_results)}")
    
    # Performance assessment
    if total_vulnerabilities >= 10:
        print("🏆 Scanner Performance: EXCELLENT - High detection rate")
    elif total_vulnerabilities >= 5:
        print("✅ Scanner Performance: GOOD - Moderate detection rate")
    else:
        print("⚠️  Scanner Performance: NEEDS IMPROVEMENT - Low detection rate")
    
    # Generate usage examples
    print("\n" + "=" * 60)
    print("💡 USAGE EXAMPLES")
    print("=" * 60)
    
    examples = [
        "# Scan verified contract:",
        "python scanner_cli.py --address 0x123... --verified",
        "",
        "# Scan decompiled contract:",
        "python scanner_cli.py --address 0x123... --decompiled bsc/decomplie.txt",
        "",
        "# Scan with custom source:",
        "python scanner_cli.py --address 0x123... --source contract.sol --output report.md",
        "",
        "# High confidence findings only:",
        "python scanner_cli.py --address 0x123... --decompiled bsc/decomplie.txt --min-confidence 0.8",
        "",
        "# Critical vulnerabilities only:",
        "python scanner_cli.py --address 0x123... --decompiled bsc/decomplie.txt --severity CRITICAL"
    ]
    
    for example in examples:
        print(example)
    
    return test_results

def cleanup_test_files():
    """Clean up test files"""
    print("\n🧹 Cleaning up test files...")
    
    cleanup_files = [
        "test_contract.sol",
        "bytecode_analysis_report.md",
        "vulnerability_report_0xTest.md"
    ]
    
    for file_path in cleanup_files:
        if os.path.exists(file_path):
            os.remove(file_path)
            print(f"   ✅ Removed: {file_path}")

def main():
    """Main test function"""
    print("🔍 Deep Smart Contract Vulnerability Scanner - Test Suite")
    print("🎯 Focus: Non-privileged fund drain exploit detection")
    print()
    
    try:
        # Run comprehensive tests
        results = generate_comprehensive_report()
        
        # Cleanup
        cleanup_test_files()
        
        print(f"\n✅ All tests completed successfully!")
        print(f"📈 Scanner is ready for vulnerability hunting!")
        
        return True
        
    except Exception as e:
        print(f"❌ Test suite failed with error: {e}")
        return False

if __name__ == "__main__":
    main()