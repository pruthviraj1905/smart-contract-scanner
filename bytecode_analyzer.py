#!/usr/bin/env python3
"""
Advanced Bytecode Analysis Module
Deep analysis of EVM bytecode for vulnerability detection
"""

import re
import struct
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass

@dataclass
class BytecodeFunction:
    selector: str
    offset: int
    name: Optional[str] = None
    is_public: bool = False
    is_payable: bool = False
    contains_external_calls: bool = False
    modifies_storage: bool = False
    has_auth_checks: bool = False

@dataclass
class StorageAccess:
    slot: str
    operation: str  # 'SLOAD' or 'SSTORE'
    offset: int
    context: str

class BytecodeAnalyzer:
    def __init__(self):
        # EVM opcodes for analysis
        self.opcodes = {
            0x54: 'SLOAD',
            0x55: 'SSTORE', 
            0xf1: 'CALL',
            0xf2: 'CALLCODE',
            0xf4: 'DELEGATECALL',
            0xfa: 'STATICCALL',
            0xff: 'SELFDESTRUCT',
            0x31: 'BALANCE',
            0xa9: 'LOG1',
            0xaa: 'LOG2',
            0xab: 'LOG3',
            0xac: 'LOG4',
            0x35: 'CALLDATALOAD',
            0x51: 'MLOAD',
            0x52: 'MSTORE',
            0x53: 'MSTORE8'
        }
        
        # Function selectors for common patterns
        self.known_selectors = {
            '0xa9059cbb': 'transfer(address,uint256)',
            '0x23b872dd': 'transferFrom(address,address,uint256)',
            '0x095ea7b3': 'approve(address,uint256)',
            '0x70a08231': 'balanceOf(address)',
            '0x3ccfd60b': 'withdraw()',
            '0x2e1a7d4d': 'withdraw(uint256)',
            '0x8da5cb5b': 'owner()',
            '0xf2fde38b': 'transferOwnership(address)',
            '0x715018a6': 'renounceOwnership()',
        }
        
        # Dangerous patterns in bytecode
        self.dangerous_patterns = {
            'unlimited_approval': [
                'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',  # type(uint256).max
                '7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',   # Large values
            ],
            'external_calls_in_loop': [
                '5b.*f1.*56',  # JUMPDEST ... CALL ... JUMP pattern
                '80.*f1.*80',  # Loop with CALL
            ],
            'storage_manipulation': [
                '55.*55',      # Multiple SSTORE operations
                '54.*55',      # SLOAD followed by SSTORE
            ],
            'reentrancy_patterns': [
                'f1.*55',      # CALL followed by SSTORE
                'fa.*55',      # STATICCALL followed by SSTORE
            ]
        }

    def analyze_bytecode(self, bytecode: str) -> Dict:
        """
        Comprehensive bytecode analysis
        """
        # Remove 0x prefix if present
        if bytecode.startswith('0x'):
            bytecode = bytecode[2:]
        
        results = {
            'functions': self._extract_functions(bytecode),
            'storage_accesses': self._analyze_storage(bytecode),
            'external_calls': self._find_external_calls(bytecode),
            'dangerous_patterns': self._detect_dangerous_patterns(bytecode),
            'vulnerabilities': []
        }
        
        # Analyze for specific vulnerabilities
        results['vulnerabilities'].extend(self._check_reentrancy_bytecode(bytecode, results))
        results['vulnerabilities'].extend(self._check_unauthorized_access(bytecode, results))
        results['vulnerabilities'].extend(self._check_storage_manipulation(bytecode, results))
        results['vulnerabilities'].extend(self._check_selfdestruct_patterns(bytecode, results))
        
        return results

    def _extract_functions(self, bytecode: str) -> List[BytecodeFunction]:
        """
        Extract function information from bytecode
        """
        functions = []
        
        # Look for function dispatcher pattern
        # PUSH4 selector, EQ, PUSH offset, JUMPI pattern
        dispatcher_pattern = r'63([0-9a-fA-F]{8}).*?14.*?61([0-9a-fA-F]{4}).*?57'
        
        matches = re.finditer(dispatcher_pattern, bytecode)
        for match in matches:
            selector = match.group(1)
            offset = int(match.group(2), 16)
            
            func = BytecodeFunction(
                selector=f"0x{selector}",
                offset=offset,
                name=self.known_selectors.get(f"0x{selector}")
            )
            
            # Analyze function properties
            func_bytecode = self._get_function_bytecode(bytecode, offset)
            func.is_payable = self._is_payable(func_bytecode)
            func.contains_external_calls = self._has_external_calls(func_bytecode)
            func.modifies_storage = self._modifies_storage(func_bytecode)
            func.has_auth_checks = self._has_auth_checks(func_bytecode)
            
            functions.append(func)
        
        return functions

    def _get_function_bytecode(self, bytecode: str, offset: int) -> str:
        """
        Extract bytecode for a specific function
        """
        # Convert offset to bytecode position (each byte = 2 hex chars)
        start = offset * 2
        
        # Find next function or end
        # Look for JUMPDEST (0x5b) patterns to find function boundaries
        end = len(bytecode)
        next_jumpdest = bytecode.find('5b', start + 10)
        if next_jumpdest != -1:
            end = next_jumpdest
            
        return bytecode[start:end]

    def _analyze_storage(self, bytecode: str) -> List[StorageAccess]:
        """
        Analyze storage operations (SLOAD/SSTORE)
        """
        storage_ops = []
        
        # Find SLOAD operations (0x54)
        for match in re.finditer(r'54', bytecode):
            offset = match.start() // 2
            context = bytecode[max(0, match.start()-20):match.end()+20]
            
            storage_ops.append(StorageAccess(
                slot="unknown",  # Would need more analysis to determine slot
                operation="SLOAD",
                offset=offset,
                context=context
            ))
        
        # Find SSTORE operations (0x55)  
        for match in re.finditer(r'55', bytecode):
            offset = match.start() // 2
            context = bytecode[max(0, match.start()-20):match.end()+20]
            
            storage_ops.append(StorageAccess(
                slot="unknown",
                operation="SSTORE", 
                offset=offset,
                context=context
            ))
            
        return storage_ops

    def _find_external_calls(self, bytecode: str) -> List[Dict]:
        """
        Find external call patterns
        """
        calls = []
        
        # CALL instruction (0xf1)
        for match in re.finditer(r'f1', bytecode):
            offset = match.start() // 2
            context = bytecode[max(0, match.start()-40):match.end()+40]
            
            calls.append({
                'type': 'CALL',
                'offset': offset,
                'context': context,
                'potentially_vulnerable': self._is_call_vulnerable(context)
            })
        
        # DELEGATECALL instruction (0xf4)
        for match in re.finditer(r'f4', bytecode):
            offset = match.start() // 2
            context = bytecode[max(0, match.start()-40):match.end()+40]
            
            calls.append({
                'type': 'DELEGATECALL',
                'offset': offset,
                'context': context,
                'potentially_vulnerable': True  # DELEGATECALL is inherently risky
            })
            
        return calls

    def _detect_dangerous_patterns(self, bytecode: str) -> Dict[str, List[str]]:
        """
        Detect known dangerous patterns in bytecode
        """
        found_patterns = {}
        
        for pattern_name, patterns in self.dangerous_patterns.items():
            found_patterns[pattern_name] = []
            
            for pattern in patterns:
                if re.search(pattern, bytecode, re.IGNORECASE):
                    found_patterns[pattern_name].append(pattern)
                    
        return found_patterns

    def _check_reentrancy_bytecode(self, bytecode: str, analysis_results: Dict) -> List[Dict]:
        """
        Check for reentrancy vulnerabilities in bytecode
        """
        vulnerabilities = []
        
        # Look for CALL followed by SSTORE pattern
        call_sstore_pattern = r'f1.{0,100}?55'
        
        if re.search(call_sstore_pattern, bytecode, re.IGNORECASE):
            vulnerabilities.append({
                'type': 'reentrancy',
                'severity': 'HIGH',
                'description': 'External call followed by storage modification detected',
                'pattern': 'CALL -> SSTORE',
                'confidence': 0.7
            })
        
        # Check if functions with external calls also modify storage
        for func in analysis_results.get('functions', []):
            if func.contains_external_calls and func.modifies_storage and not func.has_auth_checks:
                vulnerabilities.append({
                    'type': 'reentrancy',
                    'severity': 'HIGH', 
                    'description': f'Function {func.selector} has external calls and modifies storage without auth checks',
                    'function': func.selector,
                    'confidence': 0.8
                })
        
        return vulnerabilities

    def _check_unauthorized_access(self, bytecode: str, analysis_results: Dict) -> List[Dict]:
        """
        Check for unauthorized access patterns
        """
        vulnerabilities = []
        
        # Look for transfer functions without proper checks
        for func in analysis_results.get('functions', []):
            if func.name and ('transfer' in func.name.lower()) and not func.has_auth_checks:
                vulnerabilities.append({
                    'type': 'unauthorized_transfer',
                    'severity': 'CRITICAL',
                    'description': f'Transfer function {func.selector} lacks authorization checks',
                    'function': func.selector,
                    'confidence': 0.9
                })
        
        return vulnerabilities

    def _check_storage_manipulation(self, bytecode: str, analysis_results: Dict) -> List[Dict]:
        """
        Check for storage manipulation vulnerabilities
        """
        vulnerabilities = []
        
        # Count storage write operations
        storage_writes = [op for op in analysis_results.get('storage_accesses', []) 
                         if op.operation == 'SSTORE']
        
        if len(storage_writes) > 5:  # Threshold for suspicious number of storage writes
            vulnerabilities.append({
                'type': 'excessive_storage_writes',
                'severity': 'MEDIUM',
                'description': f'Function contains {len(storage_writes)} storage write operations',
                'confidence': 0.6
            })
        
        return vulnerabilities

    def _check_selfdestruct_patterns(self, bytecode: str, analysis_results: Dict) -> List[Dict]:
        """
        Check for SELFDESTRUCT patterns
        """
        vulnerabilities = []
        
        if 'ff' in bytecode.lower():
            vulnerabilities.append({
                'type': 'selfdestruct',
                'severity': 'HIGH',
                'description': 'Contract contains SELFDESTRUCT instruction',
                'confidence': 1.0
            })
        
        return vulnerabilities

    def _is_payable(self, func_bytecode: str) -> bool:
        """
        Check if function is payable by looking for CALLVALUE checks
        """
        # Look for CALLVALUE (0x34) followed by conditional logic
        return '34' in func_bytecode and '57' in func_bytecode  # CALLVALUE ... JUMPI

    def _has_external_calls(self, func_bytecode: str) -> bool:
        """
        Check if function contains external calls
        """
        call_opcodes = ['f1', 'f2', 'f4', 'fa']  # CALL, CALLCODE, DELEGATECALL, STATICCALL
        return any(opcode in func_bytecode.lower() for opcode in call_opcodes)

    def _modifies_storage(self, func_bytecode: str) -> bool:
        """
        Check if function modifies storage
        """
        return '55' in func_bytecode.lower()  # SSTORE

    def _has_auth_checks(self, func_bytecode: str) -> bool:
        """
        Heuristic to detect authorization checks
        """
        # Look for patterns that suggest authorization:
        # 1. CALLER (0x33) followed by comparison
        # 2. SLOAD followed by comparison (checking stored admin)
        # 3. Revert patterns (0xfd)
        
        auth_patterns = [
            '33.*14',  # CALLER ... EQ
            '54.*14',  # SLOAD ... EQ  
            '33.*54.*14',  # CALLER ... SLOAD ... EQ
        ]
        
        return any(re.search(pattern, func_bytecode, re.IGNORECASE) 
                  for pattern in auth_patterns)

    def _is_call_vulnerable(self, context: str) -> bool:
        """
        Determine if a CALL instruction is potentially vulnerable
        """
        # Check if call is followed by storage operations
        if '55' in context:  # SSTORE after CALL
            return True
        
        # Check if call value is not checked
        if '34' not in context:  # No CALLVALUE check
            return True
            
        return False

    def generate_bytecode_report(self, analysis_results: Dict) -> str:
        """
        Generate detailed bytecode analysis report
        """
        report = "# Bytecode Analysis Report\n\n"
        
        # Functions summary
        report += "## Functions Detected\n\n"
        for func in analysis_results.get('functions', []):
            report += f"- **{func.selector}** ({func.name or 'Unknown'})\n"
            report += f"  - Offset: 0x{func.offset:x}\n"
            report += f"  - Payable: {func.is_payable}\n"
            report += f"  - External Calls: {func.contains_external_calls}\n"
            report += f"  - Modifies Storage: {func.modifies_storage}\n"
            report += f"  - Has Auth Checks: {func.has_auth_checks}\n\n"
        
        # Storage analysis
        report += "## Storage Operations\n\n"
        storage_ops = analysis_results.get('storage_accesses', [])
        report += f"Total storage operations: {len(storage_ops)}\n"
        report += f"- SLOAD operations: {len([op for op in storage_ops if op.operation == 'SLOAD'])}\n"
        report += f"- SSTORE operations: {len([op for op in storage_ops if op.operation == 'SSTORE'])}\n\n"
        
        # External calls
        report += "## External Calls\n\n"
        calls = analysis_results.get('external_calls', [])
        report += f"Total external calls: {len(calls)}\n"
        for call in calls:
            report += f"- {call['type']} at offset 0x{call['offset']:x}"
            if call.get('potentially_vulnerable'):
                report += " ⚠️ Potentially vulnerable"
            report += "\n"
        
        # Dangerous patterns
        report += "\n## Dangerous Patterns Detected\n\n"
        patterns = analysis_results.get('dangerous_patterns', {})
        for pattern_name, matches in patterns.items():
            if matches:
                report += f"- **{pattern_name}**: {len(matches)} matches\n"
        
        # Vulnerabilities
        report += "\n## Vulnerabilities\n\n"
        vulns = analysis_results.get('vulnerabilities', [])
        if vulns:
            for vuln in vulns:
                report += f"### {vuln['type'].upper()}\n"
                report += f"- **Severity**: {vuln['severity']}\n"
                report += f"- **Description**: {vuln['description']}\n"
                report += f"- **Confidence**: {vuln['confidence']:.0%}\n\n"
        else:
            report += "No specific vulnerabilities detected in bytecode analysis.\n"
        
        return report


def main():
    """Test bytecode analyzer with sample data"""
    analyzer = BytecodeAnalyzer()
    
    # Test with sample bytecode (simplified)
    sample_bytecode = "608060405260043610610041576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff16806354fd4d5014610046575b600080fd5b34801561005257600080fd5b50f1"
    
    results = analyzer.analyze_bytecode(sample_bytecode)
    report = analyzer.generate_bytecode_report(results)
    print(report)


if __name__ == "__main__":
    main()