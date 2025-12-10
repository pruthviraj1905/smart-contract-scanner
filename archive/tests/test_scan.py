#!/usr/bin/env python3
"""
Test scan for decompiled contract 0xC59B83cCaa4626F49a040BA5E9A884A0Fe8345E1
"""

import sys
from deep_vuln_scanner import DeepContractScanner

# Read the decompiled file
with open('0xC59B83cCaa4626F49a040BA5E9A884A0Fe8345E1.txt', 'r') as f:
    decompiled_code = f.read()

print('=' * 80)
print('SMART CONTRACT VULNERABILITY SCAN')
print('=' * 80)
print(f'Contract: 0xC59B83cCaa4626F49a040BA5E9A884A0Fe8345E1')
print(f'Chain: BSC (Binance Smart Chain)')
print(f'File: 0xC59B83cCaa4626F49a040BA5E9A884A0Fe8345E1.txt (96 lines, 4.3KB)')
print(f'Type: Decompiled Code')
print('=' * 80)
print()

# Initialize scanner
scanner = DeepContractScanner(
    etherscan_api_key=None,
    use_api_free=True,
    enable_ai_validation=False  # Disable AI for faster testing
)

print('🔍 Scanning for vulnerabilities...')
print()

# Scan the contract
vulnerabilities = scanner.scan_contract(
    contract_address='0xC59B83cCaa4626F49a040BA5E9A884A0Fe8345E1',
    source_code=None,
    bytecode=None,
    decompiled_code=decompiled_code
)

print('=' * 80)
print(f'✅ SCAN COMPLETED - Found {len(vulnerabilities)} vulnerabilities')
print('=' * 80)
print()

# Group by severity
severity_groups = {}
for vuln in vulnerabilities:
    severity = vuln.severity.value
    if severity not in severity_groups:
        severity_groups[severity] = []
    severity_groups[severity].append(vuln)

# Display by severity
severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
for severity in severity_order:
    if severity in severity_groups:
        vulns = severity_groups[severity]
        print(f'\n{"=" * 80}')
        print(f'{severity} SEVERITY - {len(vulns)} vulnerabilities')
        print(f'{"=" * 80}\n')

        for i, vuln in enumerate(vulns, 1):
            print(f'{i}. {vuln.title}')
            print(f'   Confidence: {vuln.confidence:.2f}')
            print(f'   Location: {vuln.location}')
            print(f'   Description: {vuln.description}')
            if vuln.matched_text:
                matched = vuln.matched_text[:100] + '...' if len(vuln.matched_text) > 100 else vuln.matched_text
                print(f'   Matched: {matched}')
            print()

print('=' * 80)
print('SCAN SUMMARY')
print('=' * 80)
for severity in severity_order:
    count = len(severity_groups.get(severity, []))
    if count > 0:
        print(f'{severity}: {count}')
print('=' * 80)
