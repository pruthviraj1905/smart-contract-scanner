#!/usr/bin/env python3
"""Minimal scan bypassing proxy detection"""

import time
from pattern_engine import AdvancedPatternEngine
from enhanced_vulnerability_patterns import EnhancedVulnerabilityPatterns

# Read the decompiled file
with open('0xC59B83cCaa4626F49a040BA5E9A884A0Fe8345E1.txt', 'r') as f:
    code = f.read()

print('=' * 80)
print('MINIMAL VULNERABILITY SCAN (No Proxy Detection, No API Calls)')
print('=' * 80)
print(f'Contract: 0xC59B83cCaa4626F49a040BA5E9A884A0Fe8345E1')
print(f'Chain: BSC')
print(f'File size: {len(code)} bytes, {len(code.splitlines())} lines')
print('=' * 80)
print()

# Test 1: Pattern Engine
print('Test 1: Pattern Engine')
start = time.time()
engine = AdvancedPatternEngine()
vulns1 = engine.scan_for_patterns(code, code_type='solidity')
print(f'✅ Found {len(vulns1)} vulnerabilities in {time.time() - start:.3f}s')
print()

# Test 2: Enhanced Patterns
print('Test 2: Enhanced Vulnerability Patterns')
start = time.time()
enhanced = EnhancedVulnerabilityPatterns()
patterns = enhanced.get_all_patterns()
vulns2 = []
for pattern in patterns:
    matches = enhanced.check_pattern_match(pattern, code, is_decompiled=True)
    for matched_text, line_num in matches:
        vulns2.append({
            'title': pattern.name,
            'severity': pattern.severity,
            'location': f'Line {line_num}',
            'confidence': pattern.confidence
        })
print(f'✅ Found {len(vulns2)} vulnerabilities in {time.time() - start:.3f}s')
print()

# Display all findings
all_vulns = vulns1 + vulns2
print('=' * 80)
print(f'TOTAL: {len(all_vulns)} vulnerabilities found')
print('=' * 80)
print()

severity_counts = {}
for vuln in all_vulns:
    severity = vuln.get('severity', 'UNKNOWN')
    severity_counts[severity] = severity_counts.get(severity, 0) + 1

for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
    count = severity_counts.get(severity, 0)
    if count > 0:
        print(f'{severity}: {count}')

print()
print('Top vulnerabilities:')
for i, vuln in enumerate(all_vulns[:10], 1):
    title = vuln.get('title', 'Unknown')
    severity = vuln.get('severity', 'UNKNOWN')
    location = vuln.get('location', 'Unknown')
    confidence = vuln.get('confidence', 0.5)
    print(f'{i}. [{severity}] {title}')
    print(f'   Location: {location}, Confidence: {confidence:.2f}')
