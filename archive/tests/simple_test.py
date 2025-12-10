#!/usr/bin/env python3
"""Simple test for safe pattern matching"""

import time
from pattern_engine import AdvancedPatternEngine

# Read the decompiled file
with open('0xC59B83cCaa4626F49a040BA5E9A884A0Fe8345E1.txt', 'r') as f:
    code = f.read()

print(f'File size: {len(code)} bytes, {len(code.splitlines())} lines')
print()

print('Testing pattern engine with safe matcher...')
start = time.time()

engine = AdvancedPatternEngine()
vulnerabilities = engine.scan_for_patterns(code, code_type='solidity')

elapsed = time.time() - start
print(f'✅ Scan completed in {elapsed:.2f} seconds')
print(f'Found {len(vulnerabilities)} vulnerabilities')
print()

for vuln in vulnerabilities:
    print(f'- [{vuln["severity"]}] {vuln["title"]}')
    print(f'  Location: {vuln["location"]}')
    print(f'  Confidence: {vuln["confidence"]:.2f}')
    print()
