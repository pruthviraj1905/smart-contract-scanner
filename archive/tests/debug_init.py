#!/usr/bin/env python3
"""Debug initialization"""

import time

print('Step 1: Importing modules...')
start = time.time()

print(' - Importing BytecodeAnalyzer')
from bytecode_analyzer import BytecodeAnalyzer
print(f'   ✅ {time.time() - start:.3f}s')

print(' - Importing AdvancedPatternEngine')
from pattern_engine import AdvancedPatternEngine
print(f'   ✅ {time.time() - start:.3f}s')

print(' - Importing Ultra StrictValidator')
from ultra_strict_validator import UltraStrictValidator
print(f'   ✅ {time.time() - start:.3f}s')

print(' - Importing EnhancedVulnerabilityPatterns')
from enhanced_vulnerability_patterns import EnhancedVulnerabilityPatterns
print(f'   ✅ {time.time() - start:.3f}s')

print(' - Importing APIFreeFetcher')
from api_free_fetcher import APIFreeFetcher, get_fetcher
print(f'   ✅ {time.time() - start:.3f}s')

print(' - Importing DeepContractScanner')
from deep_vuln_scanner import DeepContractScanner
print(f'   ✅ {time.time() - start:.3f}s')

print('\nStep 2: Creating scanner instance...')
instance_start = time.time()

scanner = DeepContractScanner(
    etherscan_api_key=None,
    use_api_free=True,
    enable_ai_validation=False
)

print(f'✅ Scanner created in {time.time() - instance_start:.3f}s')
print(f'Total time: {time.time() - start:.3f}s')
