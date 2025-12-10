#!/usr/bin/env python3
"""Debug scan to find bottleneck"""

import time
from deep_vuln_scanner import DeepContractScanner

# Read the decompiled file
with open('0xC59B83cCaa4626F49a040BA5E9A884A0Fe8345E1.txt', 'r') as f:
    decompiled_code = f.read()

print('Initializing scanner...')
start = time.time()
scanner = DeepContractScanner(
    etherscan_api_key=None,
    use_api_free=True,
    enable_ai_validation=False
)
print(f'✅ Initialized in {time.time() - start:.2f}s\n')

print('Starting scan...')
print('This will timeout after 30 seconds if there\'s a hang\n')

try:
    import signal

    def timeout_handler(signum, frame):
        print('\n❌ TIMEOUT after 30 seconds')
        print('The hang is likely in deep_vuln_scanner.scan_contract()')
        raise TimeoutError('Scan timeout')

    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(30)

    scan_start = time.time()
    vulnerabilities = scanner.scan_contract(
        contract_address='0xC59B83cCaa4626F49a040BA5E9A884A0Fe8345E1',
        source_code=None,
        bytecode=None,
        decompiled_code=decompiled_code
    )

    signal.alarm(0)  # Cancel timeout

    print(f'✅ Scan completed in {time.time() - scan_start:.2f}s')
    print(f'Found {len(vulnerabilities)} vulnerabilities')

except TimeoutError:
    print('\nDEBUG: Check which phase the scanner is stuck in')
    print('Likely culprits:')
    print('- _check_solidity_patterns() if it has unbounded regex')
    print('- enhanced_vulnerability_patterns if it has slow patterns')
    print('- bytecode_analyzer if analyzing invalid bytecode')
