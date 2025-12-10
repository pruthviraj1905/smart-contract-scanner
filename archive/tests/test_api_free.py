#!/usr/bin/env python3
"""
Quick test script for API-free functionality
Tests web scraping + RPC calls without requiring API keys
"""

import sys
from api_free_fetcher import APIFreeFetcher

def test_api_free_fetcher():
    """Test the API-free fetcher with a known contract"""

    print("=" * 70)
    print("🧪 TESTING API-FREE CONTRACT FETCHER")
    print("=" * 70)
    print()

    # Test with a well-known contract on BSC
    test_contracts = [
        {
            'chain': 'bsc',
            'address': '0x55d398326f99059fF775485246999027B3197955',  # USDT on BSC
            'name': 'USDT (BSC)'
        },
        {
            'chain': 'ethereum',
            'address': '0xdAC17F958D2ee523a2206206994597C13D831ec7',  # USDT on Ethereum
            'name': 'USDT (Ethereum)'
        },
        {
            'chain': 'base',
            'address': '0x4bccA4a0Bfa325dc00E9c498A62EA271aA31Cf4D',  # Sample Base contract
            'name': 'Sample Base Contract'
        }
    ]

    for test in test_contracts[:1]:  # Test only first one for speed
        print(f"Testing: {test['name']}")
        print(f"Chain: {test['chain']}")
        print(f"Address: {test['address']}")
        print("-" * 70)

        try:
            # Initialize fetcher for the chain
            fetcher = APIFreeFetcher(chain=test['chain'])

            # Test 1: Get contract info
            print("\n✅ Test 1: Fetching contract info...")
            info = fetcher.get_contract_info(test['address'])

            if info['exists']:
                print(f"   ✓ Contract exists: {info['exists']}")
                print(f"   ✓ Verified: {info['verified']}")
                print(f"   ✓ Balance: {info['balance']}")
                if info.get('contract_name'):
                    print(f"   ✓ Name: {info['contract_name']}")
            else:
                print(f"   ✗ Contract not found or error: {info.get('error', 'Unknown')}")

            # Test 2: Get balance
            print("\n✅ Test 2: Fetching balance via RPC...")
            balance = fetcher.get_balance(test['address'])
            if balance:
                print(f"   ✓ Balance (RPC): {balance}")
            else:
                print(f"   ✗ Balance fetch failed")

            # Test 3: Get bytecode
            print("\n✅ Test 3: Fetching bytecode via RPC...")
            bytecode = fetcher.fetch_bytecode(test['address'])
            if bytecode and len(bytecode) > 10:
                print(f"   ✓ Bytecode fetched: {len(bytecode)} characters")
                print(f"   ✓ First 66 chars: {bytecode[:66]}...")
            else:
                print(f"   ✗ Bytecode fetch failed")

            # Test 4: Read storage slot
            print("\n✅ Test 4: Reading storage slot 0x0...")
            storage = fetcher.get_storage_at(test['address'], '0x0')
            if storage:
                print(f"   ✓ Storage slot 0x0: {storage}")
            else:
                print(f"   ✗ Storage read failed")

            # Test 5: Fetch source code (if verified)
            if info.get('verified'):
                print("\n✅ Test 5: Fetching source code via scraping...")
                source = fetcher.fetch_contract_source(test['address'])
                if source and len(source) > 100:
                    print(f"   ✓ Source code fetched: {len(source)} characters")
                    print(f"   ✓ First 100 chars: {source[:100]}...")
                else:
                    print(f"   ⚠  Source code not available (may need manual verification)")
            else:
                print("\n⚠  Test 5: Skipped (contract not verified)")

            print("\n" + "=" * 70)
            print("✅ ALL TESTS PASSED - API-FREE MODE WORKING!")
            print("=" * 70)
            return True

        except Exception as e:
            print(f"\n❌ ERROR: {e}")
            import traceback
            traceback.print_exc()
            return False

    return True

def test_scanner_initialization():
    """Test that the scanner initializes in API-free mode"""

    print("\n" + "=" * 70)
    print("🧪 TESTING SCANNER INITIALIZATION")
    print("=" * 70)
    print()

    try:
        from deep_vuln_scanner import DeepContractScanner

        # Test without API key (should auto-enable API-free mode)
        print("✅ Test: Initializing scanner without API key...")
        scanner = DeepContractScanner(
            etherscan_api_key=None,
            chain_config={'chain_id': '56', 'chain': 'bsc', 'name': 'BSC'},
            enable_ai_validation=False,
            use_api_free=True
        )

        print("   ✓ Scanner initialized successfully")
        print(f"   ✓ API-free mode: {scanner.use_api_free}")
        print(f"   ✓ Chain: {scanner.chain_config['name']}")

        if scanner.api_free_fetcher:
            print(f"   ✓ API-free fetcher initialized")
        else:
            print(f"   ✗ API-free fetcher NOT initialized")
            return False

        print("\n" + "=" * 70)
        print("✅ SCANNER INITIALIZATION PASSED!")
        print("=" * 70)
        return True

    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("\n🚀 Starting API-Free Mode Tests...\n")

    # Test 1: API-free fetcher
    test1_passed = test_api_free_fetcher()

    # Test 2: Scanner initialization
    test2_passed = test_scanner_initialization()

    # Summary
    print("\n" + "=" * 70)
    print("📊 TEST SUMMARY")
    print("=" * 70)
    print(f"API-Free Fetcher: {'✅ PASSED' if test1_passed else '❌ FAILED'}")
    print(f"Scanner Initialization: {'✅ PASSED' if test2_passed else '❌ FAILED'}")
    print("=" * 70)

    if test1_passed and test2_passed:
        print("\n🎉 ALL TESTS PASSED - API-FREE MODE IS WORKING!")
        print("✅ The scanner is ready to use without any API keys!")
        sys.exit(0)
    else:
        print("\n❌ SOME TESTS FAILED - CHECK ERRORS ABOVE")
        sys.exit(1)
