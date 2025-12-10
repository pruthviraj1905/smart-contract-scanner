#!/usr/bin/env python3
"""
Advanced Proxy Contract Detection and Analysis Module
Supports EIP-1967, EIP-1822, EIP-2535 and other proxy standards
"""

import requests
import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

class ProxyType(Enum):
    EIP1967_TRANSPARENT = "EIP-1967 Transparent Proxy"
    EIP1967_UUPS = "EIP-1967 UUPS Proxy" 
    EIP1822_UNIVERSAL = "EIP-1822 Universal Proxy"
    EIP2535_DIAMOND = "EIP-2535 Diamond Proxy"
    OPENZEPPELIN_UPGRADEABLE = "OpenZeppelin Upgradeable"
    GNOSIS_SAFE = "Gnosis Safe Proxy"
    MINIMAL_PROXY = "Minimal Proxy (EIP-1167)"
    CUSTOM_PROXY = "Custom Proxy Pattern"
    NOT_PROXY = "Not a Proxy Contract"

@dataclass
class ProxyInfo:
    proxy_type: ProxyType
    proxy_address: str
    implementation_address: Optional[str] = None
    admin_address: Optional[str] = None
    beacon_address: Optional[str] = None
    facets: List[str] = None
    confidence: float = 0.0
    detection_method: str = ""
    additional_info: Dict = None

class ProxyDetector:
    def __init__(self, api_key: str = None, chain_config: Dict = None, api_free_fetcher=None):
        self.api_key = api_key
        self.api_free_fetcher = api_free_fetcher
        self.use_api_free = api_free_fetcher is not None

        self.chain_config = chain_config or {
            'chain_id': '1',
            'chain': 'ethereum',
            'name': 'Ethereum'
        }

        # EIP-1967 Standard Storage Slots
        self.EIP1967_SLOTS = {
            'implementation': '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc',
            'admin': '0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103',
            'beacon': '0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50'
        }
        
        # EIP-1822 Storage Slot
        self.EIP1822_SLOT = '0xc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7'
        
        # Common proxy bytecode patterns
        self.PROXY_PATTERNS = {
            'minimal_proxy': r'363d3d373d3d3d363d73[a-fA-F0-9]{40}5af43d82803e903d91602b57fd5bf3',
            'transparent_proxy': r'60806040[a-fA-F0-9]*3660008037600080366000845af43d6000803e808015[a-fA-F0-9]*573d6000fd',
            'uups_proxy': r'60806040[a-fA-F0-9]*363d3d373d3d3d363d30545af43d82803e903d91601857fd5bf3',
            'diamond_proxy': r'608060405234801561001057600080fd5b50[a-fA-F0-9]*facet',
            'delegatecall_pattern': r'[a-fA-F0-9]*5b6000[a-fA-F0-9]*f4[a-fA-F0-9]*'
        }

    def detect_proxy(self, contract_address: str, source_code: str = None, bytecode: str = None) -> ProxyInfo:
        """
        Comprehensive proxy detection using multiple methods
        """
        print(f"🔍 Detecting proxy pattern for {contract_address}")
        
        # Method 1: Check EIP-1967 storage slots
        eip1967_info = self._check_eip1967_slots(contract_address)
        if eip1967_info.proxy_type != ProxyType.NOT_PROXY:
            print(f"✅ EIP-1967 proxy detected: {eip1967_info.proxy_type.value}")
            return eip1967_info
        
        # Method 2: Check EIP-1822 storage slot
        eip1822_info = self._check_eip1822_slot(contract_address)
        if eip1822_info.proxy_type != ProxyType.NOT_PROXY:
            print(f"✅ EIP-1822 proxy detected: {eip1822_info.proxy_type.value}")
            return eip1822_info
        
        # Method 3: Source code analysis
        if source_code:
            source_info = self._analyze_source_code(contract_address, source_code)
            if source_info.proxy_type != ProxyType.NOT_PROXY:
                print(f"✅ Source code proxy detected: {source_info.proxy_type.value}")
                return source_info
        
        # Method 4: Bytecode pattern analysis
        if not bytecode:
            bytecode = self._fetch_bytecode(contract_address)
        
        if bytecode:
            bytecode_info = self._analyze_bytecode_patterns(contract_address, bytecode)
            if bytecode_info.proxy_type != ProxyType.NOT_PROXY:
                print(f"✅ Bytecode proxy detected: {bytecode_info.proxy_type.value}")
                return bytecode_info
        
        # Method 5: Function signature analysis
        function_info = self._analyze_function_signatures(contract_address)
        if function_info.proxy_type != ProxyType.NOT_PROXY:
            print(f"✅ Function signature proxy detected: {function_info.proxy_type.value}")
            return function_info
        
        print("ℹ️ No proxy pattern detected")
        return ProxyInfo(
            proxy_type=ProxyType.NOT_PROXY,
            proxy_address=contract_address,
            confidence=0.9,
            detection_method="Comprehensive analysis"
        )

    def _check_eip1967_slots(self, address: str) -> ProxyInfo:
        """Check EIP-1967 standard storage slots"""
        implementation = self._read_storage_slot(address, self.EIP1967_SLOTS['implementation'])
        admin = self._read_storage_slot(address, self.EIP1967_SLOTS['admin'])
        beacon = self._read_storage_slot(address, self.EIP1967_SLOTS['beacon'])
        
        if implementation and implementation != '0x' + '0' * 64:
            # Extract address from storage (last 20 bytes)
            impl_address = '0x' + implementation[-40:]
            admin_address = None
            
            if admin and admin != '0x' + '0' * 64:
                admin_address = '0x' + admin[-40:]
            
            if beacon and beacon != '0x' + '0' * 64:
                return ProxyInfo(
                    proxy_type=ProxyType.EIP1967_UUPS,
                    proxy_address=address,
                    implementation_address=impl_address,
                    admin_address=admin_address,
                    beacon_address='0x' + beacon[-40:],
                    confidence=0.95,
                    detection_method="EIP-1967 storage slot analysis"
                )
            else:
                proxy_type = ProxyType.EIP1967_UUPS if not admin_address else ProxyType.EIP1967_TRANSPARENT
                return ProxyInfo(
                    proxy_type=proxy_type,
                    proxy_address=address,
                    implementation_address=impl_address,
                    admin_address=admin_address,
                    confidence=0.95,
                    detection_method="EIP-1967 storage slot analysis"
                )
        
        return ProxyInfo(proxy_type=ProxyType.NOT_PROXY, proxy_address=address)

    def _check_eip1822_slot(self, address: str) -> ProxyInfo:
        """Check EIP-1822 universal proxy storage slot"""
        implementation = self._read_storage_slot(address, self.EIP1822_SLOT)
        
        if implementation and implementation != '0x' + '0' * 64:
            impl_address = '0x' + implementation[-40:]
            return ProxyInfo(
                proxy_type=ProxyType.EIP1822_UNIVERSAL,
                proxy_address=address,
                implementation_address=impl_address,
                confidence=0.95,
                detection_method="EIP-1822 storage slot analysis"
            )
        
        return ProxyInfo(proxy_type=ProxyType.NOT_PROXY, proxy_address=address)

    def _analyze_source_code(self, address: str, source_code: str) -> ProxyInfo:
        """Analyze source code for proxy patterns"""
        
        # Check for Diamond proxy (EIP-2535)
        if any(keyword in source_code.lower() for keyword in ['facet', 'diamondcut', 'loupe']):
            facets = self._extract_diamond_facets(source_code)
            return ProxyInfo(
                proxy_type=ProxyType.EIP2535_DIAMOND,
                proxy_address=address,
                facets=facets,
                confidence=0.9,
                detection_method="Diamond pattern source analysis",
                additional_info={'facet_count': len(facets)}
            )
        
        # Check for OpenZeppelin upgradeable patterns
        oz_patterns = [
            'import.*@openzeppelin.*upgradeable',
            'UUPSUpgradeable',
            'TransparentUpgradeableProxy',
            'Initializable'
        ]
        
        if any(re.search(pattern, source_code, re.IGNORECASE) for pattern in oz_patterns):
            return ProxyInfo(
                proxy_type=ProxyType.OPENZEPPELIN_UPGRADEABLE,
                proxy_address=address,
                confidence=0.85,
                detection_method="OpenZeppelin upgradeable pattern analysis"
            )
        
        # Check for custom proxy patterns
        proxy_indicators = [
            r'function\s+.*fallback.*external',
            r'assembly\s*{.*delegatecall',
            r'_implementation\(\)',
            r'upgradeTo\s*\(',
            r'_setImplementation'
        ]
        
        matches = sum(1 for pattern in proxy_indicators if re.search(pattern, source_code, re.IGNORECASE))
        
        if matches >= 2:
            return ProxyInfo(
                proxy_type=ProxyType.CUSTOM_PROXY,
                proxy_address=address,
                confidence=0.7,
                detection_method=f"Custom proxy pattern analysis ({matches} indicators)"
            )
        
        return ProxyInfo(proxy_type=ProxyType.NOT_PROXY, proxy_address=address)

    def _analyze_bytecode_patterns(self, address: str, bytecode: str) -> ProxyInfo:
        """Analyze bytecode for proxy patterns"""
        
        # Check for minimal proxy (EIP-1167)
        if re.search(self.PROXY_PATTERNS['minimal_proxy'], bytecode):
            # Extract implementation address from minimal proxy bytecode
            match = re.search(r'363d3d373d3d3d363d73([a-fA-F0-9]{40})5af43d82803e903d91602b57fd5bf3', bytecode)
            impl_address = f"0x{match.group(1)}" if match else None
            
            return ProxyInfo(
                proxy_type=ProxyType.MINIMAL_PROXY,
                proxy_address=address,
                implementation_address=impl_address,
                confidence=0.95,
                detection_method="EIP-1167 minimal proxy bytecode analysis"
            )
        
        # Check for other proxy patterns
        for pattern_name, pattern in self.PROXY_PATTERNS.items():
            if re.search(pattern, bytecode):
                confidence = 0.8 if 'delegatecall' in pattern_name else 0.7
                return ProxyInfo(
                    proxy_type=ProxyType.CUSTOM_PROXY,
                    proxy_address=address,
                    confidence=confidence,
                    detection_method=f"Bytecode pattern analysis ({pattern_name})"
                )
        
        return ProxyInfo(proxy_type=ProxyType.NOT_PROXY, proxy_address=address)

    def _analyze_function_signatures(self, address: str) -> ProxyInfo:
        """Analyze function signatures for proxy indicators"""
        
        # Common proxy function signatures
        proxy_signatures = {
            'upgradeTo(address)': '0x3659cfe6',
            'upgradeToAndCall(address,bytes)': '0x4f1ef286',
            'implementation()': '0x5c60da1b',
            'admin()': '0xf851a440',
            'fallback()': '0x',  # Fallback function
            'facets()': '0x7a0ed627',  # Diamond proxy
            'facetFunctionSelectors(address)': '0xadfca15e'
        }
        
        detected_functions = []
        
        # This would require calling the contract to check function existence
        # For now, we'll use bytecode analysis as a proxy
        bytecode = self._fetch_bytecode(address)
        if bytecode:
            for func_name, signature in proxy_signatures.items():
                if signature[2:] in bytecode:  # Remove 0x prefix
                    detected_functions.append(func_name)
        
        if len(detected_functions) >= 2:
            if 'facets()' in detected_functions:
                proxy_type = ProxyType.EIP2535_DIAMOND
            elif 'upgradeTo' in str(detected_functions):
                proxy_type = ProxyType.EIP1967_UUPS
            else:
                proxy_type = ProxyType.CUSTOM_PROXY
                
            return ProxyInfo(
                proxy_type=proxy_type,
                proxy_address=address,
                confidence=0.75,
                detection_method=f"Function signature analysis ({len(detected_functions)} proxy functions)",
                additional_info={'detected_functions': detected_functions}
            )
        
        return ProxyInfo(proxy_type=ProxyType.NOT_PROXY, proxy_address=address)

    def _extract_diamond_facets(self, source_code: str) -> List[str]:
        """Extract facet addresses from Diamond proxy source code"""
        facet_pattern = r'facets?\s*\[\s*\]\s*=\s*.*?0x[a-fA-F0-9]{40}'
        matches = re.findall(facet_pattern, source_code, re.IGNORECASE | re.DOTALL)
        
        facets = []
        for match in matches:
            address_match = re.search(r'0x[a-fA-F0-9]{40}', match)
            if address_match:
                facets.append(address_match.group(0))
        
        return list(set(facets))  # Remove duplicates

    def _read_storage_slot(self, address: str, slot: str) -> Optional[str]:
        """Read storage slot from blockchain - API-free mode preferred"""
        # Try API-free mode first (RPC)
        if self.use_api_free and self.api_free_fetcher:
            try:
                result = self.api_free_fetcher.get_storage_at(address, slot)
                if result:
                    return result
            except Exception as e:
                print(f"[-] API-free storage read failed: {e}")

        # Fallback to API mode
        if self.api_key:
            try:
                url = self.chain_config.get('api_base', 'https://api.etherscan.io/api')
                params = {
                    'module': 'proxy',
                    'action': 'eth_getStorageAt',
                    'address': address,
                    'position': slot,
                    'tag': 'latest',
                    'apikey': self.api_key
                }

                if 'v2' in url:
                    params['chainid'] = self.chain_config['chain_id']

                response = requests.get(url, params=params)
                data = response.json()

                return data.get('result')

            except Exception as e:
                print(f"[-] API storage read failed: {e}")

        return None

    def _fetch_bytecode(self, address: str) -> Optional[str]:
        """Fetch contract bytecode - API-free mode preferred"""
        # Try API-free mode first (RPC or scraping)
        if self.use_api_free and self.api_free_fetcher:
            try:
                bytecode = self.api_free_fetcher.fetch_bytecode(address)
                if bytecode:
                    return bytecode
            except Exception as e:
                print(f"[-] API-free bytecode fetch failed: {e}")

        # Fallback to API mode
        if self.api_key:
            try:
                url = self.chain_config.get('api_base', 'https://api.etherscan.io/api')
                params = {
                    'module': 'proxy',
                    'action': 'eth_getCode',
                    'address': address,
                    'tag': 'latest',
                    'apikey': self.api_key
                }

                if 'v2' in url:
                    params['chainid'] = self.chain_config['chain_id']

                response = requests.get(url, params=params)
                data = response.json()

                return data.get('result')

            except Exception as e:
                print(f"[-] API bytecode fetch failed: {e}")

        return None

    def get_all_implementation_addresses(self, proxy_info: ProxyInfo) -> List[str]:
        """Get all relevant contract addresses to scan"""
        addresses = [proxy_info.proxy_address]
        
        if proxy_info.implementation_address:
            addresses.append(proxy_info.implementation_address)
        
        if proxy_info.beacon_address:
            addresses.append(proxy_info.beacon_address)
        
        if proxy_info.facets:
            addresses.extend(proxy_info.facets)
        
        return list(set(addresses))  # Remove duplicates