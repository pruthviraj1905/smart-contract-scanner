#!/usr/bin/env python3
"""
Enhanced API-Free Contract Fetcher
Complete replacement for Etherscan API with web scraping + direct RPC calls
No API keys required - works for all chains
"""

import requests
import re
import json
import time
from bs4 import BeautifulSoup
from typing import Optional, Dict, Any
from web3 import Web3
from functools import wraps

def retry_with_exponential_backoff(max_retries=3, base_delay=1, max_delay=30):
    """Decorator for exponential backoff retry logic"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            retries = 0
            while retries < max_retries:
                try:
                    return func(*args, **kwargs)
                except (requests.RequestException, ConnectionError, TimeoutError) as e:
                    retries += 1
                    if retries >= max_retries:
                        print(f"❌ Max retries ({max_retries}) exceeded for {func.__name__}: {e}")
                        raise

                    delay = min(base_delay * (2 ** (retries - 1)), max_delay)
                    print(f"⚠️  Retry {retries}/{max_retries} for {func.__name__} after {delay}s: {e}")
                    time.sleep(delay)
                except Exception as e:
                    # Non-recoverable errors
                    print(f"❌ Non-recoverable error in {func.__name__}: {e}")
                    raise
        return wrapper
    return decorator


class APIFreeFetcher:
    """API-free contract data fetcher using web scraping and direct RPC"""

    def __init__(self, chain='ethereum'):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })

        # Rate limiting
        self.last_request_time = 0
        self.min_request_interval = 0.5  # 500ms between requests
        self.request_count = 0
        self.rate_limit_window_start = time.time()
        self.max_requests_per_minute = 60

        # Chain configurations with explorer URLs and public RPC endpoints
        self.chain_configs = {
            'ethereum': {
                'name': 'Ethereum',
                'chain_id': 1,
                'explorer': 'https://etherscan.io',
                'explorer_api': 'https://etherscan.io/api',
                'rpc': 'https://eth.llamarpc.com',
                'currency': 'ETH'
            },
            'bsc': {
                'name': 'BSC',
                'chain_id': 56,
                'explorer': 'https://bscscan.com',
                'explorer_api': 'https://bscscan.com/api',
                'rpc': 'https://bsc-dataseed.binance.org',
                'currency': 'BNB'
            },
            'polygon': {
                'name': 'Polygon',
                'chain_id': 137,
                'explorer': 'https://polygonscan.com',
                'explorer_api': 'https://polygonscan.com/api',
                'rpc': 'https://polygon-rpc.com',
                'currency': 'MATIC'
            },
            'arbitrum': {
                'name': 'Arbitrum',
                'chain_id': 42161,
                'explorer': 'https://arbiscan.io',
                'explorer_api': 'https://arbiscan.io/api',
                'rpc': 'https://arb1.arbitrum.io/rpc',
                'currency': 'ETH'
            },
            'optimism': {
                'name': 'Optimism',
                'chain_id': 10,
                'explorer': 'https://optimistic.etherscan.io',
                'explorer_api': 'https://optimistic.etherscan.io/api',
                'rpc': 'https://mainnet.optimism.io',
                'currency': 'ETH'
            },
            'base': {
                'name': 'Base',
                'chain_id': 8453,
                'explorer': 'https://basescan.org',
                'explorer_api': 'https://basescan.org/api',
                'rpc': 'https://mainnet.base.org',
                'currency': 'ETH'
            },
            'avalanche': {
                'name': 'Avalanche',
                'chain_id': 43114,
                'explorer': 'https://snowtrace.io',
                'explorer_api': 'https://snowtrace.io/api',
                'rpc': 'https://api.avax.network/ext/bc/C/rpc',
                'currency': 'AVAX'
            },
            'gnosis': {
                'name': 'Gnosis',
                'chain_id': 100,
                'explorer': 'https://gnosisscan.io',
                'explorer_api': 'https://gnosisscan.io/api',
                'rpc': 'https://rpc.gnosischain.com',
                'currency': 'xDAI'
            }
        }

        self.set_chain(chain)

    def set_chain(self, chain: str):
        """Set the active blockchain"""
        if chain not in self.chain_configs:
            raise ValueError(f"Unsupported chain: {chain}. Supported: {list(self.chain_configs.keys())}")

        self.chain = chain
        self.config = self.chain_configs[chain]

        # Initialize Web3 for RPC calls
        try:
            self.web3 = Web3(Web3.HTTPProvider(self.config['rpc']))
            self.rpc_available = self.web3.is_connected()
        except Exception as e:
            print(f"⚠️  RPC connection failed for {chain}: {e}")
            self.rpc_available = False
            self.web3 = None

    def _rate_limit_check(self):
        """Check and enforce rate limiting"""
        current_time = time.time()

        # Reset counter every minute
        if current_time - self.rate_limit_window_start >= 60:
            self.request_count = 0
            self.rate_limit_window_start = current_time

        # Check requests per minute
        if self.request_count >= self.max_requests_per_minute:
            sleep_time = 60 - (current_time - self.rate_limit_window_start)
            if sleep_time > 0:
                print(f"⏸️  Rate limit: Sleeping {sleep_time:.1f}s...")
                time.sleep(sleep_time)
                self.request_count = 0
                self.rate_limit_window_start = time.time()

        # Enforce minimum interval between requests
        elapsed = current_time - self.last_request_time
        if elapsed < self.min_request_interval:
            time.sleep(self.min_request_interval - elapsed)

        self.last_request_time = time.time()
        self.request_count += 1

    @retry_with_exponential_backoff(max_retries=3, base_delay=2)
    def fetch_contract_source(self, address: str) -> Optional[str]:
        """Fetch verified contract source code by scraping the explorer"""
        if not self._is_valid_address(address):
            return None

        print(f"🔍 Scraping source code for {address} on {self.config['name']}...")

        self._rate_limit_check()

        try:
            # Try the contract page with #code anchor
            url = f"{self.config['explorer']}/address/{address}#code"
            response = self.session.get(url, timeout=15)

            if response.status_code != 200:
                return None

            html = response.text

            # Check if verified
            if not self._is_verified(html):
                print(f"⚠️  Contract not verified on {self.config['name']}")
                return None

            # Extract source code using multiple patterns
            source_code = self._extract_source_from_html(html)

            if source_code and len(source_code) > 100:
                print(f"✅ Successfully scraped {len(source_code)} characters of source code")
                return source_code

            # Fallback: Try API endpoint without key (some explorers allow limited requests)
            source_code = self._try_api_fallback(address)
            if source_code:
                return source_code

        except Exception as e:
            print(f"❌ Error scraping source code: {e}")

        return None

    @retry_with_exponential_backoff(max_retries=3, base_delay=1)
    def fetch_bytecode(self, address: str) -> Optional[str]:
        """Fetch contract bytecode using RPC or scraping"""
        if not self._is_valid_address(address):
            return None

        # Try RPC first (most reliable)
        if self.rpc_available and self.web3:
            try:
                bytecode = self.web3.eth.get_code(Web3.to_checksum_address(address))
                if bytecode and bytecode.hex() != '0x':
                    return bytecode.hex()
            except Exception as e:
                print(f"⚠️  RPC bytecode fetch failed: {e}")

        self._rate_limit_check()

        # Fallback to scraping
        try:
            url = f"{self.config['explorer']}/address/{address}#code"
            response = self.session.get(url, timeout=10)
            html = response.text

            # Look for bytecode in various formats
            bytecode = self._extract_bytecode_from_html(html)
            if bytecode:
                return bytecode

        except Exception as e:
            print(f"❌ Error fetching bytecode: {e}")

        return None

    @retry_with_exponential_backoff(max_retries=3, base_delay=1)
    def get_storage_at(self, address: str, slot: str, block: str = 'latest') -> Optional[str]:
        """Read contract storage slot using RPC"""
        if not self.rpc_available or not self.web3:
            print(f"⚠️  RPC not available for storage reading on {self.chain}")
            return None

        try:
            # Convert slot to proper format
            if isinstance(slot, str) and not slot.startswith('0x'):
                slot = hex(int(slot))

            storage_value = self.web3.eth.get_storage_at(
                Web3.to_checksum_address(address),
                int(slot, 16),
                block
            )

            return storage_value.hex()

        except Exception as e:
            print(f"❌ Error reading storage slot {slot}: {e}")
            return None

    def get_balance(self, address: str) -> Optional[str]:
        """Get contract balance using RPC or scraping"""
        if not self._is_valid_address(address):
            return None

        # Try RPC first
        if self.rpc_available and self.web3:
            try:
                balance_wei = self.web3.eth.get_balance(Web3.to_checksum_address(address))
                balance_eth = self.web3.from_wei(balance_wei, 'ether')
                return f"{balance_eth} {self.config['currency']}"
            except Exception as e:
                print(f"⚠️  RPC balance fetch failed: {e}")

        # Fallback to scraping
        try:
            url = f"{self.config['explorer']}/address/{address}"
            response = self.session.get(url, timeout=10)
            html = response.text

            # Extract balance from page
            balance_patterns = [
                rf'Balance:</div>.*?(\d+\.?\d*)\s*{self.config["currency"]}',
                rf'(\d+\.?\d*)\s*{self.config["currency"]}',
                r'balance.*?(\d+\.?\d*)',
            ]

            for pattern in balance_patterns:
                match = re.search(pattern, html, re.IGNORECASE | re.DOTALL)
                if match:
                    return f"{match.group(1)} {self.config['currency']}"

        except Exception as e:
            print(f"❌ Error fetching balance: {e}")

        return None

    def get_contract_info(self, address: str) -> Dict[str, Any]:
        """Get comprehensive contract information"""
        info = {
            'address': address,
            'chain': self.chain,
            'chain_name': self.config['name'],
            'chain_id': self.config['chain_id'],
            'exists': False,
            'verified': False,
            'balance': None,
            'contract_name': None,
            'compiler_version': None,
            'optimization': None,
            'source_code': None,
            'bytecode': None,
            'is_proxy': False,
            'implementation': None
        }

        if not self._is_valid_address(address):
            info['error'] = 'Invalid address format'
            return info

        try:
            url = f"{self.config['explorer']}/address/{address}"
            response = self.session.get(url, timeout=15)
            html = response.text

            # Check if contract exists
            if 'balance' in html.lower() or 'contract' in html.lower():
                info['exists'] = True
            else:
                info['error'] = 'Contract not found'
                return info

            # Check if verified
            info['verified'] = self._is_verified(html)

            # Extract contract name
            if info['verified']:
                name_match = re.search(r'Contract Name:.*?<[^>]*>([^<]+)', html, re.IGNORECASE)
                if name_match:
                    info['contract_name'] = name_match.group(1).strip()

                # Extract compiler version
                compiler_match = re.search(r'Compiler Version:.*?v([0-9.+]+)', html, re.IGNORECASE)
                if compiler_match:
                    info['compiler_version'] = compiler_match.group(1)

                # Check optimization
                if 'optimization enabled' in html.lower():
                    info['optimization'] = True
                elif 'optimization disabled' in html.lower():
                    info['optimization'] = False

            # Get balance
            info['balance'] = self.get_balance(address)

            # Check for proxy patterns
            info['is_proxy'] = self._check_proxy_pattern(html)

            if info['is_proxy']:
                # Try to extract implementation address
                impl_match = re.search(r'0x[a-fA-F0-9]{40}', html)
                if impl_match:
                    potential_impl = impl_match.group(0)
                    if potential_impl.lower() != address.lower():
                        info['implementation'] = potential_impl

        except Exception as e:
            info['error'] = str(e)

        return info

    def _is_valid_address(self, address: str) -> bool:
        """Validate Ethereum address format"""
        if not address:
            return False
        if not address.startswith('0x'):
            return False
        if len(address) != 42:
            return False
        try:
            int(address, 16)
            return True
        except ValueError:
            return False

    def _is_verified(self, html: str) -> bool:
        """Check if contract is verified"""
        verification_indicators = [
            'Contract Source Code Verified',
            'contract source code verified',
            'exact match',
            'constructor arguments',
            'optimization enabled',
            'pragma solidity'
        ]

        html_lower = html.lower()
        return any(indicator.lower() in html_lower for indicator in verification_indicators)

    def _extract_source_from_html(self, html: str) -> Optional[str]:
        """Extract source code from HTML using multiple methods"""

        # Method 1: BeautifulSoup with pre tags
        try:
            soup = BeautifulSoup(html, 'html.parser')

            # Look for source code in pre tags
            for pre in soup.find_all('pre'):
                text = pre.get_text()
                if 'pragma solidity' in text and len(text) > 200:
                    return self._clean_source_code(text)

            # Look for source code in textareas
            for textarea in soup.find_all('textarea'):
                text = textarea.get_text()
                if 'pragma solidity' in text and len(text) > 200:
                    return self._clean_source_code(text)

            # Look for divs with specific IDs or classes
            for div in soup.find_all('div', {'id': re.compile(r'source|code|contract', re.I)}):
                text = div.get_text()
                if 'pragma solidity' in text and len(text) > 200:
                    return self._clean_source_code(text)

        except Exception as e:
            print(f"⚠️  BeautifulSoup extraction failed: {e}")

        # Method 2: Regex patterns
        source_patterns = [
            r'<pre[^>]*class=["\'].*?js-sourcecopyarea.*?["\'][^>]*>(.*?)</pre>',
            r'<pre[^>]*id=["\'].*?editor.*?["\'][^>]*>(.*?)</pre>',
            r'<textarea[^>]*>(pragma solidity.*?)</textarea>',
            r'>(pragma solidity[\s\S]{200,}?contract\s+\w+[\s\S]+?})<',
        ]

        for pattern in source_patterns:
            match = re.search(pattern, html, re.DOTALL | re.IGNORECASE)
            if match:
                source = match.group(1)
                if len(source) > 200 and 'pragma solidity' in source:
                    return self._clean_source_code(source)

        return None

    def _extract_bytecode_from_html(self, html: str) -> Optional[str]:
        """Extract bytecode from HTML"""
        bytecode_patterns = [
            r'Deployed Bytecode.*?0x([a-fA-F0-9]{100,})',
            r'Contract Bytecode.*?0x([a-fA-F0-9]{100,})',
            r'<div[^>]*bytecode[^>]*>.*?(0x[a-fA-F0-9]{100,})',
            r'value">(0x[a-fA-F0-9]{100,})</div>',
        ]

        for pattern in bytecode_patterns:
            match = re.search(pattern, html, re.DOTALL | re.IGNORECASE)
            if match:
                bytecode = match.group(1)
                if not bytecode.startswith('0x'):
                    bytecode = '0x' + bytecode
                if len(bytecode) > 100:
                    return bytecode

        return None

    def _check_proxy_pattern(self, html: str) -> bool:
        """Check if contract appears to be a proxy"""
        proxy_indicators = [
            'proxy contract',
            'implementation',
            'upgradeable',
            'eip-1967',
            'transparent proxy',
            'uups',
            'beacon'
        ]

        html_lower = html.lower()
        return any(indicator in html_lower for indicator in proxy_indicators)

    def _clean_source_code(self, source: str) -> str:
        """Clean extracted source code"""
        # Remove HTML entities
        source = source.replace('&lt;', '<')
        source = source.replace('&gt;', '>')
        source = source.replace('&quot;', '"')
        source = source.replace('&amp;', '&')
        source = source.replace('&#39;', "'")

        # Remove extra whitespace
        lines = source.split('\n')
        cleaned_lines = [line.rstrip() for line in lines]
        source = '\n'.join(cleaned_lines)

        return source.strip()

    def _try_api_fallback(self, address: str) -> Optional[str]:
        """Try to use explorer API without key (some allow limited requests)"""
        try:
            # Some explorers allow limited API requests without key
            url = f"{self.config['explorer_api']}?module=contract&action=getsourcecode&address={address}"
            response = self.session.get(url, timeout=10)

            if response.status_code == 200:
                data = response.json()
                if data.get('status') == '1' and data.get('result'):
                    source = data['result'][0].get('SourceCode', '')
                    if source and len(source) > 100:
                        print("✅ Fallback API request succeeded")
                        return source
        except Exception:
            pass

        return None


# Singleton instance
_fetcher_instance = None

def get_fetcher(chain='ethereum') -> APIFreeFetcher:
    """Get or create the API-free fetcher singleton"""
    global _fetcher_instance
    if _fetcher_instance is None or _fetcher_instance.chain != chain:
        _fetcher_instance = APIFreeFetcher(chain)
    return _fetcher_instance
