#!/usr/bin/env python3
"""
Utility functions for input validation, address checking, and security
"""

import os
import re
from typing import Optional, Tuple

# Maximum file sizes for security
MAX_SOURCE_FILE_SIZE = 5 * 1024 * 1024  # 5MB
MAX_BYTECODE_FILE_SIZE = 2 * 1024 * 1024  # 2MB
MAX_DECOMPILED_FILE_SIZE = 10 * 1024 * 1024  # 10MB

# Supported file extensions
ALLOWED_SOURCE_EXTENSIONS = ['.sol', '.txt']
ALLOWED_BYTECODE_EXTENSIONS = ['.txt', '.bin', '.hex']


def validate_ethereum_address(address: str, chain: str = 'ethereum') -> Tuple[bool, Optional[str]]:
    """
    Validate Ethereum-compatible address format

    Args:
        address: Address to validate
        chain: Blockchain name for chain-specific validation

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not address:
        return False, "Address cannot be empty"

    # Remove whitespace
    address = address.strip()

    # Check format
    if not address.startswith('0x'):
        return False, "Address must start with '0x'"

    if len(address) != 42:
        return False, f"Address must be 42 characters (got {len(address)})"

    # Check hex characters
    try:
        int(address, 16)
    except ValueError:
        return False, "Address contains invalid hexadecimal characters"

    # Basic checksum validation (EIP-55)
    if address != address.lower() and address != address.upper():
        # Mixed case - should be checksummed
        if not _is_checksum_valid(address):
            return False, "Invalid checksum (EIP-55 violation)"

    return True, None


def _is_checksum_valid(address: str) -> bool:
    """Validate EIP-55 checksum"""
    try:
        from web3 import Web3
        return Web3.is_checksum_address(address)
    except ImportError:
        # If web3 not available, skip checksum validation
        return True


def validate_file_path(file_path: str, max_size: int, allowed_extensions: list) -> Tuple[bool, Optional[str]]:
    """
    Validate file path for security

    Args:
        file_path: Path to file
        max_size: Maximum allowed file size in bytes
        allowed_extensions: List of allowed file extensions

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not file_path:
        return False, "File path cannot be empty"

    # Check file exists
    if not os.path.exists(file_path):
        return False, f"File does not exist: {file_path}"

    # Check it's a file (not directory)
    if not os.path.isfile(file_path):
        return False, f"Path is not a file: {file_path}"

    # Check file extension
    ext = os.path.splitext(file_path)[1].lower()
    if ext not in allowed_extensions:
        return False, f"Invalid file extension '{ext}'. Allowed: {', '.join(allowed_extensions)}"

    # Check file size
    file_size = os.path.getsize(file_path)
    if file_size > max_size:
        max_mb = max_size / (1024 * 1024)
        actual_mb = file_size / (1024 * 1024)
        return False, f"File too large ({actual_mb:.2f}MB). Maximum: {max_mb:.2f}MB"

    # Check file is readable
    try:
        with open(file_path, 'r') as f:
            f.read(1)
    except (IOError, OSError, UnicodeDecodeError) as e:
        return False, f"Cannot read file: {str(e)}"

    return True, None


def validate_source_file(file_path: str) -> Tuple[bool, Optional[str]]:
    """Validate Solidity source code file"""
    return validate_file_path(file_path, MAX_SOURCE_FILE_SIZE, ALLOWED_SOURCE_EXTENSIONS)


def validate_bytecode_file(file_path: str) -> Tuple[bool, Optional[str]]:
    """Validate bytecode file"""
    is_valid, error = validate_file_path(file_path, MAX_BYTECODE_FILE_SIZE, ALLOWED_BYTECODE_EXTENSIONS)

    if not is_valid:
        return False, error

    # Additional validation: check if content looks like bytecode
    try:
        with open(file_path, 'r') as f:
            content = f.read().strip()

        # Must start with 0x and be hex
        if not content.startswith('0x'):
            return False, "Bytecode must start with '0x'"

        # Try to parse as hex
        try:
            int(content, 16)
        except ValueError:
            return False, "Invalid bytecode format (not hexadecimal)"

        # Must be reasonable length
        if len(content) < 10:
            return False, "Bytecode too short (minimum 10 characters)"

    except Exception as e:
        return False, f"Bytecode validation failed: {str(e)}"

    return True, None


def validate_decompiled_file(file_path: str) -> Tuple[bool, Optional[str]]:
    """Validate decompiled code file"""
    return validate_file_path(file_path, MAX_DECOMPILED_FILE_SIZE, ALLOWED_SOURCE_EXTENSIONS)


def sanitize_contract_address(address: str) -> str:
    """
    Sanitize and normalize contract address

    Args:
        address: Raw address input

    Returns:
        Normalized address (lowercase with 0x prefix)
    """
    if not address:
        return ''

    address = address.strip().lower()

    if not address.startswith('0x'):
        address = '0x' + address

    return address


def validate_chain_name(chain: str) -> Tuple[bool, Optional[str]]:
    """
    Validate blockchain name

    Args:
        chain: Chain name to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    supported_chains = [
        'ethereum', 'bsc', 'polygon', 'arbitrum',
        'optimism', 'base', 'avalanche', 'gnosis'
    ]

    if not chain:
        return False, "Chain name cannot be empty"

    chain_lower = chain.lower().strip()

    if chain_lower not in supported_chains:
        return False, f"Unsupported chain '{chain}'. Supported: {', '.join(supported_chains)}"

    return True, None


def safe_read_file(file_path: str, max_size: int = MAX_SOURCE_FILE_SIZE) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Safely read file with size validation

    Args:
        file_path: Path to file
        max_size: Maximum allowed file size

    Returns:
        Tuple of (success, content_or_error, error_message)
    """
    try:
        # Check file size first
        file_size = os.path.getsize(file_path)
        if file_size > max_size:
            max_mb = max_size / (1024 * 1024)
            return False, None, f"File too large (max: {max_mb:.2f}MB)"

        # Read file
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        return True, content, None

    except (IOError, OSError) as e:
        return False, None, f"File read error: {str(e)}"
    except Exception as e:
        return False, None, f"Unexpected error: {str(e)}"


def detect_potential_malicious_content(content: str) -> Tuple[bool, Optional[str]]:
    """
    Basic detection of potentially malicious content in files

    Args:
        content: File content to check

    Returns:
        Tuple of (is_safe, warning_message)
    """
    # Check for extremely long lines (potential DoS)
    lines = content.split('\n')
    for i, line in enumerate(lines[:100]):  # Check first 100 lines
        if len(line) > 50000:  # 50KB per line is suspicious
            return False, f"Suspicious: Line {i+1} is extremely long ({len(line)} chars)"

    # Check for binary content in text files
    null_bytes = content.count('\x00')
    if null_bytes > 10:
        return False, f"Suspicious: Contains {null_bytes} null bytes (binary content?)"

    # Check for potential regex DOS patterns
    suspicious_patterns = [
        r'(.+){1000,}',  # Excessive repetition
        r'(.*){500,}',   # Excessive wildcard repetition
    ]

    for pattern in suspicious_patterns:
        if re.search(pattern, content[:10000]):  # Check first 10KB
            return False, f"Suspicious: Contains potential ReDoS pattern"

    return True, None
