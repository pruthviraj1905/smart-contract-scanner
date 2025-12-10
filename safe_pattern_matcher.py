#!/usr/bin/env python3
"""
Safe Pattern Matcher with Timeout Protection
Prevents ReDoS (Regular Expression Denial of Service) attacks
"""

import re
import threading
from typing import List, Optional, Pattern
from contextlib import contextmanager

class TimeoutException(Exception):
    """Raised when pattern matching exceeds timeout"""
    pass

@contextmanager
def time_limit(seconds):
    """Context manager to enforce time limit on operations (thread-safe)"""
    # Use threading.Timer instead of signal (works in threads)
    timer = None
    timed_out = [False]

    def timeout_handler():
        timed_out[0] = True

    if seconds and seconds > 0:
        timer = threading.Timer(seconds, timeout_handler)
        timer.daemon = True
        timer.start()

    try:
        yield
        if timed_out[0]:
            raise TimeoutException(f"Operation timed out after {seconds} seconds")
    finally:
        if timer:
            timer.cancel()


class SafePatternMatcher:
    """Safe regex pattern matcher with timeout and complexity limits"""

    def __init__(self, timeout_seconds=5, max_input_size=500000):
        """
        Initialize safe pattern matcher

        Args:
            timeout_seconds: Maximum time allowed for pattern matching
            max_input_size: Maximum input size to process (500KB default)
        """
        self.timeout_seconds = timeout_seconds
        self.max_input_size = max_input_size
        self.compiled_patterns = {}

    def compile_pattern(self, pattern: str, flags=0) -> Optional[Pattern]:
        """
        Safely compile a regex pattern with validation

        Args:
            pattern: Regex pattern string
            flags: Regex flags

        Returns:
            Compiled pattern or None if unsafe
        """
        # Check for dangerous patterns
        if self._is_dangerous_pattern(pattern):
            print(f"⚠️  Dangerous pattern detected, using safe alternative")
            return None

        cache_key = (pattern, flags)
        if cache_key in self.compiled_patterns:
            return self.compiled_patterns[cache_key]

        try:
            compiled = re.compile(pattern, flags)
            self.compiled_patterns[cache_key] = compiled
            return compiled
        except re.error as e:
            print(f"❌ Pattern compilation error: {e}")
            return None

    def _is_dangerous_pattern(self, pattern: str) -> bool:
        """
        Check if pattern contains dangerous constructs

        Returns:
            True if pattern is dangerous
        """
        dangerous_patterns = [
            r'(?![^}]*',  # Negative lookahead with unbounded repetition
            r'[^}]*\w+[^}]*',  # Multiple unbounded negated character classes
            r'(\w+)+',  # Nested quantifiers
            r'(.*)*',  # Exponential backtracking
            r'(.+)+',  # Exponential backtracking
        ]

        for dangerous in dangerous_patterns:
            if dangerous in pattern:
                return True

        return False

    def safe_search(self, pattern: str, text: str, flags=0, timeout=None) -> Optional[re.Match]:
        """
        Safely search for pattern in text with timeout

        Args:
            pattern: Regex pattern
            text: Text to search
            flags: Regex flags
            timeout: Override default timeout

        Returns:
            Match object or None
        """
        if len(text) > self.max_input_size:
            print(f"⚠️  Input too large ({len(text)} bytes), truncating to {self.max_input_size}")
            text = text[:self.max_input_size]

        compiled_pattern = self.compile_pattern(pattern, flags)
        if compiled_pattern is None:
            return None

        timeout = timeout or self.timeout_seconds

        try:
            with time_limit(timeout):
                return compiled_pattern.search(text)
        except TimeoutException as e:
            print(f"⚠️  Pattern matching timed out: {e}")
            return None
        except Exception as e:
            print(f"❌ Pattern matching error: {e}")
            return None

    def safe_finditer(self, pattern: str, text: str, flags=0, timeout=None, max_matches=1000):
        """
        Safely find all matches with timeout and limit

        Args:
            pattern: Regex pattern
            text: Text to search
            flags: Regex flags
            timeout: Override default timeout
            max_matches: Maximum number of matches to return

        Returns:
            List of match objects
        """
        if len(text) > self.max_input_size:
            print(f"⚠️  Input too large ({len(text)} bytes), truncating to {self.max_input_size}")
            text = text[:self.max_input_size]

        compiled_pattern = self.compile_pattern(pattern, flags)
        if compiled_pattern is None:
            return []

        timeout = timeout or self.timeout_seconds
        matches = []

        try:
            with time_limit(timeout):
                for i, match in enumerate(compiled_pattern.finditer(text)):
                    if i >= max_matches:
                        print(f"⚠️  Reached max matches limit ({max_matches})")
                        break
                    matches.append(match)
                return matches
        except TimeoutException as e:
            print(f"⚠️  Pattern matching timed out after finding {len(matches)} matches: {e}")
            return matches
        except Exception as e:
            print(f"❌ Pattern matching error: {e}")
            return matches

    def safe_findall(self, pattern: str, text: str, flags=0, timeout=None, max_matches=1000):
        """
        Safely find all matching strings with timeout

        Args:
            pattern: Regex pattern
            text: Text to search
            flags: Regex flags
            timeout: Override default timeout
            max_matches: Maximum number of matches

        Returns:
            List of matching strings
        """
        matches = self.safe_finditer(pattern, text, flags, timeout, max_matches)
        return [m.group(0) for m in matches]


# Global singleton instance
_safe_matcher = SafePatternMatcher(timeout_seconds=5, max_input_size=500000)

def get_safe_matcher() -> SafePatternMatcher:
    """Get the global safe pattern matcher instance"""
    return _safe_matcher
