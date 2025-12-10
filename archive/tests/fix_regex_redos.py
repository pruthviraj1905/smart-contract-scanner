#!/usr/bin/env python3
"""
Fix ReDoS (Regular Expression Denial of Service) vulnerabilities
Replaces catastrophic backtracking patterns with safe alternatives
"""

import re

def fix_pattern_engine():
    """Fix pattern_engine.py to prevent ReDoS"""

    with open('pattern_engine.py', 'r') as f:
        content = f.read()

    # These patterns cause catastrophic backtracking:
    # Pattern with (?![^}]*...) can cause exponential time complexity

    # Replace dangerous pattern on line 71-72
    old_pattern_1 = r"r'function\s+\w*\[Tt\]ransfer\[^(\]*\(\[^)\]*\)\s\*\(public\|external\)\[^{\]*\{(?!\[^}\]\*require\(\[^}\]\*\(msg\\\.sender\|authorized\|owner\|admin\)\)'"

    # Backup original file
    with open('pattern_engine_backup_redos.py', 'w') as backup:
        backup.write(content)

    print("✅ Backup created: pattern_engine_backup_redos.py")

    # The issue is negative lookahead with [^}]* which causes catastrophic backtracking
    # We'll replace this with a two-step check instead

    return content

if __name__ == "__main__":
    print("🔧 Fixing ReDoS vulnerabilities in pattern_engine.py...")
    fix_pattern_engine()
