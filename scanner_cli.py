#!/usr/bin/env python3
"""
CLI Interface for Deep Smart Contract Vulnerability Scanner
"""

import argparse
import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
from deep_vuln_scanner import DeepContractScanner, VulnSeverity

def main():
    parser = argparse.ArgumentParser(
        description="Deep Smart Contract Vulnerability Scanner - Focus on non-privileged fund drain exploits",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan verified contract
  python scanner_cli.py --address 0x123... --verified

  # Scan decompiled contract
  python scanner_cli.py --address 0x123... --decompiled bsc/decompile.txt

  # Scan with custom source code
  python scanner_cli.py --address 0x123... --source contract.sol

  # Scan with bytecode
  python scanner_cli.py --address 0x123... --bytecode bsc/bytecode.txt

  # Output to file
  python scanner_cli.py --address 0x123... --decompiled bsc/decompile.txt --output report.md

  # High confidence only
  python scanner_cli.py --address 0x123... --decompiled bsc/decompile.txt --min-confidence 0.8

  # Critical vulnerabilities only
  python scanner_cli.py --address 0x123... --decompiled bsc/decompile.txt --severity CRITICAL
        """
    )
    
    parser.add_argument('--address', '-a', required=False, default='0x0000000000000000000000000000000000000000',
                       help='Contract address to scan (optional for non-deployed contracts)')
    
    # Input sources (mutually exclusive)
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument('--verified', action='store_true',
                             help='Fetch verified source code from Etherscan')
    source_group.add_argument('--decompiled', '-d',
                             help='Path to decompiled source file')
    source_group.add_argument('--source', '-s',
                             help='Path to Solidity source file')
    source_group.add_argument('--bytecode', '-b',
                             help='Path to bytecode file')
    
    # Filtering options
    parser.add_argument('--severity', choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
                       help='Minimum severity level to report')
    parser.add_argument('--min-confidence', type=float, default=0.0,
                       help='Minimum confidence level (0.0-1.0)')
    
    # Output options
    parser.add_argument('--output', '-o',
                       help='Output report to file (markdown format)')
    parser.add_argument('--format', choices=['markdown', 'json', 'text'], default='markdown',
                       help='Report format')
    parser.add_argument('--quiet', '-q', action='store_true',
                       help='Suppress verbose output')
    
    # Scanner options
    parser.add_argument('--api-key',
                       default=os.getenv('ETHERSCAN_API_KEY'),
                       help='Etherscan API key (or set ETHERSCAN_API_KEY env var)')
    parser.add_argument('--deep-analysis', action='store_true',
                       help='Enable deep analysis (slower but more thorough)')
    parser.add_argument('--check-storage', action='store_true',
                       help='Analyze contract storage state')
    parser.add_argument('--non-privileged-only', action='store_true',
                       help='Focus ONLY on non-privileged vulnerabilities (external users can exploit)')
    parser.add_argument('--chain', choices=['ethereum', 'bsc', 'polygon', 'avalanche', 'arbitrum', 'optimism', 'base', 'gnosis'],
                       default='bsc', help='Blockchain network (uses unified Etherscan API v2)')
    parser.add_argument('--combine-sources', action='store_true',
                       help='Analyze multiple source types simultaneously for comprehensive results')
    parser.add_argument('--enable-ai', action='store_true',
                       help='Enable AI-powered false positive validation (requires OpenAI API key)')
    parser.add_argument('--disable-ai', action='store_true',
                       help='Disable AI validation even if configured in .env')
    
    args = parser.parse_args()
    
    if not args.quiet:
        print("🔍 Deep Smart Contract Vulnerability Scanner")
        print("=" * 50)
        print(f"Target: {args.address}")
        print()
    
    # API-Free Chain Configuration - No API keys required!
    # Uses web scraping + direct RPC calls instead of deprecated APIs
    chain_config = {
        'ethereum': {'chain_id': '1', 'chain': 'ethereum', 'name': 'Ethereum'},
        'bsc': {'chain_id': '56', 'chain': 'bsc', 'name': 'BSC'},
        'polygon': {'chain_id': '137', 'chain': 'polygon', 'name': 'Polygon'},
        'avalanche': {'chain_id': '43114', 'chain': 'avalanche', 'name': 'Avalanche'},
        'arbitrum': {'chain_id': '42161', 'chain': 'arbitrum', 'name': 'Arbitrum'},
        'optimism': {'chain_id': '10', 'chain': 'optimism', 'name': 'Optimism'},
        'base': {'chain_id': '8453', 'chain': 'base', 'name': 'Base'},
        'gnosis': {'chain_id': '100', 'chain': 'gnosis', 'name': 'Gnosis'}
    }

    selected_chain = chain_config.get(args.chain, chain_config['ethereum'])

    # Determine AI validation setting
    enable_ai = False
    if args.enable_ai:
        enable_ai = True
    elif not args.disable_ai:
        # Check environment setting
        enable_ai = os.getenv('ENABLE_AI_VALIDATION', 'false').lower() == 'true'

    # API-free mode is now default (no API key required)
    # API key is optional fallback only
    use_api_free = not args.api_key or os.getenv('USE_API_FREE', 'true').lower() == 'true'

    scanner = DeepContractScanner(
        args.api_key,
        chain_config=selected_chain,
        enable_ai_validation=enable_ai,
        use_api_free=use_api_free
    )
    
    # Load source code based on input type
    source_code = None
    decompiled_code = None
    bytecode = None
    
    try:
        if args.verified:
            if not args.quiet:
                print("[+] Fetching verified source code from Etherscan...")
            # Scanner will fetch automatically
            pass
            
        elif args.decompiled:
            if not args.quiet:
                print(f"[+] Loading decompiled code from {args.decompiled}...")
            with open(args.decompiled, 'r') as f:
                decompiled_code = f.read()
                
        elif args.source:
            if not args.quiet:
                print(f"[+] Loading Solidity source from {args.source}...")
            with open(args.source, 'r') as f:
                source_code = f.read()
                
        elif args.bytecode:
            if not args.quiet:
                print(f"[+] Loading bytecode from {args.bytecode}...")
            with open(args.bytecode, 'r') as f:
                bytecode = f.read().strip()
                
    except FileNotFoundError as e:
        print(f"❌ Error: File not found - {e}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error loading source: {e}")
        sys.exit(1)
    
    # Run scan
    if not args.quiet:
        print("[+] Starting vulnerability scan...")
        if args.deep_analysis:
            print("[+] Deep analysis mode enabled")
        print()
    
    vulnerabilities = scanner.scan_contract(
        contract_address=args.address,
        source_code=source_code,
        decompiled_code=decompiled_code,
        bytecode=bytecode,
        combine_sources=args.combine_sources
    )
    
    # Prepare scan parameters for report naming
    scan_params = {
        'chain': args.chain,
        'non_privileged_only': args.non_privileged_only,
        'enable_ai': enable_ai,
        'severity': args.severity,
        'source_type': 'verified' if source_code else ('decompiled' if decompiled_code else ('bytecode' if bytecode else 'unknown'))
    }
    
    # Filter results
    if args.severity:
        severity_filter = VulnSeverity(args.severity)
        severity_weights = {
            VulnSeverity.CRITICAL: 4,
            VulnSeverity.HIGH: 3,
            VulnSeverity.MEDIUM: 2,
            VulnSeverity.LOW: 1,
            VulnSeverity.INFO: 0
        }
        min_weight = severity_weights[severity_filter]
        vulnerabilities = [v for v in vulnerabilities 
                         if severity_weights[v.severity] >= min_weight]
    
    if args.min_confidence > 0.0:
        vulnerabilities = [v for v in vulnerabilities 
                         if v.confidence >= args.min_confidence]
    
    # Filter for non-privileged vulnerabilities only
    if args.non_privileged_only:
        vulnerabilities = filter_non_privileged_vulnerabilities(vulnerabilities)
    
    # Display results
    if not vulnerabilities:
        print("✅ No vulnerabilities found matching your criteria")
        sys.exit(0)
    
    # Count by severity
    severity_counts = {}
    for vuln in vulnerabilities:
        severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1
    
    if not args.quiet:
        print(f"🚨 Found {len(vulnerabilities)} vulnerabilities:")
        for severity, count in severity_counts.items():
            emoji = {
                VulnSeverity.CRITICAL: "🔴",
                VulnSeverity.HIGH: "🟠", 
                VulnSeverity.MEDIUM: "🟡",
                VulnSeverity.LOW: "🔵",
                VulnSeverity.INFO: "⚪"
            }
            print(f"  {emoji[severity]} {severity.value}: {count}")
        print()
    
    # Generate report with smart naming
    if args.output:
        if args.format == 'json':
            generate_json_report(vulnerabilities, args.address, args.output)
        elif args.format == 'text':
            generate_text_report(vulnerabilities, args.address, args.output)
        else:  # markdown
            report_file = scanner.generate_report(args.address, args.output, scan_params)
        
        if not args.quiet:
            print(f"📄 Report saved to {args.output}")
    else:
        # Auto-generate report file with smart naming
        report_file = scanner.generate_report(args.address, None, scan_params)
        if report_file and not args.quiet:
            print(f"📄 Report auto-saved to {report_file}")
        
        # Also display to console
        if args.format == 'json':
            import json
            print(json.dumps([vuln_to_dict(v) for v in vulnerabilities], indent=2))
        else:
            display_console_report(vulnerabilities, args.address, args.quiet)


def vuln_to_dict(vuln):
    """Convert Vulnerability object to dictionary"""
    return {
        'title': vuln.title,
        'severity': vuln.severity.value,
        'description': vuln.description,
        'location': vuln.location,
        'exploit_path': vuln.exploit_path,
        'impact': vuln.impact,
        'proof_of_concept': vuln.proof_of_concept,
        'recommendation': vuln.recommendation,
        'confidence': vuln.confidence
    }


def generate_json_report(vulnerabilities, address, output_file):
    """Generate JSON format report"""
    import json
    from datetime import datetime
    
    report = {
        'contract_address': address,
        'scan_date': datetime.now().isoformat(),
        'total_vulnerabilities': len(vulnerabilities),
        'vulnerabilities': [vuln_to_dict(v) for v in vulnerabilities]
    }
    
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)


def generate_text_report(vulnerabilities, address, output_file):
    """Generate plain text report"""
    from datetime import datetime
    
    with open(output_file, 'w') as f:
        f.write("SMART CONTRACT VULNERABILITY REPORT\n")
        f.write("=" * 40 + "\n\n")
        f.write(f"Contract: {address}\n")
        f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total Vulnerabilities: {len(vulnerabilities)}\n\n")
        
        for i, vuln in enumerate(vulnerabilities, 1):
            f.write(f"{i}. {vuln.title}\n")
            f.write(f"   Severity: {vuln.severity.value}\n")
            f.write(f"   Confidence: {vuln.confidence:.0%}\n")
            f.write(f"   Location: {vuln.location}\n")
            f.write(f"   Description: {vuln.description}\n")
            f.write(f"   Impact: {vuln.impact}\n")
            f.write(f"   Recommendation: {vuln.recommendation}\n")
            f.write("\n" + "-" * 40 + "\n\n")


def filter_non_privileged_vulnerabilities(vulnerabilities):
    """Filter to keep only vulnerabilities that external users can exploit"""
    
    # More aggressive filtering for bug bounty focus
    non_privileged_indicators = [
        'public', 'external', 'anyone can call', 'no authorization',
        'missing authorization', 'unauthorized access', 'reentrancy',
        'transfertoken', 'decompiled transfer', 'circular dependency',
        'uninitialized mapping', 'broken access control'
    ]
    
    # Expanded privileged keywords to catch more false positives
    privileged_indicators = [
        'onlyowner', 'only owner', 'owner can', 'admin only', 'admin can',
        'requires owner', 'malicious owner', 'privileged', 'owner-only',
        'admin-only', 'requires admin', 'owner privilege', 'admin privilege',
        'governance', 'multisig', 'timelock', 'modifier', 'access control',
        'authorization check', 'permission', 'role-based'
    ]
    
    # Keywords that indicate design issues, not exploits
    design_issue_keywords = [
        'logic error', 'calculation error', 'economic model', 'profit calculation',
        'fee calculation', 'price manipulation', 'integer overflow', 'rounding',
        'initialization', 'deployment', 'configuration', 'best practice'
    ]
    
    filtered = []
    for vuln in vulnerabilities:
        description_lower = vuln.description.lower()
        title_lower = vuln.title.lower()
        poc_lower = vuln.proof_of_concept.lower() if vuln.proof_of_concept else ""
        
        # Immediate rejection criteria
        is_privileged = any(keyword in description_lower or keyword in title_lower 
                           for keyword in privileged_indicators)
        
        is_design_issue = any(keyword in description_lower or keyword in title_lower 
                             for keyword in design_issue_keywords)
        
        # Check for onlyOwner in proof of concept
        has_only_owner_poc = 'onlyowner' in poc_lower or 'only owner' in poc_lower
        
        # Must be explicitly non-privileged AND not a design issue
        is_exploitable = any(keyword in description_lower or keyword in title_lower 
                           for keyword in non_privileged_indicators)
        
        # Additional checks for real exploitability
        has_direct_fund_access = any(term in description_lower for term in [
            'drain funds', 'steal tokens', 'transfer funds', 'withdraw funds',
            'balance manipulation', 'fund extraction'
        ])
        
        # Only include if it's truly exploitable by external users
        if (not is_privileged and 
            not is_design_issue and 
            not has_only_owner_poc and 
            (is_exploitable or has_direct_fund_access) and
            vuln.severity.value in ['CRITICAL', 'HIGH']):
            filtered.append(vuln)
    
    return filtered


def display_console_report(vulnerabilities, address, quiet=False):
    """Display report to console"""
    
    if not quiet:
        print("📋 VULNERABILITY DETAILS")
        print("=" * 50)
    
    for i, vuln in enumerate(vulnerabilities, 1):
        # Severity emoji
        emoji = {
            VulnSeverity.CRITICAL: "🔴",
            VulnSeverity.HIGH: "🟠",
            VulnSeverity.MEDIUM: "🟡", 
            VulnSeverity.LOW: "🔵",
            VulnSeverity.INFO: "⚪"
        }
        
        print(f"\n{emoji[vuln.severity]} {i}. {vuln.title}")
        print(f"   📍 Location: {vuln.location}")
        print(f"   📊 Confidence: {vuln.confidence:.0%}")
        print(f"   📝 Description: {vuln.description}")
        
        if vuln.severity in [VulnSeverity.CRITICAL, VulnSeverity.HIGH]:
            print(f"   🎯 Exploit Path:")
            for step in vuln.exploit_path.split('\n'):
                if step.strip():
                    print(f"      • {step.strip()}")
            
            print(f"   💥 Impact: {vuln.impact}")
            
            if vuln.proof_of_concept and len(vuln.proof_of_concept) < 200:
                print(f"   💻 PoC: {vuln.proof_of_concept}")
        
        print(f"   🛠️  Fix: {vuln.recommendation}")
        
        if i < len(vulnerabilities):
            print("   " + "-" * 45)


if __name__ == "__main__":
    main()