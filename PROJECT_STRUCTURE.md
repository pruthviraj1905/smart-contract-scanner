# 📁 Project Structure

## Clean Project Layout

```
smart-contract-scanner/
│
├── 📚 Core Scanner Files
│   ├── deep_vuln_scanner.py              # Main scanner orchestration
│   ├── pattern_engine.py                  # Vulnerability pattern detection
│   ├── safe_pattern_matcher.py           # ReDoS-safe regex engine
│   ├── enhanced_vulnerability_patterns.py # Extended patterns
│   ├── storage_analyzer.py                # Storage-level analysis
│   ├── proxy_detector.py                  # Proxy contract detection
│   ├── bytecode_analyzer.py               # Bytecode analysis
│   ├── ai_validator.py                    # AI-powered validation
│   ├── api_free_fetcher.py                # API-free source fetching
│   ├── ultra_strict_validator.py          # False positive filtering
│   └── scanner_cli.py                     # CLI interface
│
├── 🌐 Web Application
│   └── scanner_webapp/
│       ├── app.py                         # Flask server with WebSocket
│       ├── templates/
│       │   └── index.html                 # Web GUI interface
│       ├── static/                        # CSS, JS, images
│       ├── uploads/                       # Temporary file uploads
│       └── results/                       # Scan results cache
│
├── 🚀 Startup & Configuration
│   ├── start_scanner_gui.sh               # One-command startup ⭐
│   ├── verify_setup.sh                    # Setup verification
│   ├── requirements.txt                   # Python dependencies
│   ├── .env                               # Environment configuration
│   └── valurnabilities.txt                # Vulnerability patterns
│
├── 📖 Documentation
│   ├── README.md                          # Main documentation
│   └── PROJECT_STRUCTURE.md               # This file
│
├── 🗄️ Archive (Safe Storage)
│   ├── archive/docs/                      # Old documentation
│   │   ├── PERFORMANCE_FIX.md
│   │   ├── AI_VALIDATION_GUIDE.md
│   │   ├── COMPLETE_SETUP_SUMMARY.md
│   │   └── ... (other guides)
│   │
│   └── archive/tests/                     # Test files
│       ├── test_scanner.py
│       ├── full_advanced_test.py
│       ├── debug_scan.py
│       └── ... (other tests)
│
├── 📊 Test Contracts (For Testing)
│   └── test_contracts/
│       ├── VulnerableTestContract.sol
│       ├── ultimate_vulnerable_test.sol
│       └── base_real_contract_decompiled.sol
│
└── 🔒 Auto-Generated (Git Ignored)
    ├── scanner_env/                       # Python virtual environment
    ├── __pycache__/                       # Python cache
    ├── reports/                           # Scan reports
    └── scan_results.json                  # Recent results
```

## File Descriptions

### Core Scanner Files

| File | Purpose | Lines |
|------|---------|-------|
| `deep_vuln_scanner.py` | Main scanner orchestration, coordinates all analysis phases | ~1000 |
| `pattern_engine.py` | 80+ vulnerability patterns with safe regex matching | ~600 |
| `safe_pattern_matcher.py` | ReDoS protection, threading-based timeouts | ~200 |
| `storage_analyzer.py` | Storage-level vulnerability detection (8 categories) | ~800 |
| `proxy_detector.py` | Detects 6 proxy types (EIP-1967, UUPS, etc.) | ~500 |
| `bytecode_analyzer.py` | EVM bytecode disassembly and analysis | ~400 |
| `ai_validator.py` | OpenAI GPT-4 integration for false positive reduction | ~300 |
| `api_free_fetcher.py` | Web scraping for contract source without API keys | ~600 |
| `ultra_strict_validator.py` | Additional filtering layer for high-precision results | ~300 |
| `scanner_cli.py` | Command-line interface with argument parsing | ~400 |

### Web Application

| File | Purpose |
|------|---------|
| `scanner_webapp/app.py` | Flask server with WebSocket for real-time output |
| `scanner_webapp/templates/index.html` | Responsive web GUI with progress tracking |
| `scanner_webapp/static/` | Frontend assets (CSS, JavaScript, images) |

### Startup Scripts

| Script | Purpose |
|--------|---------|
| `start_scanner_gui.sh` | One-command startup: creates venv, installs deps, starts GUI |
| `verify_setup.sh` | Verifies installation and configuration |

### Configuration Files

| File | Purpose |
|------|---------|
| `.env` | Environment variables (API keys, settings) |
| `requirements.txt` | Python package dependencies |
| `valurnabilities.txt` | Vulnerability pattern definitions |

## Archive Organization

All old files have been safely moved to `archive/` without deletion:

### archive/docs/
- All old documentation and fix reports
- Performance analysis documents
- Setup summaries and guides
- Scan result examples

### archive/tests/
- Test scripts and debugging files
- Demo and example scanners
- Backup files
- Development utilities

## Key Features by File

### Performance Optimizations
- `safe_pattern_matcher.py`: Threading-based timeouts (no signal errors)
- `storage_analyzer.py`: Reduced to 10 critical slots, timeout protection
- `pattern_engine.py`: ReDoS-safe patterns, bounded quantifiers

### Multi-Chain Support
- `api_free_fetcher.py`: 8 blockchain networks (ETH, BSC, Polygon, etc.)
- `deep_vuln_scanner.py`: Chain-specific RPC configuration

### AI Validation
- `ai_validator.py`: GPT-4 powered false positive elimination
- `ultra_strict_validator.py`: Additional validation layer

### Real-Time Output
- `scanner_webapp/app.py`: WebSocket streaming
- `scanner_webapp/templates/index.html`: Live terminal display

## Dependencies

Core Python packages (from `requirements.txt`):
- `flask==3.0.0` - Web framework
- `flask-socketio==5.3.5` - WebSocket support
- `web3==6.11.3` - Blockchain interaction
- `requests==2.31.0` - HTTP requests
- `beautifulsoup4==4.12.2` - Web scraping
- `openai==1.3.7` - AI validation (optional)

## Quick Reference

### Essential Files
1. **Start scanner**: `./start_scanner_gui.sh`
2. **Verify setup**: `./verify_setup.sh`
3. **Configuration**: `.env`
4. **Documentation**: `README.md`

### Main Entry Points
- **GUI**: `scanner_webapp/app.py` (via `start_scanner_gui.sh`)
- **CLI**: `scanner_cli.py`
- **Core**: `deep_vuln_scanner.py`

### Important Locations
- **Config**: `.env`
- **Patterns**: `valurnabilities.txt`
- **Logs**: `scanner_webapp/webapp.log`
- **Results**: `reports/` and `scan_results.json`

## Git Ignore Recommendations

Add to `.gitignore`:
```
scanner_env/
__pycache__/
*.pyc
.env
reports/
scanner_webapp/uploads/
scanner_webapp/results/
scan_results.json
*.log
```

---

**Last Updated**: 2025-12-10
**Version**: 2.0 (Cleaned & Organized)
**Status**: ✅ Production Ready
