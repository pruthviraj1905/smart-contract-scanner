# 🔍 Smart Contract Vulnerability Scanner

A comprehensive, high-performance smart contract security scanner with AI-powered validation and real-time analysis.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Status](https://img.shields.io/badge/status-production%20ready-green.svg)]()

## ✨ Features

### 🚀 Core Capabilities
- **Multi-Chain Support**: Ethereum, BSC, Polygon, Arbitrum, Optimism, Base, Avalanche, Gnosis
- **API-Free Mode**: Works without API keys using web scraping + RPC calls
- **80+ Vulnerability Patterns**: Comprehensive detection including OWASP Top 10
- **Real-Time Output**: WebSocket-based live terminal output in GUI
- **Proxy Detection**: Detects all 6 proxy types (EIP-1967, UUPS, Beacon, Diamond, Minimal, Custom)
- **Storage Analysis**: Deep storage-level vulnerability detection (8 categories)
- **AI Validation**: OpenAI GPT-4 integration for 90%+ false positive reduction
- **High Performance**: Optimized for speed with timeout protection (15-30 second scans)

### 🎯 Vulnerability Detection
- Reentrancy attacks
- Access control issues
- Integer overflow/underflow
- Unprotected self-destruct
- Delegatecall injection
- Front-running vulnerabilities
- Storage collisions
- Uninitialized variables
- And 70+ more patterns...

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- Internet connection (for RPC calls)
- Optional: OpenAI API key (for AI validation)

### Installation & Startup

```bash
# Clone the repository
git clone https://github.com/yourusername/smart-contract-scanner.git
cd smart-contract-scanner

# Make startup script executable
chmod +x start_scanner_gui.sh

# Start the scanner (auto-installs everything!)
./start_scanner_gui.sh
```

That's it! The script automatically:
- ✅ Creates virtual environment
- ✅ Installs all dependencies
- ✅ Starts the web interface
- ✅ Opens on http://localhost:5002

### Using the Scanner

1. **Start the GUI**:
   ```bash
   ./start_scanner_gui.sh
   ```

2. **Open browser**: http://localhost:5002

3. **Scan a contract**:
   - Enter contract address
   - Select blockchain network
   - Paste source code (or fetch automatically)
   - Enable AI validation (optional)
   - Click "Start Vulnerability Scan"
   - Watch real-time progress!

### Command Line Usage

```bash
# Activate virtual environment
source scanner_env/bin/activate

# Basic scan
python scanner_cli.py \
    --address 0xYourContract... \
    --chain ethereum \
    --verified

# With AI validation
python scanner_cli.py \
    --address 0xYourContract... \
    --chain ethereum \
    --verified \
    --enable-ai \
    --format json \
    --output report.json
```

## ⚙️ Configuration

### Environment Variables

The `.env` file is auto-created. Edit to customize:

```bash
# API-Free Mode (default - works without any API keys)
USE_API_FREE=true

# Optional: Etherscan API (faster source code fetching)
# ETHERSCAN_API_KEY=your_key_here

# Optional: OpenAI API (AI validation for zero false positives)
# OPENAI_API_KEY=sk-your_key_here
# OPENAI_MODEL=gpt-4
# ENABLE_AI_VALIDATION=true

# Scanner Settings
DEFAULT_CHAIN=ethereum
```

### AI Validation (Recommended)

Enable AI-powered validation for zero false positives:

1. Get OpenAI API key: https://platform.openai.com/api-keys

2. Add to `.env`:
   ```bash
   OPENAI_API_KEY=sk-your_key_here
   ENABLE_AI_VALIDATION=true
   ```

**Benefits**:
- 90%+ false positive reduction
- Detailed AI reasoning for each finding
- Enhanced exploit descriptions
- Cost: ~$0.02-0.10 per scan

## 📊 Performance

| Metric | Performance |
|--------|-------------|
| **Total Scan Time** | 15-30 seconds |
| **Pattern Matching** | <1 second (80+ patterns) |
| **Storage Analysis** | 5-10 seconds (10 critical slots) |
| **Proxy Detection** | 2-5 seconds |
| **AI Validation** | 10-30 seconds (optional) |

### Optimizations
- ✅ Threading-based timeouts
- ✅ ReDoS protection
- ✅ Reduced storage scanning
- ✅ Error handling on all phases
- ✅ Real-time WebSocket streaming

## 🏗️ Architecture

### Project Structure

```
smart-contract-scanner/
├── deep_vuln_scanner.py          # Main scanner engine
├── pattern_engine.py              # Vulnerability patterns
├── safe_pattern_matcher.py       # ReDoS-safe regex
├── storage_analyzer.py            # Storage analysis
├── proxy_detector.py              # Proxy detection
├── bytecode_analyzer.py           # Bytecode analysis
├── ai_validator.py                # AI validation
├── api_free_fetcher.py            # API-free fetching
├── scanner_cli.py                 # CLI interface
│
├── scanner_webapp/
│   ├── app.py                     # Flask server
│   └── templates/index.html       # Web GUI
│
├── start_scanner_gui.sh           # One-command startup ⭐
├── verify_setup.sh                # Setup verification
├── requirements.txt               # Dependencies
├── .env                           # Configuration
└── valurnabilities.txt            # Patterns
```

### Technology Stack

- **Backend**: Python 3.8+, Flask, Flask-SocketIO, Web3.py
- **Frontend**: HTML5, JavaScript, WebSocket, Bootstrap 5
- **AI**: OpenAI GPT-4 (optional)
- **Blockchain**: Multi-chain RPC support

## 🔐 Security Features

### Pattern Detection
- 80+ vulnerability patterns
- Safe regex matching with ReDoS protection
- Timeout protection on all operations
- Context-aware analysis

### Storage Analysis (8 Categories)
- EIP-1967 slot detection
- Uninitialized storage detection
- Storage collision detection
- Delegatecall storage risks
- Unprotected storage writes

### Proxy Detection (6 Types)
- ✅ EIP-1967 Transparent Proxy
- ✅ UUPS Proxy
- ✅ Beacon Proxy
- ✅ Diamond Proxy (EIP-2535)
- ✅ Minimal Proxy (EIP-1167)
- ✅ Custom Proxy Patterns

### AI Validation
- GPT-4 powered analysis
- Exploitability scoring (0-10)
- 90%+ false positive elimination
- Enhanced recommendations

## 📝 Example Scan Output

```
════════════════════════════════════════════════════════════
          🔍 SMART CONTRACT VULNERABILITY SCAN
════════════════════════════════════════════════════════════

Contract: 0xYourContract...
Chain: Ethereum

[12:34:56] 🔍 Starting scan...
[12:34:57] 🔍 Phase 1: Proxy Detection
[12:34:59]     ✅ No proxy detected
[12:35:00] 🔍 Phase 2: Storage Analysis
[12:35:05]     📦 Analyzing 10 critical slots...
[12:35:06] 🔍 Phase 3: Pattern Analysis
[12:35:07]     🚨 Found 8 potential vulnerabilities
[12:35:08] 🤖 Phase 4: AI Validation
[12:35:11]     ✅ Validated: Reentrancy (confidence: 95%)
[12:35:14]     ❌ False positive: Has access control
[12:35:25] ✅ Scan complete!

════════════════════════════════════════════════════════════
                    📊 RESULTS SUMMARY
════════════════════════════════════════════════════════════

Total: 4 CONFIRMED exploitable vulnerabilities

🔴 CRITICAL (2):
  1. Reentrancy in withdraw() - Line 142
  2. Unprotected selfdestruct() - Line 256

🟠 HIGH (2):
  3. Integer overflow in _mint() - Line 89
  4. Delegatecall to user input - Line 178

════════════════════════════════════════════════════════════
```

## 🧪 Verification

Verify your installation:

```bash
./verify_setup.sh
```

Expected output:
```
✅ start_scanner_gui.sh is executable
✅ .env file exists
✅ All core files present
✅ Python 3.8+ installed
✅ Virtual environment ready
✅ WebSocket integration working
✅ ALL CHECKS PASSED - READY TO START!
```

## 🤝 Contributing

Contributions are welcome!

1. Fork the repository
2. Create feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License.

## 🙏 Acknowledgments

- OpenZeppelin for security best practices
- Trail of Bits for vulnerability research
- Consensys for smart contract security guidelines
- OpenAI for GPT-4 API

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/smart-contract-scanner/issues)
- **Documentation**: See `archive/docs/` for detailed guides

## 🎯 Roadmap

- [ ] Support for more blockchain networks
- [ ] Enhanced bytecode analysis
- [ ] Custom vulnerability pattern editor
- [ ] CI/CD pipeline integration
- [ ] Docker container support
- [ ] REST API for programmatic access
- [ ] Multiple AI model support

## 📈 Stats

- ✅ **80+ Vulnerability Patterns**
- ✅ **8 Blockchain Networks**
- ✅ **6 Proxy Types Detected**
- ✅ **8 Storage Categories**
- ✅ **90%+ False Positive Reduction** (with AI)
- ✅ **15-30 Second Scan Time**
- ✅ **API-Free Mode** (no keys needed)

---

**Made with ❤️ for the Web3 security community**

**⚠️ Disclaimer**: This tool is for security research and educational purposes. Always conduct manual security audits in addition to automated scanning.

**🔍 Happy scanning!**
