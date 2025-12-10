# Deep Smart Contract Vulnerability Scanner - Web GUI

🌐 **Professional web interface for finding non-privileged fund drain exploits**

## 🚀 Quick Start

### 1. Launch the Web GUI
```bash
cd scanner_webapp
python run_webapp.py
```

### 2. Open Your Browser
Navigate to: **http://localhost:5000**

### 3. Start Scanning
1. Enter contract address (0x...)
2. Choose source type:
   - **Verified Solidity** - Upload .sol file or paste code
   - **Decompiled Code** - Upload decompiled file or paste code
   - **Raw Bytecode** - Upload bytecode file or paste hex
3. Configure scan options:
   - ✅ **Non-Privileged Only** (recommended for bug bounty)
   - Minimum severity filter
   - Confidence threshold
4. Click **Start Deep Scan**

## 🎯 Web GUI Features

### 📱 **Modern Interface**
- Responsive Bootstrap design
- Real-time progress tracking
- Professional vulnerability reports
- Multiple download formats

### 🔍 **Flexible Input Options**
- **File Upload**: Drop .sol, .txt files
- **Direct Paste**: Copy/paste code directly
- **Multi-Format**: Solidity, decompiled, bytecode

### ⚡ **Advanced Scanning**
- **Non-Privileged Focus**: Filter for exploitable vulnerabilities
- **Confidence Scoring**: ML-inspired accuracy ratings
- **Severity Filtering**: Focus on critical findings only
- **Real-time Progress**: Live scan status updates

### 📊 **Professional Reports**
- **Visual Dashboard**: Severity breakdown and statistics
- **Detailed Analysis**: Exploit paths and PoCs
- **Multiple Formats**: Markdown, JSON downloads
- **Bug Bounty Ready**: Professional formatting for submissions

## 🎪 Screenshot Guide

### Main Scan Interface
```
┌─────────────────────────────────────────────────────────┐
│ 🔍 Deep Smart Contract Vulnerability Scanner           │
│ 🎯 Focus: Non-Privileged Fund Drain Exploits           │
├─────────────────────────────────────────────────────────┤
│                                                         │
│ Contract Address: [0x1234567890...                   ] │
│                                                         │
│ Source Code Type:                                       │
│ [ Verified Solidity ] [ Decompiled Code ] [ Bytecode ] │
│                                                         │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ Upload .sol File: [Choose File]          OR        │ │
│ │                                                     │ │
│ │ Paste Solidity Code:                               │ │
│ │ ┌─────────────────────────────────────────────────┐ │ │
│ │ │ pragma solidity ^0.8.0;                       │ │ │
│ │ │                                               │ │ │
│ │ │ contract MyContract {                         │ │ │
│ │ │     // Your contract code here                │ │ │
│ │ │ }                                             │ │ │
│ │ └─────────────────────────────────────────────────┘ │ │
│ └─────────────────────────────────────────────────────┘ │
│                                                         │
│ Scan Options:                                           │
│ Min Severity: [Critical Only ▼] Confidence: [80%+ ▼]  │
│ [✓] Non-Privileged Only    API Key: [Optional...]      │
│                                                         │
│              [🚀 Start Deep Scan]                      │
└─────────────────────────────────────────────────────────┘
```

### Results Dashboard
```
┌─────────────────────────────────────────────────────────┐
│ 📄 Vulnerability Report - Contract: 0x1234...          │
│ ┌─────┬─────┬─────┬─────┬─────┬─────────────────────────┐ │
│ │  5  │ 🔴2 │ 🟠1 │ 🟡1 │ 🔵1 │      Solidity       │ │
│ │Total│Crit │High │Med  │Low  │    Source Type      │ │
│ └─────┴─────┴─────┴─────┴─────┴─────────────────────────┘ │
│                                                         │
│ 🔴 1. Unauthorized Transfer Function                    │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ Description: Function allows unlimited token        │ │
│ │ transfers without authorization checks              │ │
│ │                                                     │ │
│ │ Impact: Complete loss of funds                      │ │
│ │                                                     │ │
│ │ Exploit Path:                                       │ │
│ │ 1. Call transferToken() function                    │ │
│ │ 2. Specify target token address                     │ │
│ │ 3. Drain all contract funds                         │ │
│ └─────────────────────────────────────────────────────┘ │
│                                                         │
│ [📥 Download Markdown] [📥 Download JSON]               │
└─────────────────────────────────────────────────────────┘
```

## 🎯 Usage Examples

### Example 1: Bug Bounty Hunting
```bash
# 1. Start web GUI
python run_webapp.py

# 2. In browser:
# - Enter target contract address
# - Upload decompiled code from dedaub.com
# - Check "Non-Privileged Only"
# - Set "Critical Only" filter
# - Start scan

# 3. Get professional report for bounty submission
```

### Example 2: Security Audit
```bash
# 1. Upload verified Solidity source
# 2. Set "Medium & Above" severity
# 3. Include all vulnerability types
# 4. Generate comprehensive markdown report
```

## 🔧 Technical Details

### Backend Architecture
- **Flask Web Framework**: Lightweight Python web server
- **Async Scanning**: Background processing with progress tracking
- **File Handling**: Secure upload and processing
- **Report Generation**: Multiple format support

### Scanner Integration
- **Deep Scanner Engine**: Core vulnerability detection
- **Pattern Engine**: 15+ specialized vulnerability patterns
- **Bytecode Analyzer**: EVM-level analysis capabilities
- **Confidence Scoring**: ML-inspired accuracy ratings

### Security Features
- **Input Validation**: Contract address and code validation
- **File Size Limits**: 16MB maximum upload size
- **Secure Processing**: No code execution, analysis only
- **Session Management**: Isolated scan sessions

## 📝 File Structure
```
scanner_webapp/
├── app.py                 # Main Flask application
├── run_webapp.py          # Launcher script  
├── deep_vuln_scanner.py   # Core scanner engine
├── pattern_engine.py      # Vulnerability patterns
├── bytecode_analyzer.py   # Bytecode analysis
├── templates/
│   ├── base.html          # Base template
│   ├── index.html         # Main scan interface  
│   └── report.html        # Results display
├── uploads/               # Uploaded files (temporary)
├── results/               # Scan results storage
└── README.md             # This file
```

## 🚀 Advanced Features

### Real-time Progress Tracking
- Live scan status updates
- Progress percentage indicator
- Detailed step-by-step feedback
- Estimated completion time

### Professional Reporting
- Executive summary dashboard
- Detailed vulnerability breakdown
- Exploit paths and impact analysis
- Proof-of-concept code examples
- Bug bounty submission guidance

### Multiple Input Methods
- **Drag & Drop**: File upload interface
- **Copy & Paste**: Direct code input
- **Mixed Mode**: Combine different input types

## 🎯 Non-Privileged Focus

The web GUI includes a special **"Non-Privileged Only"** filter that focuses exclusively on vulnerabilities that external users can exploit without special permissions:

### ✅ **Included Vulnerabilities**
- Unauthorized transfer functions
- Public withdrawal functions
- Reentrancy attacks
- Broken access control initialization
- Approval manipulation exploits

### ❌ **Excluded Vulnerabilities**
- Owner-only function issues
- Admin privilege escalation
- Governance token exploits
- Multisig bypass vulnerabilities

## 🏆 Success Tips

### For Bug Bounty Hunters
1. **Use Non-Privileged Filter**: Focus on exploitable vulnerabilities
2. **Target Critical/High**: These have the highest payouts
3. **Verify Manually**: Always double-check findings
4. **Create PoCs**: Develop working exploit code
5. **Professional Reports**: Use the markdown output as a base

### For Security Auditors
1. **Comprehensive Scan**: Include all severity levels
2. **Multiple Source Types**: Test different input formats
3. **Documentation**: Generate detailed reports
4. **Follow-up Testing**: Manual verification of findings

## 🆘 Troubleshooting

### Common Issues

**Port Already in Use**
```bash
# Solution: Use different port
python -c "from app import app; app.run(port=5001)"
```

**Scanner Files Missing**
```bash
# Solution: Copy scanner files to webapp directory
cp ../deep_vuln_scanner.py ../pattern_engine.py ../bytecode_analyzer.py .
```

**Upload Fails**
- Check file size (max 16MB)
- Verify file extension (.sol, .txt)
- Ensure proper encoding (UTF-8)

**No Vulnerabilities Found**
- Try different scan options
- Check if contract has public functions
- Verify source code quality
- Consider lower confidence threshold

## 📞 Support

For issues or questions:
1. Check this README first
2. Verify all scanner files are present
3. Test with CLI version first
4. Check browser console for errors

---

**🎯 Ready to hunt for vulnerabilities? Launch the web GUI and start scanning! 🎯**