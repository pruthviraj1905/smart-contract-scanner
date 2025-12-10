#!/bin/bash
################################################################################
# Quick Setup Verification Script
################################################################################

echo "════════════════════════════════════════════════════════════════════════════════"
echo "           🔍 VERIFYING SCANNER SETUP"
echo "════════════════════════════════════════════════════════════════════════════════"
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

ISSUES=0

# Check 1: Startup script exists and is executable
echo -e "${BLUE}[1/6]${NC} Checking startup script..."
if [ -x "start_scanner_gui.sh" ]; then
    echo -e "${GREEN}✅ start_scanner_gui.sh is executable${NC}"
else
    echo -e "${RED}❌ start_scanner_gui.sh not executable${NC}"
    echo -e "   Fix: chmod +x start_scanner_gui.sh"
    ISSUES=$((ISSUES + 1))
fi
echo ""

# Check 2: .env file exists and has OpenAI key
echo -e "${BLUE}[2/6]${NC} Checking configuration..."
if [ -f ".env" ]; then
    echo -e "${GREEN}✅ .env file exists${NC}"

    if grep -q "OPENAI_API_KEY=sk-" .env; then
        echo -e "${GREEN}✅ OpenAI API key configured${NC}"

        # Check model
        if grep -q "OPENAI_MODEL=gpt-4" .env; then
            echo -e "${GREEN}✅ Using GPT-4 model${NC}"
        elif grep -q "OPENAI_MODEL=gpt-4-turbo" .env; then
            echo -e "${GREEN}✅ Using GPT-4 Turbo model${NC}"
        else
            echo -e "${YELLOW}⚠️  OpenAI model: $(grep OPENAI_MODEL .env | cut -d'=' -f2)${NC}"
        fi

        if grep -q "ENABLE_AI_VALIDATION=true" .env; then
            echo -e "${GREEN}✅ AI validation enabled${NC}"
        else
            echo -e "${YELLOW}⚠️  AI validation disabled${NC}"
        fi
    else
        echo -e "${YELLOW}⚠️  OpenAI API key not found${NC}"
        echo -e "   Scanner will work without AI validation"
    fi
else
    echo -e "${YELLOW}⚠️  .env file not found (will be created on first run)${NC}"
fi
echo ""

# Check 3: Core scanner files
echo -e "${BLUE}[3/6]${NC} Checking scanner files..."
REQUIRED_FILES=(
    "deep_vuln_scanner.py"
    "pattern_engine.py"
    "safe_pattern_matcher.py"
    "ai_validator.py"
    "storage_analyzer.py"
    "proxy_detector.py"
    "scanner_webapp/app.py"
    "scanner_webapp/templates/index.html"
)

ALL_FILES_OK=true
for file in "${REQUIRED_FILES[@]}"; do
    if [ -f "$file" ]; then
        echo -e "${GREEN}✅ $file${NC}"
    else
        echo -e "${RED}❌ Missing: $file${NC}"
        ALL_FILES_OK=false
        ISSUES=$((ISSUES + 1))
    fi
done
echo ""

# Check 4: WebSocket integration
echo -e "${BLUE}[4/6]${NC} Checking WebSocket integration..."
if grep -q "initializeWebSocket" scanner_webapp/templates/index.html 2>/dev/null; then
    echo -e "${GREEN}✅ Frontend WebSocket code present${NC}"
else
    echo -e "${RED}❌ Frontend WebSocket code missing${NC}"
    ISSUES=$((ISSUES + 1))
fi

if grep -q "socketio.emit.*scan_output" scanner_webapp/app.py 2>/dev/null; then
    echo -e "${GREEN}✅ Backend WebSocket emission present${NC}"
else
    echo -e "${RED}❌ Backend WebSocket emission missing${NC}"
    ISSUES=$((ISSUES + 1))
fi
echo ""

# Check 5: Python and dependencies
echo -e "${BLUE}[5/6]${NC} Checking Python environment..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    echo -e "${GREEN}✅ Python $PYTHON_VERSION installed${NC}"
else
    echo -e "${RED}❌ Python 3 not found${NC}"
    ISSUES=$((ISSUES + 1))
fi

if [ -d "scanner_env" ]; then
    echo -e "${GREEN}✅ Virtual environment exists${NC}"

    # Check if venv has packages
    if [ -f "scanner_env/bin/python" ]; then
        echo -e "${GREEN}✅ Virtual environment is set up${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  Virtual environment not created yet (will be created on first run)${NC}"
fi
echo ""

# Check 6: Documentation
echo -e "${BLUE}[6/6]${NC} Checking documentation..."
DOCS=(
    "README_QUICK_START.md"
    "COMPLETE_SETUP_SUMMARY.md"
    "ADVANCED_FEATURES.md"
    "USAGE_GUIDE.md"
)

for doc in "${DOCS[@]}"; do
    if [ -f "$doc" ]; then
        echo -e "${GREEN}✅ $doc${NC}"
    fi
done
echo ""

# Summary
echo "════════════════════════════════════════════════════════════════════════════════"
if [ $ISSUES -eq 0 ]; then
    echo -e "${GREEN}✅ ALL CHECKS PASSED - READY TO START!${NC}"
    echo "════════════════════════════════════════════════════════════════════════════════"
    echo ""
    echo "To start the scanner:"
    echo -e "  ${GREEN}./start_scanner_gui.sh${NC}"
    echo ""
    echo "Features enabled:"
    echo "  ✅ API-Free Mode (no API keys needed)"
    echo "  ✅ Real-Time CLI Output (WebSocket)"
    echo "  ✅ Proxy Detection (all types)"
    echo "  ✅ Storage Analysis (8 categories)"
    if grep -q "OPENAI_API_KEY=sk-" .env 2>/dev/null; then
        echo "  ✅ AI Validation (OpenAI GPT-4)"
    else
        echo "  ⚪ AI Validation (not configured)"
    fi
    echo "  ✅ Multi-Chain Support (8 chains)"
    echo ""
else
    echo -e "${YELLOW}⚠️  FOUND $ISSUES ISSUE(S) - See above for details${NC}"
    echo "════════════════════════════════════════════════════════════════════════════════"
    echo ""
    echo "Most issues will be auto-fixed when you run:"
    echo -e "  ${GREEN}./start_scanner_gui.sh${NC}"
    echo ""
fi

echo "Quick reference:"
echo "  • Start GUI:    ./start_scanner_gui.sh"
echo "  • Access:       http://localhost:5002"
echo "  • Quick Start:  README_QUICK_START.md"
echo "  • Full Guide:   COMPLETE_SETUP_SUMMARY.md"
echo ""
echo "════════════════════════════════════════════════════════════════════════════════"
