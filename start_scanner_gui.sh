#!/bin/bash
################################################################################
# Smart Contract Scanner - GUI Startup Script
# Automatically handles venv setup, dependencies, and server startup
################################################################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
VENV_DIR="scanner_env"
PYTHON_CMD="python3"
PORT=5002
HOST="0.0.0.0"

# Banner
echo -e "${CYAN}"
echo "════════════════════════════════════════════════════════════════════════════════"
echo "           🔍 SMART CONTRACT VULNERABILITY SCANNER - GUI LAUNCHER"
echo "════════════════════════════════════════════════════════════════════════════════"
echo -e "${NC}"

################################################################################
# Step 1: Check Python Installation
################################################################################
echo -e "${BLUE}[1/6]${NC} Checking Python installation..."

if ! command -v $PYTHON_CMD &> /dev/null; then
    echo -e "${RED}❌ Error: Python 3 is not installed${NC}"
    echo -e "Please install Python 3.8 or higher:"
    echo -e "  sudo apt-get install python3 python3-pip python3-venv"
    exit 1
fi

PYTHON_VERSION=$($PYTHON_CMD --version 2>&1 | awk '{print $2}')
echo -e "${GREEN}✅ Found Python $PYTHON_VERSION${NC}"
echo ""

################################################################################
# Step 2: Create/Activate Virtual Environment
################################################################################
echo -e "${BLUE}[2/6]${NC} Setting up virtual environment..."

if [ ! -d "$VENV_DIR" ]; then
    echo -e "${YELLOW}⚙️  Creating virtual environment...${NC}"
    $PYTHON_CMD -m venv $VENV_DIR
    echo -e "${GREEN}✅ Virtual environment created${NC}"
else
    echo -e "${GREEN}✅ Virtual environment already exists${NC}"
fi

# Activate virtual environment
echo -e "${YELLOW}⚙️  Activating virtual environment...${NC}"
source $VENV_DIR/bin/activate

if [ -z "$VIRTUAL_ENV" ]; then
    echo -e "${RED}❌ Error: Failed to activate virtual environment${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Virtual environment activated${NC}"
echo -e "   Path: $VIRTUAL_ENV"
echo ""

################################################################################
# Step 3: Upgrade pip
################################################################################
echo -e "${BLUE}[3/6]${NC} Upgrading pip..."

pip install --upgrade pip --quiet
echo -e "${GREEN}✅ pip upgraded to latest version${NC}"
echo ""

################################################################################
# Step 4: Install Dependencies
################################################################################
echo -e "${BLUE}[4/6]${NC} Installing dependencies..."

# Check if requirements.txt exists
if [ ! -f "requirements.txt" ]; then
    echo -e "${YELLOW}⚠️  requirements.txt not found, creating from scratch...${NC}"

    cat > requirements.txt << 'EOF'
# Core Dependencies
flask==3.0.0
flask-socketio==5.3.5
python-socketio==5.10.0
werkzeug==3.0.1

# Web3 and Blockchain
web3==6.11.3
eth-utils==2.3.1
eth-abi==4.2.1

# HTTP and Scraping
requests==2.31.0
beautifulsoup4==4.12.2
lxml==4.9.3
aiohttp==3.9.1

# Cryptography
cryptography==41.0.7

# Data Processing
python-dotenv==1.0.0

# Optional: AI Validation (requires OpenAI API key)
openai==1.3.7
EOF

    echo -e "${GREEN}✅ Created requirements.txt${NC}"
fi

# Install dependencies
echo -e "${YELLOW}⚙️  Installing Python packages (this may take a few minutes)...${NC}"

# Install in chunks for better error handling
echo -e "   📦 Installing Flask and web framework..."
pip install flask flask-socketio python-socketio werkzeug --quiet 2>&1 | grep -i "error" || true

echo -e "   📦 Installing Web3 and blockchain libraries..."
pip install web3 eth-utils eth-abi --quiet 2>&1 | grep -i "error" || true

echo -e "   📦 Installing HTTP and scraping tools..."
pip install requests beautifulsoup4 lxml aiohttp --quiet 2>&1 | grep -i "error" || true

echo -e "   📦 Installing additional dependencies..."
pip install cryptography python-dotenv --quiet 2>&1 | grep -i "error" || true

echo -e "   📦 Installing optional AI support..."
pip install openai --quiet 2>&1 | grep -i "error" || true

echo -e "${GREEN}✅ All dependencies installed${NC}"
echo ""

################################################################################
# Step 5: Environment Check
################################################################################
echo -e "${BLUE}[5/6]${NC} Verifying environment..."

# Check critical modules
MISSING_DEPS=()

for module in flask flask_socketio web3 bs4 requests; do
    if ! $PYTHON_CMD -c "import $module" 2>/dev/null; then
        MISSING_DEPS+=("$module")
    fi
done

if [ ${#MISSING_DEPS[@]} -ne 0 ]; then
    echo -e "${RED}❌ Error: Missing dependencies: ${MISSING_DEPS[*]}${NC}"
    echo -e "Try running: pip install -r requirements.txt"
    exit 1
fi

echo -e "${GREEN}✅ All required modules available${NC}"

# Check scanner files
echo -e "   🔍 Checking scanner files..."

REQUIRED_FILES=(
    "scanner_webapp/app.py"
    "deep_vuln_scanner.py"
    "pattern_engine.py"
    "safe_pattern_matcher.py"
)

for file in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "$file" ]; then
        echo -e "${RED}❌ Error: Required file not found: $file${NC}"
        exit 1
    fi
done

echo -e "${GREEN}✅ All scanner files present${NC}"

# Check .env file
if [ ! -f ".env" ]; then
    echo -e "${YELLOW}⚠️  .env file not found, creating default...${NC}"

    cat > .env << 'EOF'
# Smart Contract Scanner Configuration

# API-Free Mode (Recommended)
USE_API_FREE=true

# Optional: Etherscan API Key (for faster source code fetching)
# ETHERSCAN_API_KEY=your_api_key_here

# Optional: OpenAI API Key (for AI validation - eliminates false positives)
# OPENAI_API_KEY=sk-your_openai_key_here
# OPENAI_MODEL=gpt-4

# Scanner Settings
MAX_STORAGE_SLOTS=100
ENABLE_AI_VALIDATION=false

# Network Settings
RPC_TIMEOUT=30
MAX_RETRIES=3
RATE_LIMIT_RPM=60
EOF

    echo -e "${GREEN}✅ Created .env file${NC}"
fi

echo ""

################################################################################
# Step 6: Start Server
################################################################################
echo -e "${BLUE}[6/6]${NC} Starting scanner GUI..."
echo ""

echo -e "${CYAN}════════════════════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}✅ SCANNER READY${NC}"
echo -e "${CYAN}════════════════════════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "🌐 Access URL: ${GREEN}http://localhost:$PORT${NC}"
echo -e "🌍 Network URL: ${GREEN}http://$(hostname -I | awk '{print $1}'):$PORT${NC}"
echo ""
echo -e "Features Available:"
echo -e "  ✅ Proxy Detection (EIP-1967, UUPS, Beacon, Diamond)"
echo -e "  ✅ Storage-Level Analysis (8 vulnerability types)"
echo -e "  ✅ Real-Time CLI Output (WebSocket streaming)"
echo -e "  ✅ AI Validation (set OPENAI_API_KEY to enable)"
echo -e "  ✅ Multi-Chain Support (Ethereum, BSC, Polygon, etc.)"
echo -e "  ✅ API-Free Mode (no API keys needed)"
echo ""
echo -e "${YELLOW}📝 Notes:${NC}"
echo -e "  • Terminal output will show in GUI automatically"
echo -e "  • For AI validation: export OPENAI_API_KEY='sk-...'"
echo -e "  • For API mode: export ETHERSCAN_API_KEY='...'"
echo -e "  • Press Ctrl+C to stop the server"
echo ""
echo -e "${CYAN}════════════════════════════════════════════════════════════════════════════════${NC}"
echo ""

# Wait a moment for user to read
sleep 2

# Change to webapp directory
cd scanner_webapp

# Start Flask server with SocketIO
echo -e "${GREEN}🚀 Starting Flask server...${NC}"
echo ""

# Run the server
$PYTHON_CMD app.py

# This will only run if server is stopped
echo ""
echo -e "${YELLOW}Server stopped${NC}"
