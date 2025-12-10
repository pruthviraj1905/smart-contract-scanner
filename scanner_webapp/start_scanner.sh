#!/bin/bash

echo "🔍 Deep Smart Contract Vulnerability Scanner Web GUI"
echo "🛑 Stopping any existing instances..."

# Kill any existing Flask processes
pkill -f "python.*app.py" 2>/dev/null || true
pkill -f "flask" 2>/dev/null || true
pkill -f "debug_webapp" 2>/dev/null || true

sleep 2

echo "🧹 Cleanup complete"
echo "🚀 Starting new instance..."

cd /home/silentrud/kali-mcp/pentesting/scanner_webapp

# Check if port 5000 is available, if not use 5001
if lsof -Pi :5000 -sTCP:LISTEN -t >/dev/null 2>&1; then
    echo "⚠️  Port 5000 in use, trying port 5001..."
    python -c "from app import app; app.run(debug=True, host='0.0.0.0', port=5001)"
else
    echo "✅ Port 5000 available"
    python debug_webapp.py
fi