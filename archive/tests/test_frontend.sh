#!/bin/bash
# Test script for frontend GUI scanner

echo "=========================================="
echo "🧪 FRONTEND GUI SCANNER TEST"
echo "=========================================="
echo ""

# Check if Flask app exists
if [ ! -f "scanner_webapp/app.py" ]; then
    echo "❌ Error: scanner_webapp/app.py not found"
    exit 1
fi

echo "✅ Found scanner_webapp/app.py"
echo ""

# Check if templates exist
if [ ! -f "scanner_webapp/templates/index.html" ]; then
    echo "❌ Error: index.html not found"
    exit 1
fi

echo "✅ Found index.html template"
echo ""

# Check for WebSocket integration in HTML
if grep -q "initializeWebSocket" scanner_webapp/templates/index.html; then
    echo "✅ WebSocket integration found in HTML"
else
    echo "❌ WebSocket integration missing in HTML"
    exit 1
fi

if grep -q "joinScanRoom" scanner_webapp/templates/index.html; then
    echo "✅ joinScanRoom function found"
else
    echo "❌ joinScanRoom function missing"
    exit 1
fi

if grep -q "toggleTerminal" scanner_webapp/templates/index.html; then
    echo "✅ toggleTerminal function found"
else
    echo "❌ toggleTerminal function missing"
    exit 1
fi

echo ""

# Check backend WebSocket emission
if grep -q "socketio.emit.*scan_output" scanner_webapp/app.py; then
    echo "✅ Backend WebSocket emission found"
else
    echo "❌ Backend WebSocket emission missing"
    exit 1
fi

echo ""
echo "=========================================="
echo "✅ ALL CHECKS PASSED"
echo "=========================================="
echo ""
echo "To start the server:"
echo "  cd scanner_webapp"
echo "  python app.py"
echo ""
echo "Then open: http://localhost:5002"
echo ""
echo "Expected behavior:"
echo "  1. WebSocket connects automatically"
echo "  2. Start a scan"
echo "  3. Terminal opens and shows real-time output"
echo "  4. Output is color-coded (errors=red, success=green)"
echo "  5. Can toggle terminal with button"
echo ""
echo "=========================================="
