#!/usr/bin/env python3
"""
Launcher script for the Deep Smart Contract Vulnerability Scanner Web GUI
"""

import os
import sys
import webbrowser
from pathlib import Path

def setup_environment():
    """Setup the environment and install dependencies if needed"""
    print("🔧 Setting up Deep Smart Contract Vulnerability Scanner Web GUI...")
    
    # Check if Flask is installed
    try:
        import flask
        print("✅ Flask is available")
    except ImportError:
        print("📦 Installing Flask...")
        os.system("pip install flask")
    
    # Create necessary directories
    dirs_to_create = ['uploads', 'results', 'templates', 'static']
    for dir_name in dirs_to_create:
        os.makedirs(dir_name, exist_ok=True)
        print(f"📁 Ensured directory exists: {dir_name}")

def check_scanner_files():
    """Check if scanner files are available"""
    required_files = [
        '../deep_vuln_scanner.py',
        '../pattern_engine.py', 
        '../bytecode_analyzer.py'
    ]
    
    missing_files = []
    for file_path in required_files:
        if not os.path.exists(file_path):
            missing_files.append(file_path)
        else:
            print(f"✅ Found: {file_path}")
    
    if missing_files:
        print("❌ Missing required scanner files:")
        for file_path in missing_files:
            print(f"   - {file_path}")
        print("\n💡 Make sure you're running this from the scanner_webapp directory")
        print("💡 And that all scanner files are in the parent directory")
        return False
    
    return True

def main():
    """Main launcher function"""
    print("🔍 Deep Smart Contract Vulnerability Scanner")
    print("🌐 Web GUI Launcher")
    print("=" * 50)
    
    # Setup environment
    setup_environment()
    print()
    
    # Check scanner files
    if not check_scanner_files():
        print("\n❌ Cannot start web GUI - missing required files")
        return False
    
    print("\n🚀 Starting Web GUI...")
    print("📍 URL: http://localhost:5000")
    print("🎯 Focus: Non-privileged fund drain exploits")
    print("🛑 Press Ctrl+C to stop the server")
    print("=" * 50)
    
    # Try to open browser automatically
    try:
        webbrowser.open('http://localhost:5000')
        print("🌐 Opening browser...")
    except:
        print("💡 Manually open: http://localhost:5000")
    
    # Start the Flask app
    try:
        from app import app
        app.run(debug=False, host='0.0.0.0', port=5000)
    except KeyboardInterrupt:
        print("\n\n🛑 Web GUI stopped by user")
    except Exception as e:
        print(f"\n❌ Error starting web GUI: {e}")
        return False
    
    return True

if __name__ == "__main__":
    success = main()
    if not success:
        sys.exit(1)