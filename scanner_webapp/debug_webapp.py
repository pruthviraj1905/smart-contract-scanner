#!/usr/bin/env python3
"""
Debug version of the web app with enhanced error reporting
"""

import os
import sys
import traceback

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from app import app, scan_manager
    
    @app.errorhandler(500)
    def internal_error(error):
        """Enhanced error handler for debugging"""
        return f"""
        <h1>Internal Server Error</h1>
        <h2>Error Details:</h2>
        <pre>{traceback.format_exc()}</pre>
        <hr>
        <p><a href="/">Return to Home</a></p>
        """, 500
    
    @app.route('/debug/<scan_id>')
    def debug_scan(scan_id):
        """Debug endpoint to inspect scan data"""
        try:
            status = scan_manager.get_scan_status(scan_id)
            results = scan_manager.get_scan_results(scan_id)
            
            debug_info = {
                'scan_id': scan_id,
                'status': status,
                'results': results,
                'results_type': type(results).__name__ if results else None,
                'results_keys': list(results.keys()) if results and isinstance(results, dict) else None
            }
            
            return f"""
            <h1>Debug Information for Scan: {scan_id}</h1>
            <h2>Status:</h2>
            <pre>{status}</pre>
            <h2>Results:</h2>
            <pre>{results}</pre>
            <h2>Debug Info:</h2>
            <pre>{debug_info}</pre>
            <hr>
            <p><a href="/">Return to Home</a></p>
            """
        except Exception as e:
            return f"""
            <h1>Debug Error</h1>
            <pre>{traceback.format_exc()}</pre>
            <hr>
            <p><a href="/">Return to Home</a></p>
            """
    
    if __name__ == '__main__':
        print("🐛 Debug Mode: Deep Smart Contract Vulnerability Scanner")
        print("🌐 Access at: http://localhost:5000")
        print("🔧 Debug endpoint: http://localhost:5000/debug/<scan_id>")
        print("📋 Enhanced error reporting enabled")
        
        import logging
        logging.basicConfig(level=logging.DEBUG)
        app.config['DEBUG'] = True
        app.config['PROPAGATE_EXCEPTIONS'] = True
        
        app.run(debug=True, host='0.0.0.0', port=5000)
        
except Exception as e:
    print(f"❌ Failed to start debug webapp: {e}")
    print(f"📍 Current directory: {os.getcwd()}")
    print("📁 Files in directory:")
    for file in os.listdir('.'):
        print(f"   {file}")
    print("\n💡 Make sure you're in the scanner_webapp directory")
    traceback.print_exc()