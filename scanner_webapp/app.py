#!/usr/bin/env python3
"""
Flask Web GUI for Deep Smart Contract Vulnerability Scanner
Focus on non-privileged fund drain exploits
"""

import os
import sys
import uuid
import json
from datetime import datetime
from pathlib import Path
from flask import Flask, render_template, request, jsonify, send_file, flash, redirect, url_for
from werkzeug.utils import secure_filename
import threading
import time
import subprocess
import queue
from flask import Response, stream_template
from flask_socketio import SocketIO, emit, join_room, leave_room
from contextlib import redirect_stdout, redirect_stderr
import io

# Add parent directory to path to import scanner modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from deep_vuln_scanner import DeepContractScanner, VulnSeverity
from bytecode_analyzer import BytecodeAnalyzer
from pattern_engine import AdvancedPatternEngine
from no_api_fetcher import contract_fetcher

app = Flask(__name__)
app.secret_key = 'vuln_scanner_secret_key_2024'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Initialize SocketIO for real-time communication
socketio = SocketIO(app, cors_allowed_origins="*")

# Configuration
UPLOAD_FOLDER = 'uploads'
RESULTS_FOLDER = 'results'
ALLOWED_EXTENSIONS = {'txt', 'sol'}

# Ensure directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(RESULTS_FOLDER, exist_ok=True)

# Global variables for scan status
scan_status = {}
scan_results = {}

# Initialize scan manager
scan_manager = None

class RealTimeOutput:
    """Captures print output and streams it to WebSocket clients"""
    def __init__(self, scan_id, socketio):
        self.scan_id = scan_id
        self.socketio = socketio
        self.output_buffer = []
        
    def write(self, text):
        if text.strip():  # Only send non-empty messages
            self.output_buffer.append(text.strip())
            # Emit to WebSocket clients in the scan room
            self.socketio.emit('scan_output', {
                'scan_id': self.scan_id,
                'output': text.strip(),
                'timestamp': datetime.now().strftime('%H:%M:%S')
            }, room=f'scan_{self.scan_id}')
            
    def flush(self):
        pass  # Required for file-like object interface

class ScanManager:
    def __init__(self):
        self.active_scans = {}
        self.scan_outputs = {}  # Store terminal output for each scan
        self.real_time_outputs = {}  # Store real-time output handlers
        
    def start_scan(self, scan_id, contract_address, source_type, content, options):
        """Start a new vulnerability scan"""
        scan_info = {
            'id': scan_id,
            'status': 'starting',
            'progress': 0,
            'start_time': datetime.now(),
            'contract_address': contract_address,
            'source_type': source_type,
            'options': options,
            'results': None,
            'error': None
        }
        
        self.active_scans[scan_id] = scan_info
        self.scan_outputs[scan_id] = queue.Queue()  # Store terminal output
        
        # Start scan in background thread
        thread = threading.Thread(target=self._run_scan, args=(scan_id, content, options))
        thread.daemon = True
        thread.start()
        
        return scan_id
    
    def _run_scan(self, scan_id, content, options):
        """Run the actual vulnerability scan with real-time terminal output capture"""
        try:
            scan_info = self.active_scans[scan_id]
            scan_info['status'] = 'running'
            scan_info['progress'] = 10
            
            # Setup real-time output capture
            real_time_output = RealTimeOutput(scan_id, socketio)
            self.real_time_outputs[scan_id] = real_time_output
            
            # Add terminal output
            self._add_output(scan_id, "🔍 Starting deep vulnerability scan...")
            self._add_output(scan_id, f"📊 Contract: {scan_info['contract_address']}")
            self._add_output(scan_id, f"🔧 Source Type: {scan_info['source_type']}")
            self._add_output(scan_id, f"⚙️ Options: {options}")
            
            # Redirect stdout to capture scanner output in real-time
            original_stdout = sys.stdout
            original_stderr = sys.stderr
            
            # Initialize scanner with chain support
            api_key = options.get('api_key') or os.getenv('ETHERSCAN_API_KEY')
            
            # Unified Etherscan v2 API configuration - all chains use same endpoint with chain_id
            chain_config = {
                'ethereum': {'chain_id': '1', 'api_base': 'https://api.etherscan.io/v2/api', 'name': 'Ethereum'},
                'bsc': {'chain_id': '56', 'api_base': 'https://api.etherscan.io/v2/api', 'name': 'BSC'},
                'polygon': {'chain_id': '137', 'api_base': 'https://api.etherscan.io/v2/api', 'name': 'Polygon'},
                'avalanche': {'chain_id': '43114', 'api_base': 'https://api.etherscan.io/v2/api', 'name': 'Avalanche'},
                'arbitrum': {'chain_id': '42161', 'api_base': 'https://api.etherscan.io/v2/api', 'name': 'Arbitrum'},
                'optimism': {'chain_id': '10', 'api_base': 'https://api.etherscan.io/v2/api', 'name': 'Optimism'},
                'base': {'chain_id': '8453', 'api_base': 'https://api.basescan.org/api', 'name': 'Base'},
                'gnosis': {'chain_id': '100', 'api_base': 'https://api.etherscan.io/v2/api', 'name': 'Gnosis'}
            }
            
            selected_chain = chain_config.get(options.get('chain', 'ethereum'), chain_config['ethereum'])
            enable_ai = options.get('enable_ai', False)
            is_undeployed = options.get('undeployed_contract', False)
            
            try:
                # Redirect output to capture real-time scanner output
                sys.stdout = real_time_output
                sys.stderr = real_time_output
                
                # Phase 1: Contract validation and balance checking (only for deployed contracts)
                if not is_undeployed and scan_info['contract_address'] != '0x0000000000000000000000000000000000000000':
                    self._add_output(scan_id, "🔍 Phase 1: Contract validation and balance check...")
                    scan_info['progress'] = 5
                    
                    # Validate contract exists on selected chain
                    contract_validation = self._validate_contract_on_chain(
                        scan_info['contract_address'], 
                        selected_chain, 
                        api_key
                    )
                    
                    if not contract_validation['exists']:
                        self._add_output(scan_id, f"❌ Contract not found on {selected_chain['name']}")
                        self._add_output(scan_id, f"💡 Suggestion: Check if contract is deployed on {selected_chain['name']}")
                        self._add_output(scan_id, "💡 Or enable 'Undeployed Contract' option if analyzing source code only")
                        raise Exception(f"Contract {scan_info['contract_address']} not found on {selected_chain['name']}")
                    
                    # Display contract balance and assets
                    self._add_output(scan_id, f"✅ Contract verified on {selected_chain['name']}")
                    self._add_output(scan_id, f"💰 Native Balance: {contract_validation['native_balance']}")
                    
                    if contract_validation['token_balances']:
                        self._add_output(scan_id, "🪙 Token Balances:")
                        for token in contract_validation['token_balances'][:5]:  # Show first 5 tokens
                            self._add_output(scan_id, f"   • {token['symbol']}: {token['balance']}")
                        if len(contract_validation['token_balances']) > 5:
                            self._add_output(scan_id, f"   • ... and {len(contract_validation['token_balances'])-5} more tokens")
                    
                    scan_info['progress'] = 10
                else:
                    self._add_output(scan_id, "⚠️ Undeployed contract mode - skipping blockchain validation")
                    scan_info['progress'] = 10
                
                scanner = DeepContractScanner(api_key, chain_config=selected_chain, enable_ai_validation=enable_ai)
                
                scan_info['progress'] = 20
                
                # Run scan based on content type
                vulnerabilities = []
                
                if scan_info['source_type'] == 'solidity':
                    scan_info['status'] = 'analyzing_solidity'
                    scan_info['progress'] = 30
                    self._add_output(scan_id, "📝 Analyzing Solidity source code...")
                    self._add_output(scan_id, f"📏 Code length: {len(content)} characters")
                    
                    vulnerabilities = scanner.scan_contract(
                        scan_info['contract_address'],
                        source_code=content,
                        combine_sources=options.get('combine_sources', False)
                    )
                    
                    self._add_output(scan_id, f"🔍 Initial patterns detected: {len(vulnerabilities)} potential issues")
                    
                elif scan_info['source_type'] == 'decompiled':
                    scan_info['status'] = 'analyzing_decompiled'
                    scan_info['progress'] = 30
                    vulnerabilities = scanner.scan_contract(
                        scan_info['contract_address'],
                        decompiled_code=content,
                        combine_sources=options.get('combine_sources', False)
                    )
                    
                elif scan_info['source_type'] == 'bytecode':
                    scan_info['status'] = 'analyzing_bytecode'
                    scan_info['progress'] = 30
                    vulnerabilities = scanner.scan_contract(
                        scan_info['contract_address'],
                        bytecode=content,
                        combine_sources=options.get('combine_sources', False)
                    )
            finally:
                # Restore original stdout/stderr
                sys.stdout = original_stdout
                sys.stderr = original_stderr
            
            scan_info['progress'] = 80
            
            # Filter vulnerabilities based on options
            filtered_vulns = self._filter_vulnerabilities(vulnerabilities, options)
            
            scan_info['progress'] = 90
            
            # Generate results
            results = {
                'total_vulnerabilities': len(filtered_vulns),
                'critical_count': len([v for v in filtered_vulns if v.severity == VulnSeverity.CRITICAL]),
                'high_count': len([v for v in filtered_vulns if v.severity == VulnSeverity.HIGH]),
                'medium_count': len([v for v in filtered_vulns if v.severity == VulnSeverity.MEDIUM]),
                'low_count': len([v for v in filtered_vulns if v.severity == VulnSeverity.LOW]),
                'vulnerabilities': [self._vuln_to_dict(v) for v in filtered_vulns],
                'scan_info': {
                    'contract_address': scan_info['contract_address'],
                    'scan_time': datetime.now().isoformat(),
                    'source_type': scan_info['source_type'],
                    'options_used': options
                }
            }
            
            # Save results
            self._save_results(scan_id, results)
            
            scan_info['results'] = results
            scan_info['status'] = 'completed'
            scan_info['progress'] = 100
            scan_info['end_time'] = datetime.now()
            
        except Exception as e:
            scan_info['status'] = 'error'
            scan_info['error'] = str(e)
            scan_info['end_time'] = datetime.now()
            self._add_output(scan_id, f"❌ SCAN ERROR: {str(e)}")
            
            # Add detailed error info
            import traceback
            error_details = traceback.format_exc()
            self._add_output(scan_id, f"🐛 Error Details: {error_details}")

    def _add_output(self, scan_id, message):
        """Add terminal output message to scan and emit via WebSocket"""
        from datetime import datetime
        timestamp = datetime.now().strftime('%H:%M:%S')
        formatted_message = f"[{timestamp}] {message}"

        if scan_id in self.scan_outputs:
            self.scan_outputs[scan_id].put(formatted_message)

        # Also emit via WebSocket for real-time display
        socketio.emit('scan_output', {
            'scan_id': scan_id,
            'output': message,
            'timestamp': timestamp
        }, room=f'scan_{scan_id}')

    def get_scan_output(self, scan_id):
        """Get all terminal output for a scan"""
        if scan_id not in self.scan_outputs:
            return []
        
        messages = []
        while not self.scan_outputs[scan_id].empty():
            try:
                messages.append(self.scan_outputs[scan_id].get_nowait())
            except:
                break
        return messages
    
    def _filter_vulnerabilities(self, vulnerabilities, options):
        """Filter vulnerabilities based on scan options"""
        filtered = vulnerabilities
        
        # Severity filter
        if options.get('min_severity'):
            severity_weights = {
                'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0
            }
            min_weight = severity_weights.get(options['min_severity'], 0)
            filtered = [v for v in filtered 
                       if severity_weights.get(v.severity.value, 0) >= min_weight]
        
        # Confidence filter
        if options.get('min_confidence'):
            filtered = [v for v in filtered 
                       if v.confidence >= float(options['min_confidence'])]
        
        # Non-privileged only filter
        if options.get('non_privileged_only'):
            filtered = self._filter_non_privileged(filtered)
        
        return filtered
    
    def _filter_non_privileged(self, vulnerabilities):
        """Filter for non-privileged vulnerabilities only"""
        non_privileged_keywords = [
            'unauthorized', 'public', 'external', 'without authorization',
            'missing auth', 'no access control', 'bypass', 'circular dependency',
            'unprotected', 'anyone can call', 'external user', 'reentrancy',
            'transfertoken', 'decompiled transfer'
        ]
        
        privileged_keywords = [
            'onlyowner', 'only owner', 'admin only', 'requires owner',
            'malicious owner', 'owner can', 'admin can', 'privileged',
            'requires admin', 'owner-only', 'admin-only'
        ]
        
        filtered = []
        for vuln in vulnerabilities:
            description_lower = vuln.description.lower()
            title_lower = vuln.title.lower()
            
            # Skip if it requires owner/admin privileges
            is_privileged = any(keyword in description_lower or keyword in title_lower 
                               for keyword in privileged_keywords)
            
            # Include if it's explicitly non-privileged
            is_non_privileged = any(keyword in description_lower or keyword in title_lower 
                                   for keyword in non_privileged_keywords)
            
            if not is_privileged and is_non_privileged:
                filtered.append(vuln)
        
        return filtered
    
    def _vuln_to_dict(self, vuln):
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
    
    def _save_results(self, scan_id, results):
        """Save scan results to file"""
        results_file = os.path.join(RESULTS_FOLDER, f"scan_{scan_id}.json")
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2)
    
    def get_scan_status(self, scan_id):
        """Get current scan status"""
        return self.active_scans.get(scan_id)
    
    def get_scan_results(self, scan_id):
        """Get scan results"""
        if scan_id in self.active_scans:
            return self.active_scans[scan_id].get('results')
        return None
    
    def _validate_contract_on_chain(self, contract_address, chain_config, api_key):
        """Validate if contract exists on the selected chain using API-free method"""
        try:
            # Use API-free contract fetcher instead of Etherscan APIs
            chain_name = chain_config.get('name', 'ethereum').lower()
            contract_info = contract_fetcher.fetch_contract_info(contract_address, chain_name)
            
            if contract_info.get('error'):
                print(f"⚠️ Contract validation error: {contract_info['error']}")
                return {'exists': False, 'native_balance': '0', 'token_balances': []}
            
            exists = contract_info.get('exists', False)
            
            validation_result = {
                'exists': exists,
                'native_balance': contract_info.get('balance', '0'),
                'token_balances': []
            }
            
            if not exists:
                return validation_result
            
            # Use contract info from API-free fetcher
            validation_result['verified'] = contract_info.get('verified', False)
            validation_result['contract_name'] = contract_info.get('contract_name', 'Unknown')
            validation_result['status'] = contract_info.get('status', 'Unknown')
            validation_result['explorer_url'] = contract_info.get('explorer_url', '')
            
            # Simple token balance info (API-free doesn't get detailed token data)
            if contract_info.get('balance') and contract_info['balance'] != '0':
                validation_result['token_balances'] = [
                    {
                        'symbol': 'Native',
                        'balance': contract_info['balance'],
                        'address': contract_address
                    }
                ]
            
            return validation_result
            
        except Exception as e:
            print(f"Contract validation error: {e}")
            return {'exists': False, 'native_balance': '0', 'token_balances': []}
    
    def _get_native_symbol(self, chain_name):
        """Get native token symbol for chain"""
        symbols = {
            'Ethereum': 'ETH',
            'BSC': 'BNB', 
            'Polygon': 'MATIC',
            'Avalanche': 'AVAX',
            'Arbitrum': 'ETH',
            'Optimism': 'ETH',
            'Base': 'ETH',
            'Gnosis': 'xDAI'
        }
        return symbols.get(chain_name, 'ETH')
    
    def _get_token_balance(self, contract_address, token_address, chain_config, api_key):
        """Get token balance for a specific ERC20 token"""
        try:
            import requests
            
            # ERC20 balanceOf function call
            balance_of_data = '0x70a08231' + contract_address[2:].zfill(64)
            
            params = {
                'module': 'proxy',
                'action': 'eth_call',
                'to': token_address,
                'data': balance_of_data,
                'tag': 'latest',
                'apikey': api_key
            }
            
            response = requests.get(chain_config['api_base'], params=params, timeout=10)
            data = response.json()
            
            if data.get('result') and data['result'] != '0x':
                balance_hex = data['result']
                balance_int = int(balance_hex, 16)
                
                if balance_int > 0:
                    # Assume 18 decimals for simplicity
                    balance_formatted = balance_int / 10**18
                    if balance_formatted < 0.001:
                        return f'{balance_int} units'
                    else:
                        return f'{balance_formatted:.6f}'
                
            return None
            
        except Exception:
            return None

# Global scan manager
scan_manager = ScanManager()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    """Main page with scan options"""
    # Get list of existing reports for the reports browser
    reports = get_existing_reports()
    return render_template('index.html', existing_reports=reports)

@app.route('/test')
def test_page():
    """Simple test page without JavaScript for debugging network issues"""
    return render_template('simple_test.html')

@app.route('/reports')
def view_reports():
    """View all existing reports"""
    reports = get_existing_reports()
    return render_template('reports_browser.html', reports=reports)

@app.route('/reports/<report_filename>')
def view_saved_report(report_filename):
    """View a specific saved report"""
    import os
    report_path = os.path.join('reports', report_filename)
    
    if not os.path.exists(report_path):
        flash('Report not found', 'error')
        return redirect(url_for('view_reports'))
    
    try:
        with open(report_path, 'r') as f:
            report_content = f.read()
        
        # Parse the markdown report
        report_data = parse_markdown_report(report_content)
        return render_template('saved_report.html', 
                             report_data=report_data, 
                             filename=report_filename)
    except Exception as e:
        flash(f'Error loading report: {str(e)}', 'error')
        return redirect(url_for('view_reports'))

def get_existing_reports():
    """Get list of existing reports with metadata"""
    import os
    from datetime import datetime
    
    reports = []
    reports_dir = 'reports'
    
    if not os.path.exists(reports_dir):
        return reports
    
    for filename in os.listdir(reports_dir):
        if filename.endswith('.md'):
            filepath = os.path.join(reports_dir, filename)
            try:
                stat = os.stat(filepath)
                
                # Extract contract address from filename
                contract_addr = 'Unknown'
                if filename.startswith('0x') or len(filename.split('_')[0]) >= 16:
                    contract_addr = '0x' + filename.split('_')[0].replace('.md', '')[:16]
                
                reports.append({
                    'filename': filename,
                    'contract_address': contract_addr,
                    'size': stat.st_size,
                    'modified': datetime.fromtimestamp(stat.st_mtime),
                    'scan_params': extract_scan_params_from_filename(filename)
                })
            except Exception as e:
                print(f"Error processing {filename}: {e}")
    
    # Sort by modification time, newest first
    reports.sort(key=lambda x: x['modified'], reverse=True)
    return reports

def extract_scan_params_from_filename(filename):
    """Extract scan parameters from filename"""
    params = []
    if 'nonpriv' in filename:
        params.append('Non-Privileged')
    if 'ai' in filename:
        params.append('AI-Enhanced')
    if 'critical' in filename:
        params.append('Critical Only')
    if 'high' in filename:
        params.append('High+')
    
    return ' | '.join(params) if params else 'Standard'

def parse_markdown_report(content):
    """Parse markdown report content into structured data"""
    lines = content.split('\n')
    report_data = {
        'title': 'Vulnerability Report',
        'contract': 'Unknown',
        'scan_date': 'Unknown',
        'scan_params': 'Unknown',
        'total_vulnerabilities': 0,
        'vulnerabilities': []
    }
    
    current_vuln = None
    in_vulnerability = False
    
    for line in lines:
        line = line.strip()
        
        if line.startswith('## Contract:'):
            report_data['contract'] = line.replace('## Contract:', '').strip()
        elif line.startswith('## Scan Date:'):
            report_data['scan_date'] = line.replace('## Scan Date:', '').strip()
        elif line.startswith('## Scan Parameters:'):
            report_data['scan_params'] = line.replace('## Scan Parameters:', '').strip()
        elif line.startswith('Found') and 'vulnerabilities' in line:
            import re
            match = re.search(r'Found (\d+)', line)
            if match:
                report_data['total_vulnerabilities'] = int(match.group(1))
        elif line.startswith('### ') and '. ' in line:
            # New vulnerability section
            if current_vuln:
                report_data['vulnerabilities'].append(current_vuln)
            
            title = line.replace('###', '').strip()
            current_vuln = {
                'title': title,
                'severity': 'UNKNOWN',
                'confidence': '0%',
                'location': 'Unknown',
                'description': '',
                'exploit_path': '',
                'impact': '',
                'recommendation': ''
            }
            in_vulnerability = True
        elif in_vulnerability and current_vuln:
            if line.startswith('- **Severity**:'):
                current_vuln['severity'] = line.split(':')[1].strip()
            elif line.startswith('- **Confidence**:'):
                current_vuln['confidence'] = line.split(':')[1].strip()
            elif line.startswith('- **Location**:'):
                current_vuln['location'] = line.split(':')[1].strip()
            elif line.startswith('**Description:**'):
                current_vuln['description'] = 'Reading...'
            elif line.startswith('**Exploit Path:**'):
                current_vuln['exploit_path'] = 'Reading...'
            elif line.startswith('**Impact:**'):
                current_vuln['impact'] = 'Reading...'
            elif line.startswith('**Recommendation:**'):
                current_vuln['recommendation'] = 'Reading...'
    
    # Add the last vulnerability
    if current_vuln:
        report_data['vulnerabilities'].append(current_vuln)
    
    return report_data

@app.route('/scan', methods=['POST'])
def start_scan():
    """Start a new vulnerability scan"""
    try:
        # Get scan parameters
        contract_address = request.form.get('contract_address', '').strip()
        source_type = request.form.get('source_type')
        chain = request.form.get('chain', 'ethereum')
        
        # Validation - make address optional for non-deployed contracts
        if not contract_address:
            contract_address = '0x0000000000000000000000000000000000000000'  # Placeholder
        elif contract_address != '0x0000000000000000000000000000000000000000':
            if not contract_address.startswith('0x') or len(contract_address) != 42:
                return jsonify({'error': 'Invalid contract address format'}), 400
        
        # Get source content
        content = None
        
        if source_type == 'solidity':
            if 'solidity_file' in request.files and request.files['solidity_file'].filename:
                file = request.files['solidity_file']
                if allowed_file(file.filename):
                    content = file.read().decode('utf-8')
            elif request.form.get('solidity_text'):
                content = request.form.get('solidity_text')
            else:
                return jsonify({'error': 'Solidity source code is required'}), 400
                
        elif source_type == 'decompiled':
            if 'decompiled_file' in request.files and request.files['decompiled_file'].filename:
                file = request.files['decompiled_file']
                if allowed_file(file.filename):
                    content = file.read().decode('utf-8')
            elif request.form.get('decompiled_text'):
                content = request.form.get('decompiled_text')
            else:
                return jsonify({'error': 'Decompiled source code is required'}), 400
                
        elif source_type == 'bytecode':
            if 'bytecode_file' in request.files and request.files['bytecode_file'].filename:
                file = request.files['bytecode_file']
                if allowed_file(file.filename):
                    content = file.read().decode('utf-8')
            elif request.form.get('bytecode_text'):
                content = request.form.get('bytecode_text')
            else:
                return jsonify({'error': 'Bytecode is required'}), 400
        
        else:
            return jsonify({'error': 'Invalid source type'}), 400
        
        if not content or not content.strip():
            return jsonify({'error': 'Source content cannot be empty'}), 400
        
        # Get scan options
        options = {
            'min_severity': request.form.get('min_severity'),
            'min_confidence': request.form.get('min_confidence'),
            'non_privileged_only': request.form.get('non_privileged_only') == 'on',
            'api_key': request.form.get('api_key'),
            'chain': chain,
            'combine_sources': request.form.get('combine_sources') == 'on',
            'enable_ai': request.form.get('enable_ai') == 'on',
            'undeployed_contract': request.form.get('undeployed_contract') == 'on'
        }
        
        # Generate scan ID
        scan_id = str(uuid.uuid4())
        
        # Start scan
        scan_manager.start_scan(scan_id, contract_address, source_type, content, options)
        
        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'message': 'Scan started successfully'
        })
        
    except Exception as e:
        return jsonify({'error': f'Failed to start scan: {str(e)}'}), 500

@app.route('/status/<scan_id>')
def get_scan_status(scan_id):
    """Get scan status and progress"""
    status = scan_manager.get_scan_status(scan_id)
    
    if not status:
        return jsonify({'error': 'Scan not found'}), 404
    
    return jsonify({
        'status': status['status'],
        'progress': status['progress'],
        'start_time': status['start_time'].isoformat() if status.get('start_time') else None,
        'error': status.get('error')
    })

@app.route('/output/<scan_id>')
def get_scan_output(scan_id):
    """Get terminal output for a scan"""
    output = scan_manager.get_scan_output(scan_id)
    return jsonify({'output': output})

@app.route('/stream/<scan_id>')
def stream_scan_output(scan_id):
    """Stream terminal output in real-time"""
    def generate():
        while True:
            output = scan_manager.get_scan_output(scan_id)
            if output:
                for line in output:
                    yield f"data: {line}\\n\\n"
            
            # Check if scan is complete
            status = scan_manager.get_scan_status(scan_id)
            if status and status['status'] in ['completed', 'error']:
                yield f"data: [SCAN_COMPLETE]\\n\\n"
                break
                
            time.sleep(1)  # Poll every second
    
    return Response(generate(), mimetype='text/plain')

@app.route('/results/<scan_id>')
def get_scan_results(scan_id):
    """Get scan results"""
    results = scan_manager.get_scan_results(scan_id)
    
    if not results:
        status = scan_manager.get_scan_status(scan_id)
        if not status:
            return jsonify({'error': 'Scan not found'}), 404
        elif status['status'] in ['starting', 'running']:
            return jsonify({'error': 'Scan still in progress'}), 202
        else:
            return jsonify({'error': 'Scan failed or no results available'}), 404
    
    return jsonify(results)

@app.route('/report/<scan_id>')
def view_report(scan_id):
    """View detailed scan report"""
    try:
        results = scan_manager.get_scan_results(scan_id)
        
        if not results:
            flash('Scan results not found', 'error')
            return redirect(url_for('index'))
        
        # Ensure results has all required fields with defaults
        results.setdefault('total_vulnerabilities', 0)
        results.setdefault('critical_count', 0)
        results.setdefault('high_count', 0)
        results.setdefault('medium_count', 0)
        results.setdefault('low_count', 0)
        results.setdefault('vulnerabilities', [])
        
        if 'scan_info' not in results:
            results['scan_info'] = {
                'contract_address': 'Unknown',
                'scan_time': 'Unknown',
                'source_type': 'Unknown',
                'options_used': {}
            }
        
        return render_template('report.html', results=results, scan_id=scan_id)
        
    except Exception as e:
        app.logger.error(f"Error viewing report for scan {scan_id}: {str(e)}")
        flash(f'Error loading report: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/download/<scan_id>/<format>')
def download_report(scan_id, format):
    """Download scan report in various formats"""
    results = scan_manager.get_scan_results(scan_id)
    
    if not results:
        return jsonify({'error': 'Results not found'}), 404
    
    if format == 'json':
        # Return JSON file
        filename = f"vulnerability_report_{scan_id}.json"
        filepath = os.path.join(RESULTS_FOLDER, filename)
        
        with open(filepath, 'w') as f:
            json.dump(results, f, indent=2)
        
        return send_file(filepath, as_attachment=True, download_name=filename)
    
    elif format == 'markdown':
        # Generate markdown report
        filename = f"vulnerability_report_{scan_id}.md"
        filepath = os.path.join(RESULTS_FOLDER, filename)
        
        markdown_content = generate_markdown_report(results)
        
        with open(filepath, 'w') as f:
            f.write(markdown_content)
        
        return send_file(filepath, as_attachment=True, download_name=filename)
    
    else:
        return jsonify({'error': 'Invalid format'}), 400

def generate_markdown_report(results):
    """Generate markdown format report"""
    scan_info = results.get('scan_info', {})
    vulnerabilities = results.get('vulnerabilities', [])
    
    md = f"""# Smart Contract Vulnerability Report

## Contract Information
- **Address**: {scan_info.get('contract_address', 'Unknown')}
- **Scan Date**: {scan_info.get('scan_time', 'Unknown')}
- **Source Type**: {scan_info.get('source_type', 'Unknown')}
- **Total Vulnerabilities**: {results.get('total_vulnerabilities', 0)}

## Executive Summary
- 🔴 **Critical**: {results.get('critical_count', 0)}
- 🟠 **High**: {results.get('high_count', 0)}
- 🟡 **Medium**: {results.get('medium_count', 0)}
- 🔵 **Low**: {results.get('low_count', 0)}

## Detailed Findings

"""
    
    for i, vuln in enumerate(vulnerabilities, 1):
        emoji = {
            'CRITICAL': '🔴',
            'HIGH': '🟠', 
            'MEDIUM': '🟡',
            'LOW': '🔵',
            'INFO': '⚪'
        }.get(vuln.get('severity', 'INFO'), '⚪')
        
        md += f"""### {emoji} {i}. {vuln.get('title', 'Unknown Vulnerability')}

- **Severity**: {vuln.get('severity', 'UNKNOWN')}
- **Confidence**: {vuln.get('confidence', 0):.0%}
- **Location**: {vuln.get('location', 'Unknown')}

**Description:**
{vuln.get('description', 'No description available')}

**Impact:**
{vuln.get('impact', 'No impact information available')}

**Exploit Path:**
{vuln.get('exploit_path', 'No exploit path available')}

**Proof of Concept:**
```
{vuln.get('proof_of_concept', 'No PoC available')}
```

**Recommendation:**
{vuln.get('recommendation', 'No recommendation available')}

---

"""
    
    return md

# WebSocket Event Handlers for Real-time Communication
@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    print(f'🔌 Client connected: {request.sid}')
    emit('status', {'message': 'Connected to vulnerability scanner'})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    print(f'🔌 Client disconnected: {request.sid}')

@socketio.on('join_scan')
def handle_join_scan(data):
    """Join a specific scan room for real-time updates"""
    scan_id = data.get('scan_id')
    if scan_id:
        join_room(f'scan_{scan_id}')
        print(f'🔌 Client {request.sid} joined scan room: {scan_id}')
        emit('status', {'message': f'Joined scan {scan_id}'})
        
        # Send any existing output for this scan
        if scan_id in scan_manager.scan_outputs:
            output_messages = scan_manager.get_scan_output(scan_id)
            for msg in output_messages:
                emit('scan_output', {
                    'scan_id': scan_id,
                    'output': msg,
                    'timestamp': datetime.now().strftime('%H:%M:%S')
                })

@socketio.on('leave_scan')
def handle_leave_scan(data):
    """Leave a specific scan room"""
    scan_id = data.get('scan_id')
    if scan_id:
        leave_room(f'scan_{scan_id}')
        print(f'🔌 Client {request.sid} left scan room: {scan_id}')
        emit('status', {'message': f'Left scan {scan_id}'})

@socketio.on('get_scan_status')
def handle_get_scan_status(data):
    """Get current status of a scan"""
    scan_id = data.get('scan_id')
    if scan_id and scan_id in scan_manager.active_scans:
        scan_info = scan_manager.active_scans[scan_id]
        emit('scan_status_update', {
            'scan_id': scan_id,
            'status': scan_info['status'],
            'progress': scan_info['progress'],
            'start_time': scan_info['start_time'].isoformat() if scan_info.get('start_time') else None,
            'end_time': scan_info['end_time'].isoformat() if scan_info.get('end_time') else None,
            'error': scan_info.get('error')
        })
    else:
        emit('error', {'message': f'Scan {scan_id} not found'})

if __name__ == '__main__':
    print("🔍 Starting Deep Smart Contract Vulnerability Scanner Web GUI")
    print("🌐 Access the scanner at: http://localhost:5000")
    print("🎯 Focus: Non-privileged fund drain exploits")
    
    # Enable detailed error logging
    import logging
    logging.basicConfig(level=logging.DEBUG)
    
    # Initialize scan manager
    scan_manager = ScanManager()
    
    # Run with SocketIO support for real-time communication
    socketio.run(app, debug=True, host='0.0.0.0', port=5002, allow_unsafe_werkzeug=True)