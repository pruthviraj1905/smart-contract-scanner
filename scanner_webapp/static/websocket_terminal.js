// WebSocket Terminal Output Handler
// Handles real-time CLI output streaming from backend scanner

// Initialize SocketIO connection
let socket = null;
let currentScanId = null;
let terminalVisible = false;

function initializeWebSocket() {
    // Connect to SocketIO server
    socket = io.connect(location.protocol + '//' + document.domain + ':' + location.port);

    // Connection status
    socket.on('connect', function() {
        console.log('✅ WebSocket connected');
        addTerminalLine('[SYSTEM] Connected to scanner', 'success');
    });

    socket.on('disconnect', function() {
        console.log('❌ WebSocket disconnected');
        addTerminalLine('[SYSTEM] Disconnected from scanner', 'error');
    });

    // Receive scan output in real-time
    socket.on('scan_output', function(data) {
        console.log('📨 Received output:', data);
        addTerminalLine(data.output, classifyOutputType(data.output));
    });

    // Receive scan status updates
    socket.on('scan_status_update', function(data) {
        console.log('📊 Status update:', data);
        updateScanProgress(data);
    });

    // Error handling
    socket.on('error', function(data) {
        console.error('❌ WebSocket error:', data);
        addTerminalLine(`[ERROR] ${data.message}`, 'error');
    });
}

function joinScanRoom(scanId) {
    currentScanId = scanId;
    if (socket && socket.connected) {
        socket.emit('join_scan', {'scan_id': scanId});
        console.log(`🔗 Joined scan room: ${scanId}`);
        addTerminalLine(`[SYSTEM] Monitoring scan ${scanId}`, 'info');

        // Auto-show terminal when scan starts
        if (!terminalVisible) {
            toggleTerminal();
        }
    } else {
        console.error('❌ Socket not connected, retrying...');
        setTimeout(() => joinScanRoom(scanId), 1000);
    }
}

function leaveScanRoom(scanId) {
    if (socket && socket.connected && scanId) {
        socket.emit('leave_scan', {'scan_id': scanId});
        console.log(`🔗 Left scan room: ${scanId}`);
    }
}

function addTerminalLine(text, type = 'info') {
    const terminalContent = document.getElementById('terminal-content');
    if (!terminalContent) {
        console.error('Terminal content element not found');
        return;
    }

    const timestamp = new Date().toLocaleTimeString();
    const line = document.createElement('div');
    line.className = `terminal-line terminal-${type}`;

    line.innerHTML = `
        <span class="terminal-timestamp">[${timestamp}]</span>
        <span class="terminal-content">${escapeHtml(text)}</span>
    `;

    terminalContent.appendChild(line);

    // Auto-scroll to bottom
    const terminalOutput = document.getElementById('terminal-output');
    if (terminalOutput) {
        terminalOutput.scrollTop = terminalOutput.scrollHeight;
    }
}

function classifyOutputType(text) {
    const lowerText = text.toLowerCase();

    if (lowerText.includes('error') || lowerText.includes('❌') || lowerText.includes('failed')) {
        return 'error';
    }
    if (lowerText.includes('warning') || lowerText.includes('⚠️')) {
        return 'warning';
    }
    if (lowerText.includes('success') || lowerText.includes('✅') || lowerText.includes('completed')) {
        return 'success';
    }
    if (lowerText.includes('🔍') || lowerText.includes('📊') || lowerText.includes('phase')) {
        return 'info';
    }

    return 'info';
}

function toggleTerminal() {
    const terminal = document.getElementById('terminal-output');
    const toggleBtn = document.getElementById('terminalToggle');

    if (!terminal || !toggleBtn) {
        console.error('Terminal elements not found');
        return;
    }

    terminalVisible = !terminalVisible;

    if (terminalVisible) {
        terminal.classList.add('active');
        toggleBtn.classList.add('active');
        toggleBtn.innerHTML = '<i class="fas fa-terminal"></i> Hide CLI Output';
    } else {
        terminal.classList.remove('active');
        toggleBtn.classList.remove('active');
        toggleBtn.innerHTML = '<i class="fas fa-terminal"></i> Show CLI Output';
    }
}

function clearTerminal() {
    const terminalContent = document.getElementById('terminal-content');
    if (terminalContent) {
        terminalContent.innerHTML = '';
        addTerminalLine('[SYSTEM] Terminal cleared', 'info');
    }
}

function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
}

// Initialize WebSocket when page loads
document.addEventListener('DOMContentLoaded', function() {
    console.log('🚀 Initializing WebSocket terminal...');
    initializeWebSocket();

    // Setup terminal toggle button
    const toggleBtn = document.getElementById('terminalToggle');
    if (toggleBtn) {
        toggleBtn.addEventListener('click', toggleTerminal);
    }
});

// Export functions for use in other scripts
window.scannerWebSocket = {
    joinScan: joinScanRoom,
    leaveScan: leaveScanRoom,
    addLine: addTerminalLine,
    toggle: toggleTerminal,
    clear: clearTerminal
};
