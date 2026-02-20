// SecureChain Enterprise Gateway UI
const q = (s) => document.querySelector(s);

function updateTimestamp() {
  const timestampElement = q('#timestamp');
  if (timestampElement) {
    timestampElement.textContent = new Date().toLocaleString('en-US', {
      year: 'numeric', month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit', second: '2-digit'
    });
  }
}

function showLoading(element, text = 'Processing...') {
  element.textContent = text;
}

function showResult(element, result) {
  element.textContent = result;
}

// URL Scanner Form
document.addEventListener('DOMContentLoaded', function() {
  const form = q('#scanner-form');
  const resultContainer = q('#result-container');
  const resultOutput = q('#result-output');
  
  if (form) {
    form.addEventListener('submit', async function(e) {
      e.preventDefault();
      
      const url = q('#target-url').value;
      if (!url) return;
      
      resultContainer.style.display = 'block';
      updateTimestamp();
      showLoading(resultOutput, 'Analyzing target resource...');
      
      try {
        const response = await fetch('/api/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: url })
        });
        
        const result = await response.text();
        showResult(resultOutput, result);
      } catch (error) {
        showResult(resultOutput, 'Error: ' + error.message);
      }
    });
  }
});

// Settings Configuration
async function saveSettings() {
  const settingsJson = q('#settings-json').value;
  const statusElement = q('#settings-status');
  
  if (!settingsJson.trim()) {
    showStatus(statusElement, 'Please enter configuration', 'error');
    return;
  }
  
  try {
    JSON.parse(settingsJson);
  } catch (e) {
    showStatus(statusElement, 'Invalid JSON format', 'error');
    return;
  }
  
  try {
    const response = await fetch('/prefs', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: settingsJson
    });
    
    const result = await response.json();
    
    if (response.ok) {
      showStatus(statusElement, 'Configuration updated successfully', 'success');
    } else {
      showStatus(statusElement, 'Failed to update configuration', 'error');
    }
  } catch (error) {
    showStatus(statusElement, 'Network error: ' + error.message, 'error');
  }
}

function showStatus(element, message, type) {
  element.textContent = message;
  element.className = `status-message ${type}`;
  element.style.display = 'block';
  
  setTimeout(() => {
    element.style.display = 'none';
  }, 3000);
}

// Function to update timestamp
function updateTimestamp() {
  const timestampElement = q('#timestamp');
  if (timestampElement) {
    timestampElement.textContent = new Date().toLocaleString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
  }
}

// Function to show loading state
function showLoading(element, text = 'Processing...') {
  element.textContent = text;
  element.style.opacity = '0.7';
  updateTimestamp();
}

// Function to show result
function showResult(element, result) {
  element.textContent = JSON.stringify(result, null, 2);
  element.style.opacity = '1';
  updateTimestamp();
}

// Function to show error
function showError(element, message) {
  element.textContent = `Error: ${message}`;
  element.style.opacity = '1';
  updateTimestamp();
}

// Handle form submission for URL analyzer
if (q('#go')) {
  q('#go').onclick = async () => {
    const urlInput = q('#u');
    const outputElement = q('#out');
    
    const url = urlInput.value.trim() || '/rdr';
    
    showLoading(outputElement, 'Analyzing security threats...');
    
    try {
      const response = await fetch('/relay?u=' + encodeURIComponent(url));
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      
      const result = await response.json();
      showResult(outputElement, result);
      
    } catch (error) {
      console.error('Security analysis error:', error);
      showError(outputElement, 'Security analysis failed. Please try again.');
    }
  };
}

// Handle configuration save
if (q('#save')) {
  q('#save').onclick = async () => {
    const prefsTextarea = q('#prefs');
    const noteElement = q('#note');
    
    let data = {};
    
    try {
      const prefsValue = prefsTextarea.value.trim();
      if (prefsValue) {
        data = JSON.parse(prefsValue);
      }
    } catch (e) {
      noteElement.textContent = 'Invalid JSON format. Please check configuration syntax.';
      noteElement.className = 'status-message error';
      return;
    }
    
    noteElement.textContent = 'Applying configuration...';
    noteElement.className = 'status-message';
    
    try {
      const response = await fetch('/prefs', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
      });
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      
      const result = await response.json();
      
      if (result.ok) {
        noteElement.textContent = 'Security configuration applied successfully!';
        noteElement.className = 'status-message success';
      } else {
        noteElement.textContent = 'Failed to apply configuration.';
        noteElement.className = 'status-message error';
      }
      
    } catch (error) {
      console.error('Configuration error:', error);
      noteElement.textContent = 'Error applying security configuration.';
      noteElement.className = 'status-message error';
    }
  };
}

// Handle admin access
if (q('#ping')) {
  q('#ping').onclick = async () => {
    const flagElement = q('#flag');
    
    showLoading(flagElement, 'Authenticating admin access...');
    
    try {
      const response = await fetch('/flag', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: '{}'
      });
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      
      const result = await response.json();
      showResult(flagElement, result);
      
    } catch (error) {
      console.error('Admin authentication error:', error);
      showError(flagElement, 'Admin access denied. Multi-factor authentication required.');
    }
  };
}

// Initialize timestamp on page load
document.addEventListener('DOMContentLoaded', () => {
  updateTimestamp();
  
  // Update timestamp every 30 seconds
  setInterval(updateTimestamp, 30000);
  
  // Add smooth scrolling for anchor links
  document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
      e.preventDefault();
      const target = document.querySelector(this.getAttribute('href'));
      if (target) {
        target.scrollIntoView({
          behavior: 'smooth'
        });
      }
    });
  });

  // Generate fake dashboard data for admin pages
  generateDashboardData();
});

// Keyboard shortcuts
document.addEventListener('keydown', (e) => {
  // Ctrl+Enter to analyze URL
  if (e.ctrlKey && e.key === 'Enter' && q('#go')) {
    e.preventDefault();
    q('#go').click();
  }
  
  // Ctrl+S to save configuration
  if (e.ctrlKey && e.key === 's' && q('#save')) {
    e.preventDefault();
    q('#save').click();
  }
});

// Enter key support for URL input
if (q('#u')) {
  q('#u').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
      q('#go').click();
    }
  });
}

// Auto-resize textarea
if (q('#prefs')) {
  q('#prefs').addEventListener('input', function() {
    this.style.height = 'auto';
    this.style.height = this.scrollHeight + 'px';
  });
}

// Generate realistic dashboard data
function generateDashboardData() {
  // Update system stats
  const stats = {
    'total-requests': Math.floor(Math.random() * 10000) + 50000,
    'active-sessions': Math.floor(Math.random() * 100) + 150,
    'blocked-threats': Math.floor(Math.random() * 500) + 1200,
    'uptime-hours': Math.floor(Math.random() * 100) + 720
  };

  Object.keys(stats).forEach(id => {
    const element = q(`#${id}`);
    if (element) {
      element.textContent = stats[id].toLocaleString();
    }
  });

  // Generate audit log entries
  generateAuditLogs();
  
  // Generate security events
  generateSecurityEvents();
}

function generateAuditLogs() {
  const logTable = q('#audit-logs-table');
  if (!logTable) return;

  const logs = [
    { time: '2025-08-24 15:32:45', user: 'system', action: 'Security scan initiated', status: 'success' },
    { time: '2025-08-24 15:31:12', user: 'admin', action: 'MFA configuration updated', status: 'success' },
    { time: '2025-08-24 15:28:33', user: 'system', action: 'Proxy token rotation', status: 'success' },
    { time: '2025-08-24 15:25:41', user: 'user_192.168.1.45', action: 'Failed login attempt', status: 'warning' },
    { time: '2025-08-24 15:22:17', user: 'system', action: 'Backup service health check', status: 'success' },
    { time: '2025-08-24 15:19:55', user: 'admin', action: 'Security policy applied', status: 'success' },
    { time: '2025-08-24 15:16:28', user: 'system', action: 'Threat detection update', status: 'success' },
    { time: '2025-08-24 15:13:42', user: 'user_10.0.0.15', action: 'Suspicious URL blocked', status: 'error' }
  ];

  logs.forEach(log => {
    const row = logTable.insertRow();
    row.innerHTML = `
      <td>${log.time}</td>
      <td>${log.user}</td>
      <td>${log.action}</td>
      <td><span class="status-badge status-${log.status}">${log.status.toUpperCase()}</span></td>
    `;
  });
}

function generateSecurityEvents() {
  const eventTable = q('#security-events-table');
  if (!eventTable) return;

  const events = [
    { time: '2025-08-24 15:35:12', type: 'Threat Blocked', source: '203.0.113.42', severity: 'High' },
    { time: '2025-08-24 15:33:45', type: 'SSL Certificate Check', source: 'Internal', severity: 'Low' },
    { time: '2025-08-24 15:31:28', type: 'Malware Detected', source: '192.0.2.15', severity: 'Critical' },
    { time: '2025-08-24 15:29:15', type: 'DDoS Attempt', source: '198.51.100.23', severity: 'High' },
    { time: '2025-08-24 15:26:33', type: 'Policy Violation', source: '10.0.0.45', severity: 'Medium' },
    { time: '2025-08-24 15:24:12', type: 'Authentication Success', source: 'Admin Portal', severity: 'Low' },
    { time: '2025-08-24 15:21:55', type: 'Phishing Attempt', source: '172.16.0.12', severity: 'High' }
  ];

  events.forEach(event => {
    const row = eventTable.insertRow();
    const severityClass = event.severity.toLowerCase();
    row.innerHTML = `
      <td>${event.time}</td>
      <td>${event.type}</td>
      <td>${event.source}</td>
      <td><span class="status-badge status-${getSeverityStatus(event.severity)}">${event.severity.toUpperCase()}</span></td>
    `;
  });
}

function getSeverityStatus(severity) {
  switch(severity.toLowerCase()) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
      return 'success';
    default:
      return 'success';
  }
}

// Refresh dashboard data every 30 seconds
setInterval(() => {
  if (window.location.pathname.includes('/admin')) {
    generateDashboardData();
  }
}, 30000);
