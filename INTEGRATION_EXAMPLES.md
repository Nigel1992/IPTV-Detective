# IPTV Detective - Quick Integration Examples

This file provides ready-to-use code snippets for integrating the baseline system into your frontend.

---

## 🔑 Authentication Setup

```javascript
// Set user ID globally for all API calls
const currentUserId = localStorage.getItem('userId') || 1;
const currentUserRole = localStorage.getItem('userRole') || 'user';

// Helper function for API calls
async function callAPI(endpoint, action, data = {}) {
    const payload = {
        action,
        user_id: currentUserId,
        ...data
    };
    
    try {
        const response = await fetch(`/${endpoint}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        
        return await response.json();
    } catch (error) {
        console.error(`API Error (${endpoint}):`, error);
        return { success: false, error: error.message };
    }
}
```

---

## 📋 User Flows

### 1. Disclaimer Flow (First Time)

```javascript
async function showDisclaimerFlow() {
    // Check if user has already acknowledged
    const status = await callAPI('disclaimers.php', 'check_status');
    
    if (status.data && status.data.acknowledged) {
        console.log('User has acknowledged all disclaimers');
        return true;
    }
    
    // Show disclaimer modal
    const disclaimers = await callAPI('disclaimers.php', 'get_disclaimers');
    displayDisclaimerModal(disclaimers.data.disclaimers);
}

function displayDisclaimerModal(disclaimers) {
    const modal = `
        <div class="modal" id="disclaimerModal">
            <div class="modal-content">
                <h2>Important Disclaimers</h2>
                
                <div class="disclaimer-section">
                    <h3>${disclaimers.credential_privacy.title}</h3>
                    <div>${disclaimers.credential_privacy.content}</div>
                    <label>
                        <input type="checkbox" name="cred_privacy" required>
                        ${disclaimers.credential_privacy.checkbox_text}
                    </label>
                </div>
                
                <div class="disclaimer-section">
                    <h3>${disclaimers.trial_credentials.title}</h3>
                    <div>${disclaimers.trial_credentials.content}</div>
                    <label>
                        <input type="checkbox" name="trial_creds" required>
                        ${disclaimers.trial_credentials.checkbox_text}
                    </label>
                </div>
                
                <div class="disclaimer-section">
                    <h3>${disclaimers.data_collection.title}</h3>
                    <div>${disclaimers.data_collection.content}</div>
                    <label>
                        <input type="checkbox" name="data_collect" required>
                        ${disclaimers.data_collection.checkbox_text}
                    </label>
                </div>
                
                <button onclick="acknowledgeDisclaimers()">I Accept All Terms</button>
            </div>
        </div>
    `;
    
    document.body.insertAdjacentHTML('beforeend', modal);
}

async function acknowledgeDisclaimers() {
    const result = await callAPI('disclaimers.php', 'acknowledge', {
        credential_privacy: document.querySelector('[name="cred_privacy"]').checked,
        trial_credentials: document.querySelector('[name="trial_creds"]').checked,
        data_collection: document.querySelector('[name="data_collect"]').checked
    });
    
    if (result.success) {
        document.getElementById('disclaimerModal').remove();
        localStorage.setItem('disclaimerAcknowledged', 'true');
        console.log('Disclaimers acknowledged');
    }
}
```

---

### 2. Service Scan Flow

```javascript
async function scanIPTVService() {
    const url = document.getElementById('serviceUrl').value;
    const serviceName = document.getElementById('serviceName').value;
    const country = document.getElementById('country').value;
    
    if (!url) {
        alert('Please enter a service URL');
        return;
    }
    
    // Show loading state
    document.getElementById('scanButton').disabled = true;
    document.getElementById('scanButton').textContent = 'Scanning...';
    
    try {
        // Perform scan
        const result = await callAPI('service-matcher.php', 'scan_and_match', {
            url: url,
            service_name: serviceName,
            country: country,
            metadata: {
                channels: document.getElementById('channels').value || 0,
                vods: document.getElementById('vods').value || 0,
                resolution: document.getElementById('resolution').value,
                has_epg: document.getElementById('hasEPG').checked ? 1 : 0
            }
        });
        
        if (result.success) {
            displayScanResults(result.data);
        } else {
            alert('Scan failed: ' + result.error);
        }
    } finally {
        document.getElementById('scanButton').disabled = false;
        document.getElementById('scanButton').textContent = 'Scan Service';
    }
}

function displayScanResults(data) {
    const matches = data.matches;
    
    if (matches.length === 0) {
        displayNoMatches(data);
        return;
    }
    
    let html = '<div class="matches-container">';
    
    matches.forEach((match, index) => {
        const badgeClass = match.confidence >= 80 ? 'excellent' : 
                          match.confidence >= 60 ? 'good' : 'fair';
        
        html += `
            <div class="match-result" style="margin-bottom: 20px;">
                <div class="match-header">
                    <h3>${match.service_name}</h3>
                    <div class="match-score ${badgeClass}">
                        ${match.confidence}%
                    </div>
                </div>
                
                <div class="match-info">
                    <p><strong>Match Type:</strong> ${match.match_type}</p>
                    <p><strong>Confidence:</strong> ${getConfidenceLabel(match.confidence)}</p>
                </div>
                
                <div class="matching-criteria">
                    <h4>Matching Criteria:</h4>
                    <ul>
                        ${match.matching_criteria.map(c => `<li>✓ ${c}</li>`).join('')}
                    </ul>
                </div>
                
                ${match.non_matching_criteria.length > 0 ? `
                    <div class="non-matching">
                        <h4>Non-matching Criteria:</h4>
                        <ul>
                            ${match.non_matching_criteria.map(c => `<li>✗ ${c}</li>`).join('')}
                        </ul>
                    </div>
                ` : ''}
                
                <div class="match-actions">
                    <button onclick="downloadReport(${data.scan_id}, '${match.baseline_id}')">
                        📄 Download Report
                    </button>
                    <button onclick="viewAliases(${match.baseline_id})">
                        🏷️ View Aliases
                    </button>
                </div>
            </div>
        `;
    });
    
    html += '</div>';
    document.getElementById('scanResults').innerHTML = html;
}

function getConfidenceLabel(confidence) {
    if (confidence >= 80) return 'Excellent Match';
    if (confidence >= 60) return 'Good Match';
    if (confidence >= 40) return 'Fair Match';
    return 'Low Match';
}

function displayNoMatches(data) {
    let html = `
        <div class="no-matches">
            <p>⚠️ No matching baselines found for this service.</p>
            <p>Service: ${data.url_analyzed}</p>
            <p>Domain: ${data.domain}</p>
            <p>IP: ${data.resolved_ip}</p>
            
            ${data.is_new_service ? `
                <div class="new-service-notice">
                    <h4>New Service Detected</h4>
                    <p>This service doesn't match any known baselines.</p>
                    <p>If you provide a service name, it will be queued for baseline creation:</p>
                    <input type="text" id="newServiceName" placeholder="Enter service name...">
                    <button onclick="submitNewBaseline('${data.url_analyzed}')">
                        Submit as New Baseline
                    </button>
                </div>
            ` : ''}
        </div>
    `;
    
    document.getElementById('scanResults').innerHTML = html;
}
```

---

### 3. Download Report

```javascript
async function downloadReport(scanId, baselineId) {
    // Create a form to submit to report generator
    const form = document.createElement('form');
    form.method = 'POST';
    form.action = '/report-generator.php';
    form.target = '_blank';
    
    form.innerHTML = `
        <input type="hidden" name="action" value="generate_match_report">
        <input type="hidden" name="match_id" value="${scanId}">
        <input type="hidden" name="user_id" value="${currentUserId}">
        <input type="hidden" name="include_private" value="false">
    `;
    
    document.body.appendChild(form);
    form.submit();
    document.body.removeChild(form);
}

// Or using fetch with blob
async function downloadReportFetch(matchId) {
    const response = await fetch('/report-generator.php', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            action: 'generate_match_report',
            match_id: matchId,
            user_id: currentUserId,
            include_private: false
        })
    });
    
    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `match-report-${matchId}.pdf`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
}
```

---

### 4. View Aliases

```javascript
async function viewAliases(baselineId) {
    const result = await callAPI('admin-dashboard.php', 'get_aliases', {
        baseline_id: baselineId
    });
    
    if (!result.success) {
        alert('Error loading aliases: ' + result.error);
        return;
    }
    
    const aliases = result.data.aliases;
    
    let html = `
        <div class="aliases-modal">
            <h3>Known Aliases</h3>
            <table>
                <thead>
                    <tr>
                        <th>Alias Name</th>
                        <th>Match %</th>
                        <th>Type</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
    `;
    
    aliases.forEach(alias => {
        html += `
            <tr>
                <td>${alias.alias_name}</td>
                <td>${alias.match_percentage}%</td>
                <td>${alias.alias_type}</td>
                <td><span class="status ${alias.status}">${alias.status}</span></td>
            </tr>
        `;
    });
    
    html += `
                </tbody>
            </table>
            <p>Total: ${aliases.length} aliases</p>
            <button onclick="closeAliasesModal()">Close</button>
        </div>
    `;
    
    showModal(html);
}
```

---

## 👨‍💼 Admin Flows

### 1. Admin Dashboard

```javascript
async function loadAdminDashboard() {
    if (currentUserRole !== 'admin' && currentUserRole !== 'super_admin') {
        alert('Admin access required');
        return;
    }
    
    const stats = await callAPI('admin-dashboard.php', 'get_stats');
    displayAdminStats(stats.data);
    
    const pending = await callAPI('admin-dashboard.php', 'get_pending');
    displayPendingApprovals(pending.data.approvals);
}

function displayAdminStats(stats) {
    const html = `
        <div class="admin-stats">
            <div class="stat-box">
                <h4>Total Baselines</h4>
                <p class="stat-value">${stats.baselines.total}</p>
                <small>Approved: ${stats.baselines.approved}</small>
            </div>
            
            <div class="stat-box">
                <h4>Total Matches</h4>
                <p class="stat-value">${stats.matches.total}</p>
                <small>Avg: ${Math.round(stats.matches.avg_match_percentage)}%</small>
            </div>
            
            <div class="stat-box">
                <h4>Pending Approvals</h4>
                <p class="stat-value">${stats.pending.total}</p>
                <small>Baselines: ${stats.pending.pending_baselines}</small>
            </div>
        </div>
    `;
    
    document.getElementById('adminStats').innerHTML = html;
}

function displayPendingApprovals(approvals) {
    let html = '<table class="pending-table"><thead><tr>';
    html += '<th>Type</th><th>Service</th><th>Submitted</th><th>Actions</th></tr></thead><tbody>';
    
    approvals.forEach(approval => {
        const data = approval.submission_data || {};
        const serviceName = data.service_name || 'Unknown';
        
        html += `
            <tr>
                <td>${approval.submission_type}</td>
                <td>${serviceName}</td>
                <td>${new Date(approval.submitted_at).toLocaleDateString()}</td>
                <td>
                    <button onclick="approveSubmission(${approval.id})">✓ Approve</button>
                    <button onclick="rejectSubmission(${approval.id})">✗ Reject</button>
                </td>
            </tr>
        `;
    });
    
    html += '</tbody></table>';
    document.getElementById('pendingApprovals').innerHTML = html;
}

async function approveSubmission(approvalId, notes = '') {
    const result = await callAPI('admin-dashboard.php', 'approve', {
        approval_id: approvalId,
        notes: notes
    });
    
    if (result.success) {
        alert('Submission approved!');
        loadAdminDashboard(); // Refresh
    } else {
        alert('Error: ' + result.error);
    }
}

async function rejectSubmission(approvalId) {
    const reason = prompt('Enter rejection reason:');
    if (!reason) return;
    
    const result = await callAPI('admin-dashboard.php', 'reject', {
        approval_id: approvalId,
        reason: reason
    });
    
    if (result.success) {
        alert('Submission rejected');
        loadAdminDashboard();
    }
}
```

---

### 2. Manage Private Services

```javascript
async function createPrivateGroup() {
    const groupName = prompt('Enter group name:');
    if (!groupName) return;
    
    const result = await callAPI('private-services.php', 'create_group', {
        group_name: groupName,
        description: 'Private service group'
    });
    
    if (result.success) {
        alert(`Private group created!\nKey: ${result.data.group_key}`);
        console.log('Save this key for encryption/decryption');
    }
}

async function markServicePrivate(baselineId) {
    const groupId = prompt('Enter private group ID:');
    if (!groupId) return;
    
    const result = await callAPI('private-services.php', 'mark_private', {
        baseline_id: baselineId,
        private_group_id: groupId
    });
    
    if (result.success) {
        alert('Service marked as private!');
    }
}

async function grantUserAccess(groupId) {
    const userId = prompt('Enter user ID to grant access:');
    const accessLevel = prompt('Access level (view/moderate/admin):');
    
    if (!userId || !accessLevel) return;
    
    const result = await callAPI('private-services.php', 'grant_access', {
        group_id: groupId,
        target_user_id: userId,
        access_level: accessLevel
    });
    
    if (result.success) {
        alert('Access granted!');
    }
}
```

---

## 🛢️ Data Collection

### Enhanced Metadata Form

```html
<form id="serviceMetadataForm">
    <fieldset>
        <legend>Service Metadata (Optional)</legend>
        
        <label>
            Resolution:
            <select name="resolution">
                <option value="">Auto-detect</option>
                <option value="SD">SD (480p)</option>
                <option value="720p">HD (720p)</option>
                <option value="1080p">Full HD (1080p)</option>
                <option value="2K">2K (1440p)</option>
                <option value="4K">4K (2160p)</option>
                <option value="8K">8K (4320p)</option>
            </select>
        </label>
        
        <label>
            Bitrate (kbps):
            <input type="number" name="bitrate" placeholder="e.g., 5000">
        </label>
        
        <label>
            Country:
            <select name="country">
                <option value="">Select...</option>
                <option value="US">United States</option>
                <option value="UK">United Kingdom</option>
                <option value="FR">France</option>
                <option value="DE">Germany</option>
                <option value="IT">Italy</option>
                <!-- Add more countries -->
            </select>
        </label>
        
        <label>
            <input type="checkbox" name="has_epg">
            Has EPG (Electronic Program Guide)
        </label>
        
        <label>
            <input type="checkbox" name="has_catchup">
            Has Catchup / Replay
        </label>
        
        <label>
            Catchup Days (if applicable):
            <input type="number" name="catchup_days" min="0" max="365">
        </label>
    </fieldset>
</form>

<script>
function getFormMetadata() {
    const form = document.getElementById('serviceMetadataForm');
    const formData = new FormData(form);
    
    return {
        resolution: formData.get('resolution'),
        bitrate: formData.get('bitrate'),
        country: formData.get('country'),
        has_epg: formData.get('has_epg') ? 1 : 0,
        has_catchup: formData.get('has_catchup') ? 1 : 0,
        catchup_days: formData.get('catchup_days')
    };
}
</script>
```

---

## 🎨 CSS Styling

```css
/* Match Result Badges */
.match-score {
    font-size: 32px;
    font-weight: bold;
    padding: 10px 20px;
    border-radius: 8px;
    display: inline-block;
}

.match-score.excellent {
    background: #d4edda;
    color: #155724;
}

.match-score.good {
    background: #cfe2ff;
    color: #084298;
}

.match-score.fair {
    background: #fff3cd;
    color: #664d03;
}

/* Disclaimer Modal */
.modal {
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: rgba(0,0,0,0.7);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 1000;
}

.modal-content {
    background: white;
    padding: 30px;
    border-radius: 8px;
    max-width: 600px;
    max-height: 80vh;
    overflow-y: auto;
}

.disclaimer-section {
    margin-bottom: 20px;
    padding: 15px;
    background: #f5f5f5;
    border-radius: 4px;
}

/* Admin Dashboard */
.admin-stats {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 15px;
    margin-bottom: 30px;
}

.stat-box {
    background: #f9f9f9;
    padding: 20px;
    border-radius: 8px;
    border-left: 4px solid #00d4ff;
}

.stat-value {
    font-size: 32px;
    font-weight: bold;
    color: #00d4ff;
    margin: 10px 0;
}

.pending-table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 20px;
}

.pending-table th,
.pending-table td {
    padding: 12px;
    text-align: left;
    border-bottom: 1px solid #ddd;
}

.pending-table th {
    background: #f5f5f5;
    font-weight: bold;
}
```

---

## ✅ Complete Example

```javascript
// Full workflow example
async function completeUserWorkflow() {
    // Step 1: Check disclaimers
    await showDisclaimerFlow();
    
    // Step 2: Show scan form
    displayScanForm();
    
    // Step 3: User scans
    document.getElementById('scanButton').onclick = scanIPTVService;
    
    // Step 4: Results displayed
    // scanIPTVService() -> displayScanResults() -> user can download report or view aliases
}

async function completeAdminWorkflow() {
    // Load dashboard
    await loadAdminDashboard();
    
    // Set up auto-refresh every 60 seconds
    setInterval(loadAdminDashboard, 60000);
    
    // Handle approval/rejection
    document.addEventListener('click', (e) => {
        if (e.target.textContent.includes('Approve')) {
            const approvalId = e.target.dataset.approvalId;
            approveSubmission(approvalId);
        }
    });
}
```

---

## 🔗 API Reference Quick Links

```javascript
// Baseline Management
callAPI('baseline-manager.php', 'create', {...})
callAPI('baseline-manager.php', 'list', {limit, offset})
callAPI('baseline-manager.php', 'update', {baseline_id, ...})
callAPI('baseline-manager.php', 'archive', {baseline_id})

// Service Matching
callAPI('service-matcher.php', 'scan_and_match', {...})

// Private Services
callAPI('private-services.php', 'create_group', {...})
callAPI('private-services.php', 'mark_private', {...})
callAPI('private-services.php', 'grant_access', {...})
callAPI('private-services.php', 'check_private_match', {...})

// Versioning
callAPI('service-versioning.php', 'record_update', {...})
callAPI('service-versioning.php', 'get_history', {baseline_id})
callAPI('service-versioning.php', 'normalize', {baseline_id})
callAPI('service-versioning.php', 'auto_update', {baseline_id})

// Reports
callAPI('report-generator.php', 'generate_match_report', {match_id})

// Admin
callAPI('admin-dashboard.php', 'get_stats', {})
callAPI('admin-dashboard.php', 'get_pending', {type, limit, offset})
callAPI('admin-dashboard.php', 'approve', {approval_id, notes})
callAPI('admin-dashboard.php', 'get_audit_log', {limit, offset})

// Disclaimers
callAPI('disclaimers.php', 'get_disclaimers', {})
callAPI('disclaimers.php', 'acknowledge', {...})
callAPI('disclaimers.php', 'check_status', {})
```

---

This should provide everything you need to integrate the baseline system into your frontend!

