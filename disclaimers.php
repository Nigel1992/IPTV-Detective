<?php
error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);
header('Content-Type: application/json');

require_once __DIR__ . '/config.php';

/**
 * Disclaimers & Privacy Management
 * Handles privacy policies, disclaimers, and user acknowledgments
 */
class DisclaimersManager {
    private $db;
    private $user_id;
    private $user_ip;
    
    public function __construct() {
        $this->connectDatabase();
        $this->user_id = $_POST['user_id'] ?? $_GET['user_id'] ?? null;
        $this->user_ip = $_SERVER['REMOTE_ADDR'] ?? '';
    }
    
    private function connectDatabase() {
        $this->db = new mysqli(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME);
        if ($this->db->connect_error) {
            $this->respondError("Database connection failed", 500);
        }
        $this->db->set_charset("utf8mb4");
    }
    
    /**
     * Get all applicable disclaimers for the current session
     */
    public function getDisclaimers() {
        try {
            $disclaimers = [
                'credential_privacy' => $this->getCredentialPrivacyDisclaimer(),
                'trial_credentials' => $this->getTrialCredentialsDisclaimer(),
                'data_collection' => $this->getDataCollectionDisclaimer(),
                'service_private' => $this->getPrivateServiceDisclaimer(),
                'terms' => $this->getTermsOfService(),
                'privacy_policy' => $this->getPrivacyPolicy()
            ];
            
            // Check if user has already acknowledged these
            $user_acknowledgments = $this->getUserAcknowledgments();
            
            return $this->respondSuccess([
                'disclaimers' => $disclaimers,
                'user_acknowledgments' => $user_acknowledgments,
                'requires_acknowledgment' => !$this->hasAcknowledgedAll()
            ]);
            
        } catch (Exception $e) {
            return $this->respondError("Error retrieving disclaimers: " . $e->getMessage(), 500);
        }
    }
    
    /**
     * Record user acknowledgment of disclaimers
     */
    public function acknowledgeDisclaimers() {
        try {
            $input = json_decode(file_get_contents('php://input'), true);
            
            if (!$this->user_id) {
                return $this->respondError("User ID required to acknowledge disclaimers", 400);
            }
            
            // Validate required acknowledgments
            $required_fields = ['credential_privacy', 'trial_credentials', 'data_collection'];
            foreach ($required_fields as $field) {
                if (!isset($input[$field]) || !$input[$field]) {
                    return $this->respondError("Must acknowledge: $field", 400);
                }
            }
            
            // Check if already acknowledged
            $existing = $this->getUserAcknowledgments();
            if ($existing && isset($existing['acknowledged_at'])) {
                // Already acknowledged, update with new acknowledgment
                $stmt = $this->db->prepare("
                    UPDATE privacy_acknowledgments 
                    SET acknowledged_credential_privacy = ?,
                        acknowledged_use_trial_credentials = ?,
                        acknowledged_data_collection = ?,
                        acknowledgment_at = CURRENT_TIMESTAMP,
                        acknowledgment_ip = ?,
                        acknowledgment_user_agent = ?
                    WHERE user_id = ?
                ");
            } else {
                // First acknowledgment
                $stmt = $this->db->prepare("
                    INSERT INTO privacy_acknowledgments 
                    (user_id, acknowledged_credential_privacy, 
                     acknowledged_use_trial_credentials, acknowledged_data_collection,
                     acknowledgment_ip, acknowledgment_user_agent)
                    VALUES (?, ?, ?, ?, ?, ?)
                ");
            }
            
            if (!$stmt) {
                return $this->respondError("Database error", 500);
            }
            
            $cred_privacy = $input['credential_privacy'] ? 1 : 0;
            $trial_creds = $input['trial_credentials'] ? 1 : 0;
            $data_collection = $input['data_collection'] ? 1 : 0;
            $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
            
            if ($existing && isset($existing['acknowledged_at'])) {
                // Update
                $stmt->bind_param("iiiissi", $cred_privacy, $trial_creds, $data_collection, 
                                 $this->user_ip, $user_agent, $this->user_id);
            } else {
                // Insert
                $stmt->bind_param("iiisss", $this->user_id, $cred_privacy, $trial_creds, 
                                 $data_collection, $this->user_ip, $user_agent);
            }
            
            if (!$stmt->execute()) {
                return $this->respondError("Failed to record acknowledgment", 500);
            }
            $stmt->close();
            
            return $this->respondSuccess([
                'acknowledged' => true,
                'timestamp' => date('Y-m-d H:i:s'),
                'message' => 'Disclaimers acknowledged successfully'
            ]);
            
        } catch (Exception $e) {
            return $this->respondError("Error acknowledging disclaimers: " . $e->getMessage(), 500);
        }
    }
    
    /**
     * Check if user needs to see disclaimers
     */
    public function checkDisclaimerStatus() {
        try {
            $has_acknowledged = $this->hasAcknowledgedAll();
            
            if ($has_acknowledged) {
                return $this->respondSuccess([
                    'acknowledged' => true,
                    'message' => 'User has acknowledged all required disclaimers'
                ]);
            } else {
                return $this->respondSuccess([
                    'acknowledged' => false,
                    'message' => 'User must acknowledge disclaimers before proceeding',
                    'required_disclaimers' => [
                        'credential_privacy',
                        'trial_credentials',
                        'data_collection'
                    ]
                ]);
            }
            
        } catch (Exception $e) {
            return $this->respondError("Error checking disclaimer status: " . $e->getMessage(), 500);
        }
    }
    
    /**
     * Get detailed privacy policy
     */
    public function getPrivacyPolicy() {
        return [
            'title' => 'Privacy Policy',
            'content' => <<<HTML
# IPTV Detective Privacy Policy

## Data Collection
We collect the following information:
- IPTV service URLs and credentials (hashed for security)
- Service metadata (channel count, resolution, bitrate)
- IP addresses and geographic information from your scans
- Technical information about your device and browser

## Data Usage
Your data is used to:
- Identify and track IPTV service providers
- Build a database of known services and their aliases
- Detect reseller relationships and service chains
- Improve our forensic analysis algorithms

## Data Security
- Credentials are hashed using SHA-256 and not stored in plaintext
- Private services are encrypted using AES-256
- All data is transmitted over HTTPS
- Access logs are maintained for audit purposes

## Data Sharing
- We do not sell your personal data
- Service provider information may be shared with law enforcement when legally required
- Aggregated, anonymized data may be shared for research purposes
- Private service details are never shared without authorization

## Your Rights
- You can request deletion of your scans at any time
- You can opt-out of data collection (limited functionality)
- You have the right to access all data we hold about you

## Contact
For privacy concerns, contact: support@iptv-detective.local
HTML,
            'version' => '1.0',
            'last_updated' => '2026-02-03'
        ];
    }
    
    /**
     * Get terms of service
     */
    public function getTermsOfService() {
        return [
            'title' => 'Terms of Service',
            'content' => <<<HTML
# Terms of Service

## Accept ance
By using IPTV Detective, you agree to these terms and our privacy policy.

## Prohibited Uses
You may NOT use this service to:
- Bypass copy protection or DRM systems
- Access unauthorized IPTV services
- Violate applicable laws or regulations
- Infringe on intellectual property rights
- Engage in illegal activities

## Use of Trial Credentials Only
Users must use ONLY trial/test credentials when scanning services. 
Do not provide credentials to commercial or premium services.
The operator is not responsible for unauthorized access or credential misuse.

## No Warranty
This service is provided "as-is" without warranty or guarantee.
We are not responsible for:
- Data loss or corruption
- Service interruptions
- Inaccurate forensic results
- Consequences of using this service

## Limitation of Liability
In no event shall IPTV Detective be liable for any damages arising from use of this service.

## Modification of Terms
We reserve the right to modify these terms at any time.
Continued use constitutes acceptance of modified terms.
HTML,
            'version' => '1.0',
            'last_updated' => '2026-02-03'
        ];
    }
    
    /**
     * Get credential privacy disclaimer
     */
    private function getCredentialPrivacyDisclaimer() {
        return [
            'title' => 'Credential Privacy Disclaimer',
            'icon' => 'lock',
            'severity' => 'high',
            'content' => <<<HTML
## Your Credentials Are Safe

🔐 **We Take Your Privacy Seriously**

### How We Handle Your Credentials:
- **Hashed Storage**: Credentials are converted to irreversible hashes (SHA-256)
- **Never Stored in Plaintext**: We cannot recover or view your credentials
- **Encrypted in Transit**: All data sent to our servers uses HTTPS encryption
- **No Third-Party Access**: Credentials are never shared with third parties
- **Audit Trail**: All access is logged and monitored

### What We Can See:
- Domain names and IP addresses
- Aggregate statistics (total channels, VODs, etc.)
- Service metadata (resolution, bitrate, country)

### What We Cannot See:
- ❌ Your username or password
- ❌ Your account details
- ❌ Your login history
- ❌ Sensitive payment information

### Your Responsibility:
- ✅ Use ONLY trial/test credentials
- ✅ Do not use premium or personal credentials
- ✅ Keep your credentials confidential
- ✅ Never share reports with sensitive information
HTML,
            'checkbox_text' => 'I understand that only trial credentials should be used and my credentials are hashed for security'
        ];
    }
    
    /**
     * Get trial credentials disclaimer
     */
    private function getTrialCredentialsDisclaimer() {
        return [
            'title' => 'Trial Credentials Required',
            'icon' => 'info-circle',
            'severity' => 'high',
            'content' => <<<HTML
## Why Use Trial Credentials?

### Important Security Notice
We strongly recommend using **ONLY trial or test credentials** when scanning IPTV services.

### Reasons:
1. **Reduced Risk**: If credentials are ever compromised, limited damage can occur
2. **Legal Protection**: Trial credentials are explicitly provided for testing
3. **Service Terms**: Most IPTV services prohibit credential sharing
4. **Your Safety**: Limits exposure of your primary account

### How to Get Trial Credentials:
- Most IPTV services offer free trials
- Many providers have test/demo credentials
- Some services offer 24-48 hour free access
- Look for "Try Now" or "Demo" options on provider websites

### What NOT To Scan:
- ❌ Your primary personal IPTV accounts
- ❌ Family members' credentials
- ❌ Purchased/premium subscriptions
- ❌ Corporate or shared accounts
- ❌ Accounts with payment information linked

### Consequences of Non-Compliance:
- Account lockout or suspension
- Service terms violations
- Potential legal issues
- Credential compromise

**When in doubt, use a trial account instead.**
HTML,
            'checkbox_text' => 'I confirm that I will only use trial or test credentials for scanning'
        ];
    }
    
    /**
     * Get data collection disclaimer
     */
    private function getDataCollectionDisclaimer() {
        return [
            'title' => 'Data Collection & Usage',
            'icon' => 'database',
            'severity' => 'medium',
            'content' => <<<HTML
## What Data We Collect

### Automatically Collected:
- **Technical Data**: Device type, browser, OS, IP address
- **Usage Data**: Pages viewed, scan history, time spent
- **Scan Results**: URLs scanned, technical analysis results
- **Session Data**: Login times, actions performed

### Optionally Provided:
- **Service Information**: Names, descriptions, metadata you provide
- **Contact Information**: Email (if provided)
- **Survey Responses**: Feedback and feature requests

### How Your Data Is Used:
1. **Service Improvement**: Understanding usage patterns
2. **Database Building**: Creating baseline service catalogs
3. **Research**: Analyzing IPTV provider infrastructure
4. **Security**: Detecting abuse and protecting the system
5. **Analytics**: Aggregated statistics for development

### Data Retention:
- **Scan Results**: Stored indefinitely unless deleted
- **Session Data**: Retained for 90 days
- **Logs**: Kept for 1 year for security audit
- **User Profiles**: Deleted upon request

### Your Control:
- You can download all your data
- You can delete your scans at any time
- You can disable analytics collection
- You can request complete deletion
HTML,
            'checkbox_text' => 'I acknowledge that my usage data will be collected to improve the service'
        ];
    }
    
    /**
     * Get private service disclaimer
     */
    private function getPrivateServiceDisclaimer() {
        return [
            'title' => 'Private Services Policy',
            'icon' => 'shield-lock',
            'severity' => 'medium',
            'content' => <<<HTML
## Private and Confidential Services

### What Are Private Services?
Some IPTV services are marked as "private" because the service owner has requested strict confidentiality.

### Private Service Protections:
- 🔒 **Encrypted Names**: Service names are encrypted
- 🔐 **Reseller Chain Hidden**: Upstream providers are not disclosed
- 🚫 **Limited Access**: Only authorized admins can view details
- 🛡️ **No Public Disclosure**: Details never appear in public reports
- 📋 **Audit Trail**: All access is logged

### What You'll See:
If you match a private service, your report will show:
- ✅ "This matches a private service"
- ✅ Match confidence percentage
- ✅ Generic channel/content information
- ❌ Service name (shown as [PRIVATE SERVICE])
- ❌ Specific provider or reseller information
- ❌ Detailed reseller chains

### Why This Protection?
Private services maintain confidentiality for:
- Security reasons
- Competitive advantage
- Legal protection
- Service provider privacy

### Respecting Privacy
Users of private services should understand that:
- Share match reports carefully
- Do not attempt to bypass restrictions
- Respect service owner requests
- Comply with private group access controls
HTML
        ];
    }
    
    // ====== Helper Methods ======
    
    private function getUserAcknowledgments() {
        if (!$this->user_id) return null;
        
        $stmt = $this->db->prepare("
            SELECT * FROM privacy_acknowledgments 
            WHERE user_id = ?
            ORDER BY acknowledged_at DESC
            LIMIT 1
        ");
        
        if (!$stmt) return null;
        
        $stmt->bind_param("i", $this->user_id);
        $stmt->execute();
        $result = $stmt->get_result();
        $ack = $result->fetch_assoc();
        $stmt->close();
        
        return $ack;
    }
    
    private function hasAcknowledgedAll() {
        if (!$this->user_id) return false;
        
        $ack = $this->getUserAcknowledgments();
        
        if (!$ack) return false;
        
        return ($ack['acknowledged_credential_privacy'] && 
                $ack['acknowledged_use_trial_credentials'] && 
                $ack['acknowledged_data_collection']);
    }
    
    private function respondSuccess($data) {
        http_response_code(200);
        echo json_encode(['success' => true, 'data' => $data]);
        exit();
    }
    
    private function respondError($message, $code = 400) {
        http_response_code($code);
        echo json_encode(['success' => false, 'error' => $message, 'code' => $code]);
        exit();
    }
}

// Route the request
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $disclaimers = new DisclaimersManager();
    
    $action = $_POST['action'] ?? json_decode(file_get_contents('php://input'), true)['action'] ?? null;
    
    switch ($action) {
        case 'get_disclaimers':
            $disclaimers->getDisclaimers();
            break;
        case 'acknowledge':
            $disclaimers->acknowledgeDisclaimers();
            break;
        case 'check_status':
            $disclaimers->checkDisclaimerStatus();
            break;
        case 'get_privacy_policy':
            $disclaimers->getPrivacyPolicy();
            break;
        case 'get_terms':
            $disclaimers->getTermsOfService();
            break;
        default:
            http_response_code(400);
            echo json_encode(['success' => false, 'error' => 'Invalid action']);
    }
} elseif ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $disclaimers = new DisclaimersManager();
    
    $action = $_GET['action'] ?? null;
    switch ($action) {
        case 'get_disclaimers':
            $disclaimers->getDisclaimers();
            break;
        case 'check_status':
            $disclaimers->checkDisclaimerStatus();
            break;
        case 'get_privacy_policy':
            $disclaimers->getPrivacyPolicy();
            break;
        case 'get_terms':
            $disclaimers->getTermsOfService();
            break;
        default:
            http_response_code(405);
            echo json_encode(['success' => false, 'error' => 'Method not allowed']);
    }
} else {
    http_response_code(405);
    echo json_encode(['success' => false, 'error' => 'Method not allowed']);
}
?>
