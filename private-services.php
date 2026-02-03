<?php
error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);
header('Content-Type: application/json');

require_once __DIR__ . '/config.php';

/**
 * Private Services Manager
 * Handles encryption, access control, and privacy for sensitive services
 */
class PrivateServicesManager {
    private $db;
    private $user_id;
    private $user_role;
    private $encryption_enabled = true;
    private $cipher = 'AES-256-CBC';
    
    public function __construct() {
        $this->connectDatabase();
        $this->validateAdminAccess();
    }
    
    private function connectDatabase() {
        $this->db = new mysqli(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME);
        if ($this->db->connect_error) {
            $this->respondError("Database connection failed", 500);
        }
        $this->db->set_charset("utf8mb4");
    }
    
    private function validateAdminAccess() {
        $this->user_id = $_POST['user_id'] ?? $_GET['user_id'] ?? null;
        $this->user_role = $this->getUserRole($this->user_id);
        
        if (!in_array($this->user_role, ['admin', 'super_admin'])) {
            $this->respondError("Admin access required", 403);
        }
    }
    
    private function getUserRole($user_id) {
        if (!$user_id) return 'user';
        
        $stmt = $this->db->prepare("SELECT role FROM user_roles WHERE user_id = ?");
        if (!$stmt) return 'user';
        
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $result = $stmt->get_result();
        $row = $result->fetch_assoc();
        $stmt->close();
        
        return $row['role'] ?? 'user';
    }
    
    /**
     * Create a private service group (for grouping related services)
     */
    public function createPrivateGroup() {
        try {
            $input = json_decode(file_get_contents('php://input'), true);
            
            $group_name = $input['group_name'] ?? '';
            $description = $input['description'] ?? '';
            
            if (empty($group_name)) {
                return $this->respondError("group_name is required", 400);
            }
            
            // Generate encryption key
            $group_key = $this->generateEncryptionKey();
            
            $stmt = $this->db->prepare("
                INSERT INTO private_service_groups 
                (group_name, group_key, description, is_encrypted, encryption_method)
                VALUES (?, ?, ?, 1, 'AES-256')
            ");
            
            if (!$stmt) {
                return $this->respondError("Database error", 500);
            }
            
            $stmt->bind_param("sss", $group_name, $group_key, $description);
            
            if (!$stmt->execute()) {
                return $this->respondError("Failed to create private group", 500);
            }
            
            $group_id = $this->db->insert_id;
            $stmt->close();
            
            // Grant admin access to creator
            $this->grantGroupAccess($group_id, $this->user_id, 'admin', $this->user_id);
            
            return $this->respondSuccess([
                'group_id' => $group_id,
                'group_name' => $group_name,
                'group_key' => $group_key,
                'message' => 'Private group created successfully'
            ]);
            
        } catch (Exception $e) {
            return $this->respondError("Error creating private group: " . $e->getMessage(), 500);
        }
    }
    
    /**
     * Mark a baseline as private and assign to group
     */
    public function markBaselinePrivate() {
        try {
            $input = json_decode(file_get_contents('php://input'), true);
            
            if (empty($input['baseline_id']) || empty($input['private_group_id'])) {
                return $this->respondError("baseline_id and private_group_id are required", 400);
            }
            
            $baseline_id = $input['baseline_id'];
            $group_id = $input['private_group_id'];
            
            // Verify baseline exists
            $baseline = $this->getBaseline($baseline_id);
            if (!$baseline) {
                return $this->respondError("Baseline not found", 404);
            }
            
            // Verify group exists and user has admin access
            if (!$this->hasGroupAccess($group_id, $this->user_id, 'admin')) {
                return $this->respondError("Unauthorized to modify this group", 403);
            }
            
            // Encrypt sensitive data
            $encrypted_name = $this->encryptData($baseline['service_name'], $group_id);
            $encrypted_domain = $this->encryptData($baseline['baseline_domain'], $group_id);
            
            // Update baseline
            $stmt = $this->db->prepare("
                UPDATE baseline_services 
                SET is_private = 1, private_group_id = ?, service_name = ?
                WHERE id = ?
            ");
            
            if (!$stmt) {
                return $this->respondError("Database error", 500);
            }
            
            $stmt->bind_param("isi", $group_id, $encrypted_name, $baseline_id);
            
            if (!$stmt->execute()) {
                return $this->respondError("Failed to update baseline", 500);
            }
            $stmt->close();
            
            // Log audit
            $this->logAuditAction(
                'baseline_marked_private',
                "Marked baseline as private: ID {$baseline_id}",
                $baseline_id,
                null
            );
            
            return $this->respondSuccess([
                'baseline_id' => $baseline_id,
                'private_group_id' => $group_id,
                'message' => 'Baseline marked as private'
            ]);
            
        } catch (Exception $e) {
            return $this->respondError("Error marking baseline private: " . $e->getMessage(), 500);
        }
    }
    
    /**
     * Encrypt service name and reseller chain for private services
     */
    public function encryptServiceData() {
        try {
            $input = json_decode(file_get_contents('php://input'), true);
            
            if (empty($input['data']) || empty($input['group_id'])) {
                return $this->respondError("data and group_id are required", 400);
            }
            
            $group_id = $input['group_id'];
            $data = $input['data']; // Could be service name, reseller chain, etc.
            
            // Verify user has access to this group
            if (!$this->hasGroupAccess($group_id, $this->user_id, 'view')) {
                return $this->respondError("Unauthorized access to this group", 403);
            }
            
            $encrypted = $this->encryptData($data, $group_id);
            
            return $this->respondSuccess([
                'encrypted_data' => $encrypted,
                'group_id' => $group_id
            ]);
            
        } catch (Exception $e) {
            return $this->respondError("Encryption error: " . $e->getMessage(), 500);
        }
    }
    
    /**
     * Decrypt service data (only for authorized users)
     */
    public function decryptServiceData() {
        try {
            $input = json_decode(file_get_contents('php://input'), true);
            
            if (empty($input['encrypted_data']) || empty($input['group_id'])) {
                return $this->respondError("encrypted_data and group_id are required", 400);
            }
            
            $group_id = $input['group_id'];
            $encrypted_data = $input['encrypted_data'];
            
            // Verify user has access to this group
            if (!$this->hasGroupAccess($group_id, $this->user_id, 'view')) {
                return $this->respondError("Unauthorized access to this group", 403);
            }
            
            $decrypted = $this->decryptData($encrypted_data, $group_id);
            
            return $this->respondSuccess([
                'decrypted_data' => $decrypted,
                'group_id' => $group_id
            ]);
            
        } catch (Exception $e) {
            return $this->respondError("Decryption error: " . $e->getMessage(), 500);
        }
    }
    
    /**
     * Grant user access to private group
     */
    public function grantGroupAccess() {
        try {
            $input = json_decode(file_get_contents('php://input'), true);
            
            if (empty($input['group_id']) || empty($input['target_user_id']) || empty($input['access_level'])) {
                return $this->respondError("group_id, target_user_id, and access_level are required", 400);
            }
            
            $group_id = $input['group_id'];
            $target_user_id = $input['target_user_id'];
            $access_level = $input['access_level']; // 'view', 'moderate', 'admin'
            
            // Verify user is admin of this group
            if (!$this->hasGroupAccess($group_id, $this->user_id, 'admin')) {
                return $this->respondError("Unauthorized to grant access to this group", 403);
            }
            
            // Verify access level is valid
            if (!in_array($access_level, ['view', 'moderate', 'admin'])) {
                return $this->respondError("Invalid access level", 400);
            }
            
            // Insert or update access
            $stmt = $this->db->prepare("
                INSERT INTO private_service_access 
                (private_group_id, user_id, access_level, granted_by_user_id)
                VALUES (?, ?, ?, ?)
                ON DUPLICATE KEY UPDATE 
                access_level = ?, granted_by_user_id = ?, granted_at = CURRENT_TIMESTAMP
            ");
            
            if (!$stmt) {
                return $this->respondError("Database error", 500);
            }
            
            $stmt->bind_param("isisi", $group_id, $target_user_id, $access_level, $this->user_id, $access_level, $this->user_id);
            
            if (!$stmt->execute()) {
                return $this->respondError("Failed to grant access", 500);
            }
            $stmt->close();
            
            // Log audit
            $this->logAuditAction(
                'group_access_granted',
                "Granted $access_level access to group $group_id for user $target_user_id",
                null,
                null
            );
            
            return $this->respondSuccess([
                'group_id' => $group_id,
                'user_id' => $target_user_id,
                'access_level' => $access_level,
                'message' => 'Access granted successfully'
            ]);
            
        } catch (Exception $e) {
            return $this->respondError("Error granting access: " . $e->getMessage(), 500);
        }
    }
    
    /**
     * Revoke user access from group
     */
    public function revokeGroupAccess() {
        try {
            $input = json_decode(file_get_contents('php://input'), true);
            
            if (empty($input['group_id']) || empty($input['target_user_id'])) {
                return $this->respondError("group_id and target_user_id are required", 400);
            }
            
            $group_id = $input['group_id'];
            $target_user_id = $input['target_user_id'];
            
            // Verify user is admin of this group
            if (!$this->hasGroupAccess($group_id, $this->user_id, 'admin')) {
                return $this->respondError("Unauthorized to revoke access", 403);
            }
            
            $stmt = $this->db->prepare("
                DELETE FROM private_service_access 
                WHERE private_group_id = ? AND user_id = ?
            ");
            
            if (!$stmt) {
                return $this->respondError("Database error", 500);
            }
            
            $stmt->bind_param("ii", $group_id, $target_user_id);
            
            if (!$stmt->execute()) {
                return $this->respondError("Failed to revoke access", 500);
            }
            $stmt->close();
            
            // Log audit
            $this->logAuditAction(
                'group_access_revoked',
                "Revoked access to group $group_id for user $target_user_id",
                null,
                null
            );
            
            return $this->respondSuccess([
                'message' => 'Access revoked successfully'
            ]);
            
        } catch (Exception $e) {
            return $this->respondError("Error revoking access: " . $e->getMessage(), 500);
        }
    }
    
    /**
     * Check if match result should be marked as "private service"
     */
    public function checkPrivateServiceMatch() {
        try {
            $input = json_decode(file_get_contents('php://input'), true);
            
            if (empty($input['baseline_id'])) {
                return $this->respondError("baseline_id is required", 400);
            }
            
            $baseline = $this->getBaseline($input['baseline_id']);
            if (!$baseline) {
                return $this->respondError("Baseline not found", 404);
            }
            
            if (!$baseline['is_private']) {
                return $this->respondSuccess([
                    'is_private' => false,
                    'message' => 'Service is not private'
                ]);
            }
            
            // Check if current user has access to view private service details
            $user_access = $this->hasGroupAccess($baseline['private_group_id'], $this->user_id, 'view');
            
            return $this->respondSuccess([
                'is_private' => true,
                'user_has_access' => $user_access,
                'message' => $user_access ? 'Private service data accessible' : 'This matches a private service. Details restricted.',
                'display_message' => 'This matches a private service'
            ]);
            
        } catch (Exception $e) {
            return $this->respondError("Error checking private service: " . $e->getMessage(), 500);
        }
    }
    
    /**
     * Get access list for a group
     */
    public function getGroupAccessList() {
        try {
            $input = json_decode(file_get_contents('php://input'), true);
            
            if (empty($input['group_id'])) {
                return $this->respondError("group_id is required", 400);
            }
            
            $group_id = $input['group_id'];
            
            // Verify user is admin of this group
            if (!$this->hasGroupAccess($group_id, $this->user_id, 'admin')) {
                return $this->respondError("Unauthorized to view access list", 403);
            }
            
            $stmt = $this->db->prepare("
                SELECT psa.user_id, psa.access_level, psa.granted_at, 
                       psa.granted_by_user_id
                FROM private_service_access psa
                WHERE psa.private_group_id = ?
                ORDER BY psa.granted_at DESC
            ");
            
            if (!$stmt) {
                return $this->respondError("Database error", 500);
            }
            
            $stmt->bind_param("i", $group_id);
            $stmt->execute();
            $result = $stmt->get_result();
            
            $access_list = [];
            while ($row = $result->fetch_assoc()) {
                $access_list[] = $row;
            }
            $stmt->close();
            
            return $this->respondSuccess([
                'group_id' => $group_id,
                'access_list' => $access_list
            ]);
            
        } catch (Exception $e) {
            return $this->respondError("Error retrieving access list: " . $e->getMessage(), 500);
        }
    }
    
    // ====== Helper Methods ======
    
    private function hasGroupAccess($group_id, $user_id, $required_level = 'view') {
        $levels = ['view' => 1, 'moderate' => 2, 'admin' => 3];
        $required_priority = $levels[$required_level] ?? 1;
        
        $stmt = $this->db->prepare("
            SELECT access_level FROM private_service_access 
            WHERE private_group_id = ? AND user_id = ?
        ");
        
        if (!$stmt) return false;
        
        $stmt->bind_param("ii", $group_id, $user_id);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows === 0) {
            $stmt->close();
            return false;
        }
        
        $row = $result->fetch_assoc();
        $stmt->close();
        
        $user_priority = $levels[$row['access_level']] ?? 0;
        return $user_priority >= $required_priority;
    }
    
    private function getBaseline($baseline_id) {
        $stmt = $this->db->prepare("SELECT * FROM baseline_services WHERE id = ?");
        if (!$stmt) return null;
        
        $stmt->bind_param("i", $baseline_id);
        $stmt->execute();
        $result = $stmt->get_result();
        $baseline = $result->fetch_assoc();
        $stmt->close();
        
        return $baseline;
    }
    
    private function generateEncryptionKey() {
        return bin2hex(random_bytes(32));
    }
    
    private function encryptData($data, $group_id) {
        if (!$this->encryption_enabled) {
            return base64_encode($data);
        }
        
        // Get group key
        $key = $this->getGroupKey($group_id);
        if (!$key) {
            throw new Exception("Failed to retrieve encryption key");
        }
        
        $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($this->cipher));
        $encrypted = openssl_encrypt($data, $this->cipher, $key, 0, $iv);
        
        if ($encrypted === false) {
            throw new Exception("Encryption failed");
        }
        
        // Return IV + encrypted data (both base64)
        return base64_encode($iv . $encrypted);
    }
    
    private function decryptData($encrypted_data, $group_id) {
        if (!$this->encryption_enabled) {
            return base64_decode($encrypted_data);
        }
        
        // Get group key
        $key = $this->getGroupKey($group_id);
        if (!$key) {
            throw new Exception("Failed to retrieve encryption key");
        }
        
        $data = base64_decode($encrypted_data);
        $iv_length = openssl_cipher_iv_length($this->cipher);
        $iv = substr($data, 0, $iv_length);
        $encrypted = substr($data, $iv_length);
        
        $decrypted = openssl_decrypt($encrypted, $this->cipher, $key, 0, $iv);
        
        if ($decrypted === false) {
            throw new Exception("Decryption failed");
        }
        
        return $decrypted;
    }
    
    private function getGroupKey($group_id) {
        $stmt = $this->db->prepare("SELECT group_key FROM private_service_groups WHERE id = ?");
        if (!$stmt) return null;
        
        $stmt->bind_param("i", $group_id);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows === 0) {
            $stmt->close();
            return null;
        }
        
        $row = $result->fetch_assoc();
        $stmt->close();
        
        return hex2bin($row['group_key']);
    }
    
    private function logAuditAction($action_type, $description, $baseline_id, $alias_id) {
        $stmt = $this->db->prepare("
            INSERT INTO audit_log 
            (admin_user_id, action_type, action_description, related_baseline_id, 
             related_alias_id, admin_ip)
            VALUES (?, ?, ?, ?, ?, ?)
        ");
        
        if (!$stmt) return;
        
        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
        
        $stmt->bind_param("issiis", $this->user_id, $action_type, $description, $baseline_id, $alias_id, $ip);
        $stmt->execute();
        $stmt->close();
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
    $private_manager = new PrivateServicesManager();
    
    $action = $_POST['action'] ?? json_decode(file_get_contents('php://input'), true)['action'] ?? null;
    
    switch ($action) {
        case 'create_group':
            $private_manager->createPrivateGroup();
            break;
        case 'mark_private':
            $private_manager->markBaselinePrivate();
            break;
        case 'encrypt':
            $private_manager->encryptServiceData();
            break;
        case 'decrypt':
            $private_manager->decryptServiceData();
            break;
        case 'grant_access':
            $private_manager->grantGroupAccess();
            break;
        case 'revoke_access':
            $private_manager->revokeGroupAccess();
            break;
        case 'check_private_match':
            $private_manager->checkPrivateServiceMatch();
            break;
        case 'get_access_list':
            $private_manager->getGroupAccessList();
            break;
        default:
            http_response_code(400);
            echo json_encode(['success' => false, 'error' => 'Invalid action']);
    }
} else {
    http_response_code(405);
    echo json_encode(['success' => false, 'error' => 'Method not allowed']);
}
?>
