<?php
error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);
header('Content-Type: application/json');

require_once __DIR__ . '/config.php';

/**
 * Baseline Management System
 * Allows staff to create and manage baseline IPTV services
 */
class BaselineManager {
    private $db;
    private $user_id;
    private $user_role;
    
    public function __construct() {
        $this->connectDatabase();
        $this->validateStaffAccess();
    }
    
    private function connectDatabase() {
        $this->db = new mysqli(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME);
        if ($this->db->connect_error) {
            $this->respondError("Database connection failed", 500);
        }
        $this->db->set_charset("utf8mb4");
    }
    
    private function validateStaffAccess() {
        // TODO: Implement session validation
        // For now, accepting staff parameter or API key
        $this->user_id = $_POST['user_id'] ?? $_GET['user_id'] ?? null;
        $this->user_role = $this->getUserRole($this->user_id);
        
        if (!$this->user_id || !in_array($this->user_role, ['staff', 'admin', 'super_admin'])) {
            $this->respondError("Unauthorized access. Staff/Admin role required.", 403);
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
     * Create a new baseline service from Xtream credentials
     */
    public function createBaseline() {
        try {
            $input = json_decode(file_get_contents('php://input'), true);
            
            // Validate required fields
            $required = ['service_name', 'baseline_url', 'xtream_username', 'xtream_password'];
            foreach ($required as $field) {
                if (empty($input[$field])) {
                    return $this->respondError("Missing required field: $field", 400);
                }
            }
            
            $service_name = $input['service_name'];
            $baseline_url = $input['baseline_url'];
            $description = $input['description'] ?? '';
            $is_private = $input['is_private'] ?? 0;
            $private_group_id = $input['private_group_id'] ?? null;
            
            // Hash credentials for security
            $credentials_hash = $this->hashCredentials(
                $input['xtream_username'],
                $input['xtream_password']
            );
            
            // Extract domain and IP
            $domain = $this->extractDomain($baseline_url);
            if (!$domain) {
                return $this->respondError("Invalid baseline URL", 400);
            }
            
            // Resolve IP
            $ip = $this->resolveIP($domain);
            if (!$ip) {
                return $this->respondError("Failed to resolve IP address", 400);
            }
            
            // Check for duplicate baseline
            if ($this->baselineExists($service_name)) {
                return $this->respondError("Baseline service already exists with this name", 409);
            }
            
            // Fetch service info from Xtream API
            $serviceInfo = $this->fetchXtreamServiceInfo($baseline_url, $input['xtream_username'], $input['xtream_password']);
            if (!$serviceInfo) {
                return $this->respondError("Failed to fetch service information from Xtream API", 400);
            }
            
            // Prepare baseline data
            $baseline_data = [
                'service_name' => $service_name,
                'description' => $description,
                'baseline_domain' => $domain,
                'baseline_ip' => $ip,
                'baseline_url' => $baseline_url,
                'channel_count' => $serviceInfo['channels'] ?? 0,
                'vod_count' => $serviceInfo['vods'] ?? 0,
                'series_count' => $serviceInfo['series'] ?? 0,
                'credentials_hash' => $credentials_hash,
                'is_private' => $is_private,
                'private_group_id' => $is_private ? $private_group_id : null,
                'status' => 'pending', // Requires admin approval
                'created_by_user_id' => $this->user_id
            ];
            
            // Insert baseline
            $baseline_id = $this->insertBaseline($baseline_data);
            if (!$baseline_id) {
                return $this->respondError("Failed to create baseline", 500);
            }
            
            // Add metadata
            $this->addServiceMetadata($baseline_id, $input['metadata'] ?? [], $serviceInfo);
            
            // Create audit log entry
            $this->logAuditAction('baseline_created', "Created baseline: $service_name", $baseline_id, null, null);
            
            // Add to approval queue if requires approval
            $this->addToApprovalQueue('baseline', $baseline_id, $baseline_data);
            
            return $this->respondSuccess([
                'baseline_id' => $baseline_id,
                'service_name' => $service_name,
                'status' => 'pending',
                'message' => 'Baseline created successfully. Awaiting admin approval.',
                'service_info' => $serviceInfo
            ]);
            
        } catch (Exception $e) {
            return $this->respondError("Error creating baseline: " . $e->getMessage(), 500);
        }
    }
    
    /**
     * Update baseline service information
     */
    public function updateBaseline() {
        try {
            $input = json_decode(file_get_contents('php://input'), true);
            
            if (empty($input['baseline_id'])) {
                return $this->respondError("baseline_id is required", 400);
            }
            
            $baseline_id = $input['baseline_id'];
            
            // Check if baseline exists
            $baseline = $this->getBaseline($baseline_id);
            if (!$baseline) {
                return $this->respondError("Baseline not found", 404);
            }
            
            // Check permissions
            if ($this->user_role !== 'admin' && $this->user_role !== 'super_admin') {
                if ($baseline['created_by_user_id'] != $this->user_id) {
                    return $this->respondError("Unauthorized to update this baseline", 403);
                }
            }
            
            $updates = [];
            $params = [];
            $types = '';
            
            // Allow updates to these fields
            $allowed_fields = ['description', 'channel_count', 'vod_count', 'series_count', 'is_private'];
            
            foreach ($allowed_fields as $field) {
                if (isset($input[$field])) {
                    $updates[] = "$field = ?";
                    $params[] = $input[$field];
                    $types .= is_int($input[$field]) ? 'i' : 's';
                }
            }
            
            if (empty($updates)) {
                return $this->respondError("No fields to update", 400);
            }
            
            $types .= 'i'; // For baseline_id
            $params[] = $baseline_id;
            
            $query = "UPDATE baseline_services SET " . implode(", ", $updates) . " WHERE id = ?";
            $stmt = $this->db->prepare($query);
            
            if (!$stmt) {
                return $this->respondError("Database error", 500);
            }
            
            $stmt->bind_param($types, ...$params);
            if (!$stmt->execute()) {
                return $this->respondError("Failed to update baseline", 500);
            }
            $stmt->close();
            
            // Log audit
            $this->logAuditAction('baseline_updated', "Updated baseline ID: $baseline_id", $baseline_id, null, $baseline);
            
            return $this->respondSuccess([
                'baseline_id' => $baseline_id,
                'message' => 'Baseline updated successfully'
            ]);
            
        } catch (Exception $e) {
            return $this->respondError("Error updating baseline: " . $e->getMessage(), 500);
        }
    }
    
    /**
     * Get baseline details
     */
    public function getBaseline($baseline_id) {
        $stmt = $this->db->prepare("
            SELECT b.*, m.max_resolution, m.average_bitrate, m.has_epg
            FROM baseline_services b
            LEFT JOIN service_metadata m ON b.id = m.baseline_id
            WHERE b.id = ?
        ");
        
        if (!$stmt) return null;
        
        $stmt->bind_param("i", $baseline_id);
        $stmt->execute();
        $result = $stmt->get_result();
        $baseline = $result->fetch_assoc();
        $stmt->close();
        
        return $baseline;
    }
    
    /**
     * List all baselines (with filtering)
     */
    public function listBaselines() {
        try {
            $input = json_decode(file_get_contents('php://input'), true) ?? [];
            $filter_status = $input['status'] ?? null;
            $filter_private = $input['private_only'] ?? false;
            $sort_by = $input['sort_by'] ?? 'created_at';
            $sort_order = $input['sort_order'] ?? 'DESC';
            $limit = min($input['limit'] ?? 50, 500);
            $offset = $input['offset'] ?? 0;
            
            $query = "SELECT * FROM baseline_services WHERE 1=1";
            $params = [];
            $types = '';
            
            if ($filter_status) {
                $query .= " AND status = ?";
                $params[] = $filter_status;
                $types .= 's';
            }
            
            if ($filter_private) {
                $query .= " AND is_private = 1";
            }
            
            // Only super_admin can see all baselines; others see only approved ones
            if ($this->user_role !== 'super_admin' && $this->user_role !== 'admin') {
                $query .= " AND status = 'approved'";
            }
            
            $query .= " ORDER BY $sort_by $sort_order LIMIT ? OFFSET ?";
            $params[] = $limit;
            $params[] = $offset;
            $types .= 'ii';
            
            $stmt = $this->db->prepare($query);
            if (!$stmt) {
                return $this->respondError("Database error", 500);
            }
            
            if (!empty($params)) {
                $stmt->bind_param($types, ...$params);
            }
            
            $stmt->execute();
            $result = $stmt->get_result();
            $baselines = [];
            
            while ($row = $result->fetch_assoc()) {
                // Hide sensitive data for non-admin users
                if ($this->user_role === 'user') {
                    unset($row['credentials_hash']);
                }
                $baselines[] = $row;
            }
            $stmt->close();
            
            // Get total count
            $count_query = "SELECT COUNT(*) as total FROM baseline_services WHERE 1=1";
            if ($filter_status) $count_query .= " AND status = '$filter_status'";
            if ($filter_private) $count_query .= " AND is_private = 1";
            
            $count_result = $this->db->query($count_query);
            $total = $count_result->fetch_assoc()['total'];
            
            return $this->respondSuccess([
                'baselines' => $baselines,
                'total' => $total,
                'limit' => $limit,
                'offset' => $offset
            ]);
            
        } catch (Exception $e) {
            return $this->respondError("Error listing baselines: " . $e->getMessage(), 500);
        }
    }
    
    /**
     * Archive a baseline (soft delete)
     */
    public function archiveBaseline() {
        try {
            $input = json_decode(file_get_contents('php://input'), true);
            
            if (empty($input['baseline_id'])) {
                return $this->respondError("baseline_id is required", 400);
            }
            
            $baseline_id = $input['baseline_id'];
            
            // Only admins can archive
            if (!in_array($this->user_role, ['admin', 'super_admin'])) {
                return $this->respondError("Unauthorized", 403);
            }
            
            $stmt = $this->db->prepare("UPDATE baseline_services SET status = 'archived' WHERE id = ?");
            if (!$stmt) {
                return $this->respondError("Database error", 500);
            }
            
            $stmt->bind_param("i", $baseline_id);
            if (!$stmt->execute()) {
                return $this->respondError("Failed to archive baseline", 500);
            }
            $stmt->close();
            
            $this->logAuditAction('baseline_archived', "Archived baseline ID: $baseline_id", $baseline_id, null, null);
            
            return $this->respondSuccess(['message' => 'Baseline archived successfully']);
            
        } catch (Exception $e) {
            return $this->respondError("Error archiving baseline: " . $e->getMessage(), 500);
        }
    }
    
    // ====== Helper Methods ======
    
    private function hashCredentials($username, $password) {
        // Hash credentials for storage (never store plaintext)
        return hash('sha256', $username . ':' . $password . ':' . SECRET_KEY);
    }
    
    private function extractDomain($url) {
        $url = str_replace(['http://', 'https://'], '', $url);
        $parts = parse_url('http://' . $url);
        return $parts['host'] ?? null;
    }
    
    private function resolveIP($domain) {
        // Use DNS lookup (PHP built-in)
        $ip = gethostbyname($domain);
        return ($ip !== $domain) ? $ip : false;
    }
    
    private function baselineExists($service_name) {
        $stmt = $this->db->prepare("SELECT id FROM baseline_services WHERE service_name = ?");
        if (!$stmt) return false;
        
        $stmt->bind_param("s", $service_name);
        $stmt->execute();
        $result = $stmt->get_result();
        $exists = $result->num_rows > 0;
        $stmt->close();
        
        return $exists;
    }
    
    private function fetchXtreamServiceInfo($url, $username, $password) {
        // Connect to Xtream Codes API to get service info
        $api_url = rtrim($url, '/') . '/player_api.php';
        $params = [
            'username' => $username,
            'password' => $password,
            'action' => 'get_live_categories'
        ];
        
        $curl_url = $api_url . '?' . http_build_query($params);
        
        $curl = curl_init();
        curl_setopt($curl, CURLOPT_URL, $curl_url);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_TIMEOUT, 10);
        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, false);
        
        $response = curl_exec($curl);
        curl_close($curl);
        
        if (!$response) {
            return null;
        }
        
        $categories = json_decode($response, true);
        $channel_count = is_array($categories) ? count($categories) : 0;
        
        // Get VOD count
        $vod_params = $params;
        $vod_params['action'] = 'get_vod_categories';
        $vod_curl_url = $api_url . '?' . http_build_query($vod_params);
        
        $curl = curl_init();
        curl_setopt($curl, CURLOPT_URL, $vod_curl_url);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_TIMEOUT, 10);
        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, false);
        
        $vod_response = curl_exec($curl);
        curl_close($curl);
        
        $vod_categories = json_decode($vod_response, true);
        $vod_count = is_array($vod_categories) ? count($vod_categories) : 0;
        
        return [
            'channels' => $channel_count,
            'vods' => $vod_count,
            'series' => 0 // Would need additional API call
        ];
    }
    
    private function insertBaseline($data) {
        $stmt = $this->db->prepare("
            INSERT INTO baseline_services 
            (service_name, description, baseline_domain, baseline_ip, baseline_url, 
             channel_count, vod_count, series_count, credentials_hash, is_private, 
             private_group_id, status, created_by_user_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ");
        
        if (!$stmt) return null;
        
        $stmt->bind_param(
            "sssssiiisiii",
            $data['service_name'],
            $data['description'],
            $data['baseline_domain'],
            $data['baseline_ip'],
            $data['baseline_url'],
            $data['channel_count'],
            $data['vod_count'],
            $data['series_count'],
            $data['credentials_hash'],
            $data['is_private'],
            $data['private_group_id'],
            $data['status'],
            $data['created_by_user_id']
        );
        
        if (!$stmt->execute()) {
            return null;
        }
        
        $baseline_id = $this->db->insert_id;
        $stmt->close();
        
        return $baseline_id;
    }
    
    private function addServiceMetadata($baseline_id, $metadata, $serviceInfo) {
        $stmt = $this->db->prepare("
            INSERT INTO service_metadata 
            (baseline_id, max_resolution, average_bitrate, has_epg, 
             primary_country, language_codes, content_type)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ");
        
        if (!$stmt) return;
        
        $resolution = $metadata['max_resolution'] ?? null;
        $bitrate = $metadata['average_bitrate'] ?? null;
        $has_epg = $metadata['has_epg'] ?? 0;
        $country = $metadata['primary_country'] ?? null;
        $languages = $metadata['language_codes'] ? json_encode($metadata['language_codes']) : null;
        $content_type = $metadata['content_type'] ?? 'mixed';
        
        $stmt->bind_param(
            "isssisss",
            $baseline_id,
            $resolution,
            $bitrate,
            $has_epg,
            $country,
            $languages,
            $content_type
        );
        
        $stmt->execute();
        $stmt->close();
    }
    
    private function addToApprovalQueue($type, $baseline_id, $data) {
        $stmt = $this->db->prepare("
            INSERT INTO admin_approval_queue 
            (submission_type, baseline_id, submitted_by_user_id, submission_data, status)
            VALUES (?, ?, ?, ?, 'pending')
        ");
        
        if (!$stmt) return;
        
        $json_data = json_encode($data);
        $stmt->bind_param("siss", $type, $baseline_id, $this->user_id, $json_data);
        $stmt->execute();
        $stmt->close();
    }
    
    private function logAuditAction($action_type, $description, $baseline_id, $alias_id, $old_values) {
        $stmt = $this->db->prepare("
            INSERT INTO audit_log 
            (admin_user_id, action_type, action_description, related_baseline_id, 
             related_alias_id, old_values, admin_ip)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ");
        
        if (!$stmt) return;
        
        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
        $old_json = $old_values ? json_encode($old_values) : null;
        
        $stmt->bind_param("issiiss", $this->user_id, $action_type, $description, $baseline_id, $alias_id, $old_json, $ip);
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

// Define SECRET_KEY if not in config
if (!defined('SECRET_KEY')) {
    define('SECRET_KEY', hash('sha256', 'iptv-detective-secret'));
}

// Route the request
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $manager = new BaselineManager();
    
    $action = $_POST['action'] ?? json_decode(file_get_contents('php://input'), true)['action'] ?? null;
    
    switch ($action) {
        case 'create':
            $manager->createBaseline();
            break;
        case 'update':
            $manager->updateBaseline();
            break;
        case 'archive':
            $manager->archiveBaseline();
            break;
        case 'list':
            $manager->listBaselines();
            break;
        default:
            http_response_code(400);
            echo json_encode(['success' => false, 'error' => 'Invalid action']);
    }
} elseif ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $manager = new BaselineManager();
    
    if (isset($_GET['action']) && $_GET['action'] === 'list') {
        $manager->listBaselines();
    } else {
        http_response_code(405);
        echo json_encode(['success' => false, 'error' => 'Method not allowed']);
    }
} else {
    http_response_code(405);
    echo json_encode(['success' => false, 'error' => 'Method not allowed']);
}
?>
