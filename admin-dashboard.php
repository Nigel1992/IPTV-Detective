<?php
error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);
header('Content-Type: application/json');

require_once __DIR__ . '/config.php';

/**
 * Admin Dashboard API
 * Provides endpoints for admin panel functionality
 */
class AdminDashboard {
    private $db;
    private $user_id;
    private $user_role;
    
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
     * Get dashboard statistics
     */
    public function getDashboardStats() {
        try {
            $stats = [
                'baselines' => $this->getBaselineStats(),
                'matches' => $this->getMatchStats(),
                'pending' => $this->getPendingStats(),
                'recent_activity' => $this->getRecentActivity()
            ];
            
            return $this->respondSuccess($stats);
            
        } catch (Exception $e) {
            return $this->respondError("Error retrieving stats: " . $e->getMessage(), 500);
        }
    }
    
    /**
     * Get pending approvals
     */
    public function getPendingApprovals() {
        try {
            $input = json_decode(file_get_contents('php://input'), true);
            $filter_type = $input['type'] ?? null;
            $limit = min($input['limit'] ?? 50, 500);
            $offset = $input['offset'] ?? 0;
            
            $query = "SELECT * FROM admin_approval_queue WHERE status = 'pending'";
            $params = [];
            $types = '';
            
            if ($filter_type) {
                $query .= " AND submission_type = ?";
                $params[] = $filter_type;
                $types .= 's';
            }
            
            $query .= " ORDER BY submitted_at DESC LIMIT ? OFFSET ?";
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
            
            $approvals = [];
            while ($row = $result->fetch_assoc()) {
                // Decode JSON submission data
                $row['submission_data'] = json_decode($row['submission_data'], true);
                $approvals[] = $row;
            }
            $stmt->close();
            
            // Get count
            $count_query = "SELECT COUNT(*) as total FROM admin_approval_queue WHERE status = 'pending'";
            if ($filter_type) {
                $count_query .= " AND submission_type = '$filter_type'";
            }
            
            $count_result = $this->db->query($count_query);
            $total = $count_result->fetch_assoc()['total'];
            
            return $this->respondSuccess([
                'approvals' => $approvals,
                'total' => $total,
                'limit' => $limit,
                'offset' => $offset
            ]);
            
        } catch (Exception $e) {
            return $this->respondError("Error retrieving pending approvals: " . $e->getMessage(), 500);
        }
    }
    
    /**
     * Approve a submission
     */
    public function approveSubmission() {
        try {
            $input = json_decode(file_get_contents('php://input'), true);
            
            if (empty($input['approval_id'])) {
                return $this->respondError("approval_id is required", 400);
            }
            
            $approval_id = $input['approval_id'];
            $notes = $input['notes'] ?? '';
            
            // Get approval record
            $stmt = $this->db->prepare("SELECT * FROM admin_approval_queue WHERE id = ?");
            if (!$stmt) {
                return $this->respondError("Database error", 500);
            }
            
            $stmt->bind_param("i", $approval_id);
            $stmt->execute();
            $result = $stmt->get_result();
            $approval = $result->fetch_assoc();
            $stmt->close();
            
            if (!$approval) {
                return $this->respondError("Approval not found", 404);
            }
            
            // Update approval
            $update_stmt = $this->db->prepare("
                UPDATE admin_approval_queue 
                SET status = 'approved', reviewed_by_user_id = ?, review_notes = ?,  reviewed_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ");
            
            if (!$update_stmt) {
                return $this->respondError("Database error", 500);
            }
            
            $update_stmt->bind_param("isi", $this->user_id, $notes, $approval_id);
            
            if (!$update_stmt->execute()) {
                return $this->respondError("Failed to approve submission", 500);
            }
            $update_stmt->close();
            
            // If it's a baseline, update baseline status
            if ($approval['submission_type'] === 'baseline' && $approval['baseline_id']) {
                $baseline_stmt = $this->db->prepare("
                    UPDATE baseline_services SET status = 'approved' WHERE id = ?
                ");
                if ($baseline_stmt) {
                    $baseline_stmt->bind_param("i", $approval['baseline_id']);
                    $baseline_stmt->execute();
                    $baseline_stmt->close();
                }
            }
            
            // If it's an alias, update alias status
            if ($approval['submission_type'] === 'alias' && $approval['alias_id']) {
                $alias_stmt = $this->db->prepare("
                    UPDATE service_aliases SET status = 'approved' WHERE id = ?
                ");
                if ($alias_stmt) {
                    $alias_stmt->bind_param("i", $approval['alias_id']);
                    $alias_stmt->execute();
                    $alias_stmt->close();
                }
            }
            
            // Log audit
            $this->logAuditAction('submission_approved', "Approved {$approval['submission_type']}: {$approval_id}", $approval['baseline_id']);
            
            return $this->respondSuccess([
                'approval_id' => $approval_id,
                'message' => 'Submission approved successfully'
            ]);
            
        } catch (Exception $e) {
            return $this->respondError("Error approving submission: " . $e->getMessage(), 500);
        }
    }
    
    /**
     * Reject a submission
     */
    public function rejectSubmission() {
        try {
            $input = json_decode(file_get_contents('php://input'), true);
            
            if (empty($input['approval_id'])) {
                return $this->respondError("approval_id is required", 400);
            }
            
            $approval_id = $input['approval_id'];
            $reason = $input['reason'] ?? 'Rejected by administrator';
            
            // Update approval
            $stmt = $this->db->prepare("
                UPDATE admin_approval_queue 
                SET status = 'rejected', reviewed_by_user_id = ?, review_notes = ?, reviewed_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ");
            
            if (!$stmt) {
                return $this->respondError("Database error", 500);
            }
            
            $stmt->bind_param("isi", $this->user_id, $reason, $approval_id);
            
            if (!$stmt->execute()) {
                return $this->respondError("Failed to reject submission", 500);
            }
            $stmt->close();
            
            // Log audit
            $this->logAuditAction('submission_rejected', "Rejected approval: {$approval_id}", null);
            
            return $this->respondSuccess([
                'approval_id' => $approval_id,
                'message' => 'Submission rejected'
            ]);
            
        } catch (Exception $e) {
            return $this->respondError("Error rejecting submission: " . $e->getMessage(), 500);
        }
    }
    
    /**
     * Get aliases and reseller information for a baseline
     */
    public function getBaselineAliases() {
        try {
            $input = json_decode(file_get_contents('php://input'), true);
            
            if (empty($input['baseline_id'])) {
                return $this->respondError("baseline_id is required", 400);
            }
            
            $baseline_id = $input['baseline_id'];
            $status_filter = $input['status'] ?? null;
            
            $query = "SELECT * FROM service_aliases WHERE baseline_id = ?";
            $params = [$baseline_id];
            $types = 'i';
            
            if ($status_filter) {
                $query .= " AND status = ?";
                $params[] = $status_filter;
                $types .= 's';
            }
            
            $query .= " ORDER BY match_percentage DESC";
            
            $stmt = $this->db->prepare($query);
            if (!$stmt) {
                return $this->respondError("Database error", 500);
            }
            
            $stmt->bind_param($types, ...$params);
            $stmt->execute();
            $result = $stmt->get_result();
            
            $aliases = [];
            while ($row = $result->fetch_assoc()) {
                $aliases[] = $row;
            }
            $stmt->close();
            
            return $this->respondSuccess([
                'baseline_id' => $baseline_id,
                'aliases' => $aliases,
                'total' => count($aliases)
            ]);
            
        } catch (Exception $e) {
            return $this->respondError("Error retrieving aliases: " . $e->getMessage(), 500);
        }
    }
    
    /**
     * Get reseller chain information
     */
    public function getResellerChain() {
        try {
            $input = json_decode(file_get_contents('php://input'), true);
            
            if (empty($input['baseline_id'])) {
                return $this->respondError("baseline_id is required", 400);
            }
            
            $baseline_id = $input['baseline_id'];
            
            // Get related matches with reseller chain data
            $stmt = $this->db->prepare("
                SELECT smr.*, b.service_name
                FROM scan_match_results smr
                JOIN baseline_services b ON smr.baseline_id = b.id
                WHERE b.id = ?
                AND smr.reseller_chain IS NOT NULL
                ORDER BY smr.match_timestamp DESC
                LIMIT 20
            ");
            
            if (!$stmt) {
                return $this->respondError("Database error", 500);
            }
            
            $stmt->bind_param("i", $baseline_id);
            $stmt->execute();
            $result = $stmt->get_result();
            
            $chains = [];
            while ($row = $result->fetch_assoc()) {
                $row['reseller_chain'] = json_decode($row['reseller_chain'], true);
                $chains[] = $row;
            }
            $stmt->close();
            
            return $this->respondSuccess([
                'baseline_id' => $baseline_id,
                'reseller_chains' => $chains
            ]);
            
        } catch (Exception $e) {
            return $this->respondError("Error retrieving reseller chains: " . $e->getMessage(), 500);
        }
    }
    
    /**
     * Get audit log
     */
    public function getAuditLog() {
        try {
            $input = json_decode(file_get_contents('php://input'), true);
            
            $filter_admin = $input['admin_user_id'] ?? null;
            $filter_action = $input['action_type'] ?? null;
            $limit = min($input['limit'] ?? 50, 500);
            $offset = $input['offset'] ?? 0;
            
            $query = "SELECT * FROM audit_log WHERE 1=1";
            $params = [];
            $types = '';
            
            if ($filter_admin) {
                $query .= " AND admin_user_id = ?";
                $params[] = $filter_admin;
                $types .= 'i';
            }
            
            if ($filter_action) {
                $query .= " AND action_type = ?";
                $params[] = $filter_action;
                $types .= 's';
            }
            
            $query .= " ORDER BY action_timestamp DESC LIMIT ? OFFSET ?";
            $params[] = $limit;
            $params[] = $offset;
            $types .= 'ii';
            
            $stmt = $this->db->prepare($query);
            if (!$stmt) {
                return $this->respondError("Database error", 500);
            }
            
            $stmt->bind_param($types, ...$params);
            $stmt->execute();
            $result = $stmt->get_result();
            
            $logs = [];
            while ($row = $result->fetch_assoc()) {
                $logs[] = $row;
            }
            $stmt->close();
            
            // Get total
            $count_query = "SELECT COUNT(*) as total FROM audit_log WHERE 1=1";
            if ($filter_admin) $count_query .= " AND admin_user_id = {$filter_admin}";
            if ($filter_action) $count_query .= " AND action_type = '{$filter_action}'";
            
            $count_result = $this->db->query($count_query);
            $total = $count_result->fetch_assoc()['total'];
            
            return $this->respondSuccess([
                'logs' => $logs,
                'total' => $total,
                'limit' => $limit,
                'offset' => $offset
            ]);
            
        } catch (Exception $e) {
            return $this->respondError("Error retrieving audit log: " . $e->getMessage(), 500);
        }
    }
    
    // ====== Helper Methods ======
    
    private function getBaselineStats() {
        $result = $this->db->query("
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) as approved,
                SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending,
                SUM(CASE WHEN is_private = 1 THEN 1 ELSE 0 END) as private
            FROM baseline_services
        ");
        
        return $result->fetch_assoc() ?? [];
    }
    
    private function getMatchStats() {
        $result = $this->db->query("
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN status = 'approved_match' THEN 1 ELSE 0 END) as approved_matches,
                SUM(CASE WHEN status = 'pending_review' THEN 1 ELSE 0 END) as pending_review,
                AVG(match_percentage) as avg_match_percentage
            FROM scan_match_results
        ");
        
        return $result->fetch_assoc() ?? [];
    }
    
    private function getPendingStats() {
        $result = $this->db->query("
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN submission_type = 'baseline' THEN 1 ELSE 0 END) as pending_baselines,
                SUM(CASE WHEN submission_type = 'alias' THEN 1 ELSE 0 END) as pending_aliases
            FROM admin_approval_queue
            WHERE status = 'pending'
        ");
        
        return $result->fetch_assoc() ?? [];
    }
    
    private function getRecentActivity($limit = 10) {
        $stmt = $this->db->prepare("
            SELECT action_type, action_description, action_timestamp, admin_user_id
            FROM audit_log
            ORDER BY action_timestamp DESC
            LIMIT ?
        ");
        
        if (!$stmt) return [];
        
        $stmt->bind_param("i", $limit);
        $stmt->execute();
        $result = $stmt->get_result();
        
        $activity = [];
        while ($row = $result->fetch_assoc()) {
            $activity[] = $row;
        }
        $stmt->close();
        
        return $activity;
    }
    
    private function logAuditAction($action_type, $description, $baseline_id) {
        $stmt = $this->db->prepare("
            INSERT INTO audit_log 
            (admin_user_id, action_type, action_description, related_baseline_id, admin_ip)
            VALUES (?, ?, ?, ?, ?)
        ");
        
        if (!$stmt) return;
        
        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
        
        $stmt->bind_param("issis", $this->user_id, $action_type, $description, $baseline_id, $ip);
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
    $dashboard = new AdminDashboard();
    
    $action = $_POST['action'] ?? json_decode(file_get_contents('php://input'), true)['action'] ?? null;
    
    switch ($action) {
        case 'get_stats':
            $dashboard->getDashboardStats();
            break;
        case 'get_pending':
            $dashboard->getPendingApprovals();
            break;
        case 'approve':
            $dashboard->approveSubmission();
            break;
        case 'reject':
            $dashboard->rejectSubmission();
            break;
        case 'get_aliases':
            $dashboard->getBaselineAliases();
            break;
        case 'get_reseller_chain':
            $dashboard->getResellerChain();
            break;
        case 'get_audit_log':
            $dashboard->getAuditLog();
            break;
        default:
            http_response_code(400);
            echo json_encode(['success' => false, 'error' => 'Invalid action']);
    }
} elseif ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $dashboard = new AdminDashboard();
    
    $action = $_GET['action'] ?? null;
    switch ($action) {
        case 'get_stats':
            $dashboard->getDashboardStats();
            break;
        case 'get_pending':
            $dashboard->getPendingApprovals();
            break;
        case 'get_audit_log':
            $dashboard->getAuditLog();
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
