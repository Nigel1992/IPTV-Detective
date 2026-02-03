<?php
error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);
header('Content-Type: application/json');

require_once __DIR__ . '/config.php';

/**
 * Service Versioning & Update Tracking
 * Manages baseline updates, tracks changes over time, and normalizes variations
 */
class ServiceVersioning {
    private $db;
    private $user_id;
    private $user_role;
    
    public function __construct() {
        $this->connectDatabase();
        $this->validateAccess();
    }
    
    private function connectDatabase() {
        $this->db = new mysqli(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME);
        if ($this->db->connect_error) {
            $this->respondError("Database connection failed", 500);
        }
        $this->db->set_charset("utf8mb4");
    }
    
    private function validateAccess() {
        $this->user_id = $_POST['user_id'] ?? $_GET['user_id'] ?? null;
        $this->user_role = $this->getUserRole($this->user_id);
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
     * Record a service update when changes are detected
     * Called when a baseline is re-scanned and changes are found
     */
    public function recordServiceUpdate() {
        try {
            $input = json_decode(file_get_contents('php://input'), true);
            
            if (empty($input['baseline_id'])) {
                return $this->respondError("baseline_id is required", 400);
            }
            
            $baseline_id = $input['baseline_id'];
            $detection_type = $input['detection_type'] ?? 'auto_verify'; // auto_verify, manual_scan, user_report
            
            // Get current baseline state
            $baseline = $this->getBaseline($baseline_id);
            if (!$baseline) {
                return $this->respondError("Baseline not found", 404);
            }
            
            // Get current version number
            $current_version = $this->getCurrentVersionNumber($baseline_id);
            $new_version = $current_version + 1;
            
            // Get previous version counts
            $previous_counts = $this->getPreviousVersionCounts($baseline_id);
            
            // Prepare update data
            $channels_added = ($input['new_channels'] ?? 0) - ($previous_counts['channels'] ?? 0);
            $channels_removed = ($previous_counts['channels'] ?? 0) - ($input['new_channels'] ?? 0);
            $vods_added = ($input['new_vods'] ?? 0) - ($previous_counts['vods'] ?? 0);
            $vods_removed = ($previous_counts['vods'] ?? 0) - ($input['new_vods'] ?? 0);
            
            // Only create new version if there are actual changes
            $has_changes = ($channels_added != 0 || $channels_removed != 0 || 
                           $vods_added != 0 || $vods_removed != 0);
            
            if (!$has_changes && !$input['force_update']) {
                return $this->respondSuccess([
                    'version_number' => $current_version,
                    'has_changes' => false,
                    'message' => 'No changes detected'
                ]);
            }
            
            // Create new version record
            $stmt = $this->db->prepare("
                INSERT INTO service_versions 
                (baseline_id, version_number, change_summary, 
                 channel_count_previous, channel_count_new, channels_added, channels_removed,
                 vod_count_previous, vod_count_new,
                 scan_url, scan_domain, detection_type)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ");
            
            if (!$stmt) {
                return $this->respondError("Database error", 500);
            }
            
            $summary = "Version $new_version: ";
            if ($channels_added > 0) {
                $summary .= "+$channels_added channels, ";
            }
            if ($channels_removed > 0) {
                $summary .= "-$channels_removed channels, ";
            }
            if ($vods_added > 0) {
                $summary .= "+$vods_added VODs";
            }
            $summary = rtrim($summary, ', ');
            
            $scan_url = $input['scan_url'] ?? '';
            $scan_domain = $input['scan_domain'] ?? '';
            $prev_channels = $previous_counts['channels'] ?? 0;
            $new_channels = $input['new_channels'] ?? 0;
            $prev_vods = $previous_counts['vods'] ?? 0;
            $new_vods = $input['new_vods'] ?? 0;
            
            $stmt->bind_param(
                "iisiiiiissss",
                $baseline_id,
                $new_version,
                $summary,
                $prev_channels,
                $new_channels,
                $channels_added,
                $channels_removed,
                $prev_vods,
                $new_vods,
                $scan_url,
                $scan_domain,
                $detection_type
            );
            
            if (!$stmt->execute()) {
                return $this->respondError("Failed to record version", 500);
            }
            $stmt->close();
            
            // Update baseline counts
            $this->updateBaselineCounters($baseline_id, $new_channels, $new_vods);
            
            // Update last verified timestamp
            $update_stmt = $this->db->prepare("
                UPDATE baseline_services 
                SET last_verified_at = CURRENT_TIMESTAMP 
                WHERE id = ?
            ");
            
            if ($update_stmt) {
                $update_stmt->bind_param("i", $baseline_id);
                $update_stmt->execute();
                $update_stmt->close();
            }
            
            // Log audit action
            $this->logAuditAction('service_updated', "Version $new_version recorded for baseline $baseline_id", $baseline_id);
            
            return $this->respondSuccess([
                'baseline_id' => $baseline_id,
                'version_number' => $new_version,
                'has_changes' => $has_changes,
                'changes' => [
                    'channels_added' => max(0, $channels_added),
                    'channels_removed' => max(0, $channels_removed),
                    'vods_added' => max(0, $vods_added),
                    'vods_removed' => max(0, $vods_removed)
                ],
                'summary' => $summary
            ]);
            
        } catch (Exception $e) {
            return $this->respondError("Error recording update: " . $e->getMessage(), 500);
        }
    }
    
    /**
     * Get version history for a baseline
     */
    public function getVersionHistory() {
        try {
            $input = json_decode(file_get_contents('php://input'), true);
            
            if (empty($input['baseline_id'])) {
                return $this->respondError("baseline_id is required", 400);
            }
            
            $baseline_id = $input['baseline_id'];
            $limit = min($input['limit'] ?? 50, 500);
            $offset = $input['offset'] ?? 0;
            
            $stmt = $this->db->prepare("
                SELECT id, version_number, change_summary, 
                       channel_count_previous, channel_count_new,
                       channels_added, channels_removed,
                       vod_count_previous, vod_count_new,
                       detection_type, created_at
                FROM service_versions
                WHERE baseline_id = ?
                ORDER BY version_number DESC
                LIMIT ? OFFSET ?
            ");
            
            if (!$stmt) {
                return $this->respondError("Database error", 500);
            }
            
            $stmt->bind_param("iii", $baseline_id, $limit, $offset);
            $stmt->execute();
            $result = $stmt->get_result();
            
            $versions = [];
            while ($row = $result->fetch_assoc()) {
                $versions[] = $row;
            }
            $stmt->close();
            
            // Get total count
            $count_stmt = $this->db->prepare("
                SELECT COUNT(*) as total FROM service_versions 
                WHERE baseline_id = ?
            ");
            $count_stmt->bind_param("i", $baseline_id);
            $count_stmt->execute();
            $count_result = $count_stmt->get_result();
            $total = $count_result->fetch_assoc()['total'];
            $count_stmt->close();
            
            return $this->respondSuccess([
                'baseline_id' => $baseline_id,
                'versions' => $versions,
                'total' => $total,
                'limit' => $limit,
                'offset' => $offset
            ]);
            
        } catch (Exception $e) {
            return $this->respondError("Error retrieving version history: " . $e->getMessage(), 500);
        }
    }
    
    /**
     * Compare two versions of a baseline
     */
    public function compareVersions() {
        try {
            $input = json_decode(file_get_contents('php://input'), true);
            
            if (empty($input['baseline_id']) || empty($input['version_from']) || empty($input['version_to'])) {
                return $this->respondError("baseline_id, version_from, and version_to are required", 400);
            }
            
            $baseline_id = $input['baseline_id'];
            $version_from = $input['version_from'];
            $version_to = $input['version_to'];
            
            // Get version data
            $from_version = $this->getVersionData($baseline_id, $version_from);
            $to_version = $this->getVersionData($baseline_id, $version_to);
            
            if (!$from_version || !$to_version) {
                return $this->respondError("One or both versions not found", 404);
            }
            
            // Calculate differences
            $total_channel_change = ($to_version['channel_count_new'] ?? 0) - ($from_version['channel_count_previous'] ?? 0);
            $total_vod_change = ($to_version['vod_count_new'] ?? 0) - ($from_version['vod_count_previous'] ?? 0);
            
            return $this->respondSuccess([
                'baseline_id' => $baseline_id,
                'from_version' => $version_from,
                'to_version' => $version_to,
                'channels' => [
                    'before' => $from_version['channel_count_previous'] ?? 0,
                    'after' => $to_version['channel_count_new'] ?? 0,
                    'total_change' => $total_channel_change,
                    'change_percentage' => $from_version['channel_count_previous'] ? 
                        round(($total_channel_change / ($from_version['channel_count_previous'] ?? 1)) * 100, 2) : 0
                ],
                'vods' => [
                    'before' => $from_version['vod_count_previous'] ?? 0,
                    'after' => $to_version['vod_count_new'] ?? 0,
                    'total_change' => $total_vod_change
                ],
                'from_summary' => $from_version['change_summary'],
                'to_summary' => $to_version['change_summary']
            ]);
            
        } catch (Exception $e) {
            return $this->respondError("Error comparing versions: " . $e->getMessage(), 500);
        }
    }
    
    /**
     * Normalize variations across multiple scans (handle slight differences)
     * Used to determine if variations are normal updates or actual changes
     */
    public function normalizeVariations() {
        try {
            $input = json_decode(file_get_contents('php://input'), true);
            
            if (empty($input['baseline_id'])) {
                return $this->respondError("baseline_id is required", 400);
            }
            
            $baseline_id = $input['baseline_id'];
            $tolerance_percentage = $input['tolerance'] ?? 5; // Default 5% variation is normal
            
            // Get recent scans/versions
            $stmt = $this->db->prepare("
                SELECT version_number, channel_count_new, vod_count_new, created_at
                FROM service_versions
                WHERE baseline_id = ?
                ORDER BY version_number DESC
                LIMIT 10
            ");
            
            if (!$stmt) {
                return $this->respondError("Database error", 500);
            }
            
            $stmt->bind_param("i", $baseline_id);
            $stmt->execute();
            $result = $stmt->get_result();
            
            $versions = [];
            $total_channels = 0;
            $total_vods = 0;
            $version_count = 0;
            
            while ($row = $result->fetch_assoc()) {
                $versions[] = $row;
                $total_channels += $row['channel_count_new'] ?? 0;
                $total_vods += $row['vod_count_new'] ?? 0;
                $version_count++;
            }
            $stmt->close();
            
            if ($version_count === 0) {
                return $this->respondError("No version history found", 404);
            }
            
            // Calculate average
            $avg_channels = round($total_channels / $version_count);
            $avg_vods = round($total_vods / $version_count);
            
            // Determine normal variation range
            $channel_tolerance = round($avg_channels * ($tolerance_percentage / 100));
            $vod_tolerance = round($avg_vods * ($tolerance_percentage / 100));
            
            $min_channels = max(0, $avg_channels - $channel_tolerance);
            $max_channels = $avg_channels + $channel_tolerance;
            $min_vods = max(0, $avg_vods - $vod_tolerance);
            $max_vods = $avg_vods + $vod_tolerance;
            
            // Analyze latest versions for anomalies
            $anomalies = [];
            foreach ($versions as $version) {
                $channels = $version['channel_count_new'] ?? 0;
                $vods = $version['vod_count_new'] ?? 0;
                
                $is_anomaly = false;
                $anomaly_reason = '';
                
                if ($channels < $min_channels || $channels > $max_channels) {
                    $is_anomaly = true;
                    $anomaly_reason .= "Channel count out of range ({$min_channels}-{$max_channels}); ";
                }
                if ($vods < $min_vods || $vods > $max_vods) {
                    $is_anomaly = true;
                    $anomaly_reason .= "VOD count out of range ({$min_vods}-{$max_vods}); ";
                }
                
                if ($is_anomaly) {
                    $anomalies[] = [
                        'version' => $version['version_number'],
                        'channels' => $channels,
                        'vods' => $vods,
                        'reason' => trim($anomaly_reason, '; '),
                        'date' => $version['created_at']
                    ];
                }
            }
            
            return $this->respondSuccess([
                'baseline_id' => $baseline_id,
                'normalization_stats' => [
                    'average_channels' => $avg_channels,
                    'average_vods' => $avg_vods,
                    'tolerance_percentage' => $tolerance_percentage,
                    'channel_range' => [$min_channels, $max_channels],
                    'vod_range' => [$min_vods, $max_vods],
                    'versions_analyzed' => $version_count
                ],
                'anomalies' => $anomalies,
                'is_healthy' => count($anomalies) === 0
            ]);
            
        } catch (Exception $e) {
            return $this->respondError("Error normalizing variations: " . $e->getMessage(), 500);
        }
    }
    
    /**
     * Auto-update baseline when high-confidence matches report different counts
     */
    public function autoUpdateBaseline() {
        try {
            $input = json_decode(file_get_contents('php://input'), true);
            
            if (empty($input['baseline_id'])) {
                return $this->respondError("baseline_id is required", 400);
            }
            
            // Only admins can trigger auto-updates
            if (!in_array($this->user_role, ['admin', 'super_admin'])) {
                return $this->respondError("Admin access required", 403);
            }
            
            $baseline_id = $input['baseline_id'];
            
            // Get latest scan matches for this baseline
            $stmt = $this->db->prepare("
                SELECT smr.match_percentage, smr.matching_criteria, 
                       smr.user_scan_url, smr.match_timestamp,
                       sm.channels_detected, sm.vods_detected
                FROM scan_match_results smr
                LEFT JOIN scan_metadata sm ON smr.scan_id = sm.scan_id
                WHERE smr.baseline_id = ?
                AND smr.status = 'approved_match'
                ORDER BY smr.match_timestamp DESC
                LIMIT 5
            ");
            
            if (!$stmt) {
                return $this->respondError("Database error", 500);
            }
            
            $stmt->bind_param("i", $baseline_id);
            $stmt->execute();
            $result = $stmt->get_result();
            
            $matches = [];
            $avg_channels = 0;
            $avg_vods = 0;
            
            while ($row = $result->fetch_assoc()) {
                if ($row['match_percentage'] >= 80) { // Only high-confidence matches
                    $matches[] = $row;
                    $avg_channels += $row['channels_detected'] ?? 0;
                    $avg_vods += $row['vods_detected'] ?? 0;
                }
            }
            $stmt->close();
            
            if (count($matches) === 0) {
                return $this->respondSuccess([
                    'baseline_id' => $baseline_id,
                    'update_applied' => false,
                    'message' => 'No high-confidence matches found for auto-update'
                ]);
            }
            
            // Calculate averages
            $avg_channels = round($avg_channels / count($matches));
            $avg_vods = round($avg_vods / count($matches));
            
            // Get current baseline
            $baseline = $this->getBaseline($baseline_id);
            
            // Determine if update should be applied
            $channel_diff = abs($avg_channels - ($baseline['channel_count'] ?? 0));
            $vod_diff = abs($avg_vods - ($baseline['vod_count'] ?? 0));
            
            // Only update if difference is significant (>5%)
            $channel_threshold = round(($baseline['channel_count'] ?? 1) * 0.05);
            $vod_threshold = round(($baseline['vod_count'] ?? 1) * 0.05);
            
            if ($channel_diff <= $channel_threshold && $vod_diff <= $vod_threshold) {
                return $this->respondSuccess([
                    'baseline_id' => $baseline_id,
                    'update_applied' => false,
                    'message' => 'Variations within tolerance threshold'
                ]);
            }
            
            // Apply update
            $update_stmt = $this->db->prepare("
                UPDATE baseline_services 
                SET channel_count = ?, vod_count = ?, last_verified_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ");
            
            if (!$update_stmt) {
                return $this->respondError("Database error", 500);
            }
            
            $update_stmt->bind_param("iii", $avg_channels, $avg_vods, $baseline_id);
            
            if (!$update_stmt->execute()) {
                return $this->respondError("Failed to update baseline", 500);
            }
            $update_stmt->close();
            
            // Record version
            $this->recordServiceUpdate();
            
            // Log audit
            $this->logAuditAction(
                'baseline_auto_updated',
                "Auto-updated baseline {$baseline_id}: {$avg_channels} channels, {$avg_vods} VODs",
                $baseline_id
            );
            
            return $this->respondSuccess([
                'baseline_id' => $baseline_id,
                'update_applied' => true,
                'changes' => [
                    'channels_previous' => $baseline['channel_count'] ?? 0,
                    'channels_new' => $avg_channels,
                    'vods_previous' => $baseline['vod_count'] ?? 0,
                    'vods_new' => $avg_vods
                ],
                'matches_analyzed' => count($matches),
                'message' => 'Baseline updated successfully'
            ]);
            
        } catch (Exception $e) {
            return $this->respondError("Error auto-updating baseline: " . $e->getMessage(), 500);
        }
    }
    
    // ====== Helper Methods ======
    
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
    
    private function getCurrentVersionNumber($baseline_id) {
        $stmt = $this->db->prepare("
            SELECT MAX(version_number) as max_version FROM service_versions 
            WHERE baseline_id = ?
        ");
        
        if (!$stmt) return 0;
        
        $stmt->bind_param("i", $baseline_id);
        $stmt->execute();
        $result = $stmt->get_result();
        $row = $result->fetch_assoc();
        $stmt->close();
        
        return $row['max_version'] ?? 0;
    }
    
    private function getPreviousVersionCounts($baseline_id) {
        $stmt = $this->db->prepare("
            SELECT channel_count_new as channels, vod_count_new as vods 
            FROM service_versions
            WHERE baseline_id = ?
            ORDER BY version_number DESC
            LIMIT 1
        ");
        
        if (!$stmt) return [];
        
        $stmt->bind_param("i", $baseline_id);
        $stmt->execute();
        $result = $stmt->get_result();
        $row = $result->fetch_assoc();
        $stmt->close();
        
        if ($row) return $row;
        
        // Return baseline counts if no versions yet
        $baseline = $this->getBaseline($baseline_id);
        return [
            'channels' => $baseline['channel_count'] ?? 0,
            'vods' => $baseline['vod_count'] ?? 0
        ];
    }
    
    private function getVersionData($baseline_id, $version_number) {
        $stmt = $this->db->prepare("
            SELECT * FROM service_versions 
            WHERE baseline_id = ? AND version_number = ?
        ");
        
        if (!$stmt) return null;
        
        $stmt->bind_param("ii", $baseline_id, $version_number);
        $stmt->execute();
        $result = $stmt->get_result();
        $version = $result->fetch_assoc();
        $stmt->close();
        
        return $version;
    }
    
    private function updateBaselineCounters($baseline_id, $channels, $vods) {
        $stmt = $this->db->prepare("
            UPDATE baseline_services 
            SET channel_count = ?, vod_count = ?
            WHERE id = ?
        ");
        
        if ($stmt) {
            $stmt->bind_param("iii", $channels, $vods, $baseline_id);
            $stmt->execute();
            $stmt->close();
        }
    }
    
    private function logAuditAction($action_type, $description, $baseline_id) {
        $stmt = $this->db->prepare("
            INSERT INTO audit_log 
            (admin_user_id, action_type, action_description, related_baseline_id, admin_ip)
            VALUES (?, ?, ?, ?, ?)
        ");
        
        if (!$stmt) return;
        
        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
        $user_id = $this->user_id ?? 0;
        
        $stmt->bind_param("issis", $user_id, $action_type, $description, $baseline_id, $ip);
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
    $versioning = new ServiceVersioning();
    
    $action = $_POST['action'] ?? json_decode(file_get_contents('php://input'), true)['action'] ?? null;
    
    switch ($action) {
        case 'record_update':
            $versioning->recordServiceUpdate();
            break;
        case 'get_history':
            $versioning->getVersionHistory();
            break;
        case 'compare_versions':
            $versioning->compareVersions();
            break;
        case 'normalize':
            $versioning->normalizeVariations();
            break;
        case 'auto_update':
            $versioning->autoUpdateBaseline();
            break;
        default:
            http_response_code(400);
            echo json_encode(['success' => false, 'error' => 'Invalid action']);
    }
} elseif ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $versioning = new ServiceVersioning();
    
    $action = $_GET['action'] ?? null;
    switch ($action) {
        case 'get_history':
            $versioning->getVersionHistory();
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
