<?php
error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);
header('Content-Type: application/json');

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/scan.php';

/**
 * Service Matching Engine
 * Compares user-scanned IPTV services against baseline services
 * and generates match percentages
 */
class ServiceMatchingEngine {
    private $db;
    private $scanner;
    private $user_id;
    private $user_ip;
    
    public function __construct() {
        $this->connectDatabase();
        $this->scanner = new IPTVForensicScanner();
        $this->user_ip = $_SERVER['REMOTE_ADDR'] ?? '';
        $this->user_id = $_POST['user_id'] ?? $_GET['user_id'] ?? null;
    }
    
    private function connectDatabase() {
        $this->db = new mysqli(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME);
        if ($this->db->connect_error) {
            $this->respondError("Database connection failed", 500);
        }
        $this->db->set_charset("utf8mb4");
    }
    
    /**
     * Main scan method - scans URL and compares against baselines
     */
    public function scanAndMatch() {
        try {
            $input = json_decode(file_get_contents('php://input'), true);
            
            // Validate input
            if (empty($input['url'])) {
                return $this->respondError("URL is required", 400);
            }
            
            $url = $input['url'];
            $user_service_name = $input['service_name'] ?? '';
            $user_country = $input['country'] ?? '';
            $user_notes = $input['notes'] ?? '';
            
            // Acknowledge privacy terms if provided
            if (isset($input['acknowledge_privacy'])) {
                $this->recordPrivacyAcknowledgment($input['acknowledge_privacy']);
            }
            
            // Perform initial scan
            $scan_result = $this->performInitialScan($url);
            if (!$scan_result['success']) {
                return $this->respondError($scan_result['error'], 400);
            }
            
            $scan_data = $scan_result['data'];
            
            // Collect additional metadata
            $metadata = $this->gatherServiceMetadata($url, $input['metadata'] ?? []);
            $this->recordScanMetadata($scan_data['id'] ?? null, $metadata);
            
            // Compare against baselines
            $matches = $this->matchAgainstBaselines($scan_data, $metadata);
            
            // Prepare response
            $response = [
                'scan_id' => $scan_data['id'] ?? null,
                'url_analyzed' => $url,
                'domain' => $scan_data['domain'] ?? null,
                'resolved_ip' => $scan_data['resolved_ip'] ?? null,
                'matches' => $matches,
                'is_new_service' => empty($matches),
                'metadata' => $metadata
            ];
            
            // If new service (no matches), queue for baseline creation
            if (empty($matches) && !empty($user_service_name)) {
                $response['baseline_submission'] = $this->queueNewBaseline(
                    $user_service_name,
                    $url,
                    $scan_data,
                    $metadata,
                    $user_country,
                    $user_notes
                );
            } elseif (!empty($matches) && $matches[0]['confidence'] >= 80) {
                // Record as alias if high confidence match
                $this->recordAlias($matches[0]['baseline_id'], $user_service_name, $matches[0]['confidence']);
            }
            
            return $this->respondSuccess($response);
            
        } catch (Exception $e) {
            return $this->respondError("Scan failed: " . $e->getMessage(), 500);
        }
    }
    
    /**
     * Perform the initial forensic scan
     */
    private function performInitialScan($url) {
        try {
            // Use existing scanner from scan.php
            $originalUrl = $url;
            $domain = $this->extractDomain($url);
            $port = $this->extractPort($url);
            
            if (!$domain) {
                return ['success' => false, 'error' => 'Invalid URL format'];
            }
            
            $ip = $this->resolveIP($domain);
            if (!$ip) {
                return ['success' => false, 'error' => 'Failed to resolve IP address'];
            }
            
            // Build scan data (simplified from scan.php)
            $scan_data = [
                'original_url' => $url,
                'domain' => $domain,
                'resolved_ip' => $ip,
                'port' => $port,
                'timestamp' => time()
            ];
            
            return ['success' => true, 'data' => $scan_data];
            
        } catch (Exception $e) {
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }
    
    /**
     * Match scanned service against all baselines
     * Returns array of potential matches with confidence scores
     */
    private function matchAgainstBaselines($scan_data, $metadata) {
        $domain = $scan_data['domain'] ?? '';
        $ip = $scan_data['resolved_ip'] ?? '';
        
        // Get all approved baselines
        $stmt = $this->db->prepare("
            SELECT b.id, b.service_name, b.baseline_domain, b.baseline_ip, 
                   b.channel_count, b.vod_count, m.max_resolution, m.average_bitrate,
                   m.primary_country, m.has_epg
            FROM baseline_services b
            LEFT JOIN service_metadata m ON b.id = m.baseline_id
            WHERE b.status = 'approved'
            ORDER BY b.created_at DESC
        ");
        
        if (!$stmt) return [];
        
        $stmt->execute();
        $result = $stmt->get_result();
        $matches = [];
        
        while ($baseline = $result->fetch_assoc()) {
            $match_score = $this->calculateMatchScore($scan_data, $metadata, $baseline);
            
            // Only include matches with reasonable confidence
            if ($match_score['confidence'] >= 40) {
                $matches[] = [
                    'baseline_id' => $baseline['id'],
                    'service_name' => $baseline['service_name'],
                    'confidence' => $match_score['confidence'],
                    'match_type' => $match_score['type'],
                    'matching_criteria' => $match_score['matching_criteria'],
                    'non_matching_criteria' => $match_score['non_matching_criteria'],
                    'baseline_channels' => $baseline['channel_count'],
                    'user_channels' => $metadata['channels_detected'] ?? 0,
                    'baseline_country' => $baseline['primary_country'] ?? 'Unknown'
                ];
            }
        }
        $stmt->close();
        
        // Sort by confidence
        usort($matches, function($a, $b) {
            return $b['confidence'] <=> $a['confidence'];
        });
        
        return array_slice($matches, 0, 5); // Return top 5 matches
    }
    
    /**
     * Calculate match score between scan and baseline
     */
    private function calculateMatchScore($scan_data, $metadata, $baseline) {
        $confidence = 0;
        $matching_criteria = [];
        $non_matching_criteria = [];
        $match_type = 'none';
        
        // Exact IP match (highest confidence)
        if ($scan_data['resolved_ip'] === $baseline['baseline_ip']) {
            $confidence += 40;
            $matching_criteria[] = 'IP address exact match';
            $match_type = 'ip_exact';
        }
        
        // Domain match
        $scan_domain_parts = explode('.', $scan_data['domain']);
        $baseline_domain_parts = explode('.', $baseline['baseline_domain']);
        
        if ($scan_data['domain'] === $baseline['baseline_domain']) {
            $confidence += 30;
            $matching_criteria[] = 'Domain exact match';
            $match_type = 'domain_exact';
        } elseif (end($scan_domain_parts) === end($baseline_domain_parts)) {
            // Same TLD
            $confidence += 5;
            $matching_criteria[] = 'Same TLD';
        }
        
        // Channel count similarity (within 10%)
        $user_channels = $metadata['channels_detected'] ?? 0;
        $baseline_channels = $baseline['channel_count'] ?? 0;
        
        if ($baseline_channels > 0 && $user_channels > 0) {
            $channel_diff = abs($user_channels - $baseline_channels) / $baseline_channels;
            
            if ($channel_diff < 0.05) {
                $confidence += 15;
                $matching_criteria[] = 'Channel count near-exact match';
            } elseif ($channel_diff < 0.15) {
                $confidence += 8;
                $matching_criteria[] = 'Channel count similar (±15%)';
            } else {
                $non_matching_criteria[] = "Channel count differs: $user_channels vs {$baseline_channels}";
            }
        }
        
        // Resolution match
        if (isset($metadata['resolution']) && isset($baseline['max_resolution'])) {
            if ($metadata['resolution'] === $baseline['max_resolution']) {
                $confidence += 5;
                $matching_criteria[] = 'Resolution match';
            }
        }
        
        // Country match
        if (isset($metadata['country']) && isset($baseline['primary_country'])) {
            if (strtolower($metadata['country']) === strtolower($baseline['primary_country'])) {
                $confidence += 8;
                $matching_criteria[] = 'Country match';
            }
        }
        
        // EPG availability match
        if (isset($metadata['has_epg']) && isset($baseline['has_epg'])) {
            if ($metadata['has_epg'] === $baseline['has_epg']) {
                $confidence += 3;
                $matching_criteria[] = 'EPG availability match';
            }
        }
        
        // Bitrate similarity
        if (isset($metadata['bitrate']) && isset($baseline['average_bitrate'])) {
            $user_bitrate = $this->extractBitrate($metadata['bitrate']);
            $baseline_bitrate = $this->extractBitrate($baseline['average_bitrate']);
            
            if ($user_bitrate > 0 && $baseline_bitrate > 0) {
                $bitrate_diff = abs($user_bitrate - $baseline_bitrate) / $baseline_bitrate;
                if ($bitrate_diff < 0.20) {
                    $confidence += 4;
                    $matching_criteria[] = 'Bitrate similar';
                }
            }
        }
        
        // Cap confidence at 100
        $confidence = min($confidence, 100);
        
        return [
            'confidence' => $confidence,
            'type' => $match_type,
            'matching_criteria' => $matching_criteria,
            'non_matching_criteria' => $non_matching_criteria
        ];
    }
    
    /**
     * Gather additional service metadata during scan
     */
    private function gatherServiceMetadata($url, $user_metadata) {
        $metadata = [
            'channels_detected' => $user_metadata['channels'] ?? 0,
            'vods_detected' => $user_metadata['vods'] ?? 0,
            'series_detected' => $user_metadata['series'] ?? 0,
            'resolution' => $user_metadata['resolution'] ?? null,
            'bitrate' => $user_metadata['bitrate'] ?? null,
            'has_epg' => $user_metadata['has_epg'] ?? 0,
            'has_catchup' => $user_metadata['has_catchup'] ?? 0,
            'country' => $user_metadata['country'] ?? null,
            'protocols' => $user_metadata['protocols'] ?? [],
            'scan_duration_seconds' => $user_metadata['scan_duration'] ?? 0
        ];
        
        // Try to auto-detect channel count from API
        try {
            $channel_count = $this->detectChannelsFromXtream($url, $user_metadata['username'] ?? '', $user_metadata['password'] ?? '');
            if ($channel_count > 0) {
                $metadata['channels_detected'] = $channel_count;
            }
        } catch (Exception $e) {
            // Silently fail if API unavailable
        }
        
        return $metadata;
    }
    
    /**
     * Attempt to detect channel count from Xtream API
     */
    private function detectChannelsFromXtream($url, $username, $password) {
        if (empty($username) || empty($password)) {
            return 0;
        }
        
        $api_url = rtrim($url, '/') . '/player_api.php';
        $params = [
            'username' => $username,
            'password' => $password,
            'action' => 'get_live_streams'
        ];
        
        $curl_url = $api_url . '?' . http_build_query($params);
        
        $curl = curl_init();
        curl_setopt($curl, CURLOPT_URL, $curl_url);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_TIMEOUT, 5);
        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
        
        $response = curl_exec($curl);
        $http_code = curl_getinfo($curl, CURLINFO_HTTP_CODE);
        curl_close($curl);
        
        if ($http_code !== 200) {
            return 0;
        }
        
        $streams = json_decode($response, true);
        return is_array($streams) ? count($streams) : 0;
    }
    
    /**
     * Record scan metadata to database
     */
    private function recordScanMetadata($scan_id, $metadata) {
        if (!$scan_id) return;
        
        $stmt = $this->db->prepare("
            INSERT INTO scan_metadata 
            (scan_id, resolution, bitrate, channels_detected, vods_detected, 
             series_detected, epg_available, catchup_available, protocols_detected, scan_duration_seconds)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ");
        
        if (!$stmt) return;
        
        $protocols_json = json_encode($metadata['protocols'] ?? []);
        
        $stmt->bind_param(
            "issiiiiiisi",
            $scan_id,
            $metadata['resolution'],
            $metadata['bitrate'],
            $metadata['channels_detected'],
            $metadata['vods_detected'],
            $metadata['series_detected'],
            $metadata['has_epg'],
            $metadata['has_catchup'],
            $protocols_json,
            $metadata['scan_duration_seconds']
        );
        
        $stmt->execute();
        $stmt->close();
    }
    
    /**
     * Queue new service for baseline creation
     */
    private function queueNewBaseline($service_name, $url, $scan_data, $metadata, $country, $notes) {
        $stmt = $this->db->prepare("
            INSERT INTO admin_approval_queue 
            (submission_type, submitted_by_user_id, submission_data, status)
            VALUES (?, ?, ?, 'pending')
        ");
        
        if (!$stmt) {
            return ['success' => false, 'error' => 'Failed to queue'];
        }
        
        $submission_data = [
            'service_name' => $service_name,
            'url' => $url,
            'domain' => $scan_data['domain'],
            'ip' => $scan_data['resolved_ip'],
            'metadata' => $metadata,
            'country' => $country,
            'user_notes' => $notes,
            'submission_ip' => $this->user_ip,
            'submission_time' => date('Y-m-d H:i:s')
        ];
        
        $json_data = json_encode($submission_data);
        $type = 'baseline';
        $user_id = $this->user_id ?? 0;
        
        $stmt->bind_param("sis", $type, $user_id, $json_data);
        
        if (!$stmt->execute()) {
            $stmt->close();
            return ['success' => false, 'error' => 'Failed to queue'];
        }
        
        $queue_id = $this->db->insert_id;
        $stmt->close();
        
        return [
            'success' => true,
            'queue_id' => $queue_id,
            'message' => 'New baseline queued for admin approval',
            'service_name' => $service_name
        ];
    }
    
    /**
     * Record as alias for matching baseline
     */
    private function recordAlias($baseline_id, $alias_name, $match_percentage) {
        if (empty($alias_name)) return;
        
        // Check if alias already exists
        $check_stmt = $this->db->prepare("
            SELECT id FROM service_aliases 
            WHERE baseline_id = ? AND alias_name = ?
        ");
        
        if ($check_stmt) {
            $check_stmt->bind_param("is", $baseline_id, $alias_name);
            $check_stmt->execute();
            $result = $check_stmt->get_result();
            
            if ($result->num_rows > 0) {
                $check_stmt->close();
                return; // Alias already exists
            }
            $check_stmt->close();
        }
        
        // Insert new alias
        $stmt = $this->db->prepare("
            INSERT INTO service_aliases 
            (baseline_id, alias_name, alias_type, match_percentage, 
             submitted_by_user_id, submission_ip, status)
            VALUES (?, ?, 'user_submitted', ?, ?, ?, 'pending')
        ");
        
        if (!$stmt) return;
        
        $stmt->bind_param("isiss", $baseline_id, $alias_name, $match_percentage, $this->user_id, $this->user_ip);
        $stmt->execute();
        $stmt->close();
    }
    
    /**
     * Record privacy acknowledgment
     */
    private function recordPrivacyAcknowledgment($acknowledgments) {
        if (!$this->user_id) return;
        
        $stmt = $this->db->prepare("
            INSERT INTO privacy_acknowledgments 
            (user_id, acknowledged_credential_privacy, 
             acknowledged_use_trial_credentials, acknowledged_data_collection, 
             acknowledgment_ip, acknowledgment_user_agent)
            VALUES (?, ?, ?, ?, ?, ?)
        ");
        
        if (!$stmt) return;
        
        $cred_privacy = $acknowledgments['credential_privacy'] ?? 0;
        $trial_creds = $acknowledgments['trial_credentials'] ?? 0;
        $data_collection = $acknowledgments['data_collection'] ?? 0;
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        
        $stmt->bind_param(
            "iiisss",
            $this->user_id,
            $cred_privacy,
            $trial_creds,
            $data_collection,
            $this->user_ip,
            $user_agent
        );
        
        $stmt->execute();
        $stmt->close();
    }
    
    // ====== Helper Methods ======
    
    private function extractDomain($url) {
        $url = str_replace(['http://', 'https://'], '', $url);
        $parts = parse_url('http://' . $url);
        return $parts['host'] ?? null;
    }
    
    private function extractPort($url) {
        $parts = parse_url($url);
        return $parts['port'] ?? 80;
    }
    
    private function resolveIP($domain) {
        $ip = gethostbyname($domain);
        return ($ip !== $domain) ? $ip : false;
    }
    
    private function extractBitrate($bitrate_str) {
        if (!$bitrate_str) return 0;
        preg_match('/(\d+)/', $bitrate_str, $matches);
        return $matches[1] ?? 0;
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
    $matcher = new ServiceMatchingEngine();
    
    $action = $_POST['action'] ?? json_decode(file_get_contents('php://input'), true)['action'] ?? 'scan';
    
    switch ($action) {
        case 'scan':
        case 'scan_and_match':
            $matcher->scanAndMatch();
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
