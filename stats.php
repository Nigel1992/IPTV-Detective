<?php
header('Content-Type: application/json');
require_once __DIR__ . '/config.php';

try {
    $db = new mysqli(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME);
    if ($db->connect_error) {
        throw new Exception("Database connection failed");
    }
    $db->set_charset("utf8mb4");
    
    // Get total scanned hosts
    $totalResult = $db->query("SELECT COUNT(DISTINCT domain) as total FROM scanned_hosts");
    $total = $totalResult ? $totalResult->fetch_assoc()['total'] : 0;
    
    // Get unique IPs
    $ipsResult = $db->query("SELECT COUNT(DISTINCT resolved_ip) as total FROM scanned_hosts");
    $uniqueIps = $ipsResult ? $ipsResult->fetch_assoc()['total'] : 0;
    
    // Get reseller count (provider_count > 1)
    $resellersResult = $db->query("SELECT COUNT(DISTINCT domain) as total FROM scanned_hosts WHERE provider_count > 1");
    $resellers = $resellersResult ? $resellersResult->fetch_assoc()['total'] : 0;
    
    // Get upstream providers (is_likely_upstream = 1)
    $upstreamResult = $db->query("SELECT COUNT(*) as total FROM scanned_hosts WHERE is_likely_upstream = 1");
    $upstream = $upstreamResult ? $upstreamResult->fetch_assoc()['total'] : 0;
    
    $db->close();
    
    echo json_encode([
        'success' => true,
        'stats' => [
            'total_domains' => (int)$total,
            'unique_ips' => (int)$uniqueIps,
            'resellers_detected' => (int)$resellers,
            'upstream_providers' => (int)$upstream
        ]
    ]);
    
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => 'Failed to fetch stats'
    ]);
}
?>
