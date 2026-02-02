<?php
header('Content-Type: application/json');

try {
    @require_once 'config.php';
    
    $conn = @new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    
    if ($conn->connect_error) {
        throw new Exception("Database connection failed");
    }
    
    // Get resellers - simple query with limit
    $query = "SELECT DISTINCT provider_name, provider_count 
              FROM iptv_scans 
              WHERE provider_name IS NOT NULL 
              AND provider_name != '' 
              AND provider_count > 1 
              ORDER BY provider_count DESC 
              LIMIT 20";
    
    $result = @$conn->query($query);
    
    if (!$result) {
        throw new Exception("Query failed");
    }
    
    $resellers = [];
    
    while ($row = $result->fetch_assoc()) {
        $providerName = $row['provider_name'];
        $domains = [];
        $ips = [];
        
        // Get domains - use simple query without prepared statement
        $domainQuery = "SELECT domain FROM iptv_scans 
                       WHERE provider_name = '" . $conn->real_escape_string($providerName) . "' 
                       LIMIT 10";
        $domainResult = @$conn->query($domainQuery);
        
        if ($domainResult) {
            while ($d = $domainResult->fetch_assoc()) {
                if (!empty($d['domain'])) {
                    $domains[] = $d['domain'];
                }
            }
        }
        
        // Get IPs - use simple query without prepared statement
        $ipQuery = "SELECT DISTINCT resolved_ip FROM iptv_scans 
                   WHERE provider_name = '" . $conn->real_escape_string($providerName) . "' 
                   AND resolved_ip IS NOT NULL 
                   AND resolved_ip != '' 
                   LIMIT 5";
        $ipResult = @$conn->query($ipQuery);
        
        if ($ipResult) {
            while ($i = $ipResult->fetch_assoc()) {
                if (!empty($i['resolved_ip'])) {
                    $ips[] = $i['resolved_ip'];
                }
            }
        }
        
        $resellers[] = [
            'name' => $providerName,
            'domain_count' => (int)$row['provider_count'],
            'domains' => $domains,
            'ips' => $ips,
            'avg_age_days' => 0,
            'last_seen' => date('Y-m-d H:i:s'),
            'upstream_providers' => []
        ];
    }
    
    $conn->close();
    
    echo json_encode([
        'success' => true,
        'resellers' => $resellers,
        'relationships' => [],
        'total_resellers' => count($resellers),
        'timestamp' => date('Y-m-d H:i:s')
    ]);
    
} catch (Exception $e) {
    echo json_encode([
        'success' => true,
        'resellers' => [],
        'relationships' => [],
        'total_resellers' => 0,
        'timestamp' => date('Y-m-d H:i:s')
    ]);
}
?>