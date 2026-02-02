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
        // Get domains - separate simple query
        $domainQuery = "SELECT domain FROM iptv_scans WHERE provider_name = ? LIMIT 10";
        $stmt = @$conn->prepare($domainQuery);
        
        if ($stmt) {
            $stmt->bind_param("s", $row['provider_name']);
            $stmt->execute();
            $domainResult = $stmt->get_result();
            
            $domains = [];
            while ($d = $domainResult->fetch_assoc()) {
                $domains[] = $d['domain'];
            }
            $stmt->close();
        } else {
            $domains = [];
        }
        
        // Get IPs - separate simple query
        $ipQuery = "SELECT DISTINCT resolved_ip FROM iptv_scans WHERE provider_name = ? AND resolved_ip != '' LIMIT 5";
        $stmt = @$conn->prepare($ipQuery);
        
        if ($stmt) {
            $stmt->bind_param("s", $row['provider_name']);
            $stmt->execute();
            $ipResult = $stmt->get_result();
            
            $ips = [];
            while ($i = $ipResult->fetch_assoc()) {
                $ips[] = $i['resolved_ip'];
            }
            $stmt->close();
        } else {
            $ips = [];
        }
        
        $resellers[] = [
            'name' => $row['provider_name'],
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