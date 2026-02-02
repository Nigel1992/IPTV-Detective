<?php
header('Content-Type: application/json');

$response = [
    'success' => true,
    'resellers' => [],
    'relationships' => [],
    'total_resellers' => 0,
    'timestamp' => date('Y-m-d H:i:s')
];

// Try to get data from database
if (file_exists('config.php')) {
    try {
        require_once 'config.php';
        
        // Try connecting - use DB_PASSWORD not DB_PASS
        $conn = @mysqli_connect(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME);
        
        if ($conn) {
            // Simple query - just get resellers
            $result = @mysqli_query($conn, "SELECT provider_name, provider_count FROM iptv_scans WHERE provider_count > 1 ORDER BY provider_count DESC LIMIT 20");
            
            if ($result) {
                while ($row = @mysqli_fetch_assoc($result)) {
                    if (!empty($row['provider_name'])) {
                        $response['resellers'][] = [
                            'name' => $row['provider_name'],
                            'domain_count' => (int)$row['provider_count'],
                            'domains' => [$row['provider_name']],
                            'ips' => [],
                            'avg_age_days' => 0,
                            'last_seen' => date('Y-m-d H:i:s'),
                            'upstream_providers' => []
                        ];
                    }
                }
            }
            
            $response['total_resellers'] = count($response['resellers']);
            @mysqli_close($conn);
        }
    } catch (Exception $e) {
        // Silently fail and return empty
    }
}

echo json_encode($response);
?>