<?php
// Prevent any output before JSON
error_reporting(E_ALL);
ini_set('display_errors', 0);
ob_start();

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

try {
    if (!file_exists('config.php')) {
        throw new Exception("Configuration file not found");
    }
    
    require_once 'config.php';
    
    // Create connection
    $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    
    if ($conn->connect_error) {
        throw new Exception("Database connection failed: " . $conn->connect_error);
    }
    
    // Get all resellers (providers with count > 1) and their associated domains
    $resellerQuery = "
        SELECT 
            provider_name,
            provider_count,
            GROUP_CONCAT(DISTINCT domain ORDER BY domain SEPARATOR '|||') as domains,
            GROUP_CONCAT(DISTINCT resolved_ip ORDER BY resolved_ip SEPARATOR '|||') as ips,
            AVG(COALESCE(domain_age_days, 0)) as avg_age,
            MAX(created_at) as last_seen
        FROM iptv_scans 
        WHERE provider_name IS NOT NULL 
        AND provider_name != ''
        AND provider_count > 1
        GROUP BY provider_name, provider_count
        ORDER BY provider_count DESC, provider_name ASC
    ";
    
    $resellerResult = $conn->query($resellerQuery);
    
    if (!$resellerResult) {
        throw new Exception("Query failed: " . $conn->error);
    }
    
    $resellers = [];
    
    while ($row = $resellerResult->fetch_assoc()) {
        $domains = !empty($row['domains']) ? array_unique(array_filter(explode('|||', $row['domains']))) : [];
        $ips = !empty($row['ips']) ? array_unique(array_filter(explode('|||', $row['ips']))) : [];
        
        // Get upstream providers for each IP
        $upstreamProviders = [];
        
        if (count($ips) > 0) {
            foreach ($ips as $ip) {
                if (empty($ip)) continue;
                
                $upstreamQuery = "
                    SELECT DISTINCT 
                        provider_name,
                        domain,
                        COALESCE(domain_age_days, 0) as domain_age_days,
                        COALESCE(upstream_score, 0) as upstream_score
                    FROM iptv_scans 
                    WHERE resolved_ip = ? 
                    AND COALESCE(is_likely_upstream, 0) = 1
                    AND provider_name IS NOT NULL
                    AND provider_name != ''
                    AND provider_name != ?
                    ORDER BY domain_age_days DESC, upstream_score DESC
                    LIMIT 5
                ";
                
                $stmt = $conn->prepare($upstreamQuery);
                if (!$stmt) {
                    continue; // Skip if prepare fails
                }
                
                $stmt->bind_param("ss", $ip, $row['provider_name']);
                $stmt->execute();
                $upstreamResult = $stmt->get_result();
                
                while ($upstream = $upstreamResult->fetch_assoc()) {
                    $upstreamProviders[] = [
                        'name' => $upstream['provider_name'],
                        'domain' => $upstream['domain'],
                        'age_days' => (int)$upstream['domain_age_days'],
                        'upstream_score' => (float)$upstream['upstream_score'],
                        'shared_ip' => $ip
                    ];
                }
                $stmt->close();
            }
        }
        
        $resellers[] = [
            'name' => $row['provider_name'],
            'domain_count' => (int)$row['provider_count'],
            'domains' => $domains,
            'ips' => $ips,
            'avg_age_days' => round((float)$row['avg_age'], 1),
            'last_seen' => $row['last_seen'],
            'upstream_providers' => array_values(array_unique($upstreamProviders, SORT_REGULAR))
        ];
    }
    
    // Get relationship network data - simplified query
    $relationships = [];
    
    $networkQuery = "
        SELECT 
            t1.provider_name as reseller,
            t2.provider_name as upstream,
            t1.resolved_ip as shared_ip,
            COUNT(DISTINCT t1.domain) as connection_strength
        FROM iptv_scans t1
        INNER JOIN iptv_scans t2 ON t1.resolved_ip = t2.resolved_ip
        WHERE t1.provider_count > 1 
        AND COALESCE(t2.is_likely_upstream, 0) = 1
        AND t1.provider_name IS NOT NULL
        AND t2.provider_name IS NOT NULL
        AND t1.provider_name != t2.provider_name
        GROUP BY t1.provider_name, t2.provider_name, t1.resolved_ip
        ORDER BY connection_strength DESC
        LIMIT 100
    ";
    
    $networkResult = $conn->query($networkQuery);
    
    if ($networkResult) {
        while ($row = $networkResult->fetch_assoc()) {
            $relationships[] = [
                'reseller' => $row['reseller'],
                'upstream' => $row['upstream'],
                'shared_ip' => $row['shared_ip'],
                'strength' => (int)$row['connection_strength']
            ];
        }
    }
    
    $conn->close();
    
    // Clear any buffered output and send JSON
    ob_end_clean();
    
    echo json_encode([
        'success' => true,
        'resellers' => $resellers,
        'relationships' => $relationships,
        'total_resellers' => count($resellers),
        'timestamp' => date('Y-m-d H:i:s')
    ], JSON_PRETTY_PRINT);
    
} catch (Exception $e) {
    ob_end_clean();
    http_response_code(200); // Change to 200 so JavaScript can read the error
    echo json_encode([
        'success' => false,
        'error' => $e->getMessage(),
        'file' => basename($e->getFile()),
        'line' => $e->getLine()
    ]);
}
?>
                    upstream_score
                FROM iptv_scans 
                WHERE resolved_ip = ? 
                AND is_likely_upstream = 1
                AND provider_name != ?
                ORDER BY domain_age_days DESC, upstream_score DESC
                LIMIT 5
            ";
            
            $stmt = $conn->prepare($upstreamQuery);
            $stmt->bind_param("ss", $ip, $row['provider_name']);
            $stmt->execute();
            $upstreamResult = $stmt->get_result();
            
            while ($upstream = $upstreamResult->fetch_assoc()) {
                $upstreamProviders[] = [
                    'name' => $upstream['provider_name'],
                    'domain' => $upstream['domain'],
                    'age_days' => (int)$upstream['domain_age_days'],
                    'upstream_score' => (float)$upstream['upstream_score'],
                    'shared_ip' => $ip
                ];
            }
            $stmt->close();
        }
        
        $resellers[] = [
            'name' => $row['provider_name'],
            'domain_count' => (int)$row['provider_count'],
            'domains' => $domains,
            'ips' => $ips,
            'avg_age_days' => round((float)$row['avg_age'], 1),
            'last_seen' => $row['last_seen'],
            'upstream_providers' => array_values(array_unique($upstreamProviders, SORT_REGULAR))
        ];
    }
    
    // Get relationship network data
    $networkQuery = "
        SELECT 
            t1.provider_name as reseller,
            t2.provider_name as upstream,
            t1.resolved_ip as shared_ip,
            COUNT(DISTINCT t1.domain) as connection_strength
        FROM iptv_scans t1
        INNER JOIN iptv_scans t2 ON t1.resolved_ip = t2.resolved_ip
        WHERE t1.provider_count > 1 
        AND t2.is_likely_upstream = 1
        AND t1.provider_name != t2.provider_name
        GROUP BY t1.provider_name, t2.provider_name, t1.resolved_ip
        ORDER BY connection_strength DESC
    ";
    
    $networkResult = $conn->query($networkQuery);
    $relationships = [];
    
    if ($networkResult) {
        while ($row = $networkResult->fetch_assoc()) {
            $relationships[] = [
                'reseller' => $row['reseller'],
                'upstream' => $row['upstream'],
                'shared_ip' => $row['shared_ip'],
                'strength' => (int)$row['connection_strength']
            ];
        }
    }
    
    $conn->close();
    
    // Clear any buffered output and send JSON
    ob_end_clean();
    
    echo json_encode([
        'success' => true,
        'resellers' => $resellers,
        'relationships' => $relationships,
        'total_resellers' => count($resellers),
        'timestamp' => date('Y-m-d H:i:s')
    ], JSON_PRETTY_PRINT);
    
} catch (Exception $e) {
    ob_end_clean();
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => $e->getMessage()
    ]);
}
?>
