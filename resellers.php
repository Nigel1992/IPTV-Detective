<?php
header('Content-Type: application/json');

$response = [
    'success' => true,
    'resellers' => [],
    'relationships' => [],
    'total_resellers' => 0,
    'timestamp' => date('Y-m-d H:i:s')
];

if (file_exists('config.php')) {
    try {
        require_once 'config.php';
        
        $conn = @mysqli_connect(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME);
        
        if ($conn) {
            // Get resellers with their domains and details
            $result = @mysqli_query($conn, "SELECT provider_name, provider_count FROM scanned_hosts WHERE provider_count > 1 ORDER BY provider_count DESC LIMIT 20");
            
            if ($result) {
                while ($row = @mysqli_fetch_assoc($result)) {
                    if (!empty($row['provider_name'])) {
                        $providerName = $row['provider_name'];
                        
                        // Get all domains for this provider
                        $domainQuery = "SELECT DISTINCT domain, resolved_ip, domain_age_days, panel_type FROM scanned_hosts WHERE provider_name = '" . mysqli_real_escape_string($conn, $providerName) . "' LIMIT 50";
                        $domainResult = @mysqli_query($conn, $domainQuery);
                        
                        $domains = [];
                        $ips = [];
                        
                        if ($domainResult) {
                            while ($d = @mysqli_fetch_assoc($domainResult)) {
                                $domains[] = [
                                    'domain' => $d['domain'],
                                    'ip' => $d['resolved_ip'],
                                    'age_days' => (int)$d['domain_age_days'],
                                    'panel_type' => $d['panel_type']
                                ];
                                
                                if (!empty($d['resolved_ip']) && !in_array($d['resolved_ip'], $ips)) {
                                    $ips[] = $d['resolved_ip'];
                                }
                            }
                        }
                        
                        // Find other providers sharing same IPs/domains
                        $relatedQuery = "SELECT DISTINCT provider_name FROM scanned_hosts WHERE (";
                        $conditions = [];
                        
                        foreach ($domains as $d) {
                            $conditions[] = "domain = '" . mysqli_real_escape_string($conn, $d['domain']) . "'";
                        }
                        
                        if (!empty($conditions)) {
                            $relatedQuery .= implode(" OR ", $conditions) . ") AND provider_name != '" . mysqli_real_escape_string($conn, $providerName) . "' LIMIT 10";
                            $relatedResult = @mysqli_query($conn, $relatedQuery);
                            
                            $upstream_providers = [];
                            if ($relatedResult) {
                                while ($up = @mysqli_fetch_assoc($relatedResult)) {
                                    $upstream_providers[] = [
                                        'name' => $up['provider_name'],
                                        'domain' => '',
                                        'age_days' => 0,
                                        'upstream_score' => 0,
                                        'shared_ip' => ''
                                    ];
                                }
                            }
                        } else {
                            $upstream_providers = [];
                        }
                        
                        $response['resellers'][] = [
                            'name' => $providerName,
                            'domain_count' => (int)$row['provider_count'],
                            'domains' => $domains,
                            'ips' => $ips,
                            'avg_age_days' => 0,
                            'last_seen' => date('Y-m-d H:i:s'),
                            'upstream_providers' => $upstream_providers
                        ];
                    }
                }
            }
            
            $response['total_resellers'] = count($response['resellers']);
            @mysqli_close($conn);
        }
    } catch (Exception $e) {
        // Silently fail
    }
}

echo json_encode($response);
?>