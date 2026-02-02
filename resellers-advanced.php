<?php
/**
 * IPTV Forensics Tool - Enhanced Reseller Detection API
 * Uses: ASN clustering, nameserver analysis, SSL cert patterns, registration data
 */

header('Content-Type: application/json');

$response = [
    'success' => true,
    'resellers' => [],
    'clusters' => [],
    'total_resellers' => 0,
    'timestamp' => date('Y-m-d H:i:s')
];

if (file_exists('config.php')) {
    try {
        require_once 'config.php';

        $conn = @mysqli_connect(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME);

        if ($conn) {
            // Ensure database is up to date
            @mysqli_query($conn, "ALTER TABLE scanned_hosts ADD COLUMN IF NOT EXISTS confidence_score INT DEFAULT 0");

            // Get resellers with enhanced confidence scores
            $result = @mysqli_query($conn, 
                "SELECT DISTINCT provider_name, COUNT(*) as domain_count, 
                        AVG(confidence_score) as avg_confidence,
                        GROUP_CONCAT(DISTINCT asn_block) as asn_blocks,
                        GROUP_CONCAT(DISTINCT nameserver_hash) as ns_hashes,
                        GROUP_CONCAT(DISTINCT ssl_cert_hash) as cert_hashes
                 FROM scanned_hosts 
                 WHERE provider_name IS NOT NULL AND provider_name != ''
                 GROUP BY provider_name
                 HAVING domain_count > 1
                 ORDER BY avg_confidence DESC, domain_count DESC
                 LIMIT 50");

            if ($result) {
                $clusterMap = [];

                while ($row = @mysqli_fetch_assoc($result)) {
                    if (!empty($row['provider_name'])) {
                        $providerName = $row['provider_name'];
                        $providers = array_map('trim', explode('|', $providerName));

                        // Get detailed domains for each provider
                        $allDomains = [];
                        $allIPs = [];
                        $asnClusters = [];
                        $nsClusters = [];
                        $certClusters = [];
                        $regPatterns = [];

                        foreach ($providers as $provider) {
                            $provider = trim($provider);
                            $domainQuery = "SELECT DISTINCT 
                                            domain, resolved_ip, domain_age_days, panel_type,
                                            confidence_score, asn_block, nameserver_hash, ssl_cert_hash,
                                            relationship_reasons, domain_registrar, registration_pattern,
                                            asn_reseller_confidence, ns_reseller_confidence,
                                            cert_reseller_confidence, reg_pattern_confidence
                                           FROM scanned_hosts 
                                           WHERE provider_name LIKE '%" . mysqli_real_escape_string($conn, $provider) . "%'
                                           ORDER BY domain_age_days DESC, confidence_score DESC
                                           LIMIT 100";

                            $domainResult = @mysqli_query($conn, $domainQuery);

                            if ($domainResult) {
                                while ($d = @mysqli_fetch_assoc($domainResult)) {
                                    $allDomains[] = [
                                        'domain' => $d['domain'],
                                        'ip' => $d['resolved_ip'],
                                        'age_days' => (int)$d['domain_age_days'],
                                        'panel_type' => $d['panel_type'],
                                        'confidence' => (int)$d['confidence_score'],
                                        'relationship_reason' => $d['relationship_reasons']
                                    ];

                                    if (!empty($d['resolved_ip']) && !in_array($d['resolved_ip'], $allIPs)) {
                                        $allIPs[] = $d['resolved_ip'];
                                    }

                                    // Track clustering evidence
                                    if ($d['asn_block']) {
                                        $asnClusters[$d['asn_block']] = ($asnClusters[$d['asn_block']] ?? 0) + 1;
                                    }
                                    if ($d['nameserver_hash']) {
                                        $nsClusters[$d['nameserver_hash']] = ($nsClusters[$d['nameserver_hash']] ?? 0) + 1;
                                    }
                                    if ($d['ssl_cert_hash']) {
                                        $certClusters[$d['ssl_cert_hash']] = ($certClusters[$d['ssl_cert_hash']] ?? 0) + 1;
                                    }
                                    if ($d['registration_pattern']) {
                                        $regPatterns[$d['registration_pattern']] = ($regPatterns[$d['registration_pattern']] ?? 0) + 1;
                                    }
                                }
                            }
                        }

                        // Find related providers (sharing infrastructure)
                        $relatedProviders = [];
                        if (!empty($allDomains)) {
                            $domainList = array_map(function($d) use ($conn) {
                                return "'" . mysqli_real_escape_string($conn, $d['domain']) . "'";
                            }, $allDomains);

                            $relatedQuery = "SELECT DISTINCT provider_name, COUNT(*) as shared_count
                                            FROM scanned_hosts 
                                            WHERE domain IN (" . implode(',', $domainList) . ")
                                            AND provider_name NOT LIKE '%" . mysqli_real_escape_string($conn, implode('|', $providers)) . "%'
                                            GROUP BY provider_name
                                            ORDER BY shared_count DESC
                                            LIMIT 10";

                            $relatedResult = @mysqli_query($conn, $relatedQuery);
                            if ($relatedResult) {
                                while ($rel = @mysqli_fetch_assoc($relatedResult)) {
                                    $relatedProviders[] = [
                                        'name' => $rel['provider_name'],
                                        'shared_domains' => (int)$rel['shared_count']
                                    ];
                                }
                            }
                        }

                        // Calculate cluster strength
                        $clusterStrength = [
                            'asn_clustering' => max($asnClusters ?: [0]) ?? 0,
                            'nameserver_clustering' => max($nsClusters ?: [0]) ?? 0,
                            'cert_clustering' => max($certClusters ?: [0]) ?? 0,
                            'registration_pattern_clustering' => max($regPatterns ?: [0]) ?? 0
                        ];

                        $response['resellers'][] = [
                            'name' => $providerName,
                            'providers' => $providers,
                            'domain_count' => (int)$row['domain_count'],
                            'domains' => array_slice($allDomains, 0, 50),
                            'unique_ips' => count($allIPs),
                            'ip_addresses' => array_slice($allIPs, 0, 10),
                            'confidence_score' => (int)round($row['avg_confidence']),
                            'cluster_evidence' => $clusterStrength,
                            'related_providers' => $relatedProviders,
                            'last_updated' => date('Y-m-d H:i:s')
                        ];

                        // Track clusters for visualization
                        $clusterId = hash('md5', $providerName);
                        $response['clusters'][] = [
                            'id' => $clusterId,
                            'provider' => $providerName,
                            'domains' => count($allDomains),
                            'ips' => count($allIPs),
                            'confidence' => (int)round($row['avg_confidence']),
                            'connections' => count($relatedProviders)
                        ];
                    }
                }
            }

            $response['total_resellers'] = count($response['resellers']);
            @mysqli_close($conn);
        } else {
            $response['success'] = false;
            $response['error'] = 'Database connection failed';
        }
    } catch (Exception $e) {
        $response['success'] = false;
        $response['error'] = $e->getMessage();
    }
}

echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
?>
