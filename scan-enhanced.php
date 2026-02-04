<?php
/**
 * IPTV Forensics Tool - Enhanced Scanning Module
 * Adds: ASN analysis, nameserver clustering, SSL cert parsing, registration pattern detection
 */

// Enable error reporting for debugging
error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);

class IPTVScan {
    private $db;
    private $known_datacenters = [];
    private $datacenter_asns = [
        '14061' => 'DigitalOcean',
        '16509' => 'Amazon AWS',
        '8452' => 'TeData',
        '39798' => 'Ip-Provider',
        '9304' => 'HiNet',
        '8560' => 'IONOS',
        '12389' => 'Rostelecom',
        '2119' => 'Telenor',
        '3320' => 'Deutsche Telekom',
        '31034' => 'Aruba',
        '29140' => 'Hosteurope',
        '49453' => 'Global Layer',
    ];

    public function __construct() {
        $this->loadConfig();
        $this->initDB();
        $this->loadDatacenters();
    }

    private function loadConfig() {
        if (file_exists('config.php')) {
            require_once 'config.php';
        }
    }

    private function initDB() {
        try {
            $this->db = new mysqli(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME);
            if ($this->db->connect_error) {
                throw new Exception("Database connection failed: " . $this->db->connect_error);
            }
            $this->db->set_charset("utf8mb4");
        } catch (Exception $e) {
            die(json_encode(['success' => false, 'error' => $e->getMessage()]));
        }
    }

    private function loadDatacenters() {
        global $KNOWN_DATACENTERS;
        if (isset($KNOWN_DATACENTERS) && is_array($KNOWN_DATACENTERS)) {
            $this->known_datacenters = $KNOWN_DATACENTERS;
        } else {
            // Fallback if not defined in config
            $this->known_datacenters = [
                'ovh', 'hetzner', 'linode', 'digitalocean', 'vultr',
                'contabo', 'scaleway', 'arubacloud', 'aws', 'azure', 'google cloud'
            ];
        }
    }

    public function scanHost($url, $provider_name = '', $provider_website = '') {
        try {
            $domain = $this->extractDomain($url);
            if (!$domain) {
                return $this->respondError("Invalid URL format", 400);
            }

            $ip = $this->resolveIP($domain);
            if (!$ip) {
                return $this->respondError("Failed to resolve IP", 400);
            }

            // Collect all enhanced data
            $ipInfo = $this->fetchIPInfo($ip);
            $asnData = $this->analyzeASN($ip, $ipInfo['asn'] ?? null);
            $nameservers = $this->getNameservers($domain);
            $nsHash = $this->hashNameservers($nameservers);
            $sslData = $this->getSSLCertificateData($domain);
            $sslHash = $this->hashSSLCert($sslData);
            $domainRegData = $this->getDomainRegistrationData($domain);
            $panelInfo = $this->detectIPTVPanelEnhanced($url, $domain);
            $domainAge = $this->estimateDomainAge($domain);
            $existing = $this->getExistingRecord($domain);

            // Calculate confidence scores
            $asnConfidence = $this->calculateASNConfidence($asnData, $existing);
            $nsConfidence = $this->calculateNameserverConfidence($nsHash, $existing);
            $certConfidence = $this->calculateCertConfidence($sslHash, $existing);
            $regConfidence = $this->calculateRegistrationConfidence($domainRegData, $existing, $domainAge);

            // Build comprehensive data
            $providers = $this->buildProviderList($provider_name, $existing);
            $compositeConfidence = $this->calculateCompositeConfidence(
                $asnConfidence,
                $nsConfidence,
                $certConfidence,
                $regConfidence,
                count($providers)
            );

            // Check for baseline matches
            $domainRegData['provider_name_lookup'] = implode(' | ', $providers ?? []);
            $baselineMatches = $this->checkBaselineMatches($domain, $ip, $nsHash, $sslHash, $asnData['asn_block'] ?? null, $domainRegData);
            
            // Boost confidence if baselines match
            if (!empty($baselineMatches)) {
                $compositeConfidence = min(100, $compositeConfidence + (count($baselineMatches) * 15));
                foreach ($baselineMatches as $match) {
                    if ($match['type'] === 'nameserver') $nsConfidence = min(100, $nsConfidence + 20);
                    if ($match['type'] === 'ssl_cert') $certConfidence = min(100, $certConfidence + 20);
                    if ($match['type'] === 'asn') $asnConfidence = min(100, $asnConfidence + 15);
                    if ($match['type'] === 'ip') $asnConfidence = min(100, $asnConfidence + 10);
                }
            }

            $data = [
                'provider_name' => implode(' | ', $providers),
                'provider_count' => count($providers),
                'provider_website' => $provider_website ?: null,
                'original_url' => $url,
                'domain' => $domain,
                'resolved_ip' => $ip,
                'asn' => $ipInfo['asn'] ?? null,
                'asn_block' => $asnData['asn_block'] ?? null,
                'asn_name' => $asnData['asn_name'] ?? null,
                'organization' => $ipInfo['org'] ?? null,
                'country_code' => $ipInfo['country'] ?? null,
                'country_name' => $ipInfo['country_name'] ?? null,
                'nameserver_hash' => $nsHash,
                'nameservers' => implode(', ', array_slice($nameservers, 0, 5)),
                'ssl_cert_hash' => $sslHash,
                'ssl_issuer' => $sslData['issuer'] ?? null,
                'ssl_common_names' => implode(', ', $sslData['common_names'] ?? []),
                'domain_registrar' => $domainRegData['registrar'] ?? null,
                'domain_reg_date' => $domainRegData['reg_date'] ?? null,
                'domain_reg_email' => $domainRegData['email'] ?? null,
                'domain_age_days' => $domainAge,
                'panel_type' => $panelInfo['type'] ?? null,
                'panel_fingerprint' => $panelInfo['fingerprint'] ?? null,
                'registration_pattern' => $this->detectRegistrationPattern($domainRegData, $existing),
                'confidence_score' => $compositeConfidence,
                'asn_reseller_confidence' => $asnConfidence,
                'ns_reseller_confidence' => $nsConfidence,
                'cert_reseller_confidence' => $certConfidence,
                'reg_pattern_confidence' => $regConfidence,
                'relationship_reasons' => $this->buildRelationshipReasons(
                    $asnConfidence, $nsConfidence, $certConfidence, $regConfidence
                ),
                'is_datacenter_reseller' => ($asnConfidence > 60) ? 1 : 0,
                'is_likely_upstream' => ($compositeConfidence > 75 && $domainAge > 365) ? 1 : 0,
                'upstream_score' => $compositeConfidence,
                'baseline_matches' => $baselineMatches
            ];

            $this->saveToDatabase($data);
            return $this->respondSuccess($data);

        } catch (Exception $e) {
            return $this->respondError("Scan failed: " . $e->getMessage(), 500);
        }
    }

    // ASN Analysis
    private function analyzeASN($ip, $asn) {
        $asnInfo = $this->fetchASNInfo($asn);
        $asnBlock = $this->extractASNBlock($asn);

        return [
            'asn' => $asn,
            'asn_block' => $asnBlock,
            'asn_name' => $asnInfo['name'] ?? null,
            'is_datacenter' => $this->isDatacenterASN($asn)
        ];
    }

    private function fetchASNInfo($asn) {
        if (!$asn) return [];
        
        $url = 'https://ipinfo.io/api/asn/' . urlencode($asn);
        $context = stream_context_create([
            'http' => ['timeout' => 5, 'user_agent' => 'IPTV-Forensics/1.0']
        ]);
        
        $response = @file_get_contents($url, false, $context);
        if ($response) {
            $data = json_decode($response, true);
            return ['name' => $data['name'] ?? null];
        }
        return [];
    }

    private function extractASNBlock($asn) {
        if (!$asn) return null;
        preg_match('/\d+/', $asn, $matches);
        return $matches[0] ?? null;
    }

    private function isDatacenterASN($asn) {
        if (!$asn) return false;
        $asnNum = preg_replace('/[^0-9]/', '', $asn);
        return isset($this->datacenter_asns[$asnNum]);
    }

    private function calculateASNConfidence($asnData, $existing) {
        if (!$asnData['asn_block']) return 0;

        $score = 0;
        if ($asnData['is_datacenter']) $score += 60;

        if ($existing && $existing['asn_block'] === $asnData['asn_block']) {
            $score += 30;
        }

        return min(100, $score);
    }

    // Nameserver Clustering
    private function getNameservers($domain) {
        $nameservers = @dns_get_record($domain, DNS_NS);
        if (!$nameservers) return [];

        $servers = [];
        foreach ($nameservers as $ns) {
            $servers[] = strtolower($ns['target']);
        }
        return array_unique($servers);
    }

    private function hashNameservers($nameservers) {
        if (empty($nameservers)) return null;
        sort($nameservers);
        return hash('sha256', implode('|', $nameservers));
    }

    private function calculateNameserverConfidence($nsHash, $existing) {
        if (!$nsHash) return 0;
        if (!$existing || !$existing['nameserver_hash']) return 0;

        if ($existing['nameserver_hash'] === $nsHash) {
            return 90; // Same nameservers = strong reseller signal
        }

        return 0;
    }

    // SSL Certificate Analysis
    private function getSSLCertificateData($domain) {
        $context = stream_context_create([
            'ssl' => [
                'capture_peer_cert' => true,
                'verify_peer' => false,
                'verify_peer_name' => false
            ]
        ]);

        $fp = @stream_socket_client("ssl://{$domain}:443", $errno, $errstr, 5, STREAM_CLIENT_CONNECT, $context);
        if (!$fp) return ['common_names' => [], 'issuer' => null];

        $certData = stream_context_get_params($fp);
        @fclose($fp);

        if (!isset($certData['options']['ssl']['peer_certificate'])) {
            return ['common_names' => [], 'issuer' => null];
        }

        $cert = openssl_x509_parse($certData['options']['ssl']['peer_certificate']);
        if (!$cert) return ['common_names' => [], 'issuer' => null];

        $commonNames = [];
        if (isset($cert['subject']['CN'])) {
            $commonNames[] = $cert['subject']['CN'];
        }
        if (isset($cert['extensions']['subjectAltName'])) {
            preg_match_all('/DNS:([^,]+)/', $cert['extensions']['subjectAltName'], $matches);
            $commonNames = array_merge($commonNames, $matches[1]);
        }

        return [
            'common_names' => array_unique($commonNames),
            'issuer' => $cert['issuer']['O'] ?? null,
            'self_signed' => (isset($cert['issuer']['CN']) && $cert['issuer']['CN'] === ($cert['subject']['CN'] ?? '')) ? 1 : 0
        ];
    }

    private function hashSSLCert($sslData) {
        if (empty($sslData['common_names'])) return null;
        sort($sslData['common_names']);
        return hash('sha256', implode('|', $sslData['common_names']));
    }

    private function calculateCertConfidence($certHash, $existing) {
        if (!$certHash) return 0;
        if (!$existing || !$existing['ssl_cert_hash']) return 0;

        if ($existing['ssl_cert_hash'] === $certHash) {
            return 85; // Shared SSL cert = strong reseller signal
        }

        return 0;
    }

    // Domain Registration Analysis
    private function getDomainRegistrationData($domain) {
        if (!defined('IP2WHOIS_API_KEY') || !IP2WHOIS_API_KEY) {
            return [];
        }

        $url = IP2WHOIS_API_URL . '?key=' . IP2WHOIS_API_KEY . '&domain=' . urlencode($domain);
        $context = stream_context_create([
            'http' => ['timeout' => 10, 'user_agent' => 'IPTV-Forensics/1.0']
        ]);

        $response = @file_get_contents($url, false, $context);
        if (!$response) return [];

        $data = json_decode($response, true);
        if (!$data) return [];

        return [
            'registrar' => $data['registrar'] ?? null,
            'reg_date' => $data['create_date'] ?? null,
            'email' => $data['registrant_email'] ?? null,
            'org' => $data['registrant_organization'] ?? null
        ];
    }

    private function calculateRegistrationConfidence($regData, $existing, $domainAge) {
        $score = 0;

        if (!$existing) return $score;

        // Check for batch registration (same email/registrar)
        if ($regData['email'] && $existing['domain_reg_email'] === $regData['email']) {
            $score += 50;
        }
        if ($regData['registrar'] && $existing['domain_registrar'] === $regData['registrar']) {
            $score += 30;
        }

        // Check for bulk registration pattern (similar registration dates)
        if ($regData['reg_date'] && $existing['domain_reg_date']) {
            $regTime1 = strtotime($regData['reg_date']);
            $regTime2 = strtotime($existing['domain_reg_date']);
            if ($regTime1 && $regTime2) {
                $dayDiff = abs(($regTime1 - $regTime2) / 86400);
                if ($dayDiff < 7) $score += 40; // Registered within a week
                elseif ($dayDiff < 30) $score += 20;
            }
        }

        return min(100, $score);
    }

    private function detectRegistrationPattern($regData, $existing) {
        if (!$existing) return null;

        if ($regData['email'] && $existing['domain_reg_email'] === $regData['email']) {
            if ($regData['registrar'] && $existing['domain_registrar'] === $regData['registrar']) {
                return 'batch_registration';
            }
            return 'same_registrant';
        }

        return null;
    }

    // Enhanced Panel Detection
    private function detectIPTVPanelEnhanced($url, $domain) {
        $fingerprint = null;
        $type = null;

        // Try common IPTV panel endpoints
        $endpoints = [
            '/player_api.php' => 'xstream',
            '/get_live_categories.php' => 'xstream',
            '/api/v2/panel' => 'mag_box',
            '/live_category_list.php' => 'xstream'
        ];

        foreach ($endpoints as $endpoint => $panelType) {
            $testUrl = $url . $endpoint;
            $response = $this->curlGet($testUrl, 3);

            if ($response && strlen($response) > 10) {
                $type = $panelType;
                $fingerprint = hash('md5', substr($response, 0, 200));
                break;
            }
        }

        return ['type' => $type, 'fingerprint' => $fingerprint];
    }

    // Helper Functions
    private function calculateCompositeConfidence($asnConf, $nsConf, $certConf, $regConf, $providerCount) {
        $weights = [
            'asn' => 0.35,
            'ns' => 0.30,
            'cert' => 0.20,
            'reg' => 0.15
        ];

        $score = ($asnConf * $weights['asn']) +
                 ($nsConf * $weights['ns']) +
                 ($certConf * $weights['cert']) +
                 ($regConf * $weights['reg']);

        // Boost if multiple providers detected
        if ($providerCount > 1) {
            $score = min(100, $score + 15);
        }

        return (int)$score;
    }

    private function buildRelationshipReasons($asnConf, $nsConf, $certConf, $regConf) {
        $reasons = [];

        if ($asnConf > 50) $reasons[] = "Shared ASN ($asnConf%)";
        if ($nsConf > 50) $reasons[] = "Shared Nameservers ($nsConf%)";
        if ($certConf > 50) $reasons[] = "Shared SSL Cert ($certConf%)";
        if ($regConf > 50) $reasons[] = "Batch Registration ($regConf%)";

        return implode(', ', $reasons) ?: 'Multiple domains on shared infrastructure';
    }

    private function buildProviderList($providerName, $existing) {
        $providers = [];

        if ($existing && $existing['provider_name']) {
            $providers = explode(' | ', $existing['provider_name']);
        }

        if ($providerName && !in_array($providerName, $providers)) {
            $providers[] = $providerName;
        }

        return $providers;
    }

    private function checkBaselineMatches($domain, $resolvedIp, $nsHash, $sslHash, $asnBlock, $domainRegData) {
        $matches = [];
        
        try {
            $stmt = $this->db->prepare("
                SELECT b.id, b.service_name, b.baseline_domain,
                       GROUP_CONCAT(a.alias_name SEPARATOR ' | ') AS aliases
                FROM baseline_services b
                LEFT JOIN service_aliases a ON a.baseline_id = b.id
                WHERE b.status IN ('active', 'pending', 'approved')
                GROUP BY b.id
                LIMIT 200
            ");
            
            if (!$stmt) return $matches;
            
            $stmt->execute();
            $result = $stmt->get_result();
            
            while ($baseline = $result->fetch_assoc()) {
                $aliases = !empty($baseline['aliases']) ? explode(' | ', $baseline['aliases']) : [];
                $baselineName = $baseline['service_name'] ?? '';

                // Direct domain match (highest confidence)
                if (!empty($baseline['baseline_domain']) && $baseline['baseline_domain'] === $domain) {
                    $matches[] = [
                        'baseline_id' => $baseline['id'],
                        'baseline_name' => $baseline['service_name'],
                        'aliases' => $aliases,
                        'type' => 'direct_domain',
                        'match_reason' => 'Direct domain match with baseline',
                        'confidence' => 95
                    ];
                }

                // Alias domain match (if alias is a domain)
                if (!empty($aliases) && in_array($domain, $aliases, true)) {
                    $matches[] = [
                        'baseline_id' => $baseline['id'],
                        'baseline_name' => $baseline['service_name'],
                        'aliases' => $aliases,
                        'type' => 'alias_domain',
                        'match_reason' => 'Matched baseline alias domain',
                        'confidence' => 90
                    ];
                }

                // Provider name match (soft match)
                if (!empty($baselineName) && !empty($domainRegData['provider_name_lookup'])) {
                    $providerLookup = $domainRegData['provider_name_lookup'];
                    if (stripos($providerLookup, $baselineName) !== false) {
                        $matches[] = [
                            'baseline_id' => $baseline['id'],
                            'baseline_name' => $baseline['service_name'],
                            'aliases' => $aliases,
                            'type' => 'provider_name',
                            'match_reason' => 'Provider name contains baseline name',
                            'confidence' => 55
                        ];
                    }
                    foreach ($aliases as $alias) {
                        if (!empty($alias) && stripos($providerLookup, $alias) !== false) {
                            $matches[] = [
                                'baseline_id' => $baseline['id'],
                                'baseline_name' => $baseline['service_name'],
                                'aliases' => $aliases,
                                'type' => 'provider_name',
                                'match_reason' => 'Provider name contains baseline alias',
                                'confidence' => 50
                            ];
                            break;
                        }
                    }
                }

                // Fetch baseline's scanned data from history
                $baselineData = !empty($baseline['baseline_domain']) ? $this->getBaselineData($baseline['baseline_domain']) : null;
                if (!empty($baseline['baseline_domain'])) {
                    if (!$baselineData) {
                        $baselineData = $this->resolveBaselineSignals($baseline['baseline_domain']);
                    } else {
                        $needsFallback = empty($baselineData['nameserver_hash'])
                            && empty($baselineData['ssl_cert_hash'])
                            && empty($baselineData['resolved_ip']);
                        if ($needsFallback) {
                            $fallback = $this->resolveBaselineSignals($baseline['baseline_domain']);
                            if ($fallback) {
                                $baselineData = array_merge($baselineData, array_filter($fallback));
                            }
                        }
                    }
                }
                if (!$baselineData) continue;
                                // Check resolved IP match
                                if (!empty($resolvedIp) && !empty($baselineData['resolved_ip']) && $baselineData['resolved_ip'] === $resolvedIp) {
                                    $matches[] = [
                                        'baseline_id' => $baseline['id'],
                                        'baseline_name' => $baseline['service_name'],
                                        'aliases' => $aliases,
                                        'type' => 'ip',
                                        'match_reason' => 'Same resolved IP',
                                        'confidence' => 75
                                    ];
                                }
                
                // Check nameserver match
                if ($nsHash && $baselineData['nameserver_hash'] === $nsHash) {
                    $matches[] = [
                        'baseline_id' => $baseline['id'],
                        'baseline_name' => $baseline['service_name'],
                        'aliases' => $aliases,
                        'type' => 'nameserver',
                        'match_reason' => 'Same nameserver configuration',
                        'confidence' => 85
                    ];
                }
                
                // Check SSL certificate match
                if ($sslHash && $baselineData['ssl_cert_hash'] === $sslHash) {
                    $matches[] = [
                        'baseline_id' => $baseline['id'],
                        'baseline_name' => $baseline['service_name'],
                        'aliases' => $aliases,
                        'type' => 'ssl_cert',
                        'match_reason' => 'Same SSL certificate',
                        'confidence' => 90
                    ];
                }
                
                // Check ASN match
                if ($asnBlock && $baselineData['asn_block'] === $asnBlock) {
                    $matches[] = [
                        'baseline_id' => $baseline['id'],
                        'baseline_name' => $baseline['service_name'],
                        'aliases' => $aliases,
                        'type' => 'asn',
                        'match_reason' => 'Same ASN block',
                        'confidence' => 70
                    ];
                }
                
                // Check registrar match
                if (!empty($domainRegData['registrar']) && $baselineData['domain_registrar'] === $domainRegData['registrar']) {
                    $matches[] = [
                        'baseline_id' => $baseline['id'],
                        'baseline_name' => $baseline['service_name'],
                        'aliases' => $aliases,
                        'type' => 'registrar',
                        'match_reason' => 'Same domain registrar',
                        'confidence' => 65
                    ];
                }
            }
            
            $stmt->close();
        } catch (Exception $e) {
            // Silently fail, baselines are optional
        }
        
        return $matches;
    }

    private function getBaselineData($domain) {
        try {
            $stmt = $this->db->prepare("
                SELECT resolved_ip, nameserver_hash, ssl_cert_hash, asn_block, domain_registrar, registration_pattern
                FROM scanned_hosts 
                WHERE domain = ?
                ORDER BY created_at DESC
                LIMIT 1
            ");
            
            if (!$stmt) return null;
            
            $stmt->bind_param("s", $domain);
            $stmt->execute();
            $result = $stmt->get_result();
            $data = $result->fetch_assoc();
            $stmt->close();
            
            return $data;
        } catch (Exception $e) {
            return null;
        }
    }

    private function resolveBaselineSignals($domain) {
        try {
            $resolved_ip = gethostbyname($domain);
            if ($resolved_ip === $domain) {
                $resolved_ip = null;
            }

            $nameservers = $this->getNameservers($domain);
            $nameserver_hash = $this->hashNameservers($nameservers);
            $sslData = $this->getSSLCertificateData($domain);
            $ssl_cert_hash = $this->hashSSLCert($sslData);

            $asn_block = null;
            if (!empty($resolved_ip)) {
                $ipInfo = $this->fetchIPInfo($resolved_ip);
                $asnData = $this->analyzeASN($resolved_ip, $ipInfo['asn'] ?? null);
                $asn_block = $asnData['asn_block'] ?? null;
            }

            return [
                'resolved_ip' => $resolved_ip,
                'nameserver_hash' => $nameserver_hash,
                'ssl_cert_hash' => $ssl_cert_hash,
                'asn_block' => $asn_block,
                'domain_registrar' => null,
                'registration_pattern' => null
            ];
        } catch (Exception $e) {
            return null;
        }
    }

    private function getExistingRecord($domain) {
        $stmt = $this->db->prepare("SELECT * FROM scanned_hosts WHERE domain = ?");
        if (!$stmt) return null;

        $stmt->bind_param("s", $domain);
        $stmt->execute();
        $result = $stmt->get_result();
        $row = $result->fetch_assoc();
        $stmt->close();

        return $row;
    }

    private function extractDomain($url) {
        if (!preg_match("~^(?:f|ht)tps?://~i", $url)) {
            $url = "http://" . $url;
        }
        $domain = parse_url($url, PHP_URL_HOST);
        if (!$domain) return null;
        return preg_replace('/^www\./', '', $domain);
    }

    private function resolveIP($domain) {
        $ip = gethostbyname($domain);
        if ($ip === $domain) return null;
        if (!filter_var($ip, FILTER_VALIDATE_IP)) return null;
        return $ip;
    }

    private function fetchIPInfo($ip) {
        if (!defined('IPINFO_API_KEY') || !IPINFO_API_KEY) {
            return [];
        }

        $url = 'https://ipinfo.io/' . $ip . '?token=' . IPINFO_API_KEY;
        $context = stream_context_create([
            'http' => ['timeout' => 5, 'user_agent' => 'IPTV-Forensics/1.0']
        ]);

        $response = @file_get_contents($url, false, $context);
        if ($response) {
            return json_decode($response, true) ?? [];
        }
        return [];
    }

    private function estimateDomainAge($domain) {
        if (!defined('IP2WHOIS_API_KEY') || !IP2WHOIS_API_KEY) {
            return null;
        }

        $url = IP2WHOIS_API_URL . '?key=' . IP2WHOIS_API_KEY . '&domain=' . urlencode($domain);
        $context = stream_context_create([
            'http' => ['timeout' => 10, 'user_agent' => 'IPTV-Forensics/1.0']
        ]);

        $response = @file_get_contents($url, false, $context);
        if ($response) {
            $data = json_decode($response, true);
            if (isset($data['domain_age']) && is_numeric($data['domain_age'])) {
                return (int)$data['domain_age'];
            }
        }
        return null;
    }

    private function curlGet($url, $timeout = 5) {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($ch, CURLOPT_USERAGENT, 'IPTV-Forensics/1.0');

        $response = curl_exec($ch);
        curl_close($ch);

        return $response;
    }

    private function saveToDatabase($data) {
        $sql = "REPLACE INTO scanned_hosts 
                (provider_name, provider_count, provider_website, original_url, domain, resolved_ip, asn, asn_block, 
                 asn_name, organization, country_code, country_name, nameserver_hash, nameservers,
                 ssl_cert_hash, ssl_issuer, ssl_common_names, domain_registrar, domain_reg_date,
                 domain_reg_email, panel_type, panel_fingerprint, domain_age_days, registration_pattern,
                 confidence_score, asn_reseller_confidence, ns_reseller_confidence, 
                 cert_reseller_confidence, reg_pattern_confidence, relationship_reasons,
                 is_datacenter_reseller, is_likely_upstream, upstream_score) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

        $stmt = $this->db->prepare($sql);
        if (!$stmt) {
            throw new Exception("Database prepare failed: " . $this->db->error);
        }

        // Type string: 33 parameters
        // s=string, i=integer
        // provider_name, provider_count, provider_website, original_url, domain, resolved_ip, asn, asn_block, asn_name, organization, 
        // country_code, country_name, nameserver_hash, nameservers, ssl_cert_hash, ssl_issuer, ssl_common_names, 
        // domain_registrar, domain_reg_date, domain_reg_email, panel_type, panel_fingerprint, domain_age_days, 
        // registration_pattern, confidence_score, asn_reseller_confidence, ns_reseller_confidence, 
        // cert_reseller_confidence, reg_pattern_confidence, relationship_reasons, is_datacenter_reseller, 
        // is_likely_upstream, upstream_score
        $stmt->bind_param(
            "sissssssssssssssssssssisiiiiisiii",
            $data['provider_name'], 
            $data['provider_count'],
            $data['provider_website'], 
            $data['original_url'],
            $data['domain'], 
            $data['resolved_ip'], 
            $data['asn'], 
            $data['asn_block'],
            $data['asn_name'], 
            $data['organization'], 
            $data['country_code'], 
            $data['country_name'],
            $data['nameserver_hash'], 
            $data['nameservers'],
            $data['ssl_cert_hash'], 
            $data['ssl_issuer'], 
            $data['ssl_common_names'],
            $data['domain_registrar'], 
            $data['domain_reg_date'], 
            $data['domain_reg_email'],
            $data['panel_type'], 
            $data['panel_fingerprint'], 
            $data['domain_age_days'],
            $data['registration_pattern'], 
            $data['confidence_score'],
            $data['asn_reseller_confidence'], 
            $data['ns_reseller_confidence'],
            $data['cert_reseller_confidence'], 
            $data['reg_pattern_confidence'],
            $data['relationship_reasons'], 
            $data['is_datacenter_reseller'],
            $data['is_likely_upstream'], 
            $data['upstream_score']
        );

        if (!$stmt->execute()) {
            throw new Exception("Database execute failed: " . $stmt->error);
        }

        $stmt->close();
    }

    private function respondSuccess($data) {
        header('Content-Type: application/json');
        echo json_encode(['success' => true, 'data' => $data]);
        exit;
    }

    private function respondError($message, $code = 500) {
        header('Content-Type: application/json');
        http_response_code($code);
        echo json_encode(['success' => false, 'error' => $message]);
        exit;
    }
}

// Handle scan request
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json');
    
    try {
        // Get JSON input
        $input = json_decode(file_get_contents('php://input'), true);
        
        // Support both JSON and form-urlencoded
        $url = $input['url'] ?? $_POST['url'] ?? null;
        $provider_name = $input['provider_name'] ?? $_POST['provider_name'] ?? '';
        $provider_website = $input['provider_website'] ?? $_POST['provider_website'] ?? '';
        
        if ($url) {
            $scanner = new IPTVScan();
            $scanner->scanHost($url, $provider_name, $provider_website);
        } else {
            http_response_code(400);
            echo json_encode(['success' => false, 'error' => 'Missing url parameter']);
        }
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'error' => 'Server error: ' . $e->getMessage(), 'trace' => $e->getTraceAsString()]);
    } catch (Error $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'error' => 'Fatal error: ' . $e->getMessage(), 'trace' => $e->getTraceAsString()]);
    }
}
?>
