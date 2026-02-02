<?php
error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);
header('Content-Type: application/json');

require_once __DIR__ . '/config.php';

class IPTVForensicScanner {
    private $db;
    private $known_datacenters;
    
    public function __construct() {
        $this->known_datacenters = $GLOBALS['KNOWN_DATACENTERS'] ?? [];
        $this->connectDatabase();
    }
    
    private function connectDatabase() {
        $this->db = new mysqli(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME);
        if ($this->db->connect_error) {
            $this->respondError("Database connection failed: " . $this->db->connect_error, 500);
        }
        $this->db->set_charset("utf8mb4");
    }
    
    public function scanHost($url, $provider_name = '') {
        try {
            $originalUrl = $url;
            $domain = $this->extractDomain($url);
            $port = $this->extractPort($url);
            
            if (!$domain) {
                return $this->respondError("Invalid URL format", 400);
            }
            
            $ip = $this->resolveIP($domain);
            if (!$ip) {
                return $this->respondError("Failed to resolve IP address", 400);
            }
            
            $existing = $this->getExistingRecord($domain);
            $ipInfo = $this->fetchIPInfo($ip);
            $serverHeader = $this->getServerHeader($domain, $port);
            $panelInfo = $this->detectIPTVPanel($originalUrl, $domain, $port);
            $domainAge = $this->estimateDomainAge($domain);
            $sslInfo = ['domain' => null];
            $resellerData = $this->detectReseller($ipInfo, $serverHeader);
            
            $providers = [];
            $provider_count = 1;
            
            if ($existing) {
                $existingProviders = $existing['provider_name'] ? explode(' | ', $existing['provider_name']) : [];
                $providers = $existingProviders;
                
                if ($provider_name && !in_array($provider_name, $existingProviders)) {
                    $providers[] = $provider_name;
                    $provider_count = count($providers);
                    $resellerData['is_reseller'] = true;
                    $resellerData['probability'] = 100;
                } else {
                    $provider_count = count($providers);
                    if ($existing['provider_count'] > 1) {
                        $resellerData['is_reseller'] = true;
                        $resellerData['probability'] = 100;
                    }
                }
            } else {
                if ($provider_name) {
                    $providers[] = $provider_name;
                }
            }
            
            $upstreamScore = $this->calculateUpstreamScore($panelInfo, $domainAge, $sslInfo, $existing);
            
            // Find original provider on this IP
            $originalProvider = $this->findOriginalProvider($ip);
            
            $data = [
                'provider_name' => implode(' | ', $providers),
                'provider_count' => $provider_count,
                'original_url' => $url,
                'domain' => $domain,
                'resolved_ip' => $ip,
                'asn' => $ipInfo['asn'] ?? null,
                'organization' => $ipInfo['org'] ?? null,
                'country_code' => $ipInfo['country'] ?? null,
                'country_name' => $ipInfo['country_name'] ?? null,
                'server_header' => $serverHeader,
                'hosted_provider' => $ipInfo['provider'] ?? null,
                'panel_type' => $panelInfo['type'] ?? null,
                'domain_age_days' => $domainAge,
                'ssl_cert_domain' => $sslInfo['domain'] ?? null,
                'is_datacenter_reseller' => $resellerData['is_reseller'] ? 1 : 0,
                'reseller_probability' => $resellerData['probability'],
                'is_likely_upstream' => $upstreamScore >= 70 ? 1 : 0,
                'upstream_score' => $upstreamScore,
                'original_provider_info' => $originalProvider
            ];
            
            $this->saveToDatabase($data);
            return $this->respondSuccess($data);
            
        } catch (Exception $e) {
            return $this->respondError("Scan failed: " . $e->getMessage(), 500);
        }
    }
    
    private function getExistingRecord($domain) {
        $stmt = $this->db->prepare("SELECT * FROM scanned_hosts WHERE domain = ?");
        if (!$stmt) return null;
        $stmt->bind_param("s", $domain);
        $stmt->execute();
        $result = $stmt->get_result();
        $record = $result->fetch_assoc();
        $stmt->close();
        return $record;
    }
    
    private function findOriginalProvider($ip) {
        // Find all domains on this IP and return the oldest one (original provider)
        $stmt = $this->db->prepare("SELECT domain, provider_name, domain_age_days FROM scanned_hosts WHERE resolved_ip = ? ORDER BY domain_age_days DESC, created_at ASC LIMIT 10");
        if (!$stmt) return null;
        $stmt->bind_param("s", $ip);
        $stmt->execute();
        $result = $stmt->get_result();
        
        $domains = [];
        while ($row = $result->fetch_assoc()) {
            $domains[] = $row;
        }
        $stmt->close();
        
        if (empty($domains)) {
            return null;
        }
        
        // Return the oldest domain (most likely the original)
        return [
            'original_domain' => $domains[0]['domain'],
            'original_provider' => $domains[0]['provider_name'] ?? $domains[0]['domain'],
            'age_days' => $domains[0]['domain_age_days'],
            'related_domains' => count($domains),
            'all_domains' => $domains
        ];
    }
    
    private function detectIPTVPanel($fullUrl, $domain, $port = null) {
        $fullUrl = str_replace('https://', 'http://', $fullUrl);
        $urlLower = strtolower($fullUrl);
        
        if (stripos($urlLower, 'player_api.php') !== false) {
            return ['type' => 'Xtream Codes API'];
        }
        if (stripos($urlLower, 'get.php') !== false) {
            return ['type' => 'Xtream Codes Panel'];
        }
        if (stripos($urlLower, 'stalker_portal') !== false) {
            return ['type' => 'Stalker Portal'];
        }
        
        $response = $this->curlGet($fullUrl, 5);
        if ($response !== false && !empty($response)) {
            if (stripos($response, '#EXTM3U') !== false) {
                return ['type' => 'M3U Stream Provider'];
            }
            $decoded = json_decode($response, true);
            if ($decoded !== null && is_array($decoded)) {
                return ['type' => 'JSON API'];
            }
        }
        
        $scheme = 'http';
        $portStr = $port ? ':' . $port : '';
        $baseUrl = $scheme . '://' . $domain . $portStr;
        
        $xstreamCheck = $this->curlGet($baseUrl . '/player_api.php?username=test&password=test', 3);
        if ($xstreamCheck !== false && !empty($xstreamCheck)) {
            if (stripos($xstreamCheck, 'user_info') !== false || stripos($xstreamCheck, 'server_info') !== false) {
                return ['type' => 'Xtream Codes API'];
            }
        }
        
        return ['type' => null];
    }
    
    private function curlGet($url, $timeout = 3) {
        $url = str_replace('https://', 'http://', $url);
        if (!function_exists('curl_init')) return false;
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $timeout);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($ch, CURLOPT_USERAGENT, 'IPTV-Detective/1.0');
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($httpCode >= 200 && $httpCode < 500) {
            return $response;
        }
        return false;
    }
    
    private function estimateDomainAge($domain) {
        // Use IP2WHOIS API for accurate domain age from WHOIS data
        if (!defined('IP2WHOIS_API_KEY') || !IP2WHOIS_API_KEY) {
            return null;
        }
        
        $url = IP2WHOIS_API_URL . '?key=' . IP2WHOIS_API_KEY . '&domain=' . urlencode($domain);
        
        $context = stream_context_create([
            'http' => [
                'timeout' => 10,
                'user_agent' => 'IPTV-Forensics-Tool/1.0'
            ]
        ]);
        
        $response = @file_get_contents($url, false, $context);
        if ($response === false) {
            return null;
        }
        
        $data = json_decode($response, true);
        if (!$data || !isset($data['domain_age'])) {
            return null;
        }
        
        $age = (int)$data['domain_age'];
        if ($age >= 0 && $age < 36500) {
            return $age;
        }
        
        return null;
    }
    
    private function calculateUpstreamScore($panelInfo, $domainAge, $sslInfo, $existing) {
        $score = 0;
        if ($panelInfo['type']) $score += 30;
        if ($domainAge !== null) {
            if ($domainAge > 365) $score += 25;
            elseif ($domainAge > 180) $score += 15;
            elseif ($domainAge > 90) $score += 5;
        }
        if (!$existing || ($existing['provider_count'] ?? 1) == 1) $score += 15;
        return min(100, $score);
    }
    
    private function extractDomain($url) {
        if (!preg_match("~^(?:f|ht)tps?://~i", $url)) {
            $url = "http://" . $url;
        }
        $domain = parse_url($url, PHP_URL_HOST);
        if (!$domain) return null;
        return preg_replace('/^www\./', '', $domain);
    }
    
    private function extractPort($url) {
        if (!preg_match("~^(?:f|ht)tps?://~i", $url)) {
            $url = "http://" . $url;
        }
        $port = parse_url($url, PHP_URL_PORT);
        return $port ? (int)$port : null;
    }
    
    private function resolveIP($domain) {
        $ip = gethostbyname($domain);
        if ($ip === $domain) return null;
        if (!filter_var($ip, FILTER_VALIDATE_IP)) return null;
        return $ip;
    }
    
    private function fetchIPInfo($ip) {
        $info = ['asn' => null, 'org' => null, 'country' => null, 'country_name' => null, 'provider' => null];
        
        $url = 'https://ipinfo.io/' . $ip;
        if (defined('IPINFO_API_KEY') && IPINFO_API_KEY !== '') {
            $url .= '?token=' . IPINFO_API_KEY;
        }
        
        $context = stream_context_create([
            'http' => ['timeout' => 10, 'user_agent' => 'IPTV-Forensics-Tool/1.0']
        ]);
        
        $response = @file_get_contents($url, false, $context);
        if ($response === false) return $info;
        
        $data = json_decode($response, true);
        if (!$data) return $info;
        
        $info['asn'] = isset($data['org']) ? $this->extractASN($data['org']) : null;
        $info['org'] = $data['org'] ?? null;
        $info['country'] = $data['country'] ?? null;
        $info['country_name'] = $this->getCountryName($data['country'] ?? null);
        $info['provider'] = $this->extractProvider($data['org'] ?? '');
        
        return $info;
    }
    
    private function extractASN($orgString) {
        if (preg_match('/^(AS\d+)/', $orgString, $matches)) {
            return $matches[1];
        }
        return null;
    }
    
    private function getCountryName($countryCode) {
        $countries = [
            'US' => 'United States', 'GB' => 'United Kingdom', 'DE' => 'Germany', 
            'FR' => 'France', 'IT' => 'Italy', 'ES' => 'Spain', 'NL' => 'Netherlands', 
            'CA' => 'Canada', 'AU' => 'Australia', 'JP' => 'Japan', 'CN' => 'China', 
            'RU' => 'Russia', 'BR' => 'Brazil', 'IN' => 'India', 'MX' => 'Mexico'
        ];
        return $countries[$countryCode] ?? $countryCode ?? 'Unknown';
    }
    
    private function extractProvider($orgString) {
        $org = strtolower($orgString);
        foreach ($this->known_datacenters as $provider) {
            if (stripos($org, $provider) !== false) {
                return ucfirst($provider);
            }
        }
        if (preg_match('/^AS\d+\s+(.+)$/', $orgString, $matches)) {
            return $matches[1];
        }
        return $orgString;
    }
    
    private function getServerHeader($domain, $port = null) {
        $url = 'http://' . $domain;
        if ($port) $url .= ':' . $port;
        
        $headers = @get_headers($url, 1);
        if (is_array($headers)) {
            if (isset($headers['Server'])) return $headers['Server'];
            if (isset($headers['X-Powered-By'])) return $headers['X-Powered-By'];
        }
        return null;
    }
    
    private function detectReseller($ipInfo, $serverHeader) {
        $probability = 0;
        $is_reseller = false;
        $org_lower = strtolower($ipInfo['org'] ?? '');
        
        foreach ($this->known_datacenters as $provider) {
            if (stripos($org_lower, $provider) !== false) {
                $probability += 80;
                $is_reseller = true;
                break;
            }
        }
        
        $probability = min(100, $probability);
        return ['is_reseller' => $is_reseller, 'probability' => $probability];
    }
    
    private function saveToDatabase($data) {
        $sql = "REPLACE INTO scanned_hosts 
                (provider_name, provider_count, original_url, domain, resolved_ip, asn, organization, 
                 country_code, country_name, server_header, hosted_provider, panel_type, 
                 domain_age_days, ssl_cert_domain, is_datacenter_reseller, reseller_probability,
                 is_likely_upstream, upstream_score) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        
        $stmt = $this->db->prepare($sql);
        if (!$stmt) throw new Exception("Database prepare failed: " . $this->db->error);
        
        $stmt->bind_param(
            "sissssssssssisiiii",
            $data['provider_name'],
            $data['provider_count'],
            $data['original_url'],
            $data['domain'],
            $data['resolved_ip'],
            $data['asn'],
            $data['organization'],
            $data['country_code'],
            $data['country_name'],
            $data['server_header'],
            $data['hosted_provider'],
            $data['panel_type'],
            $data['domain_age_days'],
            $data['ssl_cert_domain'],
            $data['is_datacenter_reseller'],
            $data['reseller_probability'],
            $data['is_likely_upstream'],
            $data['upstream_score']
        );
        
        if (!$stmt->execute()) throw new Exception("Database execute failed: " . $stmt->error);
        $stmt->close();
    }
    
    private function respondSuccess($data) {
        http_response_code(200);
        echo json_encode(['success' => true, 'data' => $data, 'message' => 'Host scanned successfully']);
        exit();
    }
    
    private function respondError($message, $code = 400) {
        http_response_code($code);
        echo json_encode(['success' => false, 'error' => $message, 'code' => $code]);
        exit();
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = json_decode(file_get_contents('php://input'), true);
    $url = $input['url'] ?? $_POST['url'] ?? null;
    $provider_name = $input['provider_name'] ?? $_POST['provider_name'] ?? '';
    
    if (!$url) {
        http_response_code(400);
        echo json_encode(['success' => false, 'error' => 'URL parameter is required']);
        exit();
    }
    
    try {
        $scanner = new IPTVForensicScanner();
        $scanner->scanHost(trim($url), trim($provider_name));
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'error' => 'Server error: ' . $e->getMessage()]);
    }
} else {
    http_response_code(405);
    echo json_encode(['success' => false, 'error' => 'Method not allowed. Use POST.']);
}
?>
