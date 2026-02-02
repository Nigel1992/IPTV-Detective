<?php
/**
 * IPTV Forensics Tool - Configuration File (EXAMPLE)
 * 
 * Copy this file to config.php and fill in your actual credentials
 * DO NOT commit config.php to version control!
 */

// Database Configuration - Using TCP/IP connection
define('DB_HOST', 'your-database-host:3306');
define('DB_USER', 'your-database-user');
define('DB_PASSWORD', 'your-database-password');
define('DB_NAME', 'your-database-name');

// API Configuration
define('IPINFO_API_KEY', 'your-ipinfo-api-key');
define('IPINFO_API_URL', 'https://ipinfo.io/json');
define('IP2WHOIS_API_KEY', 'your-ip2whois-api-key');
define('IP2WHOIS_API_URL', 'https://api.ip2whois.com/v2');

// Known Data Center Providers (for reseller detection)
$KNOWN_DATACENTERS = [
    'ovh',
    'hetzner',
    'linode',
    'digitalocean',
    'vultr',
    'contabo',
    'scaleway',
    'arubacloud',
    'aws',
    'azure',
    'google cloud',
    'hostinger',
    'bluehost',
    'godaddy',
    'namecheap',
    'ionos',
    'hostgator',
    'byethost',
    'x10hosting',
    '000webhost',
    'infinityfree'
];

// Error Reporting
error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', __DIR__ . '/logs/error.log');

// Ensure logs directory exists
if (!is_dir(__DIR__ . '/logs')) {
    mkdir(__DIR__ . '/logs', 0755, true);
}

// CORS Headers
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');
header('Content-Type: application/json; charset=utf-8');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}
?>
