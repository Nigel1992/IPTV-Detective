<?php
// Enable error reporting for debugging
error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);

// Set JSON header immediately
header('Content-Type: application/json');

// Catch any fatal errors
set_error_handler(function($errno, $errstr, $errfile, $errline) {
    error_log("PHP Error [$errno]: $errstr in $errfile on line $errline");
    http_response_code(500);
    echo json_encode(['success' => false, 'error' => "PHP Error: $errstr"]);
    exit();
});

set_exception_handler(function($exception) {
    error_log("Exception: " . $exception->getMessage() . " in " . $exception->getFile() . " on line " . $exception->getLine());
    http_response_code(500);
    echo json_encode(['success' => false, 'error' => "Exception: " . $exception->getMessage()]);
    exit();
});

try {
    error_log("Script started");
    require_once __DIR__ . '/config.php';
    error_log("Config loaded");
    require_once __DIR__ . '/scan-core.php';
    error_log("Core loaded");
    
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        error_log("Processing POST request");
        $input = json_decode(file_get_contents('php://input'), true);
        $url = isset($input['url']) ? $input['url'] : (isset($_POST['url']) ? $_POST['url'] : null);
        $provider_name = isset($input['provider_name']) ? $input['provider_name'] : (isset($_POST['provider_name']) ? $_POST['provider_name'] : '');
        
        error_log("URL: $url, Provider: $provider_name");
        
        if (!$url) {
            http_response_code(400);
            echo json_encode(['success' => false, 'error' => 'URL parameter is required']);
            exit();
        }
        
        $scanner = new IPTVForensicScanner();
        $scanner->scanHost(trim($url), trim($provider_name));
        
    } else if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['test'])) {
        // Test endpoint
        echo json_encode([
            'success' => true,
            'message' => 'IPTV Detective is working!',
            'php_version' => PHP_VERSION,
            'extensions' => [
                'curl' => extension_loaded('curl'),
                'mysqli' => extension_loaded('mysqli'),
                'openssl' => extension_loaded('openssl'),
                'json' => extension_loaded('json')
            ]
        ]);
    } else {
        http_response_code(405);
        echo json_encode(['success' => false, 'error' => 'Method not allowed. Use POST.']);
    }
    
} catch (Exception $e) {
    error_log("Fatal Exception: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(['success' => false, 'error' => $e->getMessage()]);
}
?>
