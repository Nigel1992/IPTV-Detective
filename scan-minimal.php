<?php
error_reporting(E_ALL);
ini_set('display_errors', 0);
header('Content-Type: application/json');

require_once __DIR__ . '/config.php';

if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['dbtest'])) {
    try {
        $db = new mysqli(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME);
        
        if ($db->connect_error) {
            echo json_encode(['success' => false, 'error' => 'Connection: ' . $db->connect_error]);
            exit();
        }
        
        $result = $db->query("DESCRIBE scanned_hosts");
        $columns = [];
        while ($row = $result->fetch_assoc()) {
            $columns[] = $row['Field'];
        }
        
        echo json_encode([
            'success' => true,
            'columns' => $columns,
            'count' => count($columns)
        ]);
        
    } catch (Exception $e) {
        echo json_encode(['success' => false, 'error' => $e->getMessage()]);
    }
    exit();
}

echo json_encode(['success' => true, 'message' => 'Minimal test works', 'method' => $_SERVER['REQUEST_METHOD']]);
?>
