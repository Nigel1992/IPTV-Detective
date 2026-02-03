<?php
/**
 * Diagnostic: Check reseller detection and database status
 */

header('Content-Type: application/json');

if (file_exists('config.php')) {
    require_once 'config.php';
    
    $conn = @mysqli_connect(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME);
    
    if (!$conn) {
        echo json_encode(['error' => 'Database connection failed']);
        exit;
    }
    
    $diagnostics = [];
    
    // 1. Check table exists
    $result = @mysqli_query($conn, "SHOW TABLES LIKE 'scanned_hosts'");
    $diagnostics['table_exists'] = mysqli_num_rows($result) > 0;
    
    // 2. Check column exists
    $result = @mysqli_query($conn, "SHOW COLUMNS FROM scanned_hosts LIKE 'confidence_score'");
    $diagnostics['confidence_score_column_exists'] = mysqli_num_rows($result) > 0;
    
    // 3. Count total records
    $result = @mysqli_query($conn, "SELECT COUNT(*) as count FROM scanned_hosts");
    $row = @mysqli_fetch_assoc($result);
    $diagnostics['total_records'] = $row['count'];
    
    // 4. Count records with provider_count > 1 (resellers)
    $result = @mysqli_query($conn, "SELECT COUNT(*) as count FROM scanned_hosts WHERE provider_count > 1");
    $row = @mysqli_fetch_assoc($result);
    $diagnostics['reseller_count'] = $row['count'];
    
    // 5. List all resellers
    $result = @mysqli_query($conn, "SELECT DISTINCT provider_name, COUNT(*) as domain_count FROM scanned_hosts WHERE provider_name IS NOT NULL AND provider_name != '' GROUP BY provider_name HAVING domain_count > 1");
    $resellers = [];
    if ($result) {
        while ($row = @mysqli_fetch_assoc($result)) {
            $resellers[] = [
                'name' => $row['provider_name'],
                'domains' => $row['domain_count']
            ];
        }
    }
    $diagnostics['resellers'] = $resellers;
    
    // 6. Check for errors in last queries
    $diagnostics['database_error'] = @mysqli_error($conn) ?: 'None';
    
    @mysqli_close($conn);
    
    echo json_encode($diagnostics, JSON_PRETTY_PRINT);
} else {
    echo json_encode(['error' => 'config.php not found']);
}
?>
