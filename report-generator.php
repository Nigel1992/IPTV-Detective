<?php
error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);
header('Content-Type: application/pdf');

require_once __DIR__ . '/config.php';

/**
 * PDF Report Generator
 * Creates professional PDF reports for service matches
 */
class PDFReportGenerator {
    private $db;
    private $user_id;
    private $pdf_library = null;
    
    public function __construct() {
        $this->connectDatabase();
        $this->user_id = $_POST['user_id'] ?? $_GET['user_id'] ?? null;
        $this->initializePDFLibrary();
    }
    
    private function connectDatabase() {
        $this->db = new mysqli(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME);
        if ($this->db->connect_error) {
            $this->respondError("Database connection failed");
        }
        $this->db->set_charset("utf8mb4");
    }
    
    private function initializePDFLibrary() {
        // Try to use TCPDF if available, otherwise use internal HTML-to-PDF
        if (class_exists('TCPDF')) {
            $this->pdf_library = 'tcpdf';
        } else {
            $this->pdf_library = 'html2pdf';
        }
    }
    
    /**
     * Generate match report PDF
     */
    public function generateMatchReport() {
        try {
            $input = json_decode(file_get_contents('php://input'), true);
            
            if (empty($input['match_id'])) {
                $input['match_id'] = $_GET['match_id'] ?? null;
            }
            
            if (empty($input['match_id'])) {
                return $this->respondError("match_id is required");
            }
            
            $match_id = $input['match_id'];
            $include_private_details = $input['include_private'] ?? false;
            
            // Retrieve match details
            $match = $this->getScanMatchResult($match_id);
            if (!$match) {
                return $this->respondError("Match not found");
            }
            
            $baseline = $this->getBaseline($match['baseline_id']);
            if (!$baseline) {
                return $this->respondError("Baseline not found");
            }
            
            // Get aliases for this baseline
            $aliases = $this->getAliasesForBaseline($match['baseline_id']);
            
            // Build PDF content
            $pdf_html = $this->buildMatchReportHTML($match, $baseline, $aliases, $include_private_details);
            
            // Generate and output PDF
            $this->outputPDF($pdf_html, "match-report-{$match_id}");
            
        } catch (Exception $e) {
            $this->respondError("Error generating report: " . $e->getMessage());
        }
    }
    
    /**
     * Generate baseline comparison report
     */
    public function generateBaselineReport() {
        try {
            $input = json_decode(file_get_contents('php://input'), true);
            
            if (empty($input['baseline_id'])) {
                return $this->respondError("baseline_id is required");
            }
            
            $baseline_id = $input['baseline_id'];
            $include_aliases = $input['include_aliases'] ?? true;
            $include_history = $input['include_history'] ?? true;
            
            // Get baseline
            $baseline = $this->getBaseline($baseline_id);
            if (!$baseline) {
                return $this->respondError("Baseline not found");
            }
            
            // Get related data
            $aliases = $include_aliases ? $this->getAliasesForBaseline($baseline_id) : [];
            $versions = $include_history ? $this->getVersionHistory($baseline_id, 10) : [];
            $matches = $this->getMatchesForBaseline($baseline_id, 5);
            
            // Build PDF content
            $pdf_html = $this->buildBaselineReportHTML($baseline, $aliases, $versions, $matches);
            
            // Generate and output PDF
            $this->outputPDF($pdf_html, "baseline-{$baseline_id}");
            
        } catch (Exception $e) {
            $this->respondError("Error generating report: " . $e->getMessage());
        }
    }
    
    /**
     * Generate admin summary report
     */
    public function generateAdminSummaryReport() {
        try {
            // Get statistics
            $stats = $this->getAdminStatistics();
            $pending_approvals = $this->getPendingApprovals();
            $recent_matches = $this->getRecentMatches(10);
            
            // Build PDF content
            $pdf_html = $this->buildAdminSummaryHTML($stats, $pending_approvals, $recent_matches);
            
            // Generate and output PDF
            $this->outputPDF($pdf_html, "admin-summary-" . date('Y-m-d'));
            
        } catch (Exception $e) {
            $this->respondError("Error generating report: " . $e->getMessage());
        }
    }
    
    // ====== HTML Building Methods ======
    
    private function buildMatchReportHTML($match, $baseline, $aliases, $include_private) {
        $date = date('Y-m-d H:i:s');
        $match_percentage = $match['match_percentage'] ?? 0;
        
        $baseline_name = $baseline['is_private'] && !$include_private ? 
            '[PRIVATE SERVICE]' : $baseline['service_name'];
        
        $html = <<<HTML
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Service Match Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: Arial, sans-serif;
            color: #333;
            background-color: #fff;
            padding: 20px;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            background: #fff;
        }
        .header {
            border-bottom: 3px solid #00d4ff;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        .header h1 {
            color: #00d4ff;
            font-size: 28px;
            margin-bottom: 10px;
        }
        .header p {
            color: #666;
            font-size: 12px;
        }
        .section {
            margin-bottom: 25px;
            page-break-inside: avoid;
        }
        .section h2 {
            font-size: 16px;
            color: #1a1a1a;
            background-color: #f5f5f5;
            padding: 10px;
            margin-bottom: 15px;
            border-left: 4px solid #00d4ff;
        }
        .match-score {
            font-size: 48px;
            font-weight: bold;
            color: #00d4ff;
            text-align: center;
            padding: 30px 0;
            background: #f9f9f9;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        .match-score span {
            font-size: 20px;
            color: #666;
        }
        .info-grid {
            display: table;
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 15px;
        }
        .info-row {
            display: table-row;
        }
        .info-label {
            display: table-cell;
            width: 30%;
            font-weight: bold;
            padding: 8px;
            border-bottom: 1px solid #ddd;
            background-color: #fafafa;
        }
        .info-value {
            display: table-cell;
            width: 70%;
            padding: 8px;
            border-bottom: 1px solid #ddd;
        }
        .criteria-list {
            list-style: none;
            padding: 0;
        }
        .criteria-list li {
            padding: 6px 0;
            padding-left: 20px;
            position: relative;
        }
        .criteria-list li:before {
            content: "✓";
            position: absolute;
            left: 0;
            color: #10b981;
            font-weight: bold;
        }
        .aliases-box {
            background-color: #f0f9ff;
            padding: 15px;
            border-radius: 5px;
            border-left: 3px solid #0099cc;
            margin-bottom: 15px;
        }
        .alias-item {
            padding: 8px 0;
            border-bottom: 1px solid #e0e0e0;
        }
        .alias-item:last-child {
            border-bottom: none;
        }
        .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            font-size: 11px;
            color: #999;
            text-align: center;
        }
        .disclaimer {
            background-color: #fff3cd;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid #ffc107;
            margin-bottom: 20px;
            font-size: 12px;
            line-height: 1.5;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 15px;
        }
        th, td {
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f5f5f5;
            font-weight: bold;
        }
        .match-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
        }
        .match-badge.excellent {
            background-color: #d4edda;
            color: #155724;
        }
        .match-badge.good {
            background-color: #cfe2ff;
            color: #084298;
        }
        .match-badge.fair {
            background-color: #fff3cd;
            color: #664d03;
        }
        .private-notice {
            background-color: #f8d7da;
            padding: 10px;
            border-radius: 3px;
            color: #721c24;
            font-size: 11px;
            margin-bottom: 10px;
        }
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>Service Match Analysis Report</h1>
        <p>Generated: {$date}</p>
        <p>Report ID: {$match_id}</p>
    </div>

HTML;

        // Match score
        $badge_class = $match_percentage >= 80 ? 'excellent' : ($match_percentage >= 60 ? 'good' : 'fair');
        $html .= <<<HTML
    <div class="section">
        <h2>Match Result</h2>
        <div class="match-score">
            {$match_percentage}%<br>
            <span class="match-badge {$badge_class}">
                {$this->getMatchQualityText($match_percentage)}
            </span>
        </div>
    </div>

HTML;

        // Baseline service info
        $html .= <<<HTML
    <div class="section">
        <h2>Matched Service Details</h2>
        <div class="info-grid">
            <div class="info-row">
                <div class="info-label">Service Name</div>
                <div class="info-value">{$baseline_name}</div>
            </div>
            <div class="info-row">
                <div class="info-label">Domain</div>
                <div class="info-value">{$baseline['baseline_domain']}</div>
            </div>
            <div class="info-row">
                <div class="info-label">IP Address</div>
                <div class="info-value">{$baseline['baseline_ip']}</div>
            </div>
            <div class="info-row">
                <div class="info-label">Channels</div>
                <div class="info-value">{$baseline['channel_count']}</div>
            </div>
            <div class="info-row">
                <div class="info-label">VOD Content</div>
                <div class="info-value">{$baseline['vod_count']}</div>
            </div>
        </div>
    </div>

HTML;

        // User scanned service
        $html .= <<<HTML
    <div class="section">
        <h2>Your Scanned Service</h2>
        <div class="info-grid">
            <div class="info-row">
                <div class="info-label">URL Scanned</div>
                <div class="info-value">{$match['user_scan_url']}</div>
            </div>
            <div class="info-row">
                <div class="info-label">Service Name Provided</div>
                <div class="info-value">{$match['user_service_name']}</div>
            </div>
            <div class="info-row">
                <div class="info-label">Detected Channels</div>
                <div class="info-value">{$match['channels_detected'] ?? 'N/A'}</div>
            </div>
        </div>
    </div>

HTML;

        // Matching criteria
        $matching_criteria = json_decode($match['matching_criteria'], true) ?? [];
        $html .= <<<HTML
    <div class="section">
        <h2>Matching Criteria</h2>
        <ul class="criteria-list">

HTML;

        foreach ($matching_criteria as $criteria) {
            $html .= "<li>{$criteria}</li>";
        }

        $html .= <<<HTML
        </ul>
    </div>

HTML;

        // Aliases
        if (!empty($aliases)) {
            $html .= <<<HTML
    <div class="section">
        <h2>Known Aliases for This Service</h2>
        <div class="aliases-box">

HTML;

            foreach ($aliases as $alias) {
                $html .= <<<HTML
            <div class="alias-item">
                <strong>{$alias['alias_name']}</strong>
                <br><small>Match: {$alias['match_percentage']}% | Status: {$alias['status']}</small>
            </div>

HTML;
            }

            $html .= <<<HTML
        </div>
    </div>

HTML;
        }

        // Privacy notice if applicable
        if ($baseline['is_private'] && !$include_private) {
            $html .= <<<HTML
    <div class="private-notice">
        ⚠️ This service is marked as private. Detailed information including reseller chains and full service names are restricted from this report.
    </div>

HTML;
        }

        // Disclaimer
        $html .= <<<HTML
    <div class="disclaimer">
        <strong>Privacy Notice:</strong> This report is generated for your personal use and should be kept confidential. 
        The information contained herein is based on forensic analysis of IPTV services. 
        Do not share this report without the consent of the service provider. 
        All credentials used in scanning should be trial credentials only for your own security.
    </div>

    <div class="footer">
        <p>IPTV Detective | Forensics Analysis Report</p>
        <p>This report is confidential and for personal use only.</p>
    </div>
</div>
</body>
</html>

HTML;

        return $html;
    }
    
    private function buildBaselineReportHTML($baseline, $aliases, $versions, $matches) {
        $date = date('Y-m-d H:i:s');
        $service_name = $baseline['service_name'];
        
        $html = <<<HTML
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Baseline Service Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: Arial, sans-serif;
            color: #333;
            background-color: #fff;
            padding: 20px;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            background: #fff;
        }
        .header {
            border-bottom: 3px solid #00d4ff;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        .header h1 {
            color: #00d4ff;
            font-size: 28px;
            margin-bottom: 10px;
        }
        .section {
            margin-bottom: 25px;
            page-break-inside: avoid;
        }
        .section h2 {
            font-size: 16px;
            color: #1a1a1a;
            background-color: #f5f5f5;
            padding: 10px;
            margin-bottom: 15px;
            border-left: 4px solid #00d4ff;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 15px;
        }
        th, td {
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f5f5f5;
            font-weight: bold;
        }
        .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            font-size: 11px;
            color: #999;
            text-align: center;
        }
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>Baseline Service Report</h1>
        <p>Service: {$service_name}</p>
        <p>Generated: {$date}</p>
    </div>

    <div class="section">
        <h2>Service Information</h2>
        <table>
            <tr>
                <th>Property</th>
                <th>Value</th>
            </tr>
            <tr>
                <td>Service Name</td>
                <td>{$baseline['service_name']}</td>
            </tr>
            <tr>
                <td>Domain</td>
                <td>{$baseline['baseline_domain']}</td>
            </tr>
            <tr>
                <td>IP Address</td>
                <td>{$baseline['baseline_ip']}</td>
            </tr>
            <tr>
                <td>Channels</td>
                <td>{$baseline['channel_count']}</td>
            </tr>
            <tr>
                <td>VOD Content</td>
                <td>{$baseline['vod_count']}</td>
            </tr>
            <tr>
                <td>Status</td>
                <td>{$baseline['status']}</td>
            </tr>
            <tr>
                <td>Created</td>
                <td>{$baseline['created_at']}</td>
            </tr>
            <tr>
                <td>Last Verified</td>
                <td>{$baseline['last_verified_at'] ?? 'Never'}</td>
            </tr>
        </table>
    </div>

HTML;

        // Aliases
        if (!empty($aliases)) {
            $html .= <<<HTML
    <div class="section">
        <h2>Known Aliases ({count($aliases)})</h2>
        <table>
            <tr>
                <th>Alias Name</th>
                <th>Match %</th>
                <th>Status</th>
            </tr>

HTML;

            foreach ($aliases as $alias) {
                $html .= <<<HTML
            <tr>
                <td>{$alias['alias_name']}</td>
                <td>{$alias['match_percentage']}%</td>
                <td>{$alias['status']}</td>
            </tr>

HTML;
            }

            $html .= <<<HTML
        </table>
    </div>

HTML;
        }

        // Version history
        if (!empty($versions)) {
            $html .= <<<HTML
    <div class="section">
        <h2>Update History</h2>
        <table>
            <tr>
                <th>Version</th>
                <th>Summary</th>
                <th>Date</th>
            </tr>

HTML;

            foreach ($versions as $version) {
                $html .= <<<HTML
            <tr>
                <td>v{$version['version_number']}</td>
                <td>{$version['change_summary']}</td>
                <td>{$version['created_at']}</td>
            </tr>

HTML;
            }

            $html .= <<<HTML
        </table>
    </div>

HTML;
        }

        $html .= <<<HTML
    <div class="footer">
        <p>IPTV Detective | Baseline Service Report</p>
    </div>
</div>
</body>
</html>

HTML;

        return $html;
    }
    
    private function buildAdminSummaryHTML($stats, $pending, $recent) {
        $date = date('Y-m-d H:i:s');
        
        $html = <<<HTML
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Admin Summary Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: Arial, sans-serif;
            color: #333;
            background-color: #fff;
            padding: 20px;
        }
        .container {
            max-width: 900px;
            margin: 0 auto;
        }
        .header {
            border-bottom: 3px solid #00d4ff;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        .header h1 {
            color: #00d4ff;
            font-size: 28px;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            margin-bottom: 30px;
        }
        .stat-box {
            background: #f5f5f5;
            padding: 15px;
            border-radius: 5px;
            text-align: center;
            border-top: 3px solid #00d4ff;
        }
        .stat-value {
            font-size: 32px;
            font-weight: bold;
            color: #00d4ff;
        }
        .stat-label {
            font-size: 12px;
            color: #666;
            margin-top: 5px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 30px;
        }
        th, td {
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f5f5f5;
            font-weight: bold;
        }
        .section h2 {
            font-size: 16px;
            color: #1a1a1a;
            background-color: #f5f5f5;
            padding: 10px;
            margin-bottom: 15px;
            border-left: 4px solid #00d4ff;
        }
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>Admin Summary Report</h1>
        <p>Generated: {$date}</p>
    </div>

    <h2 style="margin-bottom: 15px;">System Statistics</h2>
    <div class="stats-grid">
        <div class="stat-box">
            <div class="stat-value">{$stats['total_baselines']}</div>
            <div class="stat-label">Total Baselines</div>
        </div>
        <div class="stat-box">
            <div class="stat-value">{$stats['total_matches']}</div>
            <div class="stat-label">Total Matches</div>
        </div>
        <div class="stat-box">
            <div class="stat-value">{$stats['total_aliases']}</div>
            <div class="stat-label">Known Aliases</div>
        </div>
        <div class="stat-box">
            <div class="stat-value">{$stats['pending_approvals']}</div>
            <div class="stat-label">Pending Approvals</div>
        </div>
    </div>

    <h2>Pending Approvals</h2>
    <table>
        <tr>
            <th>Type</th>
            <th>Submitted By</th>
            <th>Date</th>
        </tr>

HTML;

        foreach ($pending as $item) {
            $html .= <<<HTML
        <tr>
            <td>{$item['submission_type']}</td>
            <td>User {$item['submitted_by_user_id']}</td>
            <td>{$item['submitted_at']}</td>
        </tr>

HTML;
        }

        $html .= <<<HTML
    </table>

    <h2>Recent Matches</h2>
    <table>
        <tr>
            <th>Baseline</th>
            <th>Match %</th>
            <th>Date</th>
        </tr>

HTML;

        foreach ($recent as $match) {
            $html .= <<<HTML
        <tr>
            <td>{$match['service_name']}</td>
            <td>{$match['match_percentage']}%</td>
            <td>{$match['match_timestamp']}</td>
        </tr>

HTML;
        }

        $html .= <<<HTML
    </table>
</div>
</body>
</html>

HTML;

        return $html;
    }
    
    // ====== Database Methods ======
    
    private function getScanMatchResult($match_id) {
        $stmt = $this->db->prepare("
            SELECT * FROM scan_match_results WHERE id = ?
        ");
        
        if (!$stmt) return null;
        
        $stmt->bind_param("i", $match_id);
        $stmt->execute();
        $result = $stmt->get_result();
        $match = $result->fetch_assoc();
        $stmt->close();
        
        return $match;
    }
    
    private function getBaseline($baseline_id) {
        $stmt = $this->db->prepare("
            SELECT * FROM baseline_services WHERE id = ?
        ");
        
        if (!$stmt) return null;
        
        $stmt->bind_param("i", $baseline_id);
        $stmt->execute();
        $result = $stmt->get_result();
        $baseline = $result->fetch_assoc();
        $stmt->close();
        
        return $baseline;
    }
    
    private function getAliasesForBaseline($baseline_id, $limit = 20) {
        $stmt = $this->db->prepare("
            SELECT * FROM service_aliases 
            WHERE baseline_id = ? AND status = 'approved'
            ORDER BY match_percentage DESC
            LIMIT ?
        ");
        
        if (!$stmt) return [];
        
        $stmt->bind_param("ii", $baseline_id, $limit);
        $stmt->execute();
        $result = $stmt->get_result();
        
        $aliases = [];
        while ($row = $result->fetch_assoc()) {
            $aliases[] = $row;
        }
        $stmt->close();
        
        return $aliases;
    }
    
    private function getVersionHistory($baseline_id, $limit = 20) {
        $stmt = $this->db->prepare("
            SELECT * FROM service_versions 
            WHERE baseline_id = ?
            ORDER BY version_number DESC
            LIMIT ?
        ");
        
        if (!$stmt) return [];
        
        $stmt->bind_param("ii", $baseline_id, $limit);
        $stmt->execute();
        $result = $stmt->get_result();
        
        $versions = [];
        while ($row = $result->fetch_assoc()) {
            $versions[] = $row;
        }
        $stmt->close();
        
        return $versions;
    }
    
    private function getMatchesForBaseline($baseline_id, $limit = 10) {
        $stmt = $this->db->prepare("
            SELECT * FROM scan_match_results 
            WHERE baseline_id = ? AND status = 'approved_match'
            ORDER BY match_timestamp DESC
            LIMIT ?
        ");
        
        if (!$stmt) return [];
        
        $stmt->bind_param("ii", $baseline_id, $limit);
        $stmt->execute();
        $result = $stmt->get_result();
        
        $matches = [];
        while ($row = $result->fetch_assoc()) {
            $matches[] = $row;
        }
        $stmt->close();
        
        return $matches;
    }
    
    private function getAdminStatistics() {
        $stats = [];
        
        // Total baselines
        $result = $this->db->query("SELECT COUNT(*) as count FROM baseline_services WHERE status = 'approved'");
        $stats['total_baselines'] = $result->fetch_assoc()['count'] ?? 0;
        
        // Total matches
        $result = $this->db->query("SELECT COUNT(*) as count FROM scan_match_results WHERE status = 'approved_match'");
        $stats['total_matches'] = $result->fetch_assoc()['count'] ?? 0;
        
        // Total aliases
        $result = $this->db->query("SELECT COUNT(*) as count FROM service_aliases WHERE status = 'approved'");
        $stats['total_aliases'] = $result->fetch_assoc()['count'] ?? 0;
        
        // Pending approvals
        $result = $this->db->query("SELECT COUNT(*) as count FROM admin_approval_queue WHERE status = 'pending'");
        $stats['pending_approvals'] = $result->fetch_assoc()['count'] ?? 0;
        
        return $stats;
    }
    
    private function getPendingApprovals($limit = 10) {
        $stmt = $this->db->prepare("
            SELECT * FROM admin_approval_queue 
            WHERE status = 'pending'
            ORDER BY submitted_at DESC
            LIMIT ?
        ");
        
        if (!$stmt) return [];
        
        $stmt->bind_param("i", $limit);
        $stmt->execute();
        $result = $stmt->get_result();
        
        $items = [];
        while ($row = $result->fetch_assoc()) {
            $items[] = $row;
        }
        $stmt->close();
        
        return $items;
    }
    
    private function getRecentMatches($limit = 10) {
        $stmt = $this->db->prepare("
            SELECT smr.match_percentage, smr.match_timestamp,
                   b.service_name
            FROM scan_match_results smr
            JOIN baseline_services b ON smr.baseline_id = b.id
            WHERE smr.status = 'approved_match'
            ORDER BY smr.match_timestamp DESC
            LIMIT ?
        ");
        
        if (!$stmt) return [];
        
        $stmt->bind_param("i", $limit);
        $stmt->execute();
        $result = $stmt->get_result();
        
        $matches = [];
        while ($row = $result->fetch_assoc()) {
            $matches[] = $row;
        }
        $stmt->close();
        
        return $matches;
    }
    
    // ====== Output Methods ======
    
    private function getMatchQualityText($percentage) {
        if ($percentage >= 80) return 'Excellent Match';
        if ($percentage >= 60) return 'Good Match';
        if ($percentage >= 40) return 'Fair Match';
        return 'Low Match';
    }
    
    private function outputPDF($html, $filename) {
        if ($this->pdf_library === 'tcpdf') {
            $this->outputWithTCPDF($html, $filename);
        } else {
            $this->outputWithSimplePDF($html, $filename);
        }
    }
    
    private function outputWithSimplePDF($html, $filename) {
        // Simple implementation: convert HTML to base64-encoded PDF-like data
        // In production, you'd use a library like TCPDF, MPDF, or dompdf
        
        // For now, output HTML with proper headers
        header('Content-Disposition: attachment; filename="' . $filename . '.pdf"');
        header('Content-Type: application/octet-stream');
        
        // If TCPDF is not available, output HTML that can be printed to PDF
        header('Content-Type: text/html; charset=UTF-8');
        header('Content-Disposition: inline; filename="' . $filename . '.html"');
        echo $html;
    }
    
    private function outputWithTCPDF($html, $filename) {
        // TCPDF implementation
        $pdf = new \TCPDF();
        $pdf->AddPage();
        $pdf->writeHTML($html, true, false, true, false, '');
        $pdf->Output($filename . '.pdf', 'D');
    }
    
    private function respondError($message) {
        header('Content-Type: application/json');
        http_response_code(400);
        echo json_encode(['success' => false, 'error' => $message]);
        exit();
    }
}

// Route the request
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $pdf_generator = new PDFReportGenerator();
    
    $action = $_POST['action'] ?? json_decode(file_get_contents('php://input'), true)['action'] ?? null;
    
    switch ($action) {
        case 'generate_match_report':
            $pdf_generator->generateMatchReport();
            break;
        case 'generate_baseline_report':
            $pdf_generator->generateBaselineReport();
            break;
        case 'generate_admin_summary':
            $pdf_generator->generateAdminSummaryReport();
            break;
        default:
            header('Content-Type: application/json');
            http_response_code(400);
            echo json_encode(['success' => false, 'error' => 'Invalid action']);
    }
} elseif ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $pdf_generator = new PDFReportGenerator();
    
    $action = $_GET['action'] ?? null;
    switch ($action) {
        case 'generate_match_report':
            $pdf_generator->generateMatchReport();
            break;
        case 'generate_baseline_report':
            $pdf_generator->generateBaselineReport();
            break;
        case 'generate_admin_summary':
            $pdf_generator->generateAdminSummaryReport();
            break;
        default:
            header('Content-Type: application/json');
            http_response_code(405);
            echo json_encode(['success' => false, 'error' => 'Method not allowed']);
    }
} else {
    header('Content-Type: application/json');
    http_response_code(405);
    echo json_encode(['success' => false, 'error' => 'Method not allowed']);
}
?>
