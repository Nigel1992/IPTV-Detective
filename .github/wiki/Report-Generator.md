# Report Generator

The report generator module (`report-generator.php`) creates professional PDF reports for IPTV forensic analysis, service comparisons, and administrative summaries.

## 🎯 Overview

Generate comprehensive, print-ready PDF reports for:
- **Match Reports** - Detailed service comparison documents
- **Baseline Reports** - Complete service profiles with history
- **Admin Summaries** - Statistical overviews for management
- **Custom Reports** - Flexible report generation with templates

## 📄 Report Types

### 1. Match Report

**Purpose**: Document when a scanned service matches an existing baseline.

**Includes**:
- Match percentage and confidence score
- Side-by-side service comparison
- Infrastructure analysis
- Evidence summary
- Recommendation

**Use Case**: Legal documentation, customer inquiries, compliance reports

**Example Structure**:
```
┌─────────────────────────────────────────────┐
│  IPTV FORENSICS MATCH REPORT                │
│  Generated: 2026-02-04 12:34:56            │
├─────────────────────────────────────────────┤
│                                             │
│  MATCH SUMMARY                              │
│  Match ID: #12345                           │
│  Confidence: 87%                            │
│  Status: HIGH CONFIDENCE MATCH              │
│                                             │
│  BASELINE SERVICE                           │
│  Name: Original Provider                    │
│  Domain: original.com                       │
│  IP: 157.245.100.50                         │
│  ASN: AS14061 (DigitalOcean)               │
│                                             │
│  SCANNED SERVICE                            │
│  Name: Suspected Reseller                   │
│  Domain: reseller.com                       │
│  IP: 157.245.100.51                         │
│  ASN: AS14061 (DigitalOcean)               │
│                                             │
│  EVIDENCE                                   │
│  ✓ Same ASN cluster (AS14061)              │
│  ✓ Shared nameserver pattern               │
│  ✓ Similar SSL certificate                 │
│  ✓ Registration within 7 days              │
│                                             │
│  CONCLUSION                                 │
│  High confidence reseller relationship      │
└─────────────────────────────────────────────┘
```

### 2. Baseline Report

**Purpose**: Complete profile of a known IPTV service.

**Includes**:
- Service details and aliases
- Infrastructure information
- Domain history and changes
- Known resellers
- Version history

**Use Case**: Service documentation, monitoring reports, research

**Example Structure**:
```
┌─────────────────────────────────────────────┐
│  BASELINE SERVICE REPORT                    │
│  Service: Premium IPTV Network              │
├─────────────────────────────────────────────┤
│                                             │
│  SERVICE INFORMATION                        │
│  Primary Domain: premium-iptv.com           │
│  Aliases: 3 known aliases                   │
│  Status: Active                             │
│  First Seen: 2023-05-15                     │
│                                             │
│  INFRASTRUCTURE                             │
│  Primary IP: 157.245.100.50                 │
│  ASN: AS14061 (DigitalOcean, LLC)          │
│  Nameservers: ns1.cloudflare.com, ...      │
│  SSL Issuer: Let's Encrypt                 │
│  Panel Type: Xtream Codes v2.7             │
│                                             │
│  RESELLER ANALYSIS                          │
│  Confidence Score: 74/100                   │
│  Likely Reseller: Yes                       │
│  Known Related Services: 8                  │
│                                             │
│  VERSION HISTORY                            │
│  v5 - 2026-02-04: IP changed                │
│  v4 - 2025-11-20: Domain added              │
│  v3 - 2025-08-10: Panel update              │
│                                             │
│  MATCHES                                    │
│  Total Matches: 12                          │
│  High Confidence: 8                         │
│  Under Review: 4                            │
└─────────────────────────────────────────────┘
```

### 3. Admin Summary Report

**Purpose**: High-level statistics and analytics for administrators.

**Includes**:
- System statistics
- Recent activity
- Pending approvals
- Top reseller networks
- Growth trends

**Use Case**: Monthly reports, board presentations, performance tracking

**Example Structure**:
```
┌─────────────────────────────────────────────┐
│  ADMIN SUMMARY REPORT                       │
│  Period: January 2026                       │
├─────────────────────────────────────────────┤
│                                             │
│  STATISTICS                                 │
│  Total Scans: 1,245                         │
│  Unique Domains: 892                        │
│  Baselines: 156                             │
│  Matches Found: 234                         │
│  Avg Confidence: 67%                        │
│                                             │
│  TOP RESELLER NETWORKS                      │
│  1. SuperIPTV Network (45 domains)         │
│  2. Global Streams (32 domains)            │
│  3. Premium Services (28 domains)          │
│                                             │
│  PENDING APPROVALS                          │
│  Baseline Submissions: 12                   │
│  Match Reviews: 8                           │
│                                             │
│  RECENT ACTIVITY                            │
│  Last 7 days: 89 scans                     │
│  New baselines: 5                           │
│  Confirmed matches: 14                      │
└─────────────────────────────────────────────┘
```

## 🔌 API Usage

### 1. Generate Match Report

**Endpoint**: `POST /report-generator.php`

**Request**:
```json
{
  "report_type": "match",
  "match_id": 12345,
  "include_private": false,
  "format": "pdf"
}
```

**Response**: PDF binary data with headers:
```
Content-Type: application/pdf
Content-Disposition: attachment; filename="match-report-12345.pdf"
```

**cURL Example**:
```bash
curl -X POST http://your-domain.com/report-generator.php \
  -H "Content-Type: application/json" \
  -d '{
    "report_type": "match",
    "match_id": 12345
  }' \
  --output match-report.pdf
```

### 2. Generate Baseline Report

**Endpoint**: `POST /report-generator.php`

**Request**:
```json
{
  "report_type": "baseline",
  "baseline_id": 789,
  "include_aliases": true,
  "include_history": true,
  "include_matches": true,
  "max_matches": 10
}
```

**Response**: PDF binary data

### 3. Generate Admin Summary

**Endpoint**: `POST /report-generator.php`

**Request**:
```json
{
  "report_type": "admin_summary",
  "start_date": "2026-01-01",
  "end_date": "2026-01-31",
  "include_graphs": true
}
```

**Response**: PDF binary data

## 🎨 Customization

### Report Templates

Custom templates can be defined in `config.php`:

```php
$REPORT_TEMPLATES = [
    'match' => [
        'header_color' => '#2c3e50',
        'title_font' => 'helvetica',
        'title_size' => 18,
        'body_font' => 'helvetica',
        'body_size' => 11,
        'logo' => '/path/to/logo.png',
        'footer_text' => 'Confidential - Internal Use Only'
    ],
    'baseline' => [
        'header_color' => '#34495e',
        'include_charts' => true,
        'chart_type' => 'bar'
    ]
];
```

### Privacy Controls

Control what information appears in reports:

```php
// config.php
define('REPORT_INCLUDE_IPS', true);         // Show IP addresses
define('REPORT_INCLUDE_DOMAINS', true);     // Show domain names
define('REPORT_INCLUDE_EMAILS', false);     // Hide emails
define('REPORT_INCLUDE_WHOIS', true);       // Show WHOIS data
define('REPORT_REDACT_PRIVATE', true);      // Redact private services
```

**Example with Privacy Mode**:
```
Service Name: [REDACTED - PRIVATE SERVICE]
Domain: [REDACTED]
IP: xxx.xxx.xxx.xxx
```

### Branding

Add your organization's branding:

```php
$REPORT_BRANDING = [
    'company_name' => 'Your Organization',
    'logo_path' => '/assets/logo.png',
    'website' => 'https://example.com',
    'contact_email' => 'reports@example.com',
    'watermark' => 'CONFIDENTIAL'
];
```

## 📊 Output Formats

### PDF (Default)

```json
{
  "format": "pdf",
  "pdf_options": {
    "page_size": "A4",
    "orientation": "portrait",
    "margins": {
      "top": 15,
      "right": 15,
      "bottom": 15,
      "left": 15
    }
  }
}
```

### HTML (Preview)

```json
{
  "format": "html",
  "html_options": {
    "standalone": true,
    "include_styles": true
  }
}
```

Response will be HTML instead of PDF binary.

### JSON (Data Export)

```json
{
  "format": "json",
  "json_options": {
    "pretty_print": true
  }
}
```

Returns structured data without formatting.

## 🛠️ Advanced Features

### 1. Batch Report Generation

Generate multiple reports at once:

**Endpoint**: `POST /report-generator.php`

```json
{
  "report_type": "batch",
  "reports": [
    {"type": "match", "match_id": 123},
    {"type": "match", "match_id": 456},
    {"type": "baseline", "baseline_id": 789}
  ],
  "output": "zip"
}
```

Returns a ZIP file containing all PDFs.

### 2. Scheduled Reports

Configure automatic report generation:

```php
// config.php
$SCHEDULED_REPORTS = [
    [
        'type' => 'admin_summary',
        'frequency' => 'monthly',
        'recipients' => ['admin@example.com'],
        'day_of_month' => 1
    ],
    [
        'type' => 'reseller_summary',
        'frequency' => 'weekly',
        'recipients' => ['team@example.com'],
        'day_of_week' => 'Monday'
    ]
];
```

### 3. Report Analytics

Track report generation:

```sql
-- Track generated reports
CREATE TABLE report_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    report_type VARCHAR(50),
    report_id INT,
    generated_by VARCHAR(100),
    generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    file_size INT,
    delivery_status VARCHAR(20)
);
```

Query report statistics:
```sql
SELECT report_type, COUNT(*) as total, 
       AVG(file_size) as avg_size
FROM report_history
WHERE generated_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
GROUP BY report_type;
```

## 🔧 PDF Library Configuration

### Using TCPDF (Recommended)

Install TCPDF:
```bash
composer require tecnickcom/tcpdf
```

Configure in `config.php`:
```php
define('PDF_LIBRARY', 'tcpdf');
define('TCPDF_PATH', __DIR__ . '/vendor/tecnickcom/tcpdf/');
```

**Features**:
- Better Unicode support
- Advanced formatting
- Chart/graph generation
- QR code embedding

### Using Internal HTML2PDF

No installation required, but limited features:

```php
define('PDF_LIBRARY', 'html2pdf');
```

**Features**:
- Basic formatting
- Simple tables
- Images
- Headers/footers

## 📈 Performance Optimization

### Caching

Cache generated reports:

```php
define('REPORT_CACHE_ENABLED', true);
define('REPORT_CACHE_TTL', 3600); // 1 hour
define('REPORT_CACHE_DIR', '/tmp/report-cache/');
```

### Async Generation

For large reports, use async processing:

```php
// Queue report for background generation
$job_id = queueReport([
    'type' => 'admin_summary',
    'params' => [...]
]);

// Check status
$status = checkReportStatus($job_id);
// Returns: pending, processing, completed, failed

// Download when ready
$pdf = downloadReport($job_id);
```

### Resource Limits

Adjust PHP limits for large reports:

```php
// config.php or .htaccess
ini_set('memory_limit', '256M');
ini_set('max_execution_time', 300); // 5 minutes
set_time_limit(300);
```

## 🔒 Security

### Access Control

Restrict report generation:

```php
// Require authentication
define('REPORT_REQUIRE_AUTH', true);
define('REPORT_API_KEY', 'your-secret-key');

// Request with API key
curl -X POST http://your-domain.com/report-generator.php \
  -H "X-API-Key: your-secret-key" \
  -d '{...}'
```

### Rate Limiting

Prevent abuse:

```php
$RATE_LIMITS = [
    'reports_per_hour' => 50,
    'reports_per_day' => 200,
    'max_concurrent' => 5
];
```

### Audit Logging

Log all report generation:

```php
logReportGeneration([
    'user_id' => $user_id,
    'report_type' => $report_type,
    'report_id' => $report_id,
    'ip_address' => $_SERVER['REMOTE_ADDR'],
    'timestamp' => time()
]);
```

## 🧪 Testing

### Test Report Generation

```php
// test-report.php
require_once 'report-generator.php';

$generator = new PDFReportGenerator();

// Test match report
$match_report = $generator->generateMatchReport([
    'match_id' => 12345,
    'include_private' => false
]);

// Save to file
file_put_contents('test-match-report.pdf', $match_report);
echo "Report generated: test-match-report.pdf\n";
```

### Validate PDF Output

```bash
# Check PDF validity
pdfinfo test-report.pdf

# Extract text for verification
pdftotext test-report.pdf - | head -n 20
```

## 🐛 Troubleshooting

### Issue: "PDF generation failed"

**Possible causes**:
- Missing TCPDF library
- Memory limit exceeded
- Invalid data

**Solutions**:
```php
// Increase memory
ini_set('memory_limit', '512M');

// Use simpler library
define('PDF_LIBRARY', 'html2pdf');

// Validate data before generation
if (empty($match)) {
    throw new Exception("No match data found");
}
```

### Issue: "Report contains garbled text"

**Cause**: Character encoding issues

**Solution**:
```php
// Ensure UTF-8
$this->db->set_charset("utf8mb4");

// In TCPDF
$pdf->SetFont('dejavusans', '', 11); // Supports Unicode
```

### Issue: "Large reports timeout"

**Cause**: Execution time limit

**Solution**:
```php
set_time_limit(600); // 10 minutes
ini_set('max_execution_time', 600);

// Or use async generation
queueReportGeneration($params);
```

## 📚 Related Documentation

- [Advanced Scanning](Advanced-Scanning.md) - Data sources for reports
- [Advanced Reseller Detection](Advanced-Reseller-Detection.md) - Analysis methods
- [API Reference](API-Reference.md) - Complete API documentation
- [Configuration Guide](Configuration-Guide.md) - Setup instructions

## 💡 Best Practices

1. **Include Context** - Add sufficient context for readers unfamiliar with the case
2. **Use Privacy Controls** - Redact sensitive information appropriately
3. **Version Reports** - Include timestamp and version information
4. **Test Formatting** - Preview reports before distribution
5. **Archive Reports** - Keep generated reports for audit trail
6. **Automate Delivery** - Set up scheduled reports for regular reporting needs

## 🔮 Future Enhancements

Planned features:
- [ ] Interactive HTML reports with charts
- [ ] Export to Excel/CSV formats
- [ ] Email delivery integration
- [ ] Custom report templates (user-defined)
- [ ] Report comparison (diff between versions)
- [ ] Real-time report generation via WebSocket

---

**Next**: Learn about the complete [API Reference →](API-Reference.md)
