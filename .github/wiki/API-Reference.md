# API Reference

Complete REST API documentation for IPTV Forensics Detective advanced features.

## 🌐 Base URL

```
Production: https://your-domain.com/IPTV/
Development: http://localhost/IPTV/
```

## 🔑 Authentication

Most endpoints are public, but some require authentication for write operations.

### API Key Authentication (Optional)

Include API key in request header:
```http
X-API-Key: your-secret-api-key
```

Configure in `config.php`:
```php
define('API_KEY', 'your-secret-api-key');
define('REQUIRE_API_KEY', false); // Set true to require for all requests
```

## 📡 Endpoints

### 1. Enhanced Scanning

**Endpoint**: `POST /scan-enhanced.php`

**Description**: Perform comprehensive forensic scan of an IPTV URL with advanced clustering analysis.

**Request**:
```http
POST /scan-enhanced.php HTTP/1.1
Content-Type: application/json

{
  "url": "http://example.com:8080/player_api.php",
  "provider_name": "Example IPTV",
  "provider_website": "https://example-iptv.com"
}
```

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `url` | string | Yes | IPTV URL to scan (with or without port) |
| `provider_name` | string | No | Known provider name |
| `provider_website` | string | No | Provider's website URL |

**Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "domain": "example.com",
    "resolved_ip": "157.245.100.50",
    "asn": "AS14061",
    "asn_block": "157.245.0.0/16",
    "asn_name": "DigitalOcean, LLC",
    "organization": "DigitalOcean, LLC",
    "country_code": "US",
    "country_name": "United States",
    "nameserver_hash": "a1b2c3d4e5f6...",
    "nameservers": "ns1.digitalocean.com, ns2.digitalocean.com",
    "ssl_cert_hash": "x9y8z7w6...",
    "ssl_issuer": "Let's Encrypt",
    "ssl_common_names": "example.com, www.example.com",
    "domain_registrar": "Namecheap, Inc.",
    "domain_reg_date": "2023-05-15",
    "domain_age_days": 985,
    "panel_type": "Xtream Codes",
    "panel_fingerprint": "XC-2.7.1",
    "confidence_score": 78,
    "asn_reseller_confidence": 85,
    "ns_reseller_confidence": 70,
    "cert_reseller_confidence": 75,
    "reg_pattern_confidence": 65,
    "registration_pattern": "bulk_may_2023",
    "is_datacenter_reseller": true,
    "is_likely_upstream": false,
    "upstream_score": 62,
    "relationship_reasons": "Shared ASN cluster (85%), Common nameservers (70%), SSL pattern match (75%)",
    "scan_timestamp": "2026-02-04T12:34:56Z"
  }
}
```

**Error Response** (400 Bad Request):
```json
{
  "success": false,
  "error": "Invalid URL format",
  "code": 400
}
```

**Error Response** (500 Internal Server Error):
```json
{
  "success": false,
  "error": "Failed to resolve IP address",
  "code": 500
}
```

---

### 2. Basic Scanning (Legacy)

**Endpoint**: `POST /scan.php`

**Description**: Basic IPTV URL scanning without advanced features.

**Request**:
```http
POST /scan.php HTTP/1.1
Content-Type: application/json

{
  "url": "http://example.com:8080/get.php"
}
```

**Response**: Similar to enhanced scan but with fewer fields.

---

### 3. Advanced Reseller Detection

**Endpoint**: `GET /resellers-advanced.php`

**Description**: Retrieve detected reseller networks with clustering analysis.

**Query Parameters**:
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `min_confidence` | integer | 0 | Minimum confidence score (0-100) |
| `min_domains` | integer | 1 | Minimum domain count |
| `include_clusters` | boolean | false | Include cluster details |
| `top` | integer | 50 | Limit results to top N |
| `format` | string | json | Response format (json only) |

**Example Request**:
```http
GET /resellers-advanced.php?min_confidence=60&min_domains=3&include_clusters=true
```

**Response** (200 OK):
```json
{
  "success": true,
  "resellers": [
    {
      "name": "SuperIPTV | Super IPTV | SuperStreams",
      "providers": ["SuperIPTV", "Super IPTV", "SuperStreams"],
      "domain_count": 12,
      "domains": [
        {
          "domain": "super1.com",
          "ip": "157.245.100.50",
          "age_days": 985,
          "panel_type": "Xtream Codes",
          "confidence": 78,
          "relationship_reason": "Shared ASN, common nameservers"
        }
      ],
      "unique_ips": 8,
      "ip_addresses": ["157.245.100.50", "157.245.101.22"],
      "confidence_score": 74,
      "cluster_evidence": {
        "asn_clustering": 10,
        "nameserver_clustering": 8,
        "cert_clustering": 6,
        "registration_pattern_clustering": 9
      },
      "related_providers": [
        {
          "name": "Related Provider",
          "shared_domains": 4
        }
      ],
      "last_updated": "2026-02-04 12:34:56"
    }
  ],
  "clusters": [
    {
      "cluster_id": "asn_14061",
      "cluster_type": "ASN",
      "cluster_value": "AS14061 - DigitalOcean",
      "member_count": 15,
      "confidence": 85
    }
  ],
  "total_resellers": 25,
  "timestamp": "2026-02-04 12:34:56"
}
```

---

### 4. Basic Reseller Detection (Legacy)

**Endpoint**: `GET /resellers.php`

**Description**: Basic reseller detection without advanced clustering.

**Response**: Simplified version without clustering metrics.

---

### 5. Report Generation

**Endpoint**: `POST /report-generator.php`

**Description**: Generate PDF reports for matches, baselines, or admin summaries.

#### 5.1 Match Report

**Request**:
```http
POST /report-generator.php HTTP/1.1
Content-Type: application/json

{
  "report_type": "match",
  "match_id": 12345,
  "include_private": false,
  "format": "pdf"
}
```

**Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `report_type` | string | Yes | "match", "baseline", or "admin_summary" |
| `match_id` | integer | Yes* | Match ID for match reports |
| `baseline_id` | integer | Yes* | Baseline ID for baseline reports |
| `include_private` | boolean | No | Include private service details |
| `format` | string | No | "pdf" (default), "html", or "json" |

*Required depending on report_type

**Response**: Binary PDF data with headers:
```http
HTTP/1.1 200 OK
Content-Type: application/pdf
Content-Disposition: attachment; filename="match-report-12345.pdf"
Content-Length: 45678

[PDF binary data]
```

#### 5.2 Baseline Report

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

#### 5.3 Admin Summary Report

**Request**:
```json
{
  "report_type": "admin_summary",
  "start_date": "2026-01-01",
  "end_date": "2026-01-31",
  "include_graphs": true
}
```

---

### 6. Statistics

**Endpoint**: `GET /stats.php`

**Description**: Retrieve system statistics and metrics.

**Query Parameters**:
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `period` | string | all | "day", "week", "month", "year", "all" |
| `format` | string | json | Response format |

**Example Request**:
```http
GET /stats.php?period=month
```

**Response** (200 OK):
```json
{
  "success": true,
  "period": "month",
  "statistics": {
    "total_scans": 1245,
    "unique_domains": 892,
    "unique_ips": 456,
    "baselines": 156,
    "matches_found": 234,
    "avg_confidence": 67.5,
    "reseller_networks": 45,
    "datacenter_detections": 234,
    "top_asns": [
      {"asn": "AS14061", "count": 45, "name": "DigitalOcean"},
      {"asn": "AS16509", "count": 32, "name": "Amazon AWS"}
    ],
    "top_countries": [
      {"code": "US", "count": 456, "name": "United States"},
      {"code": "NL", "count": 234, "name": "Netherlands"}
    ],
    "panel_types": {
      "Xtream Codes": 678,
      "Stalker Portal": 234,
      "M3U Playlist": 189,
      "Unknown": 144
    }
  },
  "timestamp": "2026-02-04T12:34:56Z"
}
```

---

### 7. Dashboard Data

**Endpoint**: `GET /dashboard.php`

**Description**: Retrieve dashboard summary data.

**Response** (200 OK):
```json
{
  "success": true,
  "summary": {
    "total_scans": 1245,
    "recent_scans": 89,
    "baselines": 156,
    "matches": 234,
    "pending_approvals": 12
  },
  "recent_activity": [
    {
      "type": "scan",
      "domain": "example.com",
      "confidence": 78,
      "timestamp": "2026-02-04T12:30:00Z"
    }
  ],
  "top_resellers": [
    {
      "name": "SuperIPTV",
      "domain_count": 12,
      "confidence": 74
    }
  ]
}
```

---

### 8. Private Services

**Endpoint**: `GET /private-services.php`

**Description**: Manage private/confidential service baselines.

**Query Parameters**:
| Parameter | Type | Description |
|-----------|------|-------------|
| `action` | string | "list", "add", "remove", "update" |
| `service_id` | integer | Service ID (for specific actions) |
| `api_key` | string | Required for write operations |

**Example - List Private Services**:
```http
GET /private-services.php?action=list&api_key=your-api-key
```

**Response**:
```json
{
  "success": true,
  "services": [
    {
      "id": 123,
      "name": "[PRIVATE SERVICE]",
      "domain_count": 5,
      "is_private": true,
      "last_updated": "2026-02-04T12:34:56Z"
    }
  ]
}
```

---

### 9. Diagnostic Tool

**Endpoint**: `GET /diagnostic.php`

**Description**: System health check and configuration validation.

**Response** (200 OK):
```json
{
  "success": true,
  "system": {
    "php_version": "8.1.2",
    "mysql_version": "8.0.28",
    "extensions": {
      "mysqli": true,
      "curl": true,
      "openssl": true,
      "json": true
    }
  },
  "database": {
    "connected": true,
    "tables_exist": true,
    "record_count": 1245
  },
  "api_keys": {
    "ipinfo": {
      "configured": true,
      "valid": true,
      "quota_remaining": 48567
    },
    "ip2whois": {
      "configured": true,
      "valid": true,
      "quota_remaining": 9234
    }
  },
  "configuration": {
    "config_file": true,
    "writable_dirs": true,
    "ssl_verify": true
  },
  "recommendations": [
    "Consider increasing PHP memory_limit for large reports",
    "API quota usage at 85% - consider upgrading plan"
  ]
}
```

---

## 🔄 Response Codes

| Code | Status | Description |
|------|--------|-------------|
| 200 | OK | Request successful |
| 400 | Bad Request | Invalid parameters or malformed request |
| 401 | Unauthorized | Missing or invalid API key |
| 404 | Not Found | Resource not found |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Server error occurred |

## ⚠️ Error Handling

All errors follow this structure:

```json
{
  "success": false,
  "error": "Human-readable error message",
  "error_code": "SPECIFIC_ERROR_CODE",
  "code": 400,
  "timestamp": "2026-02-04T12:34:56Z"
}
```

**Common Error Codes**:
- `INVALID_URL` - URL format is invalid
- `DNS_RESOLUTION_FAILED` - Could not resolve domain
- `API_QUOTA_EXCEEDED` - External API quota exhausted
- `DATABASE_ERROR` - Database connection or query error
- `MISSING_PARAMETER` - Required parameter not provided
- `INVALID_API_KEY` - API key authentication failed

## 🔒 Rate Limiting

**Default Limits**:
- **Anonymous**: 100 requests/hour, 500 requests/day
- **Authenticated**: 500 requests/hour, 5000 requests/day

**Rate Limit Headers**:
```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1675512000
```

**Rate Limit Exceeded Response** (429):
```json
{
  "success": false,
  "error": "Rate limit exceeded",
  "retry_after": 3600,
  "code": 429
}
```

## 📊 Pagination

For endpoints returning lists (e.g., resellers):

**Query Parameters**:
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | integer | 1 | Page number |
| `per_page` | integer | 50 | Items per page (max 100) |
| `sort` | string | - | Sort field |
| `order` | string | asc | Sort order (asc/desc) |

**Example**:
```http
GET /resellers-advanced.php?page=2&per_page=25&sort=confidence_score&order=desc
```

**Response includes pagination metadata**:
```json
{
  "success": true,
  "resellers": [...],
  "pagination": {
    "current_page": 2,
    "per_page": 25,
    "total_items": 156,
    "total_pages": 7,
    "has_next": true,
    "has_prev": true,
    "next_page": 3,
    "prev_page": 1
  }
}
```

## 🧪 Testing

### cURL Examples

**1. Enhanced Scan**:
```bash
curl -X POST https://your-domain.com/scan-enhanced.php \
  -H "Content-Type: application/json" \
  -d '{
    "url": "http://example.com:8080/player_api.php",
    "provider_name": "Example IPTV"
  }'
```

**2. Get Resellers**:
```bash
curl -X GET "https://your-domain.com/resellers-advanced.php?min_confidence=60&top=10"
```

**3. Generate Report**:
```bash
curl -X POST https://your-domain.com/report-generator.php \
  -H "Content-Type: application/json" \
  -d '{
    "report_type": "match",
    "match_id": 12345
  }' \
  --output report.pdf
```

**4. Statistics**:
```bash
curl -X GET "https://your-domain.com/stats.php?period=month"
```

### JavaScript Examples

**Using Fetch API**:
```javascript
// Enhanced scan
async function scanURL(url) {
  const response = await fetch('/scan-enhanced.php', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      url: url,
      provider_name: 'Example IPTV'
    })
  });
  
  const data = await response.json();
  return data;
}

// Get resellers
async function getResellers(minConfidence = 60) {
  const response = await fetch(
    `/resellers-advanced.php?min_confidence=${minConfidence}`
  );
  
  const data = await response.json();
  return data.resellers;
}
```

### Python Examples

**Using requests library**:
```python
import requests

# Enhanced scan
def scan_url(url, provider_name=None):
    response = requests.post(
        'https://your-domain.com/scan-enhanced.php',
        json={
            'url': url,
            'provider_name': provider_name
        }
    )
    return response.json()

# Get resellers
def get_resellers(min_confidence=60):
    response = requests.get(
        'https://your-domain.com/resellers-advanced.php',
        params={'min_confidence': min_confidence}
    )
    return response.json()

# Generate report
def generate_report(match_id):
    response = requests.post(
        'https://your-domain.com/report-generator.php',
        json={
            'report_type': 'match',
            'match_id': match_id
        }
    )
    
    with open(f'report-{match_id}.pdf', 'wb') as f:
        f.write(response.content)
```

## 🔐 Security Best Practices

1. **HTTPS Only**: Always use HTTPS in production
2. **API Key Storage**: Never commit API keys to version control
3. **Input Validation**: Sanitize all user inputs
4. **Rate Limiting**: Implement rate limits to prevent abuse
5. **Logging**: Log all API access for audit purposes
6. **CORS**: Configure CORS headers appropriately

```php
// config.php security settings
define('FORCE_HTTPS', true);
define('ENABLE_CORS', true);
define('ALLOWED_ORIGINS', ['https://example.com']);
define('ENABLE_RATE_LIMITING', true);
define('LOG_ALL_REQUESTS', true);
```

## 📚 Related Documentation

- [Advanced Scanning](Advanced-Scanning.md) - Scanning methodology
- [Advanced Reseller Detection](Advanced-Reseller-Detection.md) - Clustering algorithms
- [Report Generator](Report-Generator.md) - Report generation details
- [Configuration Guide](Configuration-Guide.md) - Setup and configuration

---

**Questions?** Join our [Discord community](https://discord.gg/RdH5Quqvg2) for API support.
