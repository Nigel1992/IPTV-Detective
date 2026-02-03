# Advanced Scanning

The enhanced scanning module (`scan-enhanced.php`) provides deep forensic analysis of IPTV services through multi-layered infrastructure inspection.

## 🎯 Overview

Traditional scanning only resolves a domain to an IP address. Advanced scanning performs comprehensive forensic analysis:

- **ASN (Autonomous System Number) Analysis**
- **DNS Infrastructure Clustering**
- **SSL Certificate Fingerprinting**
- **Domain Registration Pattern Detection**
- **IPTV Panel Type Detection**
- **Multi-Factor Confidence Scoring**

## 🔍 Core Features

### 1. ASN Analysis

**What it does**: Identifies the hosting provider's network infrastructure by analyzing the Autonomous System Number.

**Why it matters**: Multiple IPTV services sharing the same ASN (especially datacenter ASNs) often indicate reseller relationships.

**Detection Method**:
```
IP Address → ASN Lookup → Datacenter Detection → Clustering Analysis
```

**Known Datacenter ASNs**:
| ASN | Provider | Reseller Risk |
|-----|----------|---------------|
| AS14061 | DigitalOcean | High |
| AS16509 | Amazon AWS | Medium-High |
| AS31034 | Aruba S.p.A | High |
| AS8560 | IONOS | Medium |
| AS12389 | Rostelecom | Medium |

**Example Output**:
```json
{
  "asn": "AS14061",
  "asn_block": "157.245.0.0/16",
  "asn_name": "DigitalOcean, LLC",
  "asn_reseller_confidence": 75,
  "is_datacenter_reseller": true
}
```

### 2. Nameserver Clustering

**What it does**: Creates fingerprints of DNS nameserver configurations to identify domains sharing infrastructure.

**Why it matters**: Services using identical nameserver sets are often managed by the same entity or reseller.

**Detection Method**:
```php
// Pseudocode
$nameservers = getDNSRecords($domain, 'NS');
sort($nameservers); // Normalize order
$hash = md5(implode('|', $nameservers));
```

**Clustering Algorithm**:
1. Query DNS for NS records
2. Normalize nameserver list (sort, lowercase)
3. Generate SHA-256 hash
4. Compare against database of known patterns
5. Calculate cluster size and confidence

**Example Output**:
```json
{
  "nameserver_hash": "a1b2c3d4e5f6...",
  "nameservers": "ns1.cloudflare.com, ns2.cloudflare.com",
  "ns_reseller_confidence": 45,
  "nameserver_cluster_size": 12
}
```

### 3. SSL Certificate Fingerprinting

**What it does**: Extracts and analyzes SSL certificate properties to detect shared certificate patterns.

**Why it matters**: Resellers often use the same SSL certificate issuer, organization, or even wildcard certificates across multiple domains.

**Analyzed Properties**:
- Certificate Issuer (Let's Encrypt, DigiCert, etc.)
- Subject Alternative Names (SANs)
- Organization Name
- Valid From/To dates
- Certificate serial number pattern

**Detection Method**:
```php
$cert = openssl_x509_parse($certificate);
$fingerprint = [
    'issuer' => $cert['issuer']['O'] ?? null,
    'subject' => $cert['subject']['CN'] ?? null,
    'alt_names' => $cert['extensions']['subjectAltName'] ?? []
];
$hash = hash('sha256', serialize($fingerprint));
```

**Example Output**:
```json
{
  "ssl_cert_hash": "x9y8z7...",
  "ssl_issuer": "Let's Encrypt",
  "ssl_common_names": "*.example.com, example.com",
  "cert_reseller_confidence": 60,
  "cert_cluster_size": 8
}
```

### 4. Domain Registration Pattern Detection

**What it does**: Analyzes domain registration data (WHOIS) to identify bulk registration patterns.

**Why it matters**: Resellers often register multiple domains in batches with similar registration details.

**Analyzed Patterns**:
- Registration date clustering (same day/week)
- Shared registrar
- Similar registrant email patterns
- Common privacy protection services
- Registration country patterns

**Detection Indicators**:
```
✓ Same registrar + Same month = +15 confidence
✓ Email domain pattern match = +20 confidence  
✓ Registration within 7 days = +10 confidence
✓ Privacy protection service = +5 confidence
```

**Example Output**:
```json
{
  "domain_registrar": "Namecheap, Inc.",
  "domain_reg_date": "2023-05-15",
  "domain_age_days": 985,
  "registration_pattern": "bulk_may_2023",
  "reg_pattern_confidence": 55
}
```

### 5. IPTV Panel Detection

**What it does**: Identifies the type of IPTV panel software being used.

**Detected Panel Types**:
- **Xtream Codes** - Most common panel (player_api.php, get.php endpoints)
- **Stalker Portal** - Middleware API
- **M3U Playlist** - Simple file serving
- **Custom Panel** - Proprietary systems

**Detection Methods**:
- URL pattern matching
- HTTP header analysis
- Response body fingerprinting
- API endpoint probing

**Example Output**:
```json
{
  "panel_type": "Xtream Codes",
  "panel_fingerprint": "XC-v2.7.1",
  "panel_endpoints": ["player_api.php", "xmltv.php", "get.php"]
}
```

## 📊 Composite Confidence Scoring

The system calculates an overall confidence score (0-100) based on multiple factors:

### Scoring Algorithm

```
Composite Score = (
    ASN_Confidence × 0.25 +
    NS_Confidence × 0.25 +
    Cert_Confidence × 0.20 +
    Reg_Confidence × 0.20 +
    Historical_Factor × 0.10
) × Provider_Count_Multiplier
```

### Confidence Thresholds

| Score | Classification | Meaning |
|-------|----------------|---------|
| 0-25 | **Low** | Likely original provider |
| 26-50 | **Moderate** | Some reseller indicators |
| 51-75 | **High** | Strong reseller evidence |
| 76-100 | **Very High** | Definitive reseller |

### Example Calculation

```json
{
  "asn_reseller_confidence": 75,
  "ns_reseller_confidence": 60,
  "cert_reseller_confidence": 45,
  "reg_pattern_confidence": 55,
  "confidence_score": 62,
  "classification": "High - Strong reseller evidence"
}
```

## 🔌 API Usage

### Endpoint
```
POST /scan-enhanced.php
```

### Request Body
```json
{
  "url": "http://example.com:8080/player_api.php",
  "provider_name": "Example IPTV",
  "provider_website": "https://exampleiptv.com"
}
```

### Response Example
```json
{
  "success": true,
  "data": {
    "domain": "example.com",
    "resolved_ip": "157.245.100.50",
    "asn": "AS14061",
    "asn_name": "DigitalOcean, LLC",
    "country_code": "US",
    "country_name": "United States",
    "organization": "DigitalOcean, LLC",
    "nameserver_hash": "a1b2c3...",
    "nameservers": "ns1.digitalocean.com, ns2.digitalocean.com",
    "ssl_cert_hash": "x9y8z7...",
    "ssl_issuer": "Let's Encrypt",
    "domain_registrar": "Namecheap",
    "domain_age_days": 985,
    "panel_type": "Xtream Codes",
    "confidence_score": 78,
    "asn_reseller_confidence": 85,
    "ns_reseller_confidence": 70,
    "cert_reseller_confidence": 75,
    "reg_pattern_confidence": 65,
    "is_datacenter_reseller": true,
    "is_likely_upstream": false,
    "relationship_reasons": "Shared ASN cluster (85%), Common nameservers (70%), SSL pattern match (75%)"
  }
}
```

## 🛠️ Advanced Configuration

### Custom Datacenter ASNs

Add to `config.php`:
```php
$CUSTOM_DATACENTER_ASNS = [
    '12345' => 'Custom Hosting Provider',
    '67890' => 'Another Provider'
];
```

### Confidence Thresholds

Adjust sensitivity in `config.php`:
```php
define('MIN_RESELLER_CONFIDENCE', 50); // Default: 50
define('MIN_UPSTREAM_CONFIDENCE', 75); // Default: 75
define('MIN_CLUSTER_SIZE', 3); // Default: 3
```

### SSL Certificate Verification

Toggle SSL verification:
```php
define('VERIFY_SSL_CERTS', true); // Default: true
define('SSL_TIMEOUT', 10); // Seconds, default: 10
```

## 🧪 Testing

Use the test endpoint to verify enhanced scanning:
```bash
curl -X POST http://your-domain.com/scan-enhanced.php \
  -H "Content-Type: application/json" \
  -d '{
    "url": "http://test.example.com:8080/player_api.php"
  }'
```

Or use the web interface at `test-enhanced.php`.

## 📈 Performance

- **Average scan time**: 2-4 seconds per URL
- **Database caching**: Results cached for 24 hours
- **API rate limits**: Respects IPinfo.io and IP2WHOIS quotas
- **Concurrent scans**: Supports up to 5 parallel requests

## 🔒 Privacy & Security

- API keys stored in `config.php` (never committed to git)
- Results can be marked private
- Optional result expiration
- No personally identifiable information (PII) stored

## 🐛 Troubleshooting

### Common Issues

**1. "Failed to resolve IP"**
- Check DNS resolution: `nslookup domain.com`
- Verify network connectivity
- Check for firewall rules

**2. "ASN lookup failed"**
- Verify IPinfo.io API key
- Check API quota: https://ipinfo.io/account
- Test API directly: `curl ipinfo.io/8.8.8.8/asn`

**3. "Nameserver query timeout"**
- Increase timeout in config
- Check DNS server accessibility
- Verify domain has valid NS records

**4. "SSL certificate not found"**
- Ensure HTTPS is available on domain
- Check OpenSSL PHP extension
- Verify certificate is not expired

## 📚 Related Documentation

- [Advanced Reseller Detection](Advanced-Reseller-Detection.md)
- [API Reference](API-Reference.md)
- [Database Schema](Database-Schema.md)
- [Configuration Guide](Configuration-Guide.md)

---

**Next**: Learn about [Advanced Reseller Detection →](Advanced-Reseller-Detection.md)
