# Advanced Reseller Detection

The advanced reseller detection module (`resellers-advanced.php`) uses sophisticated clustering algorithms to identify IPTV reseller networks and their relationships.

## 🎯 Overview

Advanced reseller detection goes beyond simple duplicate IP detection. It uses machine learning-inspired clustering to identify:

- **Infrastructure Sharing Patterns** - Services using the same datacenters, nameservers, certificates
- **Provider Relationships** - Hidden connections between seemingly unrelated services
- **Reseller Networks** - Groups of services reselling from common upstream providers
- **Confidence Scoring** - Quantified probability metrics for each relationship

## 🔬 Detection Methodology

### Multi-Factor Clustering Algorithm

The system analyzes four primary clustering dimensions:

```
┌─────────────────────────────────────────────────────────┐
│                  Reseller Detection Engine              │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  1. ASN Clustering        → Shared datacenter infra    │
│  2. Nameserver Clustering → Common DNS management      │
│  3. SSL Cert Clustering   → Certificate patterns       │
│  4. Registration Pattern  → Bulk domain registration   │
│                                                         │
│         ↓ Composite Analysis ↓                         │
│                                                         │
│     Confidence Score (0-100) + Evidence Report         │
└─────────────────────────────────────────────────────────┘
```

### 1. ASN-Based Clustering

**Method**: Groups domains sharing the same Autonomous System Number.

**Scoring Logic**:
```
ASN Cluster Size ≥ 5 domains   → +60 confidence
ASN is known datacenter        → +25 confidence
Same ASN /24 subnet            → +15 confidence
```

**Example Cluster**:
```json
{
  "asn_block": "AS14061",
  "domains_in_cluster": 12,
  "asn_confidence": 85,
  "reason": "12 services share DigitalOcean AS14061"
}
```

### 2. Nameserver Clustering

**Method**: Creates fingerprints of DNS nameserver configurations.

**Scoring Logic**:
```
Exact NS match with ≥3 domains  → +50 confidence
Same registrar nameservers      → +30 confidence
Cloudflare/proxy detected       → -10 confidence (less reliable)
```

**Example Cluster**:
```json
{
  "ns_hash": "a1b2c3d4...",
  "nameservers": ["ns1.custom-dns.com", "ns2.custom-dns.com"],
  "domains_sharing": 8,
  "ns_confidence": 70,
  "reason": "8 services use identical nameserver set"
}
```

### 3. SSL Certificate Clustering

**Method**: Analyzes SSL certificate properties for patterns.

**Scoring Logic**:
```
Same certificate issuer org    → +40 confidence
Wildcard cert shared           → +60 confidence
Same Subject Alternative Names → +50 confidence
Same certificate serial prefix → +30 confidence
```

**Example Cluster**:
```json
{
  "cert_hash": "x9y8z7...",
  "ssl_issuer": "Let's Encrypt",
  "common_pattern": "Wildcard certificate",
  "domains_sharing": 6,
  "cert_confidence": 75,
  "reason": "6 services share wildcard certificate pattern"
}
```

### 4. Registration Pattern Clustering

**Method**: Detects bulk domain registration behaviors.

**Scoring Logic**:
```
Registered same day            → +45 confidence
Same registrar + same month    → +35 confidence
Sequential domain names        → +25 confidence
Same registrant email pattern  → +40 confidence
```

**Example Cluster**:
```json
{
  "registration_pattern": "bulk_may_2023_namecheap",
  "domains": 15,
  "registrar": "Namecheap, Inc.",
  "reg_date_range": "2023-05-10 to 2023-05-17",
  "reg_confidence": 80,
  "reason": "15 domains registered in same week"
}
```

## 📊 Composite Confidence Calculation

### Final Score Algorithm

```javascript
// Weighted composite score
composite_confidence = (
    asn_confidence      × 0.25 +  // 25% weight
    ns_confidence       × 0.25 +  // 25% weight
    cert_confidence     × 0.20 +  // 20% weight
    reg_confidence      × 0.20 +  // 20% weight
    historical_data     × 0.10    // 10% weight
)

// Provider count multiplier
if (provider_count >= 5) {
    composite_confidence *= 1.15  // +15% bonus
}

// Cap at 100
composite_confidence = min(composite_confidence, 100)
```

### Confidence Tiers

| Range | Tier | Interpretation | Action |
|-------|------|----------------|--------|
| 0-25 | **Low** | Likely original provider | No reseller flag |
| 26-50 | **Moderate** | Some clustering detected | Review manually |
| 51-75 | **High** | Strong reseller evidence | Flag as reseller |
| 76-100 | **Very High** | Definitive reseller network | Confirmed reseller |

### Example Calculation

```json
{
  "provider_name": "SuperIPTV Network",
  "domain_count": 8,
  "asn_reseller_confidence": 85,
  "ns_reseller_confidence": 70,
  "cert_reseller_confidence": 60,
  "reg_pattern_confidence": 75,
  "composite_confidence": 74,
  "tier": "High",
  "interpretation": "Strong reseller evidence"
}
```

## 🔍 Reseller Network Mapping

### Identifying Related Providers

The system maps relationships between providers:

```
Provider A (upstream) ──┬── Provider B (reseller)
                        ├── Provider C (reseller)
                        └── Provider D (reseller)
```

**Relationship Indicators**:
- Shared infrastructure (same IPs/ASN)
- Overlapping domain pools
- Common registration patterns
- Temporal correlation (registered together)

**Example Output**:
```json
{
  "provider": "Original Provider",
  "related_providers": [
    {
      "name": "Reseller A",
      "shared_domains": 5,
      "relationship_type": "Confirmed Reseller",
      "confidence": 88
    },
    {
      "name": "Reseller B",
      "shared_domains": 3,
      "relationship_type": "Probable Reseller",
      "confidence": 72
    }
  ]
}
```

## 🔌 API Usage

### Endpoint
```
GET /resellers-advanced.php
```

### Query Parameters
```
?min_confidence=50       (optional) - Minimum confidence score
&min_domains=2           (optional) - Minimum domain count
&include_clusters=true   (optional) - Include cluster details
&format=json             (default)  - Response format
```

### Response Structure

```json
{
  "success": true,
  "resellers": [
    {
      "name": "Provider Name | Alias 1 | Alias 2",
      "providers": ["Provider Name", "Alias 1", "Alias 2"],
      "domain_count": 12,
      "domains": [
        {
          "domain": "example1.com",
          "ip": "157.245.100.50",
          "age_days": 985,
          "panel_type": "Xtream Codes",
          "confidence": 78,
          "relationship_reason": "Shared ASN, common nameservers"
        }
      ],
      "unique_ips": 8,
      "ip_addresses": ["157.245.100.50", "157.245.101.22", "..."],
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

## 📈 Clustering Metrics

### Cluster Strength Indicators

**Strong Cluster** (High confidence):
- ≥10 domains in cluster
- Multiple matching criteria (ASN + NS + Cert)
- Known datacenter ASN
- Recent registrations

**Weak Cluster** (Low confidence):
- <5 domains in cluster
- Single matching criterion
- Consumer ISP ASN
- Mixed registration dates

### Example Analysis

```
Cluster Analysis for "SuperIPTV"
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ASN Clustering:       ████████░░  85%  (12 domains on AS14061)
Nameserver Match:     ███████░░░  70%  (8 domains same NS)
SSL Certificate:      ██████░░░░  60%  (6 domains share pattern)
Registration Pattern: ████████░░  75%  (9 domains bulk-registered)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Composite Score:      ███████░░░  74%  HIGH CONFIDENCE
Verdict: Confirmed Reseller Network
```

## 🛠️ Advanced Features

### 1. Historical Tracking

Track provider evolution over time:
```sql
SELECT provider_name, COUNT(*) as domains, 
       AVG(confidence_score) as avg_confidence,
       MIN(scan_date) as first_seen,
       MAX(scan_date) as last_seen
FROM scanned_hosts
GROUP BY provider_name
ORDER BY last_seen DESC;
```

### 2. Provider Merging

Merge duplicate providers:
```sql
UPDATE scanned_hosts 
SET provider_name = 'Canonical Name'
WHERE provider_name IN ('Alias 1', 'Alias 2', 'Alias 3');
```

### 3. Custom Clustering Rules

Add custom rules in `config.php`:
```php
$CUSTOM_CLUSTER_RULES = [
    'min_cluster_size' => 3,
    'asn_weight' => 0.30,
    'ns_weight' => 0.25,
    'cert_weight' => 0.25,
    'reg_weight' => 0.20
];
```

## 📊 Statistics & Reporting

### Top Reseller Networks

```json
GET /resellers-advanced.php?top=10
```

Returns top 10 reseller networks by:
- Domain count
- Confidence score
- Cluster strength

### Cluster Distribution

```json
{
  "cluster_distribution": {
    "asn_clusters": 45,
    "nameserver_clusters": 38,
    "cert_clusters": 22,
    "registration_pattern_clusters": 31
  }
}
```

## 🔒 Privacy Considerations

- **Private Services**: Can be marked private (excluded from public API)
- **Data Retention**: Optional automatic cleanup after N days
- **Anonymization**: Option to hash sensitive data

Configuration:
```php
define('ENABLE_PRIVATE_MODE', true);
define('DATA_RETENTION_DAYS', 90);
define('ANONYMIZE_EMAILS', true);
```

## 🧪 Testing

### Test Data Generator

Create test clusters:
```php
// test-cluster-generator.php
for ($i = 0; $i < 10; $i++) {
    scanHost("test$i.example.com", "Test Provider");
}
```

### Validation Script

Verify cluster accuracy:
```bash
php validate-clusters.php --min-confidence=60 --verbose
```

## 🐛 Troubleshooting

### Issue: Low Confidence Scores

**Possible causes**:
- Insufficient data (scan more domains)
- Diverse infrastructure (may not be reseller)
- Need to adjust weights in config

**Solution**:
```php
// Increase sensitivity
$CUSTOM_CLUSTER_RULES['min_cluster_size'] = 2; // from 3
```

### Issue: False Positives

**Possible causes**:
- Popular shared hosting (e.g., Cloudflare)
- Common registrars
- Coincidental patterns

**Solution**:
```php
// Add to config.php
$IGNORE_ASNS = ['AS13335']; // Cloudflare
$IGNORE_REGISTRARS = ['GoDaddy.com, LLC'];
```

### Issue: Missing Clusters

**Possible causes**:
- Database not updated
- Cluster cache expired

**Solution**:
```bash
# Rebuild clusters
php rebuild-clusters.php --force
```

## 📚 Related Documentation

- [Advanced Scanning](Advanced-Scanning.md) - Understand data sources
- [Report Generator](Report-Generator.md) - Generate reseller reports
- [API Reference](API-Reference.md) - Complete API documentation
- [Database Schema](Database-Schema.md) - Data structure details

## 🎓 Best Practices

1. **Scan Comprehensively** - More data = better clustering
2. **Update Regularly** - Run weekly scans to track changes
3. **Validate Results** - Manual review of high-confidence matches
4. **Adjust Thresholds** - Fine-tune for your use case
5. **Document Findings** - Keep notes on confirmed resellers

## 🔮 Future Enhancements

Planned features:
- [ ] Machine learning-based clustering
- [ ] Temporal analysis (time-series patterns)
- [ ] Graph visualization of networks
- [ ] API for bulk analysis
- [ ] Export to common formats (CSV, JSON, XML)

---

**Next**: Learn about [Report Generator →](Report-Generator.md)
