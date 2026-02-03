# IPTV Forensics Detective - Advanced Features Wiki

Welcome to the advanced documentation for IPTV Forensics Detective! This wiki covers the sophisticated features and APIs that power advanced reseller detection, infrastructure analysis, and forensic reporting.

## 🚀 Quick Navigation

### Core Advanced Features
- **[Advanced Scanning](Advanced-Scanning.md)** - Enhanced scanning with ASN analysis, nameserver clustering, and SSL certificate fingerprinting
- **[Advanced Reseller Detection](Advanced-Reseller-Detection.md)** - Machine learning-based clustering and confidence scoring algorithms
- **[Report Generator](Report-Generator.md)** - Professional PDF report generation for matches and baselines
- **[API Reference](API-Reference.md)** - Complete REST API documentation for all advanced endpoints

### Additional Documentation
- **[Configuration Guide](Configuration-Guide.md)** - Advanced configuration options and environment setup
- **[Database Schema](Database-Schema.md)** - Enhanced database structure and field descriptions
- **[Deployment Guide](Deployment-Guide.md)** - Production deployment strategies and best practices

## 🔬 Advanced Features Overview

### Enhanced Scanning (`scan-enhanced.php`)
The enhanced scanning module goes beyond basic IP resolution to provide:
- **ASN (Autonomous System Number) Analysis** - Identify hosting provider infrastructure
- **Nameserver Clustering** - Detect domains sharing DNS infrastructure
- **SSL Certificate Fingerprinting** - Track relationships via certificate patterns
- **Registration Pattern Detection** - Identify bulk registration behaviors
- **Composite Confidence Scoring** - Multi-factor reseller probability calculation

### Advanced Reseller Detection (`resellers-advanced.php`)
Sophisticated algorithms for identifying reseller networks:
- **Infrastructure Clustering** - Group domains by shared ASN, nameservers, certificates
- **Provider Relationship Mapping** - Discover connections between services
- **Confidence Metrics** - Quantified probability scores (0-100)
- **Evidence Tracking** - Detailed reasoning for all determinations

### Professional Report Generation (`report-generator.php`)
Create detailed forensic reports:
- **Match Reports** - Comprehensive service comparison documents
- **Baseline Reports** - Complete service profiles with history
- **Admin Summaries** - Statistical overviews for management
- **PDF Export** - Professional formatting with privacy controls

## 🎯 Use Cases

### 1. Reseller Network Investigation
Identify when multiple IPTV services are reselling from a common upstream provider:
```
Scan URLs → Enhanced Analysis → Cluster Detection → Confidence Scoring → Report Generation
```

### 2. Infrastructure Forensics
Track service infrastructure changes over time:
```
Baseline Creation → Version Tracking → Change Detection → Impact Analysis
```

### 3. Provider Verification
Validate if a service provider is legitimate or a reseller:
```
Domain Analysis → ASN Lookup → Nameserver Check → Certificate Validation → Final Score
```

## 📊 Confidence Scoring System

The advanced features use a multi-layered confidence scoring system (0-100):

| Score Range | Classification | Description |
|------------|----------------|-------------|
| 0-25 | Low Confidence | Insufficient evidence, likely original provider |
| 26-50 | Moderate | Some clustering detected, possible reseller |
| 51-75 | High | Strong evidence of reselling behavior |
| 76-100 | Very High | Definitive reseller identification |

Confidence is calculated from multiple factors:
- **ASN Confidence (25%)** - Shared datacenter infrastructure
- **Nameserver Confidence (25%)** - Common DNS patterns
- **Certificate Confidence (20%)** - SSL certificate clustering
- **Registration Confidence (20%)** - Domain registration patterns
- **Historical Data (10%)** - Past behavior and changes

## 🔑 API Authentication

All advanced API endpoints support optional authentication:
```php
// Public endpoints (read-only)
GET /resellers-advanced.php
GET /stats.php

// Protected endpoints (require API key)
POST /scan-enhanced.php
POST /report-generator.php
```

See [API Reference](API-Reference.md) for complete authentication details.

## 🛠️ Technology Stack

- **Backend**: PHP 7.4+ with MySQLi
- **Database**: MySQL/MariaDB 5.7+
- **External APIs**: 
  - IPinfo.io (IP geolocation & ASN data)
  - IP2WHOIS (domain registration data)
- **Frontend**: Bootstrap 5 with jQuery
- **PDF Generation**: TCPDF or internal HTML2PDF

## 📖 Getting Started

1. **Basic Setup** - Follow the [main README](../../README.md) for initial installation
2. **Database Enhancement** - Run `database_enhanced.sql` for advanced features
3. **Configuration** - Review [Configuration Guide](Configuration-Guide.md) for advanced options
4. **Test Scanning** - Use `test-enhanced.php` to verify your setup
5. **Explore APIs** - Review [API Reference](API-Reference.md) for integration options

## 🤝 Contributing

Found a bug or have a feature request? Join our [Discord server](https://discord.gg/zxUq3afdn8) or open an issue on GitHub.

## 📜 License

This project is released for educational and research purposes. Always respect privacy and legal boundaries when analyzing IPTV services.

---

**Need Help?** Start with the [Basic README](../../README.md) or join our community on [Discord](https://discord.gg/zxUq3afdn8).
