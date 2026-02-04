# IPTV Forensics Detective

🌐 **[Live Site](https://astrolume.infinityfreeapp.com/IPTV/)** - Start scanning now!

A comprehensive forensics tool for analyzing IPTV trial URLs, unmasking provider information, and detecting reseller patterns.

## Features

- **IP Resolution**: Extract and resolve domain names to IP addresses
- **Provider Detection**: Identify hosting providers and data centers using ASN lookup
- **Server Signature Analysis**: Detect server headers and software signatures
- **Reseller Probability**: Calculate likelihood of reseller based on infrastructure
- **Dark Theme UI**: Modern, responsive Bootstrap interface
- **Database Caching**: Store and retrieve historical scan results

## Requirements

- PHP 7.4+
- MySQL/MariaDB 5.7+
- Web Server (Apache/Nginx with PHP support)
- Internet connection (for IPinfo API calls)

## Quick Start

### 1. Database Setup
```bash
mysql -u root -p < database.sql
```

### 2. Configure Application
Copy the example config and fill in your credentials:
```bash
cp config.example.php config.php
# Edit config.php with your settings
```

#### Required Configuration:
- **DB_HOST, DB_USER, DB_PASSWORD, DB_NAME**: Your MySQL database details
- **IPINFO_API_KEY**: Get free token at https://ipinfo.io
- **IP2WHOIS_API_KEY**: Get free token at https://www.ip2whois.com

### Getting API Keys

#### IPinfo.io (IP Geolocation)
1. Visit: https://ipinfo.io/signup
2. Sign up for free account
3. Go to https://ipinfo.io/account/token
4. Copy your token and paste into `config.php`
5. Free tier: 50,000 requests/month

#### IP2WHOIS (Domain Age & WHOIS Data)
1. Visit: https://www.ip2whois.com
2. Click "Sign Up" for free account
3. Go to https://www.ip2whois.com/api/my-api
4. Copy your API key and paste into `config.php`
5. Free tier: 10,000 requests/month

### 3. Deploy Files
Place all files in your web server directory

### 4. Access
Open `index.html` in your browser

## Usage

Enter an IPTV URL (with or without port) and click "Scan" to analyze:

**Supported URL formats:**
- `http://domain.com/path`
- `http://domain.com:8080/player_api.php`
- `domain.com:25461/get.php`
- `http://192.168.1.1:8000/playlist.m3u8`

**Results include:**
- Real Host IP Address
- Country Location
- Organization/ISP
- ASN Information
- Server Software Signature
- Panel Type Detection (Xtream Codes, Stalker, M3U)
- Domain Age (from WHOIS)
- Original Provider Detection (via IP clustering)
- Reseller Probability Score
- Upstream Provider Score

## API Integration

### IPinfo.io (IP Geolocation & ASN)
- **Purpose**: Country, Organization, ASN lookup
- **Free Plan**: 50,000 requests/month
- **Get Key**: https://ipinfo.io/signup
- **Docs**: https://ipinfo.io/docs

### IP2WHOIS (Domain Age & Registration Data)
- **Purpose**: Accurate domain creation date from WHOIS
- **Free Plan**: 10,000 requests/month
- **Get Key**: https://www.ip2whois.com
- **Docs**: https://www.ip2whois.com/api

## Reseller Detection (Enhanced)

The tool now uses a **multi-factor confidence scoring system** to identify reseller networks:

### Detection Methods

| Method | Weight | How It Works |
|--------|--------|-------------|
| **ASN Analysis** | 35% | Groups domains by datacenter ASN (DigitalOcean, AWS, OVH, Hetzner, etc.) |
| **Nameserver Clustering** | 30% | Identifies shared DNS infrastructure across multiple domains |
| **SSL Fingerprinting** | 20% | Detects domains using identical SSL certificates |
| **Registration Patterns** | 15% | Finds batch-registered domains (same registrar, email, date) |

### Confidence Scoring

- **0-40%**: Weak reseller signal - likely independent operators
- **40-70%**: Moderate reseller signal - probable shared infrastructure
- **70-90%**: Strong reseller signal - definite infrastructure sharing
- **90-100%**: Very strong reseller signal - nearly identical infrastructure

### Cluster Evidence Display

When viewing resellers, you'll see which factors triggered detection:

- **ASN Shared**: Multiple domains on same datacenter network
- **NS Shared**: Multiple domains using same nameservers
- **SSL Shared**: Multiple domains with identical SSL certificates
- **Batch Reg**: Multiple domains registered close together

### Example

Two domains detected as resellers if:
1. Both resolve to IPs in same ASN (OVH) → +35%
2. Both use ns1.panel.com, ns2.panel.com → +30%
3. Both have certificate CN: panel.example.com → +20%
4. Both registered within 7 days → +15%

**Total Confidence: 100%** (Definite reseller network)

## Database Schema

### New Enhanced Columns

The enhanced scanner (`scan-enhanced.php`) collects:

```sql
asn_block              VARCHAR(100)      -- ASN number block
asn_name               VARCHAR(255)      -- ASN organization name
nameserver_hash        VARCHAR(64)       -- SHA256 hash of nameservers
nameservers            TEXT              -- Comma-separated nameserver list
ssl_cert_hash          VARCHAR(64)       -- SHA256 hash of SSL cert
ssl_issuer             VARCHAR(255)      -- SSL certificate issuer
ssl_common_names       TEXT              -- SSL SAN domains
domain_registrar       VARCHAR(255)      -- Domain registrar
domain_reg_date        DATE              -- Domain registration date
domain_reg_email       VARCHAR(255)      -- Registrant email
panel_fingerprint      VARCHAR(255)      -- MD5 of panel response
registration_pattern   VARCHAR(50)       -- 'batch_registration' or 'same_registrant'
confidence_score       INT               -- Overall reseller confidence (0-100)
relationship_reasons   TEXT              -- Human-readable detection reasons
asn_reseller_confidence INT              -- ASN confidence (0-100)
ns_reseller_confidence INT               -- Nameserver confidence (0-100)
cert_reseller_confidence INT             -- SSL cert confidence (0-100)
reg_pattern_confidence INT               -- Registration pattern confidence (0-100)
```

### Running Database Migration

```bash
# Copy database_enhanced.sql to your server and run:
mysql -u your_user -p your_database < database_enhanced.sql
```

## API Endpoints

### scan-enhanced.php

Advanced scanning with full feature set:

```
POST /scan-enhanced.php
Parameters:
  - url: IPTV URL to scan
  - provider_name: Highly recommended provider name for reseller linking
  
Returns:
  - confidence_score: 0-100
  - asn_reseller_confidence: 0-100
  - ns_reseller_confidence: 0-100
  - cert_reseller_confidence: 0-100
  - relationship_reasons: Text explanation
  - cluster_evidence: { asn_clustering, nameserver_clustering, ... }
```

### resellers-advanced.php

Get all detected reseller networks with cluster evidence:

```
GET /resellers-advanced.php

Returns:
  {
    "resellers": [
      {
        "name": "provider1 | provider2",
        "domain_count": 15,
        "confidence_score": 87,
        "cluster_evidence": {
          "asn_clustering": 3,
          "nameserver_clustering": 15,
          "cert_clustering": 1,
          "registration_pattern_clustering": 5
        },
        "domains": [...],
        "related_providers": [...]
      }
    ],
    "clusters": [...]
  }
```

## Reseller Scoring
````

Score based on:
- **Data Center Detection** (0-80%): OVH, Hetzner, Linode, etc.
- **Server Signatures** (0-30%): Nginx, Apache, CDN headers

## Security

- SQL parameterized queries (injection-proof)
- Input validation for URLs
- Error logging (no errors shown to users)
- CORS configured
- SSL/TLS recommended for production

## Database Schema

| Column | Type | Description |
|--------|------|-------------|
| resolved_ip | VARCHAR(45) | IPv4/IPv6 address |
| asn | VARCHAR(50) | Autonomous System Number |
| organization | VARCHAR(255) | ISP/Organization |
| country_code | VARCHAR(10) | ISO country code |
| server_header | VARCHAR(255) | Server signature |
| reseller_probability | INT | Score 0-100 |
| created_at | TIMESTAMP | Scan time |

## Troubleshooting

- **Database Error**: Check MySQL running and credentials in config.php
- **IP Resolution Failed**: Verify domain is accessible, check DNS
- **No Server Header**: Some hosts don't respond to HTTP or hide headers
- **API Failed**: Verify API key, check internet connection

## License

Provided as-is for forensic and security analysis.

---
**Version**: 1.0  
**Last Updated**: February 2026
\n# Another test commit with more content Wed Feb  4 13:29:45 CET 2026
Some more lines to make this a bigger commit.
