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

## Reseller Scoring

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
