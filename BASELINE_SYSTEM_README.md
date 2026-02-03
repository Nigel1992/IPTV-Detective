# IPTV Detective - Baseline Services & Matching System

## New Features Overview

This enhanced version of IPTV Detective introduces a comprehensive baseline service management and matching system, allowing staff to establish known services and users to identify matching services with detailed forensic analysis.

---

## 🎯 Core Features

### 1. **Baseline Service Management** (`baseline-manager.php`)
Staff members can create and manage baseline IPTV services:

#### Creating Baselines
- Upload Xtream credentials (staff only)
- Automatic service information retrieval
- Stores: channels, VODs, series counts
- Service metadata collection
- Credentials are SHA-256 hashed (never stored plaintext)
- Pending admin approval workflow

**API Endpoint:**
```
POST /baseline-manager.php
Actions: create, update, list, archive
```

#### Example Request:
```json
{
  "action": "create",
  "user_id": 1,
  "service_name": "Strong8k Trial",
  "baseline_url": "http://example.com:8080/player_api.php",
  "description": "Strong8k Test Provider",
  "xtream_username": "trial_user",
  "xtream_password": "trial_pass",
  "is_private": false,
  "metadata": {
    "max_resolution": "4K",
    "average_bitrate": "8000 kbps",
    "primary_country": "France",
    "has_epg": true
  }
}
```

---

### 2. **Service Matching & User Scanning** (`service-matcher.php`)
Users can scan IPTV services and get intelligent matching against baselines:

#### Matching Algorithm
- **IP-Based Matching**: Exact IP match (40% weight)
- **Domain Matching**: Domain exact/similar match (30% weight)
- **Channel Count**: Similarity within ±15% (15% weight)
- **Resolution Matching**: Video quality comparison (5% weight)
- **Country Matching**: Geographic data (8% weight)
- **EPG Availability**: Feature parity (3% weight)
- **Bitrate Matching**: Stream quality comparison (4% weight)

#### Confidence Scoring
- **80-100%**: Excellent Match
- **60-80%**: Good Match
- **40-60%**: Fair Match
- **<40%**: Potential match for admin review

**API Endpoint:**
```
POST /service-matcher.php
Action: scan_and_match
```

#### Example Request:
```json
{
  "action": "scan_and_match",
  "url": "http://iptv-provider.com:25461/get.php",
  "service_name": "My IPTV Service",
  "country": "UK",
  "metadata": {
    "channels": 850,
    "vods": 2500,
    "resolution": "1080p",
    "bitrate": "5000 kbps",
    "has_epg": true
  }
}
```

#### Response Includes:
- Matching baselines with confidence scores
- Detailed matching criteria
- Alias information
- Option to create new baseline if no match
- Reseller chain information

---

### 3. **Alias Management**
Automatically track alternative names for services:

- User-submitted names create aliases
- Confidence scoring for alias matching
- Pending admin approval for new aliases
- Track reseller chains and relationships
- Multiple aliases per baseline

**Example:**
```
Baseline: "Strong8k Trial"
Aliases:
- "Strong 8K" (92% match)
- "S8K Test" (88% match)
- "Strong Premium" (85% match)
```

---

### 4. **Private Services (Lock & Key)** (`private-services.php`)

#### Why Privacy?
Some services request strict confidentiality for:
- Security reasons
- Competitive advantage
- Legal requirements
- Provider privacy

#### Encryption Features
- AES-256 encryption for service names
- Reseller chains encrypted per private group
- Access control via private service groups
- Three-tier access: view, moderate, admin

**API Endpoint:**
```
POST /private-services.php
Actions: create_group, mark_private, encrypt, decrypt, 
         grant_access, revoke_access, check_private_match
```

#### Access Control Example:
```json
{
  "action": "grant_access",
  "user_id": 1,
  "group_id": 5,
  "target_user_id": 42,
  "access_level": "view"  // view, moderate, or admin
}
```

#### Private Service Match Report:
```
✅ This matches a private service
Match: 92%

Details available only to authorized users.
Service name and reseller chain are encrypted.
```

---

### 5. **Service Versioning & Updates** (`service-versioning.php`)

#### Tracking Changes
- Version history for each baseline
- Detects channel/VOD additions/removals
- Normalizes natural variations (±5% tolerance)
- Auto-update baselines from verified matches
- Logs all changes with timestamps

**API Endpoint:**
```
POST /service-versioning.php
Actions: record_update, get_history, compare_versions, 
         normalize, auto_update
```

#### Example Version Record:
```json
{
  "version_number": 5,
  "change_summary": "Version 5: +12 channels, -3 VODs",
  "channel_count_previous": 850,
  "channel_count_new": 862,
  "channels_added": 12,
  "channels_removed": 3,
  "detection_type": "auto_verify"
}
```

#### Normalization Algorithm
- Calculates average across recent versions
- Determines acceptable variation range
- Flags anomalies outside tolerance
- Prevents false positives from minor fluctuations

---

### 6. **PDF Report Generation** (`report-generator.php`)

#### Professional Reports
Three types of reports:

##### A. Match Reports
- Individual service match analysis
- Confidence percentage with visual badge
- Matching criteria details
- Known aliases for matched service
- Privacy notices for private services
- Professional formatting suitable for sharing

**API:**
```
POST /report-generator.php
Action: generate_match_report
GET Parameter: match_id=X
```

##### B. Baseline Reports
- Complete baseline service profile
- All known aliases
- Version update history
- Recent matches
- Statistics and metadata

##### C. Admin Summary Reports
- System-wide statistics
- Pending approvals
- Recent matches
- Private service overview

#### Report Features:
- ✅ Professional PDF layout
- ✅ Branding and logos
- ✅ Confidentiality notice
- ✅ Privacy warnings
- ✅ Hide private details option
- ✅ Print-friendly design
- ✅ Date and report ID stamping

---

### 7. **Admin Dashboard** (`admin-dashboard.php`)

#### Dashboard Statistics
- Total baselines (approved, pending, private)
- Match results and avg match percentage
- Pending approvals count
- Recent audit activity

#### Approval Workflow
- View pending submissions
- Approve/reject with notes
- Auto-update related records
- Audit trail logging

#### Alias Management
- View all aliases per baseline
- Track alias match percentages
- See reseller chain information
- Manage private service access

**API Endpoint:**
```
POST /admin-dashboard.php
Actions: get_stats, get_pending, approve, reject, 
         get_aliases, get_reseller_chain, get_audit_log
```

---

### 8. **Disclaimers & Privacy** (`disclaimers.php`)

#### Required Acknowledgments
- ✅ Credential Privacy
- ✅ Trial Credentials Only
- ✅ Data Collection & Usage

#### Disclaimer Categories:

##### 1. Credential Privacy
- Credentials are hashed (SHA-256)
- Never stored in plaintext
- HTTPS encryption in transit
- No third-party access
- Audit trails maintained

##### 2. Trial Credentials Warning
- **MUST** use trial credentials only
- No premium/personal accounts
- No family member credentials
- Reduced risk of compromise
- Legal compliance

##### 3. Data Collection Notice
- What data is collected
- How it's used
- Retention periods
- User control/rights
- Deletion options

##### 4. Private Services Policy
- Encrypted service names
- Hidden reseller chains
- Limited access authorization
- Public report restrictions

**API Endpoint:**
```
POST /disclaimers.php
Actions: get_disclaimers, acknowledge, check_status,
         get_privacy_policy, get_terms
```

---

## 📊 Database Schema

### New Tables

1. **baseline_services**
   - Core service definitions
   - Staff-created baselines
   - Privacy flags
   - Status tracking (pending/approved)

2. **service_aliases**
   - User-submitted service names
   - Match confidence scores
   - Approval workflow
   - Reseller information

3. **service_metadata**
   - Resolution, bitrate, codec info
   - EPG and catchup details
   - Geographic/content info
   - Supported protocols

4. **service_versions**
   - Version history per baseline
   - Change tracking (channels, VODs)
   - Detection methods
   - Temporal analysis

5. **private_service_groups**
   - Private service groupings
   - Encryption keys
   - Access control settings

6. **private_service_access**
   - User access to private groups
   - Three-tier permissions
   - Audit trail for access grants

7. **admin_approval_queue**
   - Pending baseline submissions
   - Alias approval workflow
   - Admin notes and review status

8. **scan_match_results**
   - User scan results
   - Baseline matches
   - Match percentage calculations
   - Reseller chain tracking

9. **scan_metadata**
   - Enhanced scan details
   - Resolution/bitrate data
   - Protocol detection
   - Scan performance metrics

10. **user_roles**
    - Role-based access control
    - Staff/admin permissions
    - Private service access flags

11. **privacy_acknowledgments**
    - Disclaimer acceptance tracking
    - IP and user agent logging
    - Timestamp records

12. **audit_log**
    - All admin actions logged
    - Before/after values
    - IP address tracking
    - Security audit trail

---

## 🔐 Security Features

### Data Protection
- **AES-256 Encryption**: Private service names and reseller chains
- **SHA-256 Hashing**: Credentials never stored plaintext
- **HTTPS Only**: All data transmission encrypted
- **Access Control**: Role-based permissions (user, staff, admin, super_admin)

### Privacy
- **Hashed Credentials**: Cannot be recovered or viewed
- **Encrypted PII**: Private service info encrypted per group
- **Audit Trails**: All access logged with IP/timestamp
- **Automatic Deletion**: User data deletion on request

### Compliance
- **Terms of Service**: Explicitly prohibits illegal activity
- **Privacy Policy**: Clear data handling practices
- **GDPR Ready**: Data export/deletion features
- **Compliance Logging**: Full audit trail for legal review

---

## 🚀 Usage Workflows

### For Staff (Creating Baselines)
```
1. Obtain trial IPTV credentials
2. Call baseline-manager.php with action=create
3. Provide service name, URL, metadata
4. System hashes credentials and fetches service info
5. Submission queued for admin approval
6. Once approved, appears in matching database
7. Staff can update baseline info or archive old baselines
```

### For Users (Scanning Services)
```
1. Accept privacy disclaimers and terms
2. Enter IPTV service URL in scan form
3. Optionally provide service name (creates alias if new)
4. Call service-matcher.php with scan details
5. System returns:
   - Matching baseline (if found) with confidence %
   - Matching criteria (IP, domain, channels, etc.)
   - Alias information
   - Option to generate PDF report
6. If no match and service named:
   - Submission queued for new baseline creation
   - Notified of pending status
7. View PDF report with match details
8. Share report (private details hidden if applicable)
```

### For Admins (Managing System)
```
1. Log into admin dashboard (admin-dashboard.php)
2. View system statistics and pending approvals
3. Review baseline submissions:
   - Check service metadata
   - Verify against known services
   - Look for reseller relationships
4. Approve or reject with notes
5. Manage private service groups and access
6. View audit logs for compliance
7. Approve aliases as they're submitted
8. Monitor match quality and system health
```

---

## 📈 Matching Intelligence

### Match Calculation Example
```
User Scan: "Cool IPTV Trial"
- Domain: cool-iptv.com
- IP: 185.92.111.50
- Channels: 1,240
- Resolution: 1080p
- Country: Netherlands
- EPG: Yes

Baseline: "Cool TV"
- Domain: cool-iptv.com
- IP: 185.92.111.50
- Channels: 1,200
- Resolution: 1080p
- Country: Netherlands
- EPG: Yes

Scoring:
✓ IP exact match: +40
✓ Domain exact match: +30
✓ Channels similar (±3.3%): +15
✓ Resolution match: +5
✓ Country match: +8
✓ EPG match: +3

TOTAL: 101 → capped at 100%
CONFIDENCE: Excellent Match (100%)
```

---

## 🔄 Version Tracking Example

```
Version 1 (Jan 1): 1000 channels, 2000 VODs
Version 2 (Jan 8): 1015 channels, 2050 VODs (+15 channels, +50 VODs)
Version 3 (Jan 15): 1020 channels, 2080 VODs (+5 channels, +30 VODs)
Version 4 (Jan 22): 1010 channels, 2090 VODs (-10 channels, +10 VODs)
Version 5 (Jan 29): 1025 channels, 2100 VODs (+15 channels, +10 VODs)

Normalization Analysis (5% tolerance):
- Average channels: 1,014 (range: 963-1,065)
- Average VODs: 2,064 (range: 1,960-2,167)
- All versions within acceptable variation
- Status: HEALTHY (no anomalies detected)
```

---

## 🎨 Frontend Integration

The system includes ready-to-use API endpoints. Frontend implementation should include:

1. **Disclaimer Modal** (on first visit)
2. **Service Scan Form** (with baseline selector)
3. **Match Results Display** (with confidence badges)
4. **Report Download Button** (PDF generation)
5. **Admin Panel** (dashboard, approvals, audit logs)
6. **Private Service Notices** (when applicable)

---

## 📋 API Summary

| Endpoint | Action | Purpose |
|----------|--------|---------|
| `baseline-manager.php` | create | Create new baseline |
| `baseline-manager.php` | list | View baselines |
| `baseline-manager.php` | update | Update baseline info |
| `baseline-manager.php` | archive | Archive baseline |
| `service-matcher.php` | scan_and_match | Scan & match service |
| `private-services.php` | create_group | Create private group |
| `private-services.php` | mark_private | Encrypt service |
| `private-services.php` | grant_access | Allow user access |
| `service-versioning.php` | record_update | Track version change |
| `service-versioning.php` | normalize | Analyze variations |
| `report-generator.php` | generate_match_report | Create PDF |
| `admin-dashboard.php` | get_stats | View statistics |
| `admin-dashboard.php` | get_pending | View approvals |
| `disclaimers.php` | acknowledge | Accept terms |

---

## 🛠️ Installation

1. **Import Database Schema**:
   ```bash
   mysql -u root -p < database_baseline_schema.sql
   ```

2. **Verify PHP Files Deployed**:
   - baseline-manager.php
   - service-matcher.php
   - private-services.php
   - service-versioning.php
   - report-generator.php
   - admin-dashboard.php
   - disclaimers.php

3. **Set up Config** (if not already done):
   ```bash
   cp config.example.php config.php
   # Edit config.php with your credentials
   ```

4. **Create Logs Directory**:
   ```bash
   mkdir -p logs
   chmod 755 logs
   ```

---

## 🧪 Testing Endpoints

### Create a Baseline
```bash
curl -X POST http://localhost/baseline-manager.php \
  -d '{
    "action": "create",
    "user_id": 1,
    "service_name": "Test Service",
    "baseline_url": "http://test.iptv:8080/player_api.php",
    "xtream_username": "test",
    "xtream_password": "test123"
  }' \
  -H "Content-Type: application/json"
```

### Scan and Match
```bash
curl -X POST http://localhost/service-matcher.php \
  -d '{
    "action": "scan_and_match",
    "url": "http://myiptv.com:8080/player_api.php",
    "service_name": "My IPTV"
  }' \
  -H "Content-Type: application/json"
```

### Get Disclaimers
```bash
curl -X GET "http://localhost/disclaimers.php?action=get_disclaimers&user_id=1"
```

---

## 📝 Notes

- All timestamps are in UTC
- IPs are IPv4/IPv6 compatible
- JSON fields support complex nested data
- Encryption keys are stored securely (never logged)
- Audit logs include before/after values for all changes
- Deleted records are soft-deleted (status='archived')

---

## 🆘 Support

For issues or questions:
1. Check audit logs for errors
2. Review PHP error logs
3. Verify database connections
4. Ensure all tables are created
5. Check user roles and permissions

