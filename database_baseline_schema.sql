-- IPTV Forensics Tool - Baseline & Alias Management Database Schema
-- This extends the existing scanned_hosts table with baseline tracking and aliasing

-- ============================================================================
-- BASELINE SERVICES TABLE
-- Stores the core/original service definitions that staff members create
-- ============================================================================
CREATE TABLE IF NOT EXISTS baseline_services (
    id INT AUTO_INCREMENT PRIMARY KEY,
    service_name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    
    -- Baseline metadata from initial Xtream scan
    baseline_domain VARCHAR(255) NOT NULL,
    baseline_ip VARCHAR(45),
    baseline_url TEXT NOT NULL,
    
    -- Service characteristics (from Xtream API or panel)
    channel_count INT,
    vod_count INT,
    series_count INT,
    
    -- Credentials reference (hashed for security)
    credentials_hash VARCHAR(255) NOT NULL UNIQUE,
    last_verified_at TIMESTAMP NULL,
    
    -- Privacy settings
    is_private BOOLEAN DEFAULT 0,
    private_group_id INT NULL,
    
    -- Status tracking
    status ENUM('pending', 'approved', 'rejected', 'archived') DEFAULT 'pending',
    created_by_user_id INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    INDEX idx_status (status),
    INDEX idx_is_private (is_private),
    INDEX idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- SERVICE ALIASES TABLE
-- User-submitted names and matches for baseline services
-- Used to identify when different names refer to the same service
-- ============================================================================
CREATE TABLE IF NOT EXISTS service_aliases (
    id INT AUTO_INCREMENT PRIMARY KEY,
    baseline_id INT NOT NULL,
    
    -- Alias information
    alias_name VARCHAR(255) NOT NULL,
    alias_type ENUM('user_submitted', 'auto_detected', 'manual_admin') DEFAULT 'user_submitted',
    
    -- Matching metrics
    match_percentage INT DEFAULT 0,
    match_criteria_met TEXT, -- JSON array of what matched (channels, IPs, etc.)
    
    -- Source tracking
    submitted_by_user_id INT,
    submission_ip VARCHAR(45),
    submission_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Confidence level
    confidence_score INT DEFAULT 0,
    requires_admin_approval BOOLEAN DEFAULT 1,
    approved_by_user_id INT NULL,
    approved_at TIMESTAMP NULL,
    
    status ENUM('pending', 'approved', 'rejected') DEFAULT 'pending',
    
    FOREIGN KEY (baseline_id) REFERENCES baseline_services(id) ON DELETE CASCADE,
    UNIQUE KEY unique_alias_per_baseline (baseline_id, alias_name),
    INDEX idx_match_percentage (match_percentage),
    INDEX idx_status (status),
    INDEX idx_submission_date (submission_date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- SERVICE METADATA TABLE
-- Captures additional technical details about services
-- Resolution, bitrate, EPG availability, etc.
-- ============================================================================
CREATE TABLE IF NOT EXISTS service_metadata (
    id INT AUTO_INCREMENT PRIMARY KEY,
    baseline_id INT NOT NULL,
    
    -- Video metadata
    max_resolution VARCHAR(50), -- 720p, 1080p, 4K, 8K, etc.
    average_bitrate VARCHAR(50), -- e.g., "5000 kbps"
    codec_types TEXT, -- JSON array: ['h264', 'h265', 'av1']
    
    -- Service features
    has_epg BOOLEAN DEFAULT 0,
    epg_update_frequency VARCHAR(100),
    has_catchup BOOLEAN DEFAULT 0,
    catchup_days INT DEFAULT 0,
    
    -- Geographic/Content info
    primary_country VARCHAR(100),
    language_codes TEXT, -- JSON array
    content_type ENUM('mixed', 'live_only', 'vod_only') DEFAULT 'mixed',
    
    -- Streaming info
    supported_protocols TEXT, -- JSON array: ['http', 'rtmp', 'hls', 'dash']
    max_concurrent_streams INT,
    geographic_restrictions TEXT,
    
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    FOREIGN KEY (baseline_id) REFERENCES baseline_services(id) ON DELETE CASCADE,
    UNIQUE KEY unique_metadata_per_baseline (baseline_id),
    INDEX idx_resolution (max_resolution),
    INDEX idx_country (primary_country)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- SERVICE VERSIONS TABLE
-- Tracks changes to baseline services over time
-- Allows detection of updates and playlist changes
-- ============================================================================
CREATE TABLE IF NOT EXISTS service_versions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    baseline_id INT NOT NULL,
    
    -- Version info
    version_number INT NOT NULL,
    change_summary TEXT,
    
    -- Changes detected
    channel_count_previous INT,
    channel_count_new INT,
    channels_added INT,
    channels_removed INT,
    
    vod_count_previous INT,
    vod_count_new INT,
    
    -- Scan that triggered the version
    scan_url VARCHAR(500),
    scan_domain VARCHAR(255),
    
    -- Detection method
    detected_by_scan_id INT, -- Reference to scanned_hosts table
    detection_type ENUM('manual_scan', 'auto_verify', 'user_report') DEFAULT 'auto_verify',
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (baseline_id) REFERENCES baseline_services(id) ON DELETE CASCADE,
    INDEX idx_baseline (baseline_id),
    INDEX idx_version_number (version_number),
    INDEX idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- PRIVATE SERVICES TABLE
-- Manages access control for services marked as "private"
-- ============================================================================
CREATE TABLE IF NOT EXISTS private_service_groups (
    id INT AUTO_INCREMENT PRIMARY KEY,
    group_name VARCHAR(255) NOT NULL,
    group_key VARCHAR(255) NOT NULL UNIQUE, -- Encryption key or access code
    description TEXT,
    
    -- Access control
    is_encrypted BOOLEAN DEFAULT 1,
    encryption_method VARCHAR(50) DEFAULT 'AES-256',
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    INDEX idx_group_name (group_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- PRIVATE SERVICE ACCESS TABLE
-- Controls which users/admins can access private services
-- ============================================================================
CREATE TABLE IF NOT EXISTS private_service_access (
    id INT AUTO_INCREMENT PRIMARY KEY,
    private_group_id INT NOT NULL,
    user_id INT NOT NULL,
    access_level ENUM('view', 'moderate', 'admin') DEFAULT 'view',
    
    granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    granted_by_user_id INT,
    
    FOREIGN KEY (private_group_id) REFERENCES private_service_groups(id) ON DELETE CASCADE,
    UNIQUE KEY unique_user_access (private_group_id, user_id),
    INDEX idx_access_level (access_level)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- ADMIN APPROVAL QUEUE TABLE
-- Tracks baseline and alias submissions pending admin approval
-- ============================================================================
CREATE TABLE IF NOT EXISTS admin_approval_queue (
    id INT AUTO_INCREMENT PRIMARY KEY,
    
    -- What is being approved
    submission_type ENUM('baseline', 'alias', 'metadata_update') DEFAULT 'baseline',
    baseline_id INT,
    alias_id INT,
    
    -- Submission details
    submitted_by_user_id INT,
    submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Submission content (JSON for flexibility)
    submission_data LONGTEXT, -- JSON with all details
    
    -- Review status
    status ENUM('pending', 'approved', 'rejected', 'needs_revision') DEFAULT 'pending',
    reviewed_by_user_id INT NULL,
    review_notes TEXT,
    reviewed_at TIMESTAMP NULL,
    
    -- Admin scoring
    confidence_rating INT DEFAULT 0, -- 1-10 scale
    
    FOREIGN KEY (baseline_id) REFERENCES baseline_services(id) ON DELETE SET NULL,
    FOREIGN KEY (alias_id) REFERENCES service_aliases(id) ON DELETE SET NULL,
    INDEX idx_status (status),
    INDEX idx_submission_type (submission_type),
    INDEX idx_submitted_at (submitted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- SCAN MATCH RESULTS TABLE
-- Stores results of user scans compared against baselines
-- ============================================================================
CREATE TABLE IF NOT EXISTS scan_match_results (
    id INT AUTO_INCREMENT PRIMARY KEY,
    
    -- Original scan reference
    scan_id INT, -- Can reference original scanned_hosts table
    user_scan_url VARCHAR(500),
    user_scan_domain VARCHAR(255),
    
    -- Baseline matching
    baseline_id INT NOT NULL,
    match_percentage INT,
    match_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Detailed matching info
    matching_criteria TEXT, -- JSON: what matched (channel count, IP, domain, etc.)
    non_matching_criteria TEXT, -- JSON: what didn't match
    
    -- User-provided information
    user_service_name VARCHAR(255),
    user_country VARCHAR(100),
    user_notes TEXT,
    
    -- Reseller chain information
    reseller_chain_depth INT,
    reseller_chain TEXT, -- JSON array of domains from user to baseline
    
    status ENUM('pending_review', 'approved_match', 'approved_new_baseline', 'rejected') DEFAULT 'pending_review',
    admin_notes TEXT,
    
    FOREIGN KEY (baseline_id) REFERENCES baseline_services(id) ON DELETE CASCADE,
    INDEX idx_baseline_id (baseline_id),
    INDEX idx_match_percentage (match_percentage),
    INDEX idx_status (status),
    INDEX idx_match_timestamp (match_timestamp)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- SCAN METADATA TABLE
-- Enhanced scanning data collection
-- ============================================================================
CREATE TABLE IF NOT EXISTS scan_metadata (
    id INT AUTO_INCREMENT PRIMARY KEY,
    scan_id INT,
    
    -- Resolution and bitrate info
    resolution VARCHAR(50),
    bitrate VARCHAR(50),
    fps INT,
    
    -- Counts and availability
    channels_detected INT,
    vods_detected INT,
    series_detected INT,
    epg_available BOOLEAN DEFAULT 0,
    catchup_available BOOLEAN DEFAULT 0,
    
    -- Stream info
    protocols_detected TEXT, -- JSON array
    concurrent_streams INT,
    
    -- Timing
    scan_duration_seconds INT,
    successful_connections INT,
    failed_connections INT,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_resolution (resolution),
    INDEX idx_channels_detected (channels_detected)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- USER ROLES & PERMISSIONS TABLE
-- Manage access levels for staff, admins, and regular users
-- ============================================================================
CREATE TABLE IF NOT EXISTS user_roles (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    role ENUM('user', 'staff', 'admin', 'super_admin') DEFAULT 'user',
    
    can_create_baseline BOOLEAN DEFAULT 0,
    can_approve_baselines BOOLEAN DEFAULT 0,
    can_manage_private_services BOOLEAN DEFAULT 0,
    can_access_admin_panel BOOLEAN DEFAULT 0,
    can_view_reseller_chains BOOLEAN DEFAULT 0,
    can_view_private_services BOOLEAN DEFAULT 0,
    
    granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    granted_by_user_id INT,
    
    UNIQUE KEY unique_user_role (user_id),
    INDEX idx_role (role)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- DISCLAIMERS & PRIVACY TRACKING TABLE
-- Track user acceptance of terms and privacy policies
-- ============================================================================
CREATE TABLE IF NOT EXISTS privacy_acknowledgments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    
    -- Acknowledgments
    acknowledged_credential_privacy BOOLEAN DEFAULT 0,
    acknowledged_use_trial_credentials BOOLEAN DEFAULT 0,
    acknowledged_data_collection BOOLEAN DEFAULT 0,
    
    -- Tracking
    acknowledged_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    acknowledgment_ip VARCHAR(45),
    acknowledgment_user_agent TEXT,
    
    INDEX idx_user_id (user_id),
    INDEX idx_acknowledged_at (acknowledged_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- AUDIT LOG TABLE
-- Track all admin actions for security and compliance
-- ============================================================================
CREATE TABLE IF NOT EXISTS audit_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    admin_user_id INT NOT NULL,
    action_type VARCHAR(100),
    action_description TEXT,
    
    -- What was modified
    related_baseline_id INT,
    related_alias_id INT,
    related_user_id INT,
    
    -- Before/After
    old_values LONGTEXT, -- JSON
    new_values LONGTEXT, -- JSON
    
    action_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    admin_ip VARCHAR(45),
    
    INDEX idx_admin_user_id (admin_user_id),
    INDEX idx_action_type (action_type),
    INDEX idx_action_timestamp (action_timestamp)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
