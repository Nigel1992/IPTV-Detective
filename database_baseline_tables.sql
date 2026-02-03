-- IPTV Forensics Tool - Add Missing Baseline Tables
-- Run this migration to add baseline_services, service_aliases, and admin_users tables
-- This is safe to run on existing databases (uses IF NOT EXISTS)

USE your_database_name;

-- Create baseline_services table
CREATE TABLE IF NOT EXISTS baseline_services (
    id INT AUTO_INCREMENT PRIMARY KEY,
    service_name VARCHAR(255) NOT NULL,
    baseline_domain VARCHAR(255),
    credentials_hash VARCHAR(64) UNIQUE,
    channel_count INT DEFAULT 0,
    panel_type VARCHAR(100),
    epg_source VARCHAR(255),
    status VARCHAR(50) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_status (status),
    INDEX idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Create service_aliases table
CREATE TABLE IF NOT EXISTS service_aliases (
    id INT AUTO_INCREMENT PRIMARY KEY,
    baseline_id INT,
    alias_name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (baseline_id) REFERENCES baseline_services(id) ON DELETE CASCADE,
    INDEX idx_baseline (baseline_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Create admin_users table
CREATE TABLE IF NOT EXISTS admin_users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'moderator',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Add missing columns to scanned_hosts if they don't exist
ALTER TABLE scanned_hosts ADD COLUMN IF NOT EXISTS provider_website VARCHAR(255);
ALTER TABLE scanned_hosts ADD COLUMN IF NOT EXISTS asn_block VARCHAR(100);
ALTER TABLE scanned_hosts ADD COLUMN IF NOT EXISTS asn_name VARCHAR(255);
ALTER TABLE scanned_hosts ADD COLUMN IF NOT EXISTS nameserver_hash VARCHAR(64);
ALTER TABLE scanned_hosts ADD COLUMN IF NOT EXISTS nameservers TEXT;
ALTER TABLE scanned_hosts ADD COLUMN IF NOT EXISTS ssl_cert_hash VARCHAR(64);
ALTER TABLE scanned_hosts ADD COLUMN IF NOT EXISTS ssl_issuer VARCHAR(255);
ALTER TABLE scanned_hosts ADD COLUMN IF NOT EXISTS ssl_common_names TEXT;
ALTER TABLE scanned_hosts ADD COLUMN IF NOT EXISTS domain_registrar VARCHAR(255);
ALTER TABLE scanned_hosts ADD COLUMN IF NOT EXISTS domain_reg_date DATE;
ALTER TABLE scanned_hosts ADD COLUMN IF NOT EXISTS domain_reg_email VARCHAR(255);
ALTER TABLE scanned_hosts ADD COLUMN IF NOT EXISTS panel_fingerprint VARCHAR(255);
ALTER TABLE scanned_hosts ADD COLUMN IF NOT EXISTS registration_pattern VARCHAR(50);
ALTER TABLE scanned_hosts ADD COLUMN IF NOT EXISTS confidence_score INT DEFAULT 0;
ALTER TABLE scanned_hosts ADD COLUMN IF NOT EXISTS relationship_reasons TEXT;
ALTER TABLE scanned_hosts ADD COLUMN IF NOT EXISTS asn_reseller_confidence INT DEFAULT 0;
ALTER TABLE scanned_hosts ADD COLUMN IF NOT EXISTS ns_reseller_confidence INT DEFAULT 0;
ALTER TABLE scanned_hosts ADD COLUMN IF NOT EXISTS cert_reseller_confidence INT DEFAULT 0;
ALTER TABLE scanned_hosts ADD COLUMN IF NOT EXISTS reg_pattern_confidence INT DEFAULT 0;

-- Ensure indexes exist for performance
ALTER TABLE scanned_hosts ADD INDEX IF NOT EXISTS idx_asn_block (asn_block);
ALTER TABLE scanned_hosts ADD INDEX IF NOT EXISTS idx_nameserver_hash (nameserver_hash);
ALTER TABLE scanned_hosts ADD INDEX IF NOT EXISTS idx_ssl_cert_hash (ssl_cert_hash);
ALTER TABLE scanned_hosts ADD INDEX IF NOT EXISTS idx_confidence (confidence_score);
ALTER TABLE scanned_hosts ADD INDEX IF NOT EXISTS idx_domain_reg_date (domain_reg_date);
