-- IPTV Forensics Tool Database Schema
-- Use existing database: your_database_name

USE your_database_name;

CREATE TABLE IF NOT EXISTS scanned_hosts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    provider_name TEXT,
    provider_count INT DEFAULT 1,
    original_url VARCHAR(500) NOT NULL,
    domain VARCHAR(255) NOT NULL,
    resolved_ip VARCHAR(45) NOT NULL,
    asn VARCHAR(50),
    organization VARCHAR(255),
    country_code VARCHAR(10),
    country_name VARCHAR(100),
    server_header VARCHAR(255),
    hosted_provider VARCHAR(255),
    panel_type VARCHAR(100),
    domain_age_days INT,
    ssl_cert_domain VARCHAR(255),
    is_datacenter_reseller BOOLEAN DEFAULT 0,
    reseller_probability INT DEFAULT 0,
    is_likely_upstream BOOLEAN DEFAULT 0,
    upstream_score INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY unique_domain (domain),
    INDEX idx_ip (resolved_ip),
    INDEX idx_created (created_at),
    INDEX idx_upstream (is_likely_upstream)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

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

CREATE TABLE IF NOT EXISTS service_aliases (
    id INT AUTO_INCREMENT PRIMARY KEY,
    baseline_id INT,
    alias_name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (baseline_id) REFERENCES baseline_services(id) ON DELETE CASCADE,
    INDEX idx_baseline (baseline_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS admin_users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'moderator',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
