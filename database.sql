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
