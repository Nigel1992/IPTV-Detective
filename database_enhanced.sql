-- IPTV Forensics Tool - Enhanced Database Schema
-- Migration to add reseller detection enhancements

USE your_database_name;

-- Add new columns for enhanced reseller detection
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

-- Add indexes for new columns
ALTER TABLE scanned_hosts ADD INDEX IF NOT EXISTS idx_asn_block (asn_block);
ALTER TABLE scanned_hosts ADD INDEX IF NOT EXISTS idx_nameserver_hash (nameserver_hash);
ALTER TABLE scanned_hosts ADD INDEX IF NOT EXISTS idx_ssl_cert_hash (ssl_cert_hash);
ALTER TABLE scanned_hosts ADD INDEX IF NOT EXISTS idx_confidence (confidence_score);
ALTER TABLE scanned_hosts ADD INDEX IF NOT EXISTS idx_domain_reg_date (domain_reg_date);
