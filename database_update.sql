-- Add provider_name column to existing scanned_hosts table
-- Run this in phpMyAdmin if the table already exists

USE your_database_name;

-- Modify provider_name to TEXT to support multiple providers
ALTER TABLE scanned_hosts 
MODIFY COLUMN provider_name TEXT;

-- Add provider_count column
ALTER TABLE scanned_hosts 
ADD COLUMN IF NOT EXISTS provider_count INT DEFAULT 1 AFTER provider_name;

-- Add upstream detection columns
ALTER TABLE scanned_hosts 
ADD COLUMN IF NOT EXISTS panel_type VARCHAR(100) AFTER hosted_provider;

ALTER TABLE scanned_hosts 
ADD COLUMN IF NOT EXISTS domain_age_days INT AFTER panel_type;

ALTER TABLE scanned_hosts 
ADD COLUMN IF NOT EXISTS ssl_cert_domain VARCHAR(255) AFTER domain_age_days;

ALTER TABLE scanned_hosts 
ADD COLUMN IF NOT EXISTS is_likely_upstream BOOLEAN DEFAULT 0 AFTER reseller_probability;

ALTER TABLE scanned_hosts 
ADD COLUMN IF NOT EXISTS upstream_score INT DEFAULT 0 AFTER is_likely_upstream;

-- Add unique constraint on domain to prevent duplicates
ALTER TABLE scanned_hosts 
ADD UNIQUE KEY IF NOT EXISTS unique_domain (domain);

-- Add index for upstream searches
ALTER TABLE scanned_hosts 
ADD INDEX IF NOT EXISTS idx_upstream (is_likely_upstream);
