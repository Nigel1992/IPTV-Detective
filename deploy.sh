#!/bin/bash

# IPTV Forensics Detective - FTP Deployment Script
# This script uploads all necessary files to your web server via FTP
# Run this locally: bash deploy.sh

set -e

echo "=========================================="
echo "IPTV Forensics Detective - FTP Deployer"
echo "=========================================="
echo ""

# Prompt for FTP credentials
read -p "FTP Host (e.g., ftp.example.com): " FTP_HOST
read -p "FTP Username: " FTP_USER
read -sp "FTP Password: " FTP_PASS
echo ""
read -p "Remote Directory (e.g., /public_html/iptv-detective): " FTP_DIR

# Validate inputs
if [[ -z "$FTP_HOST" || -z "$FTP_USER" || -z "$FTP_PASS" || -z "$FTP_DIR" ]]; then
    echo "❌ Error: All fields are required"
    exit 1
fi

# Check if files exist locally
FILES=("index.html" "scan.php" "config.php" "database.sql" "README.md")
for file in "${FILES[@]}"; do
    if [[ ! -f "$file" ]]; then
        echo "❌ Error: $file not found in current directory"
        exit 1
    fi
done

echo ""
echo "📤 Connecting to FTP server..."
echo "Host: $FTP_HOST"
echo "User: $FTP_USER"
echo "Directory: $FTP_DIR"
echo ""

# Create FTP batch commands
FTP_COMMANDS=$(cat <<'FTPEOF'
set auto-login no
open $FTP_HOST
user $FTP_USER $FTP_PASS
binary
mkdir $FTP_DIR
cd $FTP_DIR
put index.html
put scan.php
put config.php
put database.sql
put README.md
mkdir logs
bye
FTPEOF
)

# Execute FTP upload
echo "$FTP_COMMANDS" | ftp -inv

if [[ $? -eq 0 ]]; then
    echo ""
    echo "✅ Upload successful!"
    echo ""
    echo "📋 Next steps:"
    echo "1. Update config.php with your database credentials"
    echo "2. Update config.php with your IPinfo.io API key"
    echo "3. Import database.sql into your MySQL database"
    echo "4. Access: http://$FTP_HOST/$(basename $FTP_DIR)/"
    echo ""
else
    echo ""
    echo "❌ Upload failed. Please check:"
    echo "   - FTP credentials are correct"
    echo "   - Remote directory path is valid"
    echo "   - You have write permissions"
    exit 1
fi
