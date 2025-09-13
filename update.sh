#!/bin/bash
# Backup and update script for tiktokpredators.com

# Variables
WEBROOT="/var/www/html/tiktokpredators.com"
FILE="$WEBROOT/index.php"
BACKUP_DIR="$WEBROOT/backups"

# Ensure backup directory exists
mkdir -p "$BACKUP_DIR"

# Create backup with current Unix timestamp
TIMESTAMP=$(date +%s)
BACKUP_FILE="$BACKUP_DIR/index_${TIMESTAMP}.php"

if [ -f "$FILE" ]; then
    cp "$FILE" "$BACKUP_FILE"
    echo "Backup created: $BACKUP_FILE"
else
    echo "Error: $FILE does not exist!"
    exit 1
fi

# Git pull to update repository
cd "$WEBROOT" || { echo "Failed to cd into $WEBROOT"; exit 1; }
git pull

echo "Update complete."

