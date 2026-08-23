#!/bin/bash
# Backup and update script for tiktokpredators.com

# Variables
WEBROOT="/var/www/html/tiktokpredators.com"
FILE="$WEBROOT/index.php"
# Backups contain executable PHP and must never live below the public document root.
BACKUP_DIR="/var/backups/tiktokpredators.com"
PRIVATE_STORAGE="${EVIDENCE_PRIVATE_STORAGE_PATH:-/var/lib/tiktokpredators/evidence}"

# Never let a malformed override turn the filesystem root (or a relative path)
# into the evidence directory. PHP enforces the same absolute-path contract.
case "$PRIVATE_STORAGE" in
    /|//*)
        echo "Error: private evidence storage cannot be the filesystem root."
        exit 1
        ;;
    /*)
        ;;
    *)
        echo "Error: private evidence storage must be an absolute dedicated directory."
        exit 1
        ;;
esac
case "/$PRIVATE_STORAGE/" in
    *"/../"*|*"/./"*)
        echo "Error: private evidence storage must not contain dot path segments."
        exit 1
        ;;
esac

# Ensure the private backup directory exists before changing the live checkout.
if ! mkdir -p "$BACKUP_DIR"; then
    echo "Error: unable to create private backup directory: $BACKUP_DIR"
    exit 1
fi

# Evidence originals and generated public copies must sit outside the OpenResty document root.
case "$PRIVATE_STORAGE/" in
    "$WEBROOT/"*)
        echo "Error: private evidence storage must be outside $WEBROOT"
        exit 1
        ;;
esac
if ! mkdir -p "$PRIVATE_STORAGE"; then
    echo "Error: unable to create private evidence storage: $PRIVATE_STORAGE"
    exit 1
fi

# Resolve symlinks and dot segments before granting the web process access. The
# lexical check above catches the normal case; this canonical check also rejects
# paths such as /var/lib/../www/... and symlinks that resolve below the web root.
if ! WEBROOT_REAL=$(cd "$WEBROOT" && pwd -P); then
    echo "Error: unable to resolve web root: $WEBROOT"
    exit 1
fi
if ! PRIVATE_STORAGE_REAL=$(cd "$PRIVATE_STORAGE" && pwd -P); then
    echo "Error: unable to resolve private evidence storage: $PRIVATE_STORAGE"
    exit 1
fi
if [ "$PRIVATE_STORAGE_REAL" = "/" ]; then
    echo "Error: private evidence storage resolves to the filesystem root."
    exit 1
fi
case "$PRIVATE_STORAGE_REAL" in
    "$WEBROOT_REAL"|"$WEBROOT_REAL"/*)
        echo "Error: private evidence storage resolves inside $WEBROOT_REAL"
        exit 1
        ;;
esac
case "$WEBROOT_REAL" in
    "$PRIVATE_STORAGE_REAL"/*)
        echo "Error: private evidence storage must not contain the web root $WEBROOT_REAL"
        exit 1
        ;;
esac
PRIVATE_STORAGE="$PRIVATE_STORAGE_REAL"

if ! mkdir -p "$PRIVATE_STORAGE/evidence" "$PRIVATE_STORAGE/notes" "$PRIVATE_STORAGE/redactions"; then
    echo "Error: unable to create private evidence namespaces: $PRIVATE_STORAGE"
    exit 1
fi

if [ -d "$WEBROOT/uploads" ]; then
    if ! chown --reference="$WEBROOT/uploads" "$PRIVATE_STORAGE" "$PRIVATE_STORAGE/evidence" "$PRIVATE_STORAGE/notes" "$PRIVATE_STORAGE/redactions"; then
        echo "Error: unable to grant the web process ownership of private evidence storage."
        exit 1
    fi
fi
if ! chmod 0770 "$PRIVATE_STORAGE" "$PRIVATE_STORAGE/evidence" "$PRIVATE_STORAGE/notes" "$PRIVATE_STORAGE/redactions"; then
    echo "Error: unable to protect private evidence storage permissions."
    exit 1
fi

# Move any executable backups created by older versions of this script out of the web root.
if [ -d "$WEBROOT/backups" ]; then
    for LEGACY_BACKUP in "$WEBROOT"/backups/index_*.php; do
        [ -f "$LEGACY_BACKUP" ] || continue
        LEGACY_NAME=${LEGACY_BACKUP##*/}
        if ! mv "$LEGACY_BACKUP" "$BACKUP_DIR/${LEGACY_NAME}.txt" || ! chmod 0600 "$BACKUP_DIR/${LEGACY_NAME}.txt"; then
            echo "Error: unable to quarantine legacy web backup: $LEGACY_BACKUP"
            exit 1
        fi
    done
fi

# Create backup with current Unix timestamp
TIMESTAMP=$(date +%s)
BACKUP_FILE="$BACKUP_DIR/index_${TIMESTAMP}.php.txt"

if [ -f "$FILE" ]; then
    if ! cp "$FILE" "$BACKUP_FILE" || ! chmod 0600 "$BACKUP_FILE"; then
        echo "Error: unable to create a protected backup: $BACKUP_FILE"
        exit 1
    fi
    echo "Backup created: $BACKUP_FILE"
else
    echo "Error: $FILE does not exist!"
    exit 1
fi

# Git pull to update repository
cd "$WEBROOT" || { echo "Failed to cd into $WEBROOT"; exit 1; }
if ! git pull; then
    echo "Error: git pull failed."
    exit 1
fi

echo "Update complete."
