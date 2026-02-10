#!/bin/bash

# SQLMap WebUI Burp Extension - File Synchronization Script
# This script synchronizes shared files between legacy-api and montoya-api modules

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Directory paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LEGACY_DIR="$SCRIPT_DIR/legacy-api/src/main/java/com/sqlmapwebui/burp"
MONTOYA_DIR="$SCRIPT_DIR/montoya-api/src/main/java/com/sqlmapwebui/burp"
BACKUP_DIR="$SCRIPT_DIR/backup_$(date +%Y%m%d_%H%M%S)"

echo "============================================"
echo "SQLMap WebUI Burp Extension Sync Script"
echo "============================================"
echo ""
echo "Source: $LEGACY_DIR"
echo "Target: $MONTOYA_DIR"
echo ""

# Create backup
echo "Creating backup of montoya-api..."
mkdir -p "$BACKUP_DIR"
cp -r "$MONTOYA_DIR" "$BACKUP_DIR/"
echo -e "${GREEN}Backup created: $BACKUP_DIR${NC}"
echo ""

# Function to sync a single file
sync_file() {
    local file_name="$1"
    local source_file="$LEGACY_DIR/$file_name"
    local target_file="$MONTOYA_DIR/$file_name"
    
    if [ -f "$source_file" ]; then
        if [ -f "$target_file" ]; then
            cp "$source_file" "$target_file"
            echo -e "${GREEN}[OK]${NC} Synced: $file_name"
        else
            echo -e "${YELLOW}[SKIP]${NC} Target not found: $file_name"
        fi
    else
        echo -e "${YELLOW}[SKIP]${NC} Source not found: $file_name"
    fi
}

# Function to sync a directory
sync_dir() {
    local dir_name="$1"
    local source_dir="$LEGACY_DIR/$dir_name"
    local target_dir="$MONTOYA_DIR/$dir_name"
    
    if [ -d "$source_dir" ]; then
        if [ -d "$target_dir" ]; then
            # Remove old files and copy new ones
            rm -rf "$target_dir"/*
            cp -r "$source_dir"/* "$target_dir/"
            echo -e "${GREEN}[OK]${NC} Synced directory: $dir_name"
        else
            echo -e "${YELLOW}[SKIP]${NC} Target directory not found: $dir_name"
        fi
    else
        echo -e "${YELLOW}[SKIP]${NC} Source directory not found: $dir_name"
    fi
}

echo "Synchronizing shared files..."

# Model classes
sync_file "ScanConfig.java"
sync_file "PresetConfig.java"
sync_file "ParseResult.java"
sync_file "ParamMeta.java"

# Utility classes
sync_file "ScanConfigParser.java"
sync_file "BinaryContentDetector.java"
sync_file "RequestDeduplicator.java"
sync_file "ApiClient.java"
sync_file "SqlmapApiClient.java"
sync_file "PresetConfigDatabase.java"
sync_file "ConfigManager.java"

# UI Tab
sync_file "SqlmapUITab.java"

# Panel classes
sync_dir "panels"

# Dialog classes
sync_dir "dialogs"

echo ""
echo "============================================"
echo -e "${GREEN}Synchronization completed!${NC}"
echo "============================================"
echo ""
echo "Note: The following files are API-specific and NOT synced:"
echo "  - BurpExtender.java (Legacy entry point)"
echo "  - SqlmapWebUIExtension.java (Montoya entry point)"
echo "  - SqlmapContextMenuProvider.java (Montoya-specific)"
echo "  - HttpRequestUtils.java (Montoya-specific)"
echo "  - util/PayloadBuilder.java (Montoya-specific)"
echo "  - util/LoggerUtil.java (Montoya-specific)"
echo ""
