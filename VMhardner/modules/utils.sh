#!/bin/bash

# =================================================================
# Utility functions for VM Host Hardening
# =================================================================

# Color codes for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to display messages
print_message() {
    echo -e "${GREEN}$1${NC}"
}

print_warning() {
    echo -e "${YELLOW}$1${NC}"
}

print_error() {
    echo -e "${RED}$1${NC}"
}

print_header() {
    echo -e "${BLUE}==================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}==================================================${NC}"
}

# Helper function to safely modify configuration files
sed_if_not_exists() {
    local pattern="$1"
    local setting="$2"
    local file="$3"
    
    if grep -q "^$pattern" "$file"; then
        sed -i "s/^$pattern.*/$setting/" "$file"
    elif grep -q "^#$pattern" "$file"; then
        sed -i "s/^#$pattern.*/$setting/" "$file"
    else
        echo "$setting" >> "$file"
    fi
}

# Check if a package is installed
is_package_installed() {
    dpkg -l "$1" 2>/dev/null | grep -q "^ii"
    return $?
}

# Create backup of configuration files
backup_config_file() {
    local file="$1"
    local backup="${file}.bak"
    
    if [ ! -f "$backup" ] && [ -f "$file" ]; then
        cp "$file" "$backup"
        print_message "Backed up $file to $backup"
    fi
}
