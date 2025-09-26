#!/bin/bash

# =================================================================
# Multi-IP Bulk Mail Server Master Installer
# Version: 16.0.0
# Repository: https://github.com/fumingtomato/maileristhegame
# =================================================================

set -e

INSTALLER_NAME="Multi-IP Bulk Mail Server Installer"
INSTALLER_VERSION="16.0.0"
GITHUB_USER="fumingtomato"
GITHUB_REPO="shibi"
GITHUB_BRANCH="main"
BASE_URL="https://raw.githubusercontent.com/$GITHUB_USER/$GITHUB_REPO/$GITHUB_BRANCH/Postfix_MultiIP/"
INSTALLER_DIR="/tmp/multiip-installer-$$"

# Colors
RED='\033[0;31m'
GREEN='\033[38;5;208m'
YELLOW='\033[1;33m'
BLUE='\033[1;33m'
NC='\033[0m'

# Simple print functions for bootstrap
print_message() {
    echo -e "${GREEN}$1${NC}"
}

print_error() {
    echo -e "${RED}$1${NC}"
}

print_warning() {
    echo -e "${YELLOW}$1${NC}"
}

print_header() {
    echo -e "${BLUE}==================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}==================================================${NC}"
}

# Check if running as root
if [ "$(id -u)" != "0" ]; then
    print_error "This script must be run as root or with sudo"
    exit 1
fi

print_header "$INSTALLER_NAME v$INSTALLER_VERSION"
print_message "Initializing installation process..."
print_message ""

# Create temporary directory
print_message "Creating temporary installation directory..."
mkdir -p "$INSTALLER_DIR"
cd "$INSTALLER_DIR"

# Download all modules
print_message "Downloading installer modules..."

# Important: main_installer_part2.sh must be loaded before main_installer.sh
modules=(
    "core_functions.sh"
    "multiip_config.sh"
    "mysql_dovecot.sh"
    "postfix_setup.sh" 
    "dkim_spf.sh"
    "dns_ssl.sh"
    "monitoring_scripts.sh"
    "security_hardening.sh"
    "mailwizz_integration.sh"
    "utility_scripts.sh"
    "sticky_ip.sh"
    "main_installer_part2.sh"
    "main_installer.sh"
)

for module in "${modules[@]}"; do
    print_message "Downloading $module..."
    if ! wget -q -O "$module" "$BASE_URL/modules/$module"; then
        print_warning "Trying alternative download method..."
        if ! curl -s -o "$module" "$BASE_URL/modules/$module"; then
            print_error "Failed to download $module"
            exit 1
        fi
    fi
    chmod +x "$module"
done

print_message "All modules downloaded successfully"

# Source all modules
print_message "Loading modules..."
for module in "${modules[@]}"; do
    print_message "Loading module: $module"
    source "./$module"
done

print_message "All modules loaded successfully"

# Run the main menu
main_menu

# Cleanup
cd /
rm -rf "$INSTALLER_DIR"

print_message "Installation process completed!"
