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

# Important: make sure main_installer_part2.sh loads BEFORE main_installer.sh
modules=(
    "core_functions.sh"
    "multiip_config.sh"
    "postfix_setup.sh"
    "mysql_dovecot.sh"
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
        print_error "Failed to download $module"
        print_warning "Trying alternative download method..."
        if ! curl -s -o "$module" "$BASE_URL/modules/$module"; then
            print_error "Failed to download $module with curl"
            exit 1
        fi
    fi
    
    # Make module executable
    chmod +x "$module"
done

print_message "All modules downloaded successfully"

# Define a fallback main_menu function in case something goes wrong with loading it
main_menu() {
    print_header "$INSTALLER_NAME v$INSTALLER_VERSION"
    print_message "Optimized for commercial bulk mailing with multiple IP addresses"
    
    echo
    echo "Please select an option:"
    echo "1) Install Multi-IP Bulk Mail Server with MailWizz optimization"
    echo "2) Exit"
    echo
    
    read -p "Enter your choice [1-2]: " choice
    
    case $choice in
        1)
            first_time_installation_multi_ip
            ;;
        2)
            print_message "Exiting installer. No changes were made."
            exit 0
            ;;
        *)
            print_error "Invalid option. Exiting."
            exit 1
            ;;
    esac
}

# Source all modules
print_message "Loading modules..."
for module in "${modules[@]}"; do
    print_message "Loading module: $module"
    source "./$module"
    
    # Verify key functions after loading sticky_ip.sh
    if [[ "$module" == "sticky_ip.sh" ]]; then
        if ! type setup_sticky_ip_db &>/dev/null; then
            print_error "Failed to load setup_sticky_ip_db function from sticky_ip.sh"
            exit 1
        else
            print_message "Successfully loaded sticky IP functions"
        fi
    fi
    
    # Verify main_menu function is loaded from main_installer_part2.sh
    if [[ "$module" == "main_installer_part2.sh" ]]; then
        if ! type main_menu &>/dev/null; then
            print_warning "main_menu function not found in $module, will use fallback version"
        else
            print_message "Successfully loaded main_menu function"
        fi
    fi
done

print_message "All modules loaded successfully"

# Make sure main_menu exists and is exported
export -f main_menu

# Run the main menu
main_menu

# Cleanup
cd /
rm -rf "$INSTALLER_DIR"

print_message "Installation process completed!"
