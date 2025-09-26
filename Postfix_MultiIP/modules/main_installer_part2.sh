#!/bin/bash

# =================================================================
# Multi-IP Bulk Mail Server Master Installer
# Version: 16.0.0
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

# Important: ensure correct module load order
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
    "main_installer_part2.sh"  # Load this before main_installer.sh
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

# Define main menu function manually as backup
main_menu() {
    print_header "$INSTALLER_NAME v$INSTALLER_VERSION"
    print_message "Optimized for commercial bulk mailing with multiple IP addresses"
    print_message "Current Date and Time (UTC): $(date -u '+%Y-%m-%d %H:%M:%S')"
    print_message "Current User: $(whoami)"
    echo
    
    echo "Please select an option:"
    echo "1) Install Multi-IP Bulk Mail Server with MailWizz optimization"
    echo "2) Add additional IP to existing installation"
    echo "3) View current IP configuration"
    echo "4) Run diagnostics"
    echo "5) Update installer"
    echo "6) Exit"
    echo
    
    read -p "Enter your choice [1-6]: " choice
    
    case $choice in
        1)
            first_time_installation_multi_ip
            ;;
        2)
            add_additional_ip
            ;;
        3)
            view_ip_configuration
            ;;
        4)
            run_diagnostics
            ;;
        5)
            update_installer
            ;;
        6)
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
    
    # Verify key functions after loading each module
    if [[ "$module" == "main_installer_part2.sh" ]]; then
        if ! typeset -f main_menu >/dev/null; then
            print_warning "main_menu function not found in $module, using backup version"
        else
            print_message "Found main_menu function in $module"
        fi
    fi
done

print_message "All modules loaded successfully"

# Explicitly export key functions
export -f main_menu

# Run the main menu
print_message "Starting main menu..."
main_menu

# Cleanup
cd /
rm -rf "$INSTALLER_DIR"

print_message "Installation process completed!"
