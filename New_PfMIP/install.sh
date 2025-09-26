#!/bin/bash

# =================================================================
# Multi-IP Bulk Mail Server Master Installer
# Version: 16.0.1
# Repository: https://github.com/fumingtomato/shibi
# =================================================================

set -e

INSTALLER_NAME="Multi-IP Bulk Mail Server Installer"
INSTALLER_VERSION="16.0.1"
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

# Function to handle errors
handle_error() {
    local line_no=$1
    print_error "An error occurred at line $line_no"
    print_error "Installation failed. Cleaning up..."
    
    # Cleanup
    cd /
    rm -rf "$INSTALLER_DIR"
    
    print_error "Please check the logs and try again."
    exit 1
}

# Set error trap
trap 'handle_error $LINENO' ERR

# Check if running as root
if [ "$(id -u)" != "0" ]; then
    print_error "This script must be run as root or with sudo"
    exit 1
fi

print_header "$INSTALLER_NAME v$INSTALLER_VERSION"
print_message "Initializing installation process..."
print_message ""

# Check internet connectivity
print_message "Checking internet connectivity..."
if ! ping -c 1 google.com &>/dev/null && ! ping -c 1 8.8.8.8 &>/dev/null; then
    print_error "No internet connection detected. Please check your network."
    exit 1
fi

# Create temporary directory
print_message "Creating temporary installation directory..."
mkdir -p "$INSTALLER_DIR"
cd "$INSTALLER_DIR"

# Function to download a module with retry
download_module() {
    local module=$1
    local max_attempts=3
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        print_message "Downloading $module (attempt $attempt/$max_attempts)..."
        
        if wget -q -O "$module" "$BASE_URL/modules/$module" 2>/dev/null; then
            if [ -s "$module" ]; then
                chmod +x "$module"
                return 0
            else
                print_warning "Downloaded file is empty, retrying..."
            fi
        else
            print_warning "wget failed, trying curl..."
            if curl -s -o "$module" "$BASE_URL/modules/$module" 2>/dev/null; then
                if [ -s "$module" ]; then
                    chmod +x "$module"
                    return 0
                fi
            fi
        fi
        
        attempt=$((attempt + 1))
        if [ $attempt -le $max_attempts ]; then
            sleep 2
        fi
    done
    
    print_error "Failed to download $module after $max_attempts attempts"
    return 1
}

# Download all modules in the correct order
print_message "Downloading installer modules..."

# CRITICAL: Module loading order is important for dependencies
modules=(
    "core_functions.sh"          # Basic functions needed by all
    "packages_system.sh"          # NEW - System packages and missing functions
    "multiip_config.sh"          # IP configuration
    "mysql_dovecot.sh"           # MySQL and Dovecot setup
    "postfix_setup.sh"           # Postfix configuration
    "dkim_spf.sh"                # DKIM/SPF setup
    "dns_ssl.sh"                 # DNS and SSL configuration
    "monitoring_scripts.sh"       # Monitoring utilities
    "security_hardening.sh"      # Security configuration
    "mailwizz_integration.sh"    # MailWizz integration
    "utility_scripts.sh"         # Utility scripts
    "sticky_ip.sh"               # Sticky IP feature
    "main_installer_part2.sh"    # Additional installer functions
    "main_installer.sh"          # Main installation logic
)

# Download each module
failed_modules=()
for module in "${modules[@]}"; do
    if ! download_module "$module"; then
        failed_modules+=("$module")
    fi
done

# Check if any modules failed to download
if [ ${#failed_modules[@]} -gt 0 ]; then
    print_error "Failed to download the following modules:"
    for module in "${failed_modules[@]}"; do
        echo "  - $module"
    done
    print_error "Installation cannot continue."
    cd /
    rm -rf "$INSTALLER_DIR"
    exit 1
fi

print_message "All modules downloaded successfully"

# Verify all files exist and are readable
print_message "Verifying module integrity..."
for module in "${modules[@]}"; do
    if [ ! -r "$module" ]; then
        print_error "Module $module is not readable"
        cd /
        rm -rf "$INSTALLER_DIR"
        exit 1
    fi
    
    # Check for basic shell script syntax
    if ! bash -n "$module" 2>/dev/null; then
        print_warning "Module $module may have syntax issues"
    fi
done

# Source all modules with error handling
print_message "Loading modules..."
for module in "${modules[@]}"; do
    print_message "Loading module: $module"
    
    # Use a subshell to test if the module sources correctly
    if ! (source "./$module" 2>/dev/null); then
        print_warning "Warning: Issues detected while loading $module"
        print_message "Attempting to continue..."
    fi
    
    # Source the module in the main shell
    source "./$module"
done

print_message "All modules loaded successfully"

# Verify critical functions are available
print_message "Verifying critical functions..."
critical_functions=(
    "main_menu"
    "check_root"
    "install_required_packages"
    "configure_hostname"
    "setup_mysql"
    "setup_postfix_multi_ip"
    "save_configuration"
    "create_final_documentation"
)

missing_functions=()
for func in "${critical_functions[@]}"; do
    if ! type "$func" &>/dev/null; then
        missing_functions+=("$func")
    fi
done

if [ ${#missing_functions[@]} -gt 0 ]; then
    print_error "Critical functions are missing:"
    for func in "${missing_functions[@]}"; do
        echo "  - $func"
    done
    print_error "Installation cannot continue."
    cd /
    rm -rf "$INSTALLER_DIR"
    exit 1
fi

print_message "All critical functions verified"

# Create log directory
mkdir -p /var/log
LOG_FILE="/var/log/mail-installer-$(date +%Y%m%d-%H%M%S).log"
print_message "Installation log will be saved to: $LOG_FILE"

# Export log file location for use by modules
export LOG_FILE

# Display system information
print_message ""
print_message "System Information:"
print_message "  OS: $(lsb_release -ds 2>/dev/null || cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)"
print_message "  Kernel: $(uname -r)"
print_message "  Architecture: $(uname -m)"
print_message "  Hostname: $(hostname -f)"
print_message ""

# Run the main menu
print_message "Starting installer interface..."
if type main_menu &>/dev/null; then
    # Redirect output to both terminal and log file
    main_menu 2>&1 | tee -a "$LOG_FILE"
else
    print_error "main_menu function not available. Installation failed."
    cd /
    rm -rf "$INSTALLER_DIR"
    exit 1
fi

# Cleanup temporary files
print_message "Cleaning up temporary files..."
cd /
rm -rf "$INSTALLER_DIR"

print_message ""
print_message "Installation process completed!"
print_message "Log file saved at: $LOG_FILE"
print_message ""
print_message "If you encountered any issues, please check the log file."
print_message "For support, visit: https://github.com/$GITHUB_USER/$GITHUB_REPO/issues"
