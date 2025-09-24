#!/bin/bash

# =================================================================
# VM Host Hardening Script v1.0.0
# For systems running libvirt/KVM with externally accessible VMs
# Designed for Ubuntu 24.04 LTS
# =================================================================

set -e

# Script version
VERSION="1.0.0"

# Base URL for downloading script modules
REPO_URL="https://raw.githubusercontent.com/fumingtomato/vm-host-hardener/main"

# Local paths
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
CONFIG_DIR="${SCRIPT_DIR}/config"
MODULES_DIR="${SCRIPT_DIR}/modules"

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

# Check if script is run as root
if [ "$(id -u)" != "0" ]; then
    print_error "This script must be run as root or with sudo privileges"
    exit 1
fi

# Function to download a file if it doesn't exist or force download is specified
download_file() {
    local file_path="$1"
    local file_url="$2"
    local force="$3"
    local dir=$(dirname "$file_path")
    
    # Create directory if it doesn't exist
    mkdir -p "$dir"
    
    if [ ! -f "$file_path" ] || [ "$force" == "force" ]; then
        print_message "Downloading $file_path..."
        curl -s -o "$file_path" "$file_url" || {
            print_error "Failed to download $file_url"
            exit 1
        }
        chmod +x "$file_path" 2>/dev/null || true
    fi
}

# Download and setup the required files
setup_files() {
    print_header "Setting up VM Host Hardening Script"
    
    # Create necessary directories
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$MODULES_DIR"
    
    # Download configuration files
    download_file "${CONFIG_DIR}/settings.conf" "${REPO_URL}/config/settings.conf" "$1"
    
    # Download module files
    MODULE_FILES=(
        "00-common.sh"
        "01-system-checks.sh"
        "02-system-updates.sh"
        "03-ssh-hardening.sh"
        "04-firewall.sh"
        "05-libvirt-hardening.sh"
        "06-vm-resources.sh"
        "07-network-security.sh"
        "08-storage-security.sh"
        "09-monitoring.sh"
        "10-backups.sh"
        "11-kernel-hardening.sh"
        "12-security-report.sh"
    )
    
    for module in "${MODULE_FILES[@]}"; do
        download_file "${MODULES_DIR}/${module}" "${REPO_URL}/modules/${module}" "$1"
    done
}

# Function to source a module file and handle errors
source_module() {
    local module="$1"
    if [ -f "$module" ]; then
        source "$module"
    else
        print_error "Module $module not found. Please run the script with --update to download all modules."
        exit 1
    fi
}

# Main function to run the hardening process
run_hardening() {
    print_header "VM Host Hardening Process v$VERSION"
    
    # Source common functions and variables
    source_module "${MODULES_DIR}/00-common.sh"
    
    # Source and execute each module in sequence
    source_module "${MODULES_DIR}/01-system-checks.sh"
    run_system_checks
    
    source_module "${MODULES_DIR}/02-system-updates.sh"
    run_system_updates
    
    source_module "${MODULES_DIR}/03-ssh-hardening.sh"
    run_ssh_hardening
    
    source_module "${MODULES_DIR}/04-firewall.sh"
    run_firewall_configuration
    
    source_module "${MODULES_DIR}/05-libvirt-hardening.sh"
    run_libvirt_hardening
    
    source_module "${MODULES_DIR}/06-vm-resources.sh"
    run_vm_resources
    
    source_module "${MODULES_DIR}/07-network-security.sh"
    run_network_security
    
    source_module "${MODULES_DIR}/08-storage-security.sh"
    run_storage_security
    
    source_module "${MODULES_DIR}/09-monitoring.sh"
    run_monitoring
    
    source_module "${MODULES_DIR}/10-backups.sh"
    run_backups
    
    source_module "${MODULES_DIR}/11-kernel-hardening.sh"
    run_kernel_hardening
    
    source_module "${MODULES_DIR}/12-security-report.sh"
    run_security_report
    
    print_header "VM Host Hardening Complete"
    print_message "Your VM host has been hardened according to security best practices."
    print_message "Please review the security report at /root/vm-host-security-report.txt"
    print_message "Remember to restart your system to fully apply all security settings."
}

# Parse command line arguments
case "$1" in
    --update)
        setup_files "force"
        ;;
    --help|-h)
        echo "Usage: $0 [OPTION]"
        echo "Options:"
        echo "  --help, -h    Display this help message"
        echo "  --update      Force update all script files"
        echo "  --version     Display version information"
        echo "  No option will run the hardening process"
        ;;
    --version|-v)
        echo "VM Host Hardening Script v$VERSION"
        ;;
    *)
        # Setup files if they don't exist
        setup_files
        
        # Run the hardening process
        run_hardening
        ;;
esac

exit 0
