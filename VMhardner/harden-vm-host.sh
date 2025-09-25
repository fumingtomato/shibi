#!/bin/bash

# =================================================================
# VM Host Hardening Script v1.0.0
# For systems running libvirt/KVM with externally accessible VMs
# Designed for Ubuntu 24.04 LTS
# =================================================================

set -e

# Script version
VERSION="1.0.0"

# Get the real path of the script (resolving symlinks)
if [ -L "${BASH_SOURCE[0]}" ]; then
    # Script is a symlink, resolve it
    SCRIPT_PATH=$(readlink -f "${BASH_SOURCE[0]}")
else
    SCRIPT_PATH="${BASH_SOURCE[0]}"
fi

# Get the directory where the actual script is located
SCRIPT_DIR="$( cd "$( dirname "$SCRIPT_PATH" )" && pwd )"

# Local paths
CONFIG_DIR="${SCRIPT_DIR}/config"
MODULES_DIR="${SCRIPT_DIR}/modules"

# Export these for use in modules
export CONFIG_DIR
export MODULES_DIR
export VERSION

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

# Export print functions for use in modules
export -f print_message
export -f print_warning
export -f print_error
export -f print_header

# Check if script is run as root
if [ "$(id -u)" != "0" ]; then
    print_error "This script must be run as root or with sudo privileges"
    exit 1
fi

# Function to check if all required files exist
check_files() {
    local missing_files=0
    
    # Debug: Show where we're looking for files
    print_message "Looking for files in: $SCRIPT_DIR"
    
    # Check for config file
    if [ ! -f "${CONFIG_DIR}/settings.conf" ]; then
        print_error "Missing configuration file: ${CONFIG_DIR}/settings.conf"
        missing_files=1
    fi
    
    # Check for module files
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
        if [ ! -f "${MODULES_DIR}/${module}" ]; then
            print_error "Missing module file: ${MODULES_DIR}/${module}"
            missing_files=1
        fi
    done
    
    if [ $missing_files -eq 1 ]; then
        print_error ""
        print_error "Required files are missing. Please ensure all files are present."
        print_error "Run the install.sh script first if you haven't already."
        exit 1
    fi
}

# Function to source a module file and handle errors
source_module() {
    local module="$1"
    if [ -f "$module" ]; then
        source "$module"
    else
        print_error "Module $module not found."
        exit 1
    fi
}

# Main function to run the hardening process
run_hardening() {
    print_header "VM Host Hardening Process v$VERSION"
    
    # Check that all required files exist
    check_files
    
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
    setup_monitoring
    
    source_module "${MODULES_DIR}/10-backups.sh"
    configure_backups
    
    source_module "${MODULES_DIR}/11-kernel-hardening.sh"
    harden_kernel
    
    source_module "${MODULES_DIR}/12-security-report.sh"
    run_security_report
    
    print_header "VM Host Hardening Complete"
    print_message "Your VM host has been hardened according to security best practices."
    print_message "Please review the security report at /root/vm-host-security-report.txt"
    print_message "Remember to restart your system to fully apply all security settings."
}

# Parse command line arguments
case "$1" in
    --help|-h)
        echo "Usage: $0 [OPTION]"
        echo "Options:"
        echo "  --help, -h    Display this help message"
        echo "  --version     Display version information"
        echo "  --check       Check if all required files are present"
        echo "  No option     Run the hardening process"
        ;;
    --version|-v)
        echo "VM Host Hardening Script v$VERSION"
        ;;
    --check)
        check_files
        print_message "All required files are present."
        ;;
    *)
        # Run the hardening process
        run_hardening
        ;;
esac

exit 0
