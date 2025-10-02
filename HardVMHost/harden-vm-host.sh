#!/bin/bash
# =================================================================
# VM Host Hardener v2.0
# Description: A script to apply security best practices to a
# KVM/libvirt host on Ubuntu 24.04 LTS.
# Author: GitHub Copilot
# =================================================================

# Exit immediately if a command exits with a non-zero status.
set -e
# Treat unset variables as an error when substituting.
set -u
# Pipes fail on the first command that fails, not the last.
set -o pipefail

# --- Global Variables ---
# Script version
readonly VERSION="2.0.0"

# Get the directory where the actual script is located
readonly SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
readonly CONFIG_DIR="${SCRIPT_DIR}/config"
readonly MODULES_DIR="${SCRIPT_DIR}/modules"

# Export paths for use in modules
export CONFIG_DIR
export MODULES_DIR
export VERSION

# Color codes for output
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly RED='\033[0;31m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# --- Core Functions ---

# These functions are exported for use in all modules.
print_message() { echo -e "${GREEN}$1${NC}"; }
print_warning() { echo -e "${YELLOW}$1${NC}"; }
print_error() { echo -e "${RED}$1${NC}"; }
print_header() {
    echo -e "${BLUE}==================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}==================================================${NC}"
}
export -f print_message print_warning print_error print_header

# Function to source a module file and handle errors
source_module() {
    local module_path="${MODULES_DIR}/${1}"
    if [ -f "$module_path" ]; then
        # shellcheck source=/dev/null
        source "$module_path"
    else
        print_error "FATAL: Module ${1} not found at ${module_path}."
        exit 1
    fi
}

# Function to check for root privileges
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        print_error "FATAL: This script must be run as root or with sudo privileges."
        exit 1
    fi
}

# --- Main Execution Logic ---

main() {
    check_root
    print_header "VM Host Hardener v${VERSION}"

    # Source common functions and configuration
    source_module "00-common.sh"
    load_config

    # Initialize logging
    init_log

    log "Hardening process started."
    
    # --- Execute Modules in Sequence ---
    # Each function call represents a distinct stage of the hardening process.
    # The script will exit if any of them fail.

    source_module "01-prerequisites.sh"
    run_prerequisites

    source_module "02-system-updates.sh"
    run_system_updates

    source_module "03-ssh-hardening.sh"
    run_ssh_hardening

    source_module "04-firewall.sh"
    run_firewall_configuration

    source_module "05-libvirt-hardening.sh"
    run_libvirt_hardening

    source_module "06-kernel-hardening.sh"
    run_kernel_hardening

    source_module "07-storage-security.sh"
    run_storage_security

    source_module "08-monitoring-auditing.sh"
    run_monitoring_auditing
    
    source_module "09-backups.sh"
    run_backups

    source_module "10-security-report.sh"
    run_security_report

    log "Hardening process completed successfully."
    print_header "VM Host Hardening Complete"
    print_message "The system has been hardened. A reboot is recommended to apply all changes."
    print_message "Please review the final security report at ${REPORT_FILE}"
}

# --- Script Entry Point ---
# Using a main function allows the entire script to be parsed before execution.
main "$@"

exit 0
