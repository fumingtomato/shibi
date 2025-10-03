#!/bin/bash
# =================================================================
# VM Host Hardener v2.0.0
#
# Main execution script for the VM Host Hardener.
# This script sources and runs modules in a specific order to
# secure a KVM/QEMU virtualization host.
# =================================================================

set -e

# --- CRITICAL: Define Script Directory ---
# This ensures that the script can find its modules and config files
# regardless of where it is called from (e.g., via a symlink).
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
readonly SCRIPT_DIR

# --- Source Common Functions ---
# This line now uses the absolute path determined above.
if [ -f "${SCRIPT_DIR}/modules/00-common.sh" ]; then
    # shellcheck source=modules/00-common.sh
    source "${SCRIPT_DIR}/modules/00-common.sh"
else
    echo "FATAL: Module 00-common.sh not found at ${SCRIPT_DIR}/modules/00-common.sh."
    exit 1
fi

# --- Main Execution Logic ---
main() {
    print_header "VM Host Hardener v${VERSION}"
    
    # 1. Check for root privileges
    if [ "$(id -u)" -ne 0 ]; then
        print_error "This script must be run as root or with sudo privileges."
        log "ERROR: Script not run as root."
        exit 1
    fi

    # 2. Load configuration and initialize log
    load_config
    init_log

    log "===== VM Host Hardener v${VERSION} Started ====="
    log "User: $(logname)"
    log "Timestamp: $(date)"

    # 3. Execute all modules in order
    # The 'run_module' function handles sourcing and executing each module file.
    run_module "01-prerequisites.sh"
    run_module "02-system-updates.sh"
    run_module "03-ssh-hardening.sh"
    run_module "04-firewall.sh"
    run_module "05-libvirt-hardening.sh"
    run_module "06-kernel-hardening.sh"
    run_module "07-storage-security.sh"
    run_module "08-monitoring-auditing.sh"
    run_module "09-backups.sh"
    run_module "10-security-report.sh"

    print_header "Hardening process completed successfully!"
    log "===== VM Host Hardener Finished ====="
}

# --- Entry Point ---
main
