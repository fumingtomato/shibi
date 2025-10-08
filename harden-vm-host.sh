#!/bin/bash
# =================================================================
# VM Host Hardener v2.0.1 - Corrected Main Script
# =================================================================

set -e

# --- THE FIX: Hardcode the absolute path to the installation directory ---
readonly INSTALL_DIR="/opt/vm-host-hardener"

# Source the common functions using the guaranteed correct path.
source "${INSTALL_DIR}/modules/00-common.sh"

# --- Main Execution Logic ---
main() {
    print_header "VM Host Hardener v${VERSION}"

    if [ "$(id -u)" -ne 0 ]; then
        print_error "This script must be run as root or with sudo privileges."
        log "ERROR: Script not run as root."
        exit 1
    fi

    # The 'run_module' function (from 00-common.sh) will now be found correctly.
    load_config
    init_log

    log "===== VM Host Hardener v${VERSION} Started ====="
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

main
