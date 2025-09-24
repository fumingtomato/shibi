#!/bin/bash

# =================================================================
# VM Host Hardening Script v1.0.0
# For systems running libvirt/KVM with externally accessible VMs
# Developed to work with existing mail and web server VMs
# =================================================================

set -e

# Source utility functions
source "$(dirname "$0")/modules/utils.sh"

# Check if script is run as root
if [ "$(id -u)" != "0" ]; then
    print_error "This script must be run as root or with sudo privileges"
    exit 1
fi

print_header "VM Host Hardening Script v1.0.0"
print_message "Starting VM host security hardening process..."

# Source and execute modules in order
source "$(dirname "$0")/modules/system_checks.sh"
source "$(dirname "$0")/modules/system_updates.sh"
source "$(dirname "$0")/modules/ssh_hardening.sh"
source "$(dirname "$0")/modules/firewall_config.sh"
source "$(dirname "$0")/modules/libvirt_security.sh"
source "$(dirname "$0")/modules/network_security.sh"
source "$(dirname "$0")/modules/storage_security.sh"
source "$(dirname "$0")/modules/monitoring.sh"
source "$(dirname "$0")/modules/backup_config.sh"
source "$(dirname "$0")/modules/kernel_hardening.sh"
source "$(dirname "$0")/modules/reporting.sh"

# Initial checks and information gathering
run_system_checks

# Core system hardening
run_system_updates
harden_ssh
create_vm_admin

# Network security
configure_firewall

# VM security
harden_libvirt
setup_vm_resources
secure_vm_networking
secure_vm_storage

# Monitoring and maintenance
setup_monitoring
configure_backups

# Advanced security
harden_kernel

# Generate final report
generate_security_report

print_header "VM Host Hardening Complete"
print_message "Your VM host has been hardened according to security best practices."
print_message "Please review the security report at /root/vm-host-security-report.txt"
print_message "Remember to restart your system to fully apply all security settings."
