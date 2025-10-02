#!/bin/bash
# =================================================================
# VM Host Hardener v2.0 - Module 01: Prerequisites
#
# Description: This module performs initial system checks to ensure
# the host is a compatible KVM/libvirt environment. It verifies
# virtualization support and installs necessary client tools.
# =================================================================

run_prerequisites() {
    print_header "Module 01: Running Prerequisite Checks"
    log "Starting prerequisite checks."

    check_virtualization_support
    install_required_packages

    log "Prerequisite checks completed successfully."
    print_message "System prerequisites are met."
}

# Verifies that KVM is enabled and modules are loaded.
check_virtualization_support() {
    print_message "Checking for KVM virtualization support..."

    # Check for the KVM device
    if [ ! -e /dev/kvm ]; then
        print_error "FATAL: /dev/kvm device not found."
        print_error "Please ensure that hardware virtualization (VT-x/AMD-V) is enabled in your BIOS/UEFI."
        log "FATAL: /dev/kvm not found. Virtualization may be disabled in firmware."
        exit 1
    fi

    # Check if KVM kernel modules are loaded
    if ! lsmod | grep -q 'kvm_intel\|kvm_amd'; then
        print_warning "KVM kernel modules not loaded. Attempting to load them..."
        log "KVM modules not loaded, attempting modprobe."
        modprobe kvm_intel || modprobe kvm_amd || {
            print_error "FATAL: Failed to load KVM kernel modules. Your CPU may not support virtualization."
            log "FATAL: Failed to load KVM modules."
            exit 1
        }
    fi
    log "KVM support is enabled and modules are loaded."
    print_message "KVM virtualization is active."
}

# Installs libvirt client and other essential tools if they are missing.
install_required_packages() {
    print_message "Checking for essential packages (libvirt, ufw, etc.)..."
    local packages_to_install=()

    # List of essential packages for the script to function
    local essential_packages=(
        "libvirt-clients"     # For virsh command
        "libvirt-daemon-system" # For the libvirt daemon
        "ufw"                 # Uncomplicated Firewall
        "auditd"              # Linux Audit Daemon
        "apparmor"            # Application Armor
        "chrony"              # For time synchronization
        "unattended-upgrades" # For automatic security updates
    )

    for pkg in "${essential_packages[@]}"; do
        if ! package_installed "$pkg"; then
            packages_to_install+=("$pkg")
        fi
    done

    if [ ${#packages_to_install[@]} -gt 0 ]; then
        print_message "The following required packages are missing: ${packages_to_install[*]}"
        log "Missing packages: ${packages_to_install[*]}. Installing now."
        
        print_message "Updating package lists..."
        apt-get update -y
        
        print_message "Installing missing packages..."
        apt-get install -y "${packages_to_install[@]}"
        
        log "Successfully installed missing prerequisite packages."
        print_message "Required packages installed."
    else
        log "All prerequisite packages are already installed."
        print_message "All essential packages are present."
    fi
}
