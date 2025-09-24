#!/bin/bash
# =================================================================
# System checks and information gathering
# =================================================================

run_system_checks() {
    print_header "VM Host Hardening - Initial System Checks"
    log "Starting system checks"
    
    # Check if KVM and libvirt are installed
    check_virtualization_tools
    
    # Get current VMs
    get_vms
    
    # Detect network interfaces
    detect_public_interfaces
    
    # Collect information about VM networks
    detect_vm_networks
    
    log "System checks completed"
}

# Check if virtualization tools are installed
check_virtualization_tools() {
    print_message "Checking for required virtualization tools..."
    log "Checking virtualization tools"
    
    if ! command_exists virsh; then
        print_warning "virsh command not found. Installing libvirt-clients..."
        log "Installing libvirt-clients and libvirt-daemon-system"
        apt update
        apt install -y libvirt-clients libvirt-daemon-system
    else
        print_message "virsh is installed."
        log "virsh is already installed"
    fi
    
    # Check if KVM modules are loaded
    if lsmod | grep -q kvm; then
        print_message "KVM modules are loaded."
        log "KVM modules are loaded"
    else
        print_error "KVM modules are not loaded. Please ensure virtualization is enabled in BIOS."
        log "ERROR: KVM modules not loaded"
        print_warning "Attempting to load KVM modules..."
        
        # Try to load KVM modules
        modprobe kvm 2>/dev/null || log "Failed to load kvm module"
        modprobe kvm_intel 2>/dev/null || modprobe kvm_amd 2>/dev/null || log "Failed to load kvm_intel/kvm_amd module"
        
        if lsmod | grep -q kvm; then
            print_message "Successfully loaded KVM modules."
            log "Successfully loaded KVM modules"
        else
            print_error "Failed to load KVM modules. Please check virtualization support."
            log "ERROR: Failed to load KVM modules"
        fi
    fi
}

# Get current VMs
get_vms() {
    print_message "Detecting virtual machines..."
    log "Detecting virtual machines"
    
    VM_LIST=$(virsh list --all --name)
    
    if [ -z "$VM_LIST" ]; then
        print_warning "No virtual machines detected."
        log "No virtual machines detected"
    else
        print_message "Detected VMs:"
        log "Detected VMs: $VM_LIST"
        echo "$VM_LIST"
    fi
}

# Determine the system's public interfaces
detect_public_interfaces() {
    print_message "Detecting network interfaces..."
    log "Detecting network interfaces"
    
    PUBLIC_INTERFACES=()
    ALL_INTERFACES=$(ip -o link show | awk -F': ' '{print $2}' | grep -v "lo\|virbr\|vnet")
    
    for iface in $ALL_INTERFACES; do
        # Check if interface has a public IP
        if ip addr show dev $iface | grep -q "inet "; then
            PUBLIC_INTERFACES+=($iface)
        fi
    done
    
    if [ ${#PUBLIC_INTERFACES[@]} -eq 0 ]; then
        print_error "No public network interfaces detected."
        log "ERROR: No public network interfaces detected"
        exit 1
    fi
    
    print_message "Detected public interfaces: ${PUBLIC_INTERFACES[*]}"
    log "Detected public interfaces: ${PUBLIC_INTERFACES[*]}"
}

# Collect information about VM networks
detect_vm_networks() {
    print_message "Detecting VM networks..."
    log "Detecting VM networks"
    
    # List all libvirt networks
    LIBVIRT_NETWORKS=$(virsh net-list --all --name)
    
    if [ -z "$LIBVIRT_NETWORKS" ]; then
        print_warning "No libvirt networks detected."
        log "No libvirt networks detected"
    else
        print_message "Detected libvirt networks:"
        log "Detected libvirt networks: $LIBVIRT_NETWORKS"
        echo "$LIBVIRT_NETWORKS"
    fi
}
