#!/bin/bash

# =================================================================
# SECTION 1: SYSTEM PREPARATION & INITIAL CHECKS
# =================================================================

# Global variables for system information
VM_LIST=""
PUBLIC_INTERFACES=()
LIBVIRT_NETWORKS=""

run_system_checks() {
    print_header "VM Host Hardening - Initial System Checks"
    check_virtualization_tools
    get_vms
    detect_public_interfaces
    detect_vm_networks
}

# Check if KVM and libvirt are installed
check_virtualization_tools() {
    print_message "Checking for required virtualization tools..."
    
    if ! command -v virsh &> /dev/null; then
        print_warning "virsh command not found. Installing libvirt-clients..."
        apt update
        apt install -y libvirt-clients libvirt-daemon-system
    else
        print_message "virsh is installed."
    fi
    
    # Check if KVM modules are loaded
    if lsmod | grep -q kvm; then
        print_message "KVM modules are loaded."
    else
        print_error "KVM modules are not loaded. Please ensure virtualization is enabled in BIOS."
        print_warning "Attempting to load KVM modules..."
        modprobe kvm
        modprobe kvm_intel 2>/dev/null || modprobe kvm_amd 2>/dev/null
    fi
}

# Get current VMs
get_vms() {
    print_message "Detecting virtual machines..."
    VM_LIST=$(virsh list --all --name)
    
    if [ -z "$VM_LIST" ]; then
        print_warning "No virtual machines detected."
    else
        print_message "Detected VMs:"
        echo "$VM_LIST"
    fi
}

# Determine the system's public interfaces
detect_public_interfaces() {
    print_message "Detecting network interfaces..."
    
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
        exit 1
    fi
    
    print_message "Detected public interfaces: ${PUBLIC_INTERFACES[*]}"
}

# Collect information about VM networks
detect_vm_networks() {
    print_message "Detecting VM networks..."
    
    # List all libvirt networks
    LIBVIRT_NETWORKS=$(virsh net-list --all --name)
    
    if [ -z "$LIBVIRT_NETWORKS" ]; then
        print_warning "No libvirt networks detected."
    else
        print_message "Detected libvirt networks:"
        echo "$LIBVIRT_NETWORKS"
    fi
}
