#!/bin/bash
# Module: 11-kernel-hardening.sh - Kernel and System Security Hardening
# Part of VM Host Hardening Script

# Check if we're being run standalone or as part of the main script
if [ -z "$LOG_FILE" ]; then
    # Running standalone, need to source common
    SCRIPT_DIR="$(dirname "$0")"
    if [ -f "${SCRIPT_DIR}/00-common.sh" ]; then
        source "${SCRIPT_DIR}/00-common.sh"
    else
        echo "Error: Could not find common functions file"
        exit 1
    fi
fi

harden_kernel() {
    print_header "Kernel Hardening"
    
    # Create a backup of sysctl.conf if it doesn't exist
    if [ ! -f /etc/sysctl.conf.bak ]; then
        print_message "Backing up sysctl configuration..."
        cp /etc/sysctl.conf /etc/sysctl.conf.bak
    fi
    
    print_message "Applying kernel security settings..."
    
    # Create a new sysctl configuration file for hardening if it doesn't exist
    if [ ! -f /etc/sysctl.d/80-vm-host-hardening.conf ]; then
        cat > /etc/sysctl.d/80-vm-host-hardening.conf <<EOF
# Kernel hardening parameters for VM host

# Network security settings
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_timestamps = 0

# IPv6 security settings
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Memory management settings for VM host
vm.swappiness = 10
vm.dirty_ratio = 20
vm.dirty_background_ratio = 5
vm.mmap_min_addr = 65536

# Kernel hardening
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.sysrq = 0
kernel.dmesg_restrict = 1
kernel.printk = 3 4 1 3
kernel.yama.ptrace_scope = 1
kernel.panic = 60
kernel.panic_on_oops = 60

# File system hardening
fs.suid_dumpable = 0
fs.protected_fifos = 2
fs.protected_regular = 2
EOF
        print_message "Created kernel hardening configuration"
    else
        print_message "Kernel hardening configuration already exists"
    fi
    
    # Apply the settings
    print_message "Applying kernel parameters..."
    if ! sysctl -p /etc/sysctl.d/80-vm-host-hardening.conf; then
        print_warning "Some kernel parameters could not be applied. This is normal if the kernel doesn't support all features."
    fi
    
    # Enable AppArmor if available
    if command -v aa-status &> /dev/null; then
        print_message "Enabling AppArmor..."
        
        # Ensure AppArmor is enabled and started
        systemctl enable apparmor
        systemctl start apparmor
        
        # Create a custom AppArmor profile for libvirt if it doesn't exist
        if [ ! -f /etc/apparmor.d/local/libvirt ]; then
            mkdir -p /etc/apparmor.d/local/
            cat > /etc/apparmor.d/local/libvirt <<EOF
# Additional AppArmor rules for libvirt
/var/lib/libvirt/** rwk,
/etc/libvirt/** r,
/dev/net/tun rw,
EOF
            
            # Restart AppArmor to load new profile
            systemctl restart apparmor
            print_message "AppArmor profile for libvirt created"
        else
            print_message "AppArmor profile for libvirt already exists"
        fi
    else
        print_warning "AppArmor is not installed. Consider installing it for enhanced security."
    fi
    
    # Set secure limits for system resources
    if [ ! -f /etc/security/limits.d/10-kernel-hardening.conf ]; then
        print_message "Setting secure resource limits..."
        cat > /etc/security/limits.d/10-kernel-hardening.conf <<EOF
# Limits for VM host security
* hard core 0
* soft nproc 1000
* hard nproc 2000
* soft nofile 4096
* hard nofile 65536
root soft nofile 16384
root hard nofile 65536
EOF
        print_message "System resource limits configured"
    else
        print_message "System resource limits already configured"
    fi
    
    print_message "Kernel hardening complete"
}

# Execute function if script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    harden_kernel
fi
