#!/bin/bash

# =================================================================
# SECTION 10: KERNEL HARDENING
# =================================================================

harden_kernel() {
    print_header "Kernel Hardening"
    
    # Create a backup of sysctl.conf if it doesn't exist
    backup_config_file /etc/sysctl.conf
    
    print_message "Applying kernel security settings..."
    
    # Create a new sysctl configuration file for hardening
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
    
    # Apply the settings
    print_message "Applying kernel parameters..."
    sysctl -p /etc/sysctl.d/80-vm-host-hardening.conf
    
    # Enable AppArmor
    if command -v aa-status &> /dev/null; then
        print_message "Enabling AppArmor..."
        
        # Ensure AppArmor is enabled and started
        systemctl enable apparmor
        systemctl start apparmor
        
        # Create a custom AppArmor profile for libvirt
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
        fi
    fi
    
    print_message "Kernel hardening complete."
}
