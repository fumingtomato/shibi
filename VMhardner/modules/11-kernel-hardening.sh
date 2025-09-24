#!/bin/bash
# VM Host Hardening - Kernel Hardening Module

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
    else
        print_message "Kernel hardening configuration already exists."
    fi
    
    # Apply the settings
    print_message "Applying kernel parameters..."
    sysctl -p /etc/sysctl.d/80-vm-host-hardening.conf
    
    # Enable AppArmor if available
    if command -v aa-status &> /dev/null; then
        print_message "Configuring AppArmor..."
        
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
        fi
    else
        print_warning "AppArmor not found. Installing..."
        apt-get install -y apparmor apparmor-utils
        systemctl enable apparmor
        systemctl start apparmor
        # Recursive call to continue configuration
        harden_kernel
        return
    fi
    
    # Set up kernel module blacklisting for unused/dangerous modules
    if [ ! -f /etc/modprobe.d/vm-host-blacklist.conf ]; then
        print_message "Setting up kernel module blacklisting..."
        
        cat > /etc/modprobe.d/vm-host-blacklist.conf <<EOF
# Blacklist potentially dangerous or unnecessary modules
# Unused network protocols
blacklist dccp
blacklist sctp
blacklist rds
blacklist tipc
# Uncommon filesystem types - enable if needed
blacklist cramfs
blacklist freevxfs
blacklist jffs2
blacklist hfs
blacklist hfsplus
blacklist squashfs
# Disable firewire to prevent DMA attacks
blacklist firewire-core
blacklist firewire-ohci
EOF
    fi
    
    # Apply module blacklisting
    rmmod -f dccp sctp rds tipc cramfs freevxfs jffs2 hfs hfsplus squashfs firewire-core firewire-ohci 2>/dev/null || true
    
    print_message "Kernel hardening complete."
}
