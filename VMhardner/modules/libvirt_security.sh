#!/bin/bash

# =================================================================
# SECTION 5: LIBVIRT & VM HARDENING
# =================================================================

harden_libvirt() {
    print_header "Securing Libvirt/QEMU Configuration"
    
    # Create backup of libvirt configuration if it doesn't exist
    backup_config_file /etc/libvirt/libvirtd.conf
    backup_config_file /etc/libvirt/qemu.conf
    
    # Configure libvirt security settings
    print_message "Hardening libvirt configuration..."
    
    # Secure libvirt daemon
    sed_if_not_exists "auth_unix_ro" "auth_unix_ro = \"none\"" /etc/libvirt/libvirtd.conf
    sed_if_not_exists "auth_unix_rw" "auth_unix_rw = \"polkit\"" /etc/libvirt/libvirtd.conf
    sed_if_not_exists "unix_sock_group" "unix_sock_group = \"libvirt\"" /etc/libvirt/libvirtd.conf
    sed_if_not_exists "unix_sock_ro_perms" "unix_sock_ro_perms = \"0770\"" /etc/libvirt/libvirtd.conf
    sed_if_not_exists "unix_sock_rw_perms" "unix_sock_rw_perms = \"0770\"" /etc/libvirt/libvirtd.conf
    sed_if_not_exists "unix_sock_admin_perms" "unix_sock_admin_perms = \"0700\"" /etc/libvirt/libvirtd.conf
    sed_if_not_exists "log_filters" "log_filters=\"3:remote 4:event 3:json 3:rpc\"" /etc/libvirt/libvirtd.conf
    sed_if_not_exists "log_outputs" "log_outputs=\"1:file:/var/log/libvirt/libvirtd.log\"" /etc/libvirt/libvirtd.conf
    
    # Configure QEMU settings for security
    sed_if_not_exists "security_driver" "security_driver = \"apparmor\"" /etc/libvirt/qemu.conf
    sed_if_not_exists "user" "user = \"root\"" /etc/libvirt/qemu.conf
    sed_if_not_exists "group" "group = \"root\"" /etc/libvirt/qemu.conf
    sed_if_not_exists "dynamic_ownership" "dynamic_ownership = 1" /etc/libvirt/qemu.conf
    sed_if_not_exists "remember_owner" "remember_owner = 1" /etc/libvirt/qemu.conf
    sed_if_not_exists "clear_emulator_capabilities" "clear_emulator_capabilities = 1" /etc/libvirt/qemu.conf
    sed_if_not_exists "seccomp_sandbox" "seccomp_sandbox = 1" /etc/libvirt/qemu.conf
    
    # Create directory for libvirt logs if it doesn't exist
    mkdir -p /var/log/libvirt
    
    # Restart libvirt if configuration changed
    if ! diff -q /etc/libvirt/libvirtd.conf /etc/libvirt/libvirtd.conf.bak > /dev/null || \
       ! diff -q /etc/libvirt/qemu.conf /etc/libvirt/qemu.conf.bak > /dev/null; then
        print_message "Libvirt configuration changed, restarting service..."
        systemctl restart libvirtd
    else
        print_message "Libvirt configuration is already hardened, no changes needed."
    fi
}

setup_vm_resources() {
    print_header "Virtual Machine Resource Controls"
    
    # Check if cgroups tools are installed
    if ! command -v cgcreate &> /dev/null; then
        print_message "Installing cgroups tools..."
        apt-get install -y cgroup-tools
    fi
    
    # Create a systemd slice for VM resource control if it doesn't exist
    if [ ! -f /etc/systemd/system/machine.slice.d/resources.conf ]; then
        print_message "Creating VM resource control settings..."
        
        mkdir -p /etc/systemd/system/machine.slice.d/
        cat > /etc/systemd/system/machine.slice.d/resources.conf <<EOF
[Slice]
# Memory resource controls
MemoryAccounting=true
MemoryLow=512M

# CPU resource controls
CPUAccounting=true
CPUQuota=90%

# IO resource controls
IOAccounting=true
IOWeight=100
EOF
        
        systemctl daemon-reload
    fi
    
    print_message "Setting up OOM protection for libvirtd..."
    if ! grep -q "OOMScoreAdjust=-900" /etc/systemd/system/libvirtd.service.d/override.conf 2>/dev/null; then
        mkdir -p /etc/systemd/system/libvirtd.service.d/
        cat > /etc/systemd/system/libvirtd.service.d/override.conf <<EOF
[Service]
OOMScoreAdjust=-900
EOF
        
        systemctl daemon-reload
        systemctl restart libvirtd
    fi
}
