#!/bin/bash
# =================================================================
# Libvirt/QEMU hardening configuration
# =================================================================

run_libvirt_hardening() {
    print_header "Securing Libvirt/QEMU Configuration"
    log "Starting libvirt/QEMU hardening"
    
    harden_libvirt
    
    log "Libvirt/QEMU hardening completed"
}

harden_libvirt() {
    # Create backup of libvirt configuration if it doesn't exist
    if [ ! -f /etc/libvirt/libvirtd.conf.bak ] && [ -f /etc/libvirt/libvirtd.conf ]; then
        print_message "Backing up libvirt configuration..."
        log "Backing up libvirt configuration"
        cp /etc/libvirt/libvirtd.conf /etc/libvirt/libvirtd.conf.bak
    fi
    
    # Configure libvirt security settings
    print_message "Hardening libvirt configuration..."
    log "Hardening libvirt configuration"
    
    # Secure libvirt daemon
    configure_setting "/etc/libvirt/libvirtd.conf" "auth_unix_ro" "\"none\"" "Read-only socket authentication"
    configure_setting "/etc/libvirt/libvirtd.conf" "auth_unix_rw" "\"polkit\"" "Read-write socket authentication"
    configure_setting "/etc/libvirt/libvirtd.conf" "unix_sock_group" "\"libvirt\"" "Socket group ownership"
    configure_setting "/etc/libvirt/libvirtd.conf" "unix_sock_ro_perms" "\"0770\"" "Read-only socket permissions"
    configure_setting "/etc/libvirt/libvirtd.conf" "unix_sock_rw_perms" "\"0770\"" "Read-write socket permissions"
    configure_setting "/etc/libvirt/libvirtd.conf" "unix_sock_admin_perms" "\"0700\"" "Admin socket permissions"
    configure_setting "/etc/libvirt/libvirtd.conf" "log_filters" "\"3:remote 4:event 3:json 3:rpc\"" "Log filters"
    configure_setting "/etc/libvirt/libvirtd.conf" "log_outputs" "\"1:file:/var/log/libvirt/libvirtd.log\"" "Log outputs"
    
    # Configure QEMU settings for security
    if [ ! -f /etc/libvirt/qemu.conf.bak ] && [ -f /etc/libvirt/qemu.conf ]; then
        print_message "Hardening QEMU configuration..."
        log "Hardening QEMU configuration"
        cp /etc/libvirt/qemu.conf /etc/libvirt/qemu.conf.bak
        
        configure_setting "/etc/libvirt/qemu.conf" "security_driver" "\"apparmor\"" "Security driver"
        configure_setting "/etc/libvirt/qemu.conf" "user" "\"root\"" "User for QEMU processes"
        configure_setting "/etc/libvirt/qemu.conf" "group" "\"root\"" "Group for QEMU processes"
        configure_setting "/etc/libvirt/qemu.conf" "dynamic_ownership" "1" "Dynamic ownership of VM resources"
        configure_setting "/etc/libvirt/qemu.conf" "remember_owner" "1" "Remember owner of VM resources"
        configure_setting "/etc/libvirt/qemu.conf" "clear_emulator_capabilities" "1" "Clear emulator capabilities"
        configure_setting "/etc/libvirt/qemu.conf" "seccomp_sandbox" "1" "Enable seccomp sandbox"
    fi
    
    # Create directory for libvirt logs if it doesn't exist
    mkdir -p /var/log/libvirt
    log "Created directory for libvirt logs"
    
    # Restart libvirt if configuration changed
    if [ -f /etc/libvirt/libvirtd.conf.bak ] && ! diff -q /etc/libvirt/libvirtd.conf /etc/libvirt/libvirtd.conf.bak > /dev/null 2>&1 || \
       [ -f /etc/libvirt/qemu.conf.bak ] && ! diff -q /etc/libvirt/qemu.conf /etc/libvirt/qemu.conf.bak > /dev/null 2>&1; then
        print_message "Libvirt configuration changed, restarting service..."
        log "Libvirt configuration changed, restarting service"
        systemctl restart libvirtd
    else
        print_message "Libvirt configuration is already hardened or no changes were made."
        log "Libvirt configuration is already hardened or no changes were made"
    fi
}
