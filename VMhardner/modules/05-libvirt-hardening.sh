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
    
    # Function to set libvirt config with proper syntax
    set_libvirt_config() {
        local file="$1"
        local param="$2"
        local value="$3"
        
        # Check if parameter exists (commented or not)
        if grep -q "^#*${param} =" "$file" 2>/dev/null; then
            # Parameter exists, update it
            sed -i "s|^#*${param} =.*|${param} = ${value}|" "$file"
        else
            # Add parameter if it doesn't exist
            echo "${param} = ${value}" >> "$file"
        fi
    }
    
    # Secure libvirt daemon settings
    set_libvirt_config "/etc/libvirt/libvirtd.conf" "auth_unix_ro" '"none"'
    set_libvirt_config "/etc/libvirt/libvirtd.conf" "auth_unix_rw" '"polkit"'
    set_libvirt_config "/etc/libvirt/libvirtd.conf" "unix_sock_group" '"libvirt"'
    set_libvirt_config "/etc/libvirt/libvirtd.conf" "unix_sock_ro_perms" '"0770"'
    set_libvirt_config "/etc/libvirt/libvirtd.conf" "unix_sock_rw_perms" '"0770"'
    set_libvirt_config "/etc/libvirt/libvirtd.conf" "unix_sock_admin_perms" '"0700"'
    
    # Configure QEMU settings for security
    if [ ! -f /etc/libvirt/qemu.conf.bak ] && [ -f /etc/libvirt/qemu.conf ]; then
        print_message "Hardening QEMU configuration..."
        log "Hardening QEMU configuration"
        cp /etc/libvirt/qemu.conf /etc/libvirt/qemu.conf.bak
        
        # QEMU security settings
        set_libvirt_config "/etc/libvirt/qemu.conf" "security_driver" '"apparmor"'
        set_libvirt_config "/etc/libvirt/qemu.conf" "dynamic_ownership" "1"
        set_libvirt_config "/etc/libvirt/qemu.conf" "remember_owner" "1"
        set_libvirt_config "/etc/libvirt/qemu.conf" "clear_emulator_capabilities" "1"
        set_libvirt_config "/etc/libvirt/qemu.conf" "seccomp_sandbox" "1"
    fi
    
    # Create directory for libvirt logs if it doesn't exist
    mkdir -p /var/log/libvirt
    log "Created directory for libvirt logs"
    
    # Test the configuration before restarting
    print_message "Testing libvirt configuration..."
    if libvirtd --config /etc/libvirt/libvirtd.conf --timeout 0 --version >/dev/null 2>&1; then
        # Restart libvirt if configuration changed
        if [ -f /etc/libvirt/libvirtd.conf.bak ] && ! diff -q /etc/libvirt/libvirtd.conf /etc/libvirt/libvirtd.conf.bak > /dev/null 2>&1 || \
           [ -f /etc/libvirt/qemu.conf.bak ] && ! diff -q /etc/libvirt/qemu.conf /etc/libvirt/qemu.conf.bak > /dev/null 2>&1; then
            print_message "Libvirt configuration changed, restarting service..."
            log "Libvirt configuration changed, restarting service"
            systemctl restart libvirtd
            
            # Check if the service started successfully
            if ! systemctl is-active --quiet libvirtd; then
                print_error "Failed to restart libvirtd! Restoring original configuration..."
                log "ERROR: Failed to restart libvirtd, restoring backup"
                cp /etc/libvirt/libvirtd.conf.bak /etc/libvirt/libvirtd.conf
                if [ -f /etc/libvirt/qemu.conf.bak ]; then
                    cp /etc/libvirt/qemu.conf.bak /etc/libvirt/qemu.conf
                fi
                systemctl restart libvirtd
                print_error "Configuration has been restored. Please check libvirt logs for details."
                return 1
            fi
        else
            print_message "Libvirt configuration is already hardened or no changes were made."
            log "Libvirt configuration is already hardened or no changes were made"
        fi
    else
        print_error "Configuration validation failed! Not applying changes."
        log "ERROR: Libvirt configuration validation failed"
        return 1
    fi
}
