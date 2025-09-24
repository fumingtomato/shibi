#!/bin/bash
# =================================================================
# SSH service hardening
# =================================================================

run_ssh_hardening() {
    print_header "SSH Service Hardening"
    log "Starting SSH hardening"
    
    harden_ssh
    create_vm_admin
    
    log "SSH hardening completed"
}

harden_ssh() {
    # Create a backup of the SSH config if it doesn't exist
    if [ ! -f /etc/ssh/sshd_config.bak ]; then
        print_message "Backing up SSH configuration..."
        log "Backing up SSH configuration"
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
    fi
    
    print_message "Hardening SSH configuration..."
    log "Hardening SSH configuration"
    
    # Apply SSH hardening settings
    if [ "$DISABLE_ROOT_SSH" == "true" ]; then
        configure_setting "/etc/ssh/sshd_config" "PermitRootLogin" "prohibit-password" "Disable root login with password"
    fi
    
    if [ "$DISABLE_PASSWORD_AUTH" == "true" ]; then
        configure_setting "/etc/ssh/sshd_config" "PasswordAuthentication" "no" "Disable password authentication"
    fi
    
    configure_setting "/etc/ssh/sshd_config" "X11Forwarding" "no" "Disable X11 Forwarding"
    configure_setting "/etc/ssh/sshd_config" "MaxAuthTries" "3" "Limit authentication attempts"
    configure_setting "/etc/ssh/sshd_config" "ClientAliveInterval" "300" "Client alive interval"
    configure_setting "/etc/ssh/sshd_config" "ClientAliveCountMax" "2" "Client alive count max"
    configure_setting "/etc/ssh/sshd_config" "Protocol" "2" "Use SSH protocol 2"
    
    # Check for use of strong ciphers and MACs
    if ! grep -q "^Ciphers" /etc/ssh/sshd_config; then
        echo "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" >> /etc/ssh/sshd_config
        log "Added strong cipher configuration to SSH"
    fi
    
    if ! grep -q "^MACs" /etc/ssh/sshd_config; then
        echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256" >> /etc/ssh/sshd_config
        log "Added strong MACs configuration to SSH"
    fi
    
    if ! grep -q "^KexAlgorithms" /etc/ssh/sshd_config; then
        echo "KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256" >> /etc/ssh/sshd_config
        log "Added strong KexAlgorithms configuration to SSH"
    fi
    
    # If SSH is running on non-standard port, configure it
    if [ "$SSH_PORT" != "22" ] && [ -n "$SSH_PORT" ]; then
        configure_setting "/etc/ssh/sshd_config" "Port" "$SSH_PORT" "SSH custom port"
    fi
    
    # Restart SSH service if configuration has changed
    if ! diff -q /etc/ssh/sshd_config /etc/ssh/sshd_config.bak > /dev/null 2>&1; then
        print_message "SSH configuration changed, restarting service..."
        log "SSH configuration changed, restarting service"
        systemctl restart ssh || systemctl restart sshd
    else
        print_message "SSH is already hardened, no changes needed."
        log "SSH is already hardened, no changes needed"
    fi
}

create_vm_admin() {
    print_header "VM Administrator Account Setup"
    log "Starting VM administrator account setup"
    
    read -p "Create a dedicated VM administrator user? (y/n): " create_admin
    if [[ "$create_admin" == "y" || "$create_admin" == "Y" ]]; then
        read -p "Enter username for VM administrator: " VM_ADMIN_USER
        
        # Check if user exists
        if id "$VM_ADMIN_USER" &>/dev/null; then
            print_message "User $VM_ADMIN_USER already exists."
            log "User $VM_ADMIN_USER already exists"
        else
            print_message "Creating VM administrator user: $VM_ADMIN_USER"
            log "Creating VM administrator user: $VM_ADMIN_USER"
            useradd -m -s /bin/bash "$VM_ADMIN_USER"
            
            # Generate a strong random password
            VM_ADMIN_PASS=$(openssl rand -base64 12)
            echo "$VM_ADMIN_USER:$VM_ADMIN_PASS" | chpasswd
            
            print_message "Generated password for $VM_ADMIN_USER: $VM_ADMIN_PASS"
            log "Generated password for $VM_ADMIN_USER"
            print_warning "Please change this password immediately after logging in!"
        fi
        
        # Add user to required groups for VM management
        for group in libvirt kvm libvirt-qemu; do
            if getent group $group > /dev/null; then
                if ! id -nG "$VM_ADMIN_USER" | grep -qw "$group"; then
                    usermod -aG $group "$VM_ADMIN_USER"
                    print_message "Added $VM_ADMIN_USER to $group group"
                    log "Added $VM_ADMIN_USER to $group group"
                fi
            fi
        done
        
        # Create sudo rule for VM management if it doesn't exist
        if [ ! -f /etc/sudoers.d/vm-admin ]; then
            print_message "Creating sudo rules for VM administrator..."
            log "Creating sudo rules for VM administrator"
            
            cat > /etc/sudoers.d/vm-admin <<EOF
# VM administrator privileges
$VM_ADMIN_USER ALL=(ALL) NOPASSWD: /usr/bin/virsh
$VM_ADMIN_USER ALL=(ALL) NOPASSWD: /usr/bin/virt-*
$VM_ADMIN_USER ALL=(ALL) NOPASSWD: /usr/sbin/iptables
Defaults:$VM_ADMIN_USER !requiretty
EOF
            chmod 440 /etc/sudoers.d/vm-admin
            log "Created sudo rules for $VM_ADMIN_USER"
        fi
    else
        print_message "Skipping VM administrator user creation."
        log "Skipping VM administrator user creation"
    fi
}
