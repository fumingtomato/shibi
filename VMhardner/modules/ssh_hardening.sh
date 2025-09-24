#!/bin/bash

# =================================================================
# SECTION 3: USER AND SSH HARDENING
# =================================================================

harden_ssh() {
    print_header "SSH Service Hardening"
    
    # Create a backup of the SSH config if it doesn't exist
    backup_config_file /etc/ssh/sshd_config
    
    print_message "Hardening SSH configuration..."
    
    # Apply SSH hardening settings
    sed_if_not_exists "PermitRootLogin" "PermitRootLogin prohibit-password" /etc/ssh/sshd_config
    sed_if_not_exists "PasswordAuthentication" "PasswordAuthentication no" /etc/ssh/sshd_config
    sed_if_not_exists "X11Forwarding" "X11Forwarding no" /etc/ssh/sshd_config
    sed_if_not_exists "MaxAuthTries" "MaxAuthTries 3" /etc/ssh/sshd_config
    sed_if_not_exists "ClientAliveInterval" "ClientAliveInterval 300" /etc/ssh/sshd_config
    sed_if_not_exists "ClientAliveCountMax" "ClientAliveCountMax 2" /etc/ssh/sshd_config
    sed_if_not_exists "Protocol" "Protocol 2" /etc/ssh/sshd_config
    
    # Check for use of strong ciphers and MACs
    if ! grep -q "^Ciphers" /etc/ssh/sshd_config; then
        echo "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" >> /etc/ssh/sshd_config
    fi
    
    if ! grep -q "^MACs" /etc/ssh/sshd_config; then
        echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256" >> /etc/ssh/sshd_config
    fi
    
    if ! grep -q "^KexAlgorithms" /etc/ssh/sshd_config; then
        echo "KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256" >> /etc/ssh/sshd_config
    fi
    
    # Restart SSH service if configuration has changed
    if ! diff -q /etc/ssh/sshd_config /etc/ssh/sshd_config.bak > /dev/null; then
        print_message "SSH configuration changed, restarting service..."
        systemctl restart sshd
    else
        print_message "SSH is already hardened, no changes needed."
    fi
}

create_vm_admin() {
    print_header "VM Administrator Account Setup"
    
    read -p "Create a dedicated VM administrator user? (y/n): " create_admin
    if [[ "$create_admin" == "y" || "$create_admin" == "Y" ]]; then
        read -p "Enter username for VM administrator: " VM_ADMIN_USER
        
        # Check if user exists
        if id "$VM_ADMIN_USER" &>/dev/null; then
            print_message "User $VM_ADMIN_USER already exists."
        else
            print_message "Creating VM administrator user: $VM_ADMIN_USER"
            useradd -m -s /bin/bash "$VM_ADMIN_USER"
            
            # Generate a strong random password
            VM_ADMIN_PASS=$(openssl rand -base64 12)
            echo "$VM_ADMIN_USER:$VM_ADMIN_PASS" | chpasswd
            
            print_message "Generated password for $VM_ADMIN_USER: $VM_ADMIN_PASS"
            print_warning "Please change this password immediately after logging in!"
        fi
        
        # Add user to required groups for VM management
        for group in libvirt kvm libvirt-qemu; do
            if getent group $group > /dev/null; then
                if ! id -nG "$VM_ADMIN_USER" | grep -qw "$group"; then
                    usermod -aG $group "$VM_ADMIN_USER"
                    print_message "Added $VM_ADMIN_USER to $group group"
                fi
            fi
        done
        
        # Create sudo rule for VM management if it doesn't exist
        if [ ! -f /etc/sudoers.d/vm-admin ]; then
            print_message "Creating sudo rules for VM administrator..."
            cat > /etc/sudoers.d/vm-admin <<EOF
# VM administrator privileges
$VM_ADMIN_USER ALL=(ALL) NOPASSWD: /usr/bin/virsh
$VM_ADMIN_USER ALL=(ALL) NOPASSWD: /usr/bin/virt-*
$VM_ADMIN_USER ALL=(ALL) NOPASSWD: /usr/sbin/iptables
Defaults:$VM_ADMIN_USER !requiretty
EOF
            chmod 440 /etc/sudoers.d/vm-admin
        fi
    else
        print_message "Skipping VM administrator user creation."
    fi
}
