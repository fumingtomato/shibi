#!/bin/bash

# =================================================================
# SECTION 4: FIREWALL CONFIGURATION
# =================================================================

configure_firewall() {
    print_header "Firewall Configuration"
    
    # Check if UFW is enabled
    if ! ufw status | grep -q "Status: active"; then
        print_message "Configuring UFW firewall..."
        
        # Reset UFW to default
        ufw --force reset
        
        # Set default policies
        ufw default deny incoming
        ufw default allow outgoing
        
        # Allow SSH (always required)
        ufw allow ssh
        
        # Allow access to libvirt management
        # NOTE: In production, restrict by source IP
        ufw allow 16514/tcp comment 'Libvirt TLS'
        
        # Ask for SSH port if different
        read -p "Is SSH running on a non-standard port? (y/n): " custom_ssh
        if [[ "$custom_ssh" == "y" || "$custom_ssh" == "Y" ]]; then
            read -p "Enter custom SSH port: " ssh_port
            ufw allow "$ssh_port/tcp" comment 'SSH custom port'
        fi
        
        # Enable the firewall
        print_message "Enabling UFW firewall..."
        echo "y" | ufw enable
    else
        print_message "UFW is already enabled."
        
        # Check if SSH is allowed
        if ! ufw status | grep -q "22/tcp"; then
            print_warning "SSH port may not be open in the firewall!"
            read -p "Allow SSH access? (y/n): " allow_ssh
            if [[ "$allow_ssh" == "y" || "$allow_ssh" == "Y" ]]; then
                ufw allow ssh
            fi
        fi
    fi
    
    # Configure bridge filtering for VM traffic
    if [ ! -f /etc/ufw/sysctl.conf.bak ]; then
        print_message "Configuring bridge filtering for VM traffic..."
        backup_config_file /etc/ufw/sysctl.conf
        
        # Add bridge filtering rules if they don't exist
        if ! grep -q "net.bridge.bridge-nf-call-ip" /etc/ufw/sysctl.conf; then
            cat >> /etc/ufw/sysctl.conf <<EOF

# Allow bridge networking for VMs
net.bridge.bridge-nf-call-ip6tables = 0
net.bridge.bridge-nf-call-iptables = 0
net.bridge.bridge-nf-call-arptables = 0
EOF
        fi
        
        # Apply the changes
        sysctl -p /etc/ufw/sysctl.conf
    fi
}
