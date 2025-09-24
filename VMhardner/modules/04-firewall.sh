#!/bin/bash
# =================================================================
# Firewall configuration
# =================================================================

run_firewall_configuration() {
    print_header "Firewall Configuration"
    log "Starting firewall configuration"
    
    if [ "$ENABLE_UFW" != "false" ]; then
        configure_firewall
    else
        print_message "UFW configuration disabled in settings. Skipping."
        log "UFW configuration disabled in settings"
    fi
    
    log "Firewall configuration completed"
}

configure_firewall() {
    # Check if UFW is enabled
    if ! ufw status | grep -q "Status: active"; then
        print_message "Configuring UFW firewall..."
        log "Configuring UFW firewall"
        
        # Reset UFW to default
        ufw --force reset
        log "Reset UFW to defaults"
        
        # Set default policies
        ufw default deny incoming
        ufw default allow outgoing
        log "Set default UFW policies: deny incoming, allow outgoing"
        
        # Allow SSH (always required)
        if [ "$ALLOW_SSH" == "true" ]; then
            if [ "$SSH_PORT" == "22" ] || [ -z "$SSH_PORT" ]; then
                ufw allow ssh
                log "Allowed SSH on default port 22"
            else
                ufw allow "$SSH_PORT/tcp" comment 'SSH custom port'
                log "Allowed SSH on custom port $SSH_PORT"
            fi
        fi
        
        # Allow access to libvirt management
        if [ "$ALLOW_LIBVIRT" == "true" ]; then
            ufw allow 16514/tcp comment 'Libvirt TLS'
            log "Allowed libvirt TLS port 16514"
        fi
        
        # Ask for other ports that need to be allowed
        read -p "Do you want to allow additional ports? (y/n): " allow_more
        if [[ "$allow_more" == "y" || "$allow_more" == "Y" ]]; then
            read -p "Enter additional ports to allow (comma-separated, e.g., 80,443,3306): " additional_ports
            IFS=',' read -ra PORT_ARRAY <<< "$additional_ports"
            for port in "${PORT_ARRAY[@]}"; do
                port=$(echo "$port" | tr -d '[:space:]')
                if [[ "$port" =~ ^[0-9]+$ ]]; then
                    ufw allow "$port/tcp" comment "User requested port"
                    log "Allowed additional port $port/tcp"
                else
                    print_warning "Invalid port: $port, skipping."
                    log "Invalid port specified: $port"
                fi
            done
        fi
        
        # Enable the firewall
        print_message "Enabling UFW firewall..."
        log "Enabling UFW firewall"
        echo "y" | ufw enable
        log "UFW enabled"
    else
        print_message "UFW is already enabled."
        log "UFW is already enabled"
        
        # Check if SSH is allowed
        if ! ufw status | grep -q "$SSH_PORT/tcp\|ssh"; then
            print_warning "SSH port may not be open in the firewall!"
            log "WARNING: SSH port may not be open in firewall"
            read -p "Allow SSH access? (y/n): " allow_ssh
            if [[ "$allow_ssh" == "y" || "$allow_ssh" == "Y" ]]; then
                if [ "$SSH_PORT" == "22" ] || [ -z "$SSH_PORT" ]; then
                    ufw allow ssh
                    log "Allowed SSH on default port 22"
                else
                    ufw allow "$SSH_PORT/tcp" comment 'SSH custom port'
                    log "Allowed SSH on custom port $SSH_PORT"
                fi
            fi
        fi
    fi
    
    # Configure bridge filtering for VM traffic
    if [ ! -f /etc/ufw/sysctl.conf.bak ]; then
        print_message "Configuring bridge filtering for VM traffic..."
        log "Configuring bridge filtering for VM traffic"
        
        cp /etc/ufw/sysctl.conf /etc/ufw/sysctl.conf.bak
        
        # Add bridge filtering rules if they don't exist
        if ! grep -q "net.bridge.bridge-nf-call-ip" /etc/ufw/sysctl.conf; then
            cat >> /etc/ufw/sysctl.conf <<EOF

# Allow bridge networking for VMs
net.bridge.bridge-nf-call-ip6tables = 0
net.bridge.bridge-nf-call-iptables = 0
net.bridge.bridge-nf-call-arptables = 0
EOF
            log "Added bridge filtering rules to /etc/ufw/sysctl.conf"
        fi
        
        # Apply the changes
        sysctl -p /etc/ufw/sysctl.conf
        log "Applied bridge filtering settings"
    else
        log "Bridge filtering is already configured"
    fi
}
