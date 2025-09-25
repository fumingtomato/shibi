#!/bin/bash
# =================================================================
# Firewall configuration for VM Host with mail, web, and NextCloud VMs
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
        print_message "Configuring UFW firewall for VM host with mail, web, and NextCloud services..."
        log "Configuring UFW firewall"
        
        # Reset UFW to default
        ufw --force reset
        log "Reset UFW to defaults"
        
        # Set default policies
        ufw default deny incoming
        ufw default allow outgoing
        log "Set default UFW policies: deny incoming, allow outgoing"
        
        print_message "Configuring firewall rules for your VM services..."
        
        # Allow SSH (always required)
        if [ "$ALLOW_SSH" == "true" ]; then
            if [ "$SSH_PORT" == "22" ] || [ -z "$SSH_PORT" ]; then
                ufw allow ssh comment 'SSH access'
                print_message "✓ Allowed SSH (port 22)"
                log "Allowed SSH on default port 22"
            else
                ufw allow "$SSH_PORT/tcp" comment 'SSH custom port'
                print_message "✓ Allowed SSH (port $SSH_PORT)"
                log "Allowed SSH on custom port $SSH_PORT"
            fi
        fi
        
        # Allow access to libvirt management if configured
        if [ "$ALLOW_LIBVIRT" == "true" ]; then
            ufw allow 16514/tcp comment 'Libvirt TLS management'
            print_message "✓ Allowed Libvirt TLS management (port 16514)"
            log "Allowed libvirt TLS port 16514"
        fi
        
        print_header "Configuring Ports for VM Services"
        
        # Web Server and NextCloud VM ports
        print_message "Configuring Web and NextCloud VM ports:"
        ufw allow 80/tcp comment 'HTTP for Web and NextCloud VMs'
        print_message "  ✓ HTTP (port 80) - Web server and NextCloud access"
        
        ufw allow 443/tcp comment 'HTTPS for Web and NextCloud VMs'
        print_message "  ✓ HTTPS (port 443) - Secure web and NextCloud access"
        
        # Mail Server VM ports
        print_message ""
        print_message "Configuring Mail Server VM ports:"
        ufw allow 25/tcp comment 'SMTP for mail delivery'
        print_message "  ✓ SMTP (port 25) - Mail delivery between servers"
        
        ufw allow 587/tcp comment 'SMTP Submission'
        print_message "  ✓ Submission (port 587) - Mail client submission"
        
        ufw allow 465/tcp comment 'SMTPS secure submission'
        print_message "  ✓ SMTPS (port 465) - Secure mail submission"
        
        ufw allow 143/tcp comment 'IMAP for mail retrieval'
        print_message "  ✓ IMAP (port 143) - Mail retrieval"
        
        ufw allow 993/tcp comment 'IMAPS secure mail retrieval'
        print_message "  ✓ IMAPS (port 993) - Secure mail retrieval"
        
        # Optional: Ask about additional ports
        print_message ""
        print_warning "Standard ports for mail, web, and NextCloud services have been configured."
        print_message "Currently configured ports:"
        print_message "  • SSH: ${SSH_PORT:-22}"
        print_message "  • Web/NextCloud: 80 (HTTP), 443 (HTTPS)"
        print_message "  • Mail: 25 (SMTP), 587 (Submission), 465 (SMTPS), 143 (IMAP), 993 (IMAPS)"
        if [ "$ALLOW_LIBVIRT" == "true" ]; then
            print_message "  • Management: 16514 (Libvirt TLS)"
        fi
        print_message ""
        
        read -p "Do you need to allow any ADDITIONAL ports not listed above? (y/n): " allow_more
        if [[ "$allow_more" == "y" || "$allow_more" == "Y" ]]; then
            print_message "Enter additional ports (comma-separated)."
            print_message "Examples:"
            print_message "  • 110,995 for POP3/POP3S"
            print_message "  • 3306 for MySQL access"
            print_message "  • 8080 for alternative HTTP"
            print_message "  • 4443 for alternative HTTPS"
            read -p "Additional ports: " additional_ports
            
            if [ -n "$additional_ports" ]; then
                IFS=',' read -ra PORT_ARRAY <<< "$additional_ports"
                for port in "${PORT_ARRAY[@]}"; do
                    port=$(echo "$port" | tr -d '[:space:]')
                    if [[ "$port" =~ ^[0-9]+$ ]]; then
                        ufw allow "$port/tcp" comment "User requested port"
                        print_message "  ✓ Allowed additional port $port/tcp"
                        log "Allowed additional port $port/tcp"
                    else
                        print_warning "  ✗ Invalid port: $port, skipping."
                        log "Invalid port specified: $port"
                    fi
                done
            fi
        else
            log "No additional ports requested"
        fi
        
        # Enable the firewall
        print_message ""
        print_message "Enabling UFW firewall..."
        log "Enabling UFW firewall"
        echo "y" | ufw enable
        print_message "✓ Firewall enabled successfully"
        log "UFW enabled"
        
    else
        print_message "UFW is already enabled. Checking configuration..."
        log "UFW is already enabled"
        
        # Display current firewall status
        print_message "Current firewall rules:"
        ufw status numbered | grep -v "^$"
        
        # Check if SSH is allowed
        if ! ufw status | grep -q "$SSH_PORT/tcp\|ssh"; then
            print_warning "WARNING: SSH port may not be open in the firewall!"
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
        
        # Check for required VM service ports
        print_message ""
        print_message "Checking for required VM service ports..."
        
        REQUIRED_PORTS=(
            "80:HTTP"
            "443:HTTPS"
            "25:SMTP"
            "587:Submission"
            "465:SMTPS"
            "143:IMAP"
            "993:IMAPS"
        )
        
        for port_desc in "${REQUIRED_PORTS[@]}"; do
            port="${port_desc%%:*}"
            desc="${port_desc##*:}"
            if ! ufw status | grep -q "^$port/tcp"; then
                print_warning "Port $port ($desc) is not open. Opening it now..."
                ufw allow $port/tcp comment "$desc for VMs"
                print_message "  ✓ Opened port $port ($desc)"
            else
                print_message "  ✓ Port $port ($desc) is already open"
            fi
        done
    fi
    
    # Configure bridge filtering for VM traffic
    if [ ! -f /etc/ufw/sysctl.conf.bak ]; then
        print_message ""
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
        sysctl -p /etc/ufw/sysctl.conf 2>/dev/null || true
        log "Applied bridge filtering settings"
    else
        log "Bridge filtering is already configured"
    fi
    
    print_message ""
    print_message "Firewall configuration completed successfully!"
    print_message "All standard ports for mail, web, and NextCloud VMs are configured."
}
