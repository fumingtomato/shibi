#!/bin/bash

# =================================================================
# MAIN INSTALLER MODULE - PART 1
# Core installation logic and menu system
# =================================================================

# Main installation function for multi-IP setup
first_time_installation_multi_ip() {
    print_header "Mail Server Installation - Multi-IP Bulk Mail Edition"
    
    # Check system requirements
    check_system_requirements
    
    # Get all server IPs
    get_all_server_ips
    
    # Gather basic information
    read -p "Enter the primary domain name (e.g. example.com): " DOMAIN_NAME
    validate_domain "$DOMAIN_NAME" || exit 1
    
    read -p "Enter your server's primary hostname (e.g. mail.example.com): " HOSTNAME
    validate_domain "$HOSTNAME" || exit 1
    
    read -p "Enter admin email address: " ADMIN_EMAIL
    validate_email "$ADMIN_EMAIL" || exit 1
    
    # Automatically use domain name as brand name (no question asked)
    BRAND_NAME="$DOMAIN_NAME"
    print_message "Using domain name as brand name: $BRAND_NAME"
    
    read -p "Enter the username for the first mail account: " MAIL_USERNAME
    read -s -p "Enter password for mail account: " MAIL_PASSWORD
    echo
    read -s -p "Confirm password: " MAIL_PASSWORD_CONFIRM
    echo
    
    if [ "$MAIL_PASSWORD" != "$MAIL_PASSWORD_CONFIRM" ]; then
        print_error "Passwords do not match. Please try again."
        exit 1
    fi
    
    # Setup timezone and export the variable
    setup_timezone
    export timezone
    
    # Ask about Sticky IP feature
    print_header "Sticky IP Configuration"
    print_message "The Sticky IP feature ensures that contacts who engage with your emails"
    print_message "always receive future emails from the same IP address, improving deliverability."
    
    read -p "Enable Sticky IP feature? (y/n) [y]: " enable_sticky_ip
    enable_sticky_ip=${enable_sticky_ip:-y}
    
    # Cloudflare integration - Fix variable consistency
    print_header "Cloudflare Integration (Optional)"
    print_message "To automatically configure DNS records, please provide your Cloudflare credentials."
    print_message "Leave blank to skip automatic DNS configuration."
    read -p "Enter your Cloudflare API token (or press Enter to skip): " CF_API_TOKEN
    
    if [ ! -z "$CF_API_TOKEN" ]; then
        read -p "Enter your Cloudflare zone ID for $DOMAIN_NAME: " CF_ZONE_ID
    fi
    
    # Configuration summary
    print_header "Configuration Summary"
    echo "Primary Domain: $DOMAIN_NAME"
    echo "Brand Name: $BRAND_NAME"
    echo "Primary Hostname: $HOSTNAME"
    echo "Admin Email: $ADMIN_EMAIL"
    echo "Mail Username: $MAIL_USERNAME@$DOMAIN_NAME"
    echo "Number of IPs: ${#IP_ADDRESSES[@]}"
    echo "IP Addresses:"
    for ip in "${IP_ADDRESSES[@]}"; do
        echo "  - $ip"
    done
    echo "IP Distribution: Round-robin (default)"
    echo "Sticky IP Feature: $([[ "$enable_sticky_ip" == "y" ]] && echo "Enabled" || echo "Disabled")"
    echo "Timezone: ${timezone:-$(timedatectl | grep 'Time zone' | awk '{print $3}')}"
    
    read -p "Is this information correct? (y/n): " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        print_error "Installation cancelled. Please run the script again."
        exit 1
    fi
    
    # Export variables for other modules
    export DOMAIN_NAME HOSTNAME ADMIN_EMAIL BRAND_NAME
    export MAIL_USERNAME MAIL_PASSWORD
    export CF_API_TOKEN CF_ZONE_ID
    export ENABLE_STICKY_IP=$enable_sticky_ip
    
    # Start installation
    print_message "Starting multi-IP mail server installation..."
    
    # Install packages
    install_required_packages
    
    # Configure hostname
    configure_hostname "$HOSTNAME"
    
    # Configure network interfaces for multiple IPs
    if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
        configure_network_interfaces
    fi
    
    # Fixed order: MySQL must be setup before anything that uses it
    setup_mysql                 # 1. First - Install MySQL & postfix-mysql
    
    # Small delay to ensure MySQL is fully ready
    sleep 2
    
    # Now add domain and user to MySQL
    add_domain_to_mysql "$DOMAIN_NAME"
    add_email_user "${MAIL_USERNAME}@${DOMAIN_NAME}" "${MAIL_PASSWORD}"
    
    # Setup Sticky IP if enabled (after MySQL is ready)
    if [[ "$ENABLE_STICKY_IP" == "y" ]]; then
        if type setup_sticky_ip_db &>/dev/null; then
            setup_sticky_ip_db
        else
            print_warning "Sticky IP module not loaded properly. Skipping sticky IP setup."
        fi
    fi
    
    # Setup Dovecot (needs MySQL)
    setup_dovecot "$DOMAIN_NAME" "$HOSTNAME"
    
    # Setup Postfix (needs MySQL)
    setup_postfix_multi_ip "$DOMAIN_NAME" "$HOSTNAME"
    
    # Configure IP rotation
    create_ip_rotation_config
    
    # Configure Sticky IP Postfix settings if enabled
    if [[ "$ENABLE_STICKY_IP" == "y" ]]; then
        if type configure_sticky_ip_postfix &>/dev/null; then
            configure_sticky_ip_postfix
        else
            print_warning "Sticky IP module not loaded properly. Skipping sticky IP postfix config."
        fi
    fi
    
    # Setup DKIM (must be done before DNS configuration)
    setup_opendkim "$DOMAIN_NAME"
    
    # Wait a moment for DKIM keys to be generated
    sleep 2
    
    # Setup web and SSL
    setup_nginx "$DOMAIN_NAME" "$HOSTNAME"
    
    # Setup DNS records (now DKIM keys are ready)
    if [ ! -z "$CF_API_TOKEN" ] && [ ! -z "$CF_ZONE_ID" ]; then
        create_multi_ip_dns_records "$DOMAIN_NAME" "$HOSTNAME"
    else
        print_message "Skipping automatic DNS configuration (no Cloudflare credentials provided)"
        
        # Create manual DNS instructions
        create_manual_dns_instructions "$DOMAIN_NAME" "$HOSTNAME"
    fi
    
    # Get SSL certificates
    get_ssl_certificates "$DOMAIN_NAME" "$HOSTNAME" "$ADMIN_EMAIL"
    
    # Setup website
    setup_website "$DOMAIN_NAME" "$ADMIN_EMAIL" "$BRAND_NAME"
    
    # Create management scripts
    create_utility_scripts "$DOMAIN_NAME"
    create_ip_warmup_scripts
    create_monitoring_scripts
    create_mailwizz_multi_ip_guide "$DOMAIN_NAME"
    
    # Create Sticky IP utilities if enabled
    if [[ "$ENABLE_STICKY_IP" == "y" ]]; then
        if type create_sticky_ip_utility &>/dev/null; then
            create_sticky_ip_utility
            create_mailwizz_sticky_ip_integration
        else
            print_warning "Sticky IP module not loaded properly. Skipping sticky IP utilities."
        fi
    fi
    
    # Create PTR instructions
    create_ptr_instructions
    
    # Apply hardening
    harden_server "$DOMAIN_NAME" "$HOSTNAME"
    
    # Setup email aliases
    setup_email_aliases
    
    # Restart services in the correct order
    restart_services_ordered
    
    # Save configuration
    save_configuration
    
    # Create final documentation
    create_final_documentation
    
    # Run post-installation checks
    run_post_installation_checks
    
    print_header "Installation Complete!"
    print_message "Your Multi-IP Bulk Mail Server has been successfully installed!"
    print_message ""
    print_message "Configured with ${#IP_ADDRESSES[@]} IP address(es) for load balancing and rotation."
    print_message "Default IP distribution: Round-robin"
    
    if [[ "$ENABLE_STICKY_IP" == "y" ]]; then
        print_message "Sticky IP feature is ENABLED: Contacts who open/click emails will receive"
        print_message "future emails from the same IP address."
        print_message ""
        print_message "Sticky IP management: /usr/local/bin/sticky-ip-manager"
        print_message "See the guide at: /root/mailwizz-sticky-ip-guide.txt"
    fi
    
    print_message ""
    print_message "NEXT STEPS:"
    print_message "1. Configure reverse DNS for all IPs with your hosting provider"
    print_message "2. Set up MailWizz delivery servers (see /root/mailwizz-multi-ip-guide.txt)"
    print_message "3. Begin IP warmup process using /usr/local/bin/ip-warmup-manager"
    print_message "4. Monitor delivery with /usr/local/bin/mail-stats"
    print_message ""
    print_message "Complete documentation available at:"
    print_message "- /root/mail-server-multiip-info.txt"
    print_message "- /root/mailwizz-multi-ip-guide.txt"
    print_message "- /root/ptr-records-setup.txt"
    
    if [ ! -z "$CF_API_TOKEN" ]; then
        print_message ""
        print_message "DNS records have been automatically configured in Cloudflare."
        print_message "Please allow 5-30 minutes for DNS propagation."
    else
        print_message ""
        print_message "IMPORTANT: Manual DNS configuration required!"
        print_message "See /root/manual-dns-setup.txt for the records you need to add."
    fi
}

# Create manual DNS instructions when Cloudflare is not used
create_manual_dns_instructions() {
    local domain=$1
    local hostname=$2
    
    print_message "Creating manual DNS configuration instructions..."
    
    cat > /root/manual-dns-setup.txt <<EOF
==========================================================
MANUAL DNS CONFIGURATION REQUIRED
==========================================================

Since Cloudflare API was not configured, you need to manually
add the following DNS records to your domain's DNS management:

1. A RECORDS (for each IP address):
-----------------------------------
EOF
    
    local idx=1
    for ip in "${IP_ADDRESSES[@]}"; do
        if [ $idx -eq 1 ]; then
            echo "   Type: A, Name: @, Value: $ip" >> /root/manual-dns-setup.txt
            echo "   Type: A, Name: mail, Value: $ip" >> /root/manual-dns-setup.txt
        else
            echo "   Type: A, Name: mail${idx}, Value: $ip" >> /root/manual-dns-setup.txt
        fi
        idx=$((idx + 1))
    done
    
    cat >> /root/manual-dns-setup.txt <<EOF

2. MX RECORD:
-------------
   Type: MX, Name: @, Priority: 10, Value: $hostname

3. SPF RECORD:
--------------
   Type: TXT, Name: @
   Value: See /root/spf-record-${domain}.txt

4. DKIM RECORD:
---------------
   Type: TXT, Name: mail._domainkey
   Value: See /root/dkim-record-${domain}.txt

5. DMARC RECORD:
----------------
   Type: TXT, Name: _dmarc
   Value: See /root/dmarc-record-${domain}.txt

6. PTR RECORDS (Reverse DNS):
-----------------------------
   These must be configured with your hosting provider.
   See /root/ptr-records-setup.txt for details.

IMPORTANT:
----------
After adding these records, wait at least 5-30 minutes for
DNS propagation before testing your mail server.

You can verify DNS records using:
   dig A $domain
   dig MX $domain
   dig TXT $domain
   dig TXT mail._domainkey.$domain

==========================================================
EOF
    
    print_message "Manual DNS instructions saved to /root/manual-dns-setup.txt"
}

# Restart services in the correct order with dependency checking
restart_services_ordered() {
    print_header "Restarting Services in Correct Order"
    
    # Fix configuration before restarting services
    fix_mysql_config
    
    # Define service order (dependencies first)
    local services=("mysql" "opendkim" "dovecot" "postfix" "nginx")
    
    for service in "${services[@]}"; do
        print_message "Restarting $service..."
        
        # Stop the service first
        systemctl stop $service 2>/dev/null || true
        
        # Small delay to ensure clean stop
        sleep 1
        
        # Start the service
        if systemctl start $service; then
            print_message "✓ $service started successfully"
            
            # Enable service to start on boot
            systemctl enable $service 2>/dev/null || true
            
            # Special wait for MySQL to be fully ready
            if [ "$service" = "mysql" ]; then
                print_message "Waiting for MySQL to be fully ready..."
                for i in {1..10}; do
                    if mysqladmin ping &>/dev/null; then
                        print_message "✓ MySQL is ready"
                        break
                    fi
                    sleep 1
                done
            fi
        else
            print_error "✗ Failed to start $service"
            print_message "Attempting to diagnose issue..."
            systemctl status $service --no-pager | tail -n 10
        fi
    done
    
    print_message "All services restarted"
}

# Run post-installation checks to verify everything is working
run_post_installation_checks() {
    print_header "Running Post-Installation Checks"
    
    local all_good=true
    
    # Check if all critical services are running
    print_message "Checking service status..."
    for service in mysql postfix dovecot nginx opendkim; do
        if systemctl is-active --quiet $service; then
            print_message "✓ $service is running"
        else
            print_error "✗ $service is not running"
            all_good=false
        fi
    done
    
    # Check if MySQL database is accessible
    print_message "Checking database connectivity..."
    if mysql -u mailuser -p$(cat /root/.mail_db_password 2>/dev/null) -e "SELECT 1;" mailserver &>/dev/null; then
        print_message "✓ Database connection successful"
    else
        print_error "✗ Database connection failed"
        all_good=false
    fi
    
    # Check if Postfix configuration is valid
    print_message "Checking Postfix configuration..."
    if postfix check 2>/dev/null; then
        print_message "✓ Postfix configuration is valid"
    else
        print_error "✗ Postfix configuration has errors"
        all_good=false
    fi
    
    # Check if ports are listening
    print_message "Checking network ports..."
    local ports=("25:SMTP" "143:IMAP" "587:Submission" "993:IMAPS" "80:HTTP" "443:HTTPS")
    for port_info in "${ports[@]}"; do
        IFS=':' read -r port name <<< "$port_info"
        if netstat -tuln | grep -q ":$port "; then
            print_message "✓ Port $port ($name) is listening"
        else
            print_warning "⚠ Port $port ($name) is not listening"
        fi
    done
    
    # Check DKIM key
    print_message "Checking DKIM configuration..."
    if [ -f "/etc/opendkim/keys/${DOMAIN_NAME}/mail.private" ]; then
        print_message "✓ DKIM key exists"
    else
        print_error "✗ DKIM key not found"
        all_good=false
    fi
    
    # Summary
    echo ""
    if [ "$all_good" = true ]; then
        print_message "✓ All post-installation checks passed!"
    else
        print_warning "⚠ Some checks failed. Please review the errors above."
        print_message "You may need to manually fix these issues."
    fi
}

# Export the main function
export -f first_time_installation_multi_ip
export -f create_manual_dns_instructions
export -f restart_services_ordered
export -f run_post_installation_checks
