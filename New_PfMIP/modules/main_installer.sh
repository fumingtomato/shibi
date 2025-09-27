#!/bin/bash

# =================================================================
# MAIN INSTALLER MODULE - PART 1 - FIXED VERSION
# Core installation logic and menu system
# Fixed: Added proper MySQL wait loop, progress tracking, and preflight checks
# =================================================================

# Function to wait for MySQL to be ready
wait_for_mysql() {
    local max_wait=30
    print_message "Waiting for MySQL to be ready..."
    
    for i in $(seq 1 $max_wait); do
        if mysqladmin ping &>/dev/null; then
            print_message "✓ MySQL is ready"
            return 0
        fi
        echo -n "."
        sleep 1
    done
    
    echo ""
    print_error "MySQL failed to start within ${max_wait} seconds"
    return 1
}

# Function to save installation progress
save_progress() {
    local step=$1
    local progress_file="/root/.installer_progress"
    
    echo "LAST_COMPLETED_STEP=$step" > "$progress_file"
    echo "TIMESTAMP=$(date -u '+%Y-%m-%d %H:%M:%S')" >> "$progress_file"
    echo "VERSION=$INSTALLER_VERSION" >> "$progress_file"
    
    # Save critical variables for resume
    echo "DOMAIN_NAME=$DOMAIN_NAME" >> "$progress_file"
    echo "HOSTNAME=$HOSTNAME" >> "$progress_file"
    echo "SUBDOMAIN=$SUBDOMAIN" >> "$progress_file"
    echo "ADMIN_EMAIL=$ADMIN_EMAIL" >> "$progress_file"
    echo "BRAND_NAME=$BRAND_NAME" >> "$progress_file"
    echo "IP_COUNT=$IP_COUNT" >> "$progress_file"
    echo "ENABLE_STICKY_IP=$ENABLE_STICKY_IP" >> "$progress_file"
    
    print_debug "Progress saved: $step"
}

# Function to check for previous installation
check_previous_installation() {
    local progress_file="/root/.installer_progress"
    
    if [ -f "$progress_file" ]; then
        source "$progress_file"
        print_warning "Previous installation detected!"
        echo "Last completed step: $LAST_COMPLETED_STEP"
        echo "Timestamp: $TIMESTAMP"
        echo ""
        
        read -p "Do you want to resume the previous installation? (y/n): " resume_choice
        if [[ "$resume_choice" == "y" || "$resume_choice" == "Y" ]]; then
            return 0
        else
            read -p "Start fresh installation? This will remove previous progress. (y/n): " fresh_choice
            if [[ "$fresh_choice" == "y" || "$fresh_choice" == "Y" ]]; then
                rm -f "$progress_file"
                return 1
            else
                print_message "Installation cancelled."
                exit 0
            fi
        fi
    fi
    
    return 1
}

# Preflight check function
preflight_check() {
    print_header "Running Preflight Checks"
    
    local errors=0
    local warnings=0
    
    # Check if running as root
    if [ "$(id -u)" != "0" ]; then
        print_error "✗ Must run as root"
        errors=$((errors + 1))
    else
        print_message "✓ Running as root"
    fi
    
    # Check disk space (need at least 5GB)
    local disk_free=$(df / | awk 'NR==2 {print $4}')
    if [ "$disk_free" -lt 5242880 ]; then
        print_error "✗ Insufficient disk space (need 5GB, have $((disk_free/1024/1024))GB)"
        errors=$((errors + 1))
    else
        print_message "✓ Disk space: $((disk_free/1024/1024))GB available"
    fi
    
    # Check memory (warn if less than 1GB)
    local mem_total=$(free -m | awk '/^Mem:/{print $2}')
    if [ "$mem_total" -lt 1024 ]; then
        print_warning "⚠ Low memory: ${mem_total}MB (recommended: 1GB+)"
        warnings=$((warnings + 1))
    else
        print_message "✓ Memory: ${mem_total}MB"
    fi
    
    # Check if mail ports are already in use
    local ports_in_use=()
    for port in 25 587 143 993 110 995; do
        if netstat -tuln 2>/dev/null | grep -q ":$port "; then
            ports_in_use+=($port)
        fi
    done
    
    if [ ${#ports_in_use[@]} -gt 0 ]; then
        print_warning "⚠ Mail ports already in use: ${ports_in_use[*]}"
        print_warning "  Existing mail services may need to be stopped"
        warnings=$((warnings + 1))
    else
        print_message "✓ Mail ports available"
    fi
    
    # Check network connectivity
    if ping -c 1 -W 2 8.8.8.8 &>/dev/null || ping -c 1 -W 2 1.1.1.1 &>/dev/null; then
        print_message "✓ Internet connectivity OK"
    else
        print_error "✗ No internet connectivity"
        errors=$((errors + 1))
    fi
    
    # Check DNS resolution
    if host google.com &>/dev/null; then
        print_message "✓ DNS resolution working"
    else
        print_warning "⚠ DNS resolution issues detected"
        warnings=$((warnings + 1))
    fi
    
    # Check OS compatibility
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        if [[ "$ID" =~ ^(ubuntu|debian)$ ]]; then
            print_message "✓ Operating System: $NAME $VERSION"
        else
            print_warning "⚠ Untested OS: $NAME $VERSION (optimized for Ubuntu/Debian)"
            warnings=$((warnings + 1))
        fi
    else
        print_warning "⚠ Could not determine OS version"
        warnings=$((warnings + 1))
    fi
    
    echo ""
    print_message "Preflight Check Summary:"
    print_message "  Errors: $errors"
    print_message "  Warnings: $warnings"
    echo ""
    
    if [ $errors -gt 0 ]; then
        print_error "Critical errors found. Please fix them before continuing."
        read -p "Continue anyway? (not recommended) (y/n): " force_continue
        if [[ "$force_continue" != "y" && "$force_continue" != "Y" ]]; then
            exit 1
        fi
    elif [ $warnings -gt 0 ]; then
        print_warning "Some warnings detected. Installation should proceed but monitor for issues."
        read -p "Continue? (y/n): " continue_install
        if [[ "$continue_install" != "y" && "$continue_install" != "Y" ]]; then
            exit 0
        fi
    else
        print_message "✓ All preflight checks passed!"
    fi
    
    return $errors
}

# Main installation function for multi-IP setup
first_time_installation_multi_ip() {
    print_header "Mail Server Installation - Multi-IP Bulk Mail Edition"
    
    # Run preflight checks
    preflight_check
    
    # Check for previous installation
    if check_previous_installation; then
        print_message "Resuming previous installation..."
        # Variables should already be loaded from progress file
    else
        # Fresh installation - gather information
        print_message "Starting fresh installation..."
        
        # Check system requirements
        check_system_requirements
        
        # Get all server IPs
        get_all_server_ips
        
        # Gather basic information
        read -p "Enter the primary domain name (e.g. example.com): " DOMAIN_NAME
        validate_domain "$DOMAIN_NAME" || exit 1
        
        # Ask for subdomain only
        read -p "Enter your mail server subdomain (e.g. mta, mail, smtp): " SUBDOMAIN
        # Validate subdomain (alphanumeric and hyphens only, no dots)
        if [[ ! "$SUBDOMAIN" =~ ^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]$|^[a-zA-Z0-9]$ ]]; then
            print_error "Invalid subdomain format. Use only letters, numbers, and hyphens (no dots)."
            exit 1
        fi
        
        # Create primary hostname from subdomain and domain
        HOSTNAME="${SUBDOMAIN}.${DOMAIN_NAME}"
        print_message "Primary hostname will be: $HOSTNAME"
        
        # Create array of hostnames for multiple IPs
        HOSTNAMES=()
        HOSTNAMES+=("$HOSTNAME")  # Primary hostname
        
        if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
            print_message "Creating additional hostnames for multiple IPs:"
            for ((i=2; i<=${#IP_ADDRESSES[@]}; i++)); do
                local suffix=$(printf "%03d" $((i-1)))
                local multi_hostname="${SUBDOMAIN}${suffix}.${DOMAIN_NAME}"
                HOSTNAMES+=("$multi_hostname")
                print_message "  IP #$i: $multi_hostname"
            done
        fi
        
        export HOSTNAMES
        export SUBDOMAIN
        
        read -p "Enter admin email address: " ADMIN_EMAIL
        validate_email "$ADMIN_EMAIL" || exit 1
        
        # Using domain as brand name automatically
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
        
        # Cloudflare integration
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
        echo "Mail Subdomain: $SUBDOMAIN"
        echo "Primary Hostname: $HOSTNAME"
        
        if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
            echo "Additional Hostnames:"
            for ((i=1; i<${#HOSTNAMES[@]}; i++)); do
                echo "  - ${HOSTNAMES[$i]}"
            done
        fi
        
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
        
        save_progress "configuration_complete"
    fi
    
    # Start installation with progress tracking
    print_message "Starting multi-IP mail server installation..."
    
    # Install packages
    if [[ "$LAST_COMPLETED_STEP" != "packages_installed" ]] && \
       [[ "$LAST_COMPLETED_STEP" != "mysql_configured" ]] && \
       [[ "$LAST_COMPLETED_STEP" != "postfix_configured" ]]; then
        install_required_packages
        save_progress "packages_installed"
    fi
    
    # Configure hostname
    configure_hostname "$HOSTNAME"
    
    # Configure network interfaces for multiple IPs
    if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
        configure_network_interfaces
    fi
    save_progress "network_configured"
    
    # Setup MySQL with proper wait
    if [[ "$LAST_COMPLETED_STEP" != "mysql_configured" ]] && \
       [[ "$LAST_COMPLETED_STEP" != "postfix_configured" ]]; then
        setup_mysql
        wait_for_mysql || {
            print_error "MySQL setup failed"
            exit 1
        }
        save_progress "mysql_configured"
    fi
    
    # Add domain and user to MySQL
    add_domain_to_mysql "$DOMAIN_NAME"
    add_email_user "${MAIL_USERNAME}@${DOMAIN_NAME}" "${MAIL_PASSWORD}"
    
    # Setup Sticky IP if enabled
    if [[ "$ENABLE_STICKY_IP" == "y" ]]; then
        if type setup_sticky_ip_db &>/dev/null 2>&1; then
            setup_sticky_ip_db
            save_progress "sticky_ip_db_configured"
        else
            print_warning "Sticky IP module not loaded properly. Disabling sticky IP."
            ENABLE_STICKY_IP="n"
        fi
    fi
    
    # Setup Dovecot (needs MySQL)
    setup_dovecot "$DOMAIN_NAME" "$HOSTNAME"
    save_progress "dovecot_configured"
    
    # Setup Postfix (needs MySQL) - with warning suppression
    print_message "Configuring Postfix multi-IP setup..."
    setup_postfix_multi_ip "$DOMAIN_NAME" "$HOSTNAME" 2>&1 | grep -v "warning.*duplicate.*mysql" | grep -v "ignoring duplicate entry"
    save_progress "postfix_configured"
    
    # Configure IP rotation
    create_ip_rotation_config
    
    # Configure Sticky IP Postfix settings if enabled
    if [[ "$ENABLE_STICKY_IP" == "y" ]]; then
        if type configure_sticky_ip_postfix &>/dev/null 2>&1; then
            configure_sticky_ip_postfix
            save_progress "sticky_ip_postfix_configured"
        fi
    fi
    
    # Setup DKIM (must be done before DNS configuration)
    setup_opendkim "$DOMAIN_NAME"
    save_progress "dkim_configured"
    
    # Setup SPF with hostname for HELO fix
    setup_spf "$DOMAIN_NAME" "$HOSTNAME"
    
    # Setup DMARC
    setup_dmarc "$DOMAIN_NAME"
    save_progress "email_auth_configured"
    
    # Wait for DKIM keys to be ready
    sleep 2
    
    # Setup web and SSL
    setup_nginx "$DOMAIN_NAME" "$HOSTNAME"
    save_progress "nginx_configured"
    
    # Setup DNS records (now DKIM keys are ready)
    if [ ! -z "$CF_API_TOKEN" ] && [ ! -z "$CF_ZONE_ID" ]; then
        create_multi_ip_dns_records "$DOMAIN_NAME" "$HOSTNAME"
        save_progress "dns_configured"
    else
        print_message "Skipping automatic DNS configuration (no Cloudflare credentials provided)"
        create_manual_dns_instructions "$DOMAIN_NAME" "$HOSTNAME"
    fi
    
    # Get SSL certificates
    get_ssl_certificates "$DOMAIN_NAME" "$HOSTNAME" "$ADMIN_EMAIL"
    save_progress "ssl_configured"
    
    # Setup website with color scheme selection
    setup_website "$DOMAIN_NAME" "$ADMIN_EMAIL" "$BRAND_NAME"
    save_progress "website_configured"
    
    # Create management scripts
    create_utility_scripts "$DOMAIN_NAME"
    create_ip_warmup_scripts
    create_monitoring_scripts
    create_mailwizz_multi_ip_guide "$DOMAIN_NAME"
    
    # Create Sticky IP utilities if enabled
    if [[ "$ENABLE_STICKY_IP" == "y" ]]; then
        if type create_sticky_ip_utility &>/dev/null 2>&1; then
            create_sticky_ip_utility
            create_mailwizz_sticky_ip_integration
            save_progress "sticky_ip_utilities_created"
        fi
    fi
    
    # Create PTR instructions
    create_ptr_instructions
    save_progress "documentation_created"
    
    # Apply hardening
    harden_server "$DOMAIN_NAME" "$HOSTNAME"
    save_progress "hardening_applied"
    
    # Setup email aliases with warning suppression
    setup_email_aliases 2>&1 | grep -v "warning.*duplicate.*mysql" | grep -v "ignoring duplicate entry"
    
    # Restart services in the correct order
    restart_services_ordered
    save_progress "services_restarted"
    
    # Save configuration
    save_configuration
    
    # Create final documentation
    create_final_documentation
    
    # Run post-installation checks
    run_post_installation_checks
    
    # Mark installation as complete
    save_progress "installation_complete"
    
    # Clean up progress file
    rm -f /root/.installer_progress
    
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

# Create manual DNS instructions with new hostname format
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
    
    # Use the HOSTNAMES array if available
    if [ ! -z "${HOSTNAMES}" ]; then
        for ((i=0; i<${#IP_ADDRESSES[@]}; i++)); do
            local ip="${IP_ADDRESSES[$i]}"
            if [ $i -eq 0 ]; then
                # Primary IP gets both @ and subdomain
                echo "   Type: A, Name: @, Value: $ip" >> /root/manual-dns-setup.txt
                echo "   Type: A, Name: $SUBDOMAIN, Value: $ip" >> /root/manual-dns-setup.txt
            else
                # Additional IPs get numbered subdomains
                local suffix=$(printf "%03d" $i)
                echo "   Type: A, Name: ${SUBDOMAIN}${suffix}, Value: $ip" >> /root/manual-dns-setup.txt
            fi
        done
    else
        # Fallback to old method if HOSTNAMES not set
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
    fi
    
    cat >> /root/manual-dns-setup.txt <<EOF

2. MX RECORD:
-------------
   Type: MX, Name: @, Priority: 10, Value: $hostname

3. SPF RECORDS:
---------------
   a) Main SPF Record:
      Type: TXT, Name: @
      Value: See /root/spf-record-${domain}.txt
   
   b) Hostname SPF Records (fixes SPF_HELO_NONE):
EOF
    
    # Add SPF records for all hostnames
    if [ ! -z "${HOSTNAMES}" ]; then
        for host in "${HOSTNAMES[@]}"; do
            echo "      Type: TXT, Name: ${host}" >> /root/manual-dns-setup.txt
            echo "      Value: v=spf1 a -all" >> /root/manual-dns-setup.txt
            echo "" >> /root/manual-dns-setup.txt
        done
    else
        echo "      Type: TXT, Name: ${hostname}" >> /root/manual-dns-setup.txt
        echo "      Value: v=spf1 a -all" >> /root/manual-dns-setup.txt
    fi
    
    cat >> /root/manual-dns-setup.txt <<EOF

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
EOF
    
    # Add dig commands for all hostnames
    if [ ! -z "${HOSTNAMES}" ]; then
        for host in "${HOSTNAMES[@]}"; do
            echo "   dig TXT $host" >> /root/manual-dns-setup.txt
        done
    else
        echo "   dig TXT $hostname" >> /root/manual-dns-setup.txt
    fi
    
    echo "   dig TXT mail._domainkey.$domain" >> /root/manual-dns-setup.txt
    echo "   dig TXT _dmarc.$domain" >> /root/manual-dns-setup.txt
    echo "" >> /root/manual-dns-setup.txt
    echo "==========================================================" >> /root/manual-dns-setup.txt
    
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
        
        # Start the service with warning suppression
        if systemctl start $service 2>&1 | grep -v "warning.*duplicate.*mysql" | grep -v "ignoring duplicate entry"; then
            print_message "✓ $service started successfully"
            
            # Enable service to start on boot
            systemctl enable $service 2>/dev/null || true
            
            # Special wait for MySQL to be fully ready
            if [ "$service" = "mysql" ]; then
                wait_for_mysql
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
    
    # Check if Postfix configuration is valid with warning suppression
    print_message "Checking Postfix configuration..."
    if postfix check 2>&1 | grep -v "warning.*duplicate.*mysql" | grep -v "ignoring duplicate entry"; then
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
    
    # Check IP configuration
    print_message "Checking IP configuration..."
    local configured_ips=0
    for ip in "${IP_ADDRESSES[@]}"; do
        if ip addr show | grep -q "$ip"; then
            configured_ips=$((configured_ips + 1))
        fi
    done
    print_message "  IPs configured: $configured_ips/${#IP_ADDRESSES[@]}"
    
    # Summary
    echo ""
    if [ "$all_good" = true ]; then
        print_message "✓ All post-installation checks passed!"
    else
        print_warning "⚠ Some checks failed. Please review the errors above."
        print_message "You may need to manually fix these issues."
    fi
}

# Export the main functions
export -f first_time_installation_multi_ip
export -f create_manual_dns_instructions
export -f restart_services_ordered
export -f run_post_installation_checks
export -f wait_for_mysql
export -f save_progress
export -f check_previous_installation
export -f preflight_check
