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
    
    read -p "Enter your brand or company name: " BRAND_NAME
    read -p "Enter the username for the first mail account: " MAIL_USERNAME
    read -s -p "Enter password for mail account: " MAIL_PASSWORD
    echo
    read -s -p "Confirm password: " MAIL_PASSWORD_CONFIRM
    echo
    
    if [ -z "$BRAND_NAME" ]; then
        BRAND_NAME="$DOMAIN_NAME"
        print_message "Using domain name as brand name: $BRAND_NAME"
    fi
    
    if [ "$MAIL_PASSWORD" != "$MAIL_PASSWORD_CONFIRM" ]; then
        print_error "Passwords do not match. Please try again."
        exit 1
    fi
    
    # Setup timezone
    setup_timezone
    
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
    echo "Primary Hostname: $HOSTNAME"
    echo "Admin Email: $ADMIN_EMAIL"
    echo "Mail Username: $MAIL_USERNAME@$DOMAIN_NAME"
    echo "Number of IPs: ${#IP_ADDRESSES[@]}"
    echo "IP Addresses:"
    for ip in "${IP_ADDRESSES[@]}"; do
        echo "  - $ip"
    done
    echo "Timezone: $timezone"
    
    read -p "Is this information correct? (y/n): " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        print_error "Installation cancelled. Please run the script again."
        exit 1
    fi
    
    # Export variables for other modules
    export DOMAIN_NAME HOSTNAME ADMIN_EMAIL BRAND_NAME
    export MAIL_USERNAME MAIL_PASSWORD
    export CF_API_TOKEN CF_ZONE_ID
    
    # Start installation
    print_message "Starting multi-IP mail server installation..."
    
    # Install packages
    install_required_packages
    
    # Configure hostname
    configure_hostname
    
    # Configure network interfaces for multiple IPs
    if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
        configure_network_interfaces
    fi
    
    # Setup components
    setup_mysql_database
    add_domain_and_user "$DOMAIN_NAME" "$MAIL_USERNAME" "$MAIL_PASSWORD" "$PRIMARY_IP"
    setup_postfix_multi_ip "$DOMAIN_NAME" "$HOSTNAME"
    create_ip_rotation_config
    setup_dovecot "$DOMAIN_NAME" "$HOSTNAME"
    setup_opendkim "$DOMAIN_NAME"
    
    # Setup web and SSL
    setup_nginx "$DOMAIN_NAME" "$HOSTNAME"
    
    if [ ! -z "$CF_API_TOKEN" ]; then
        create_multi_ip_dns_records "$DOMAIN_NAME" "$HOSTNAME"
    fi
    
    get_ssl_certificates "$DOMAIN_NAME" "$HOSTNAME" "$ADMIN_EMAIL"
    setup_website "$DOMAIN_NAME" "$ADMIN_EMAIL" "$BRAND_NAME"
    
    # Create management scripts
    create_utility_scripts "$DOMAIN_NAME"
    create_ip_warmup_scripts
    create_monitoring_scripts
    create_mailwizz_multi_ip_guide "$DOMAIN_NAME"
    create_ptr_instructions
    
    # Apply hardening
    harden_server "$DOMAIN_NAME" "$HOSTNAME"
    
    # Setup email aliases
    setup_email_aliases
    
    # Restart services
    restart_all_services
    
    # Save configuration
    save_configuration
    
    # Create final documentation
    create_final_documentation
    
    print_header "Installation Complete!"
    print_message "Your Multi-IP Bulk Mail Server has been successfully installed!"
    print_message ""
    print_message "Configured with ${#IP_ADDRESSES[@]} IP address(es) for load balancing and rotation."
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
}
