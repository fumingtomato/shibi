#!/bin/bash

# =================================================================
# MAIN INSTALLER MODULE - PART 2
# Supporting functions and utilities with proper permissions
# =================================================================

# Fix Postfix MySQL configuration issues
fix_mysql_config() {
    print_message "Fixing MySQL configuration issues..."
    
    # Check if directory exists
    if [ ! -d /etc/postfix/dynamicmaps.cf.d ]; then
        mkdir -p /etc/postfix/dynamicmaps.cf.d
    fi
    
    # Remove all existing mysql entries to prevent duplicates
    if [ -f /etc/postfix/dynamicmaps.cf.d/mysql ]; then
        rm -f /etc/postfix/dynamicmaps.cf.d/mysql
    fi
    
    # Create a clean mysql configuration file
    cat > /etc/postfix/dynamicmaps.cf.d/mysql <<EOF
mysql   postfix-mysql.so.1.0.1   dict_mysql_open
EOF
    
    # Fix permissions for all critical files
    if [ -f /etc/postfix/dynamicmaps.cf ]; then
        chown root:root /etc/postfix/dynamicmaps.cf
        chmod 644 /etc/postfix/dynamicmaps.cf
    fi
    
    chown root:root /etc/postfix/dynamicmaps.cf.d/mysql
    chmod 644 /etc/postfix/dynamicmaps.cf.d/mysql
    
    print_message "MySQL configuration fixed"
}

# Setup email aliases
setup_email_aliases() {
    print_message "Setting up email aliases for postmaster..."
    
    # First, remove any existing postmaster entries to avoid duplicates
    if [ -f /etc/aliases ]; then
        sed -i '/^postmaster:/d' /etc/aliases
    fi
    
    # Ensure root alias exists
    if ! grep -q "^root:" /etc/aliases; then
        echo "root: $ADMIN_EMAIL" >> /etc/aliases
    fi
    
    # Add required aliases
    cat >> /etc/aliases <<EOF
postmaster: root
abuse: root
webmaster: root
hostmaster: root
mailer-daemon: root
EOF
    
    # Fix permissions and ownership of critical files
    fix_mysql_config
    
    # Apply aliases
    newaliases
    print_message "Email aliases configured"
}

# Restart all services
restart_all_services() {
    print_message "Restarting all services..."
    
    # Fix configuration before restarting services
    fix_mysql_config
    
    local services=("mysql" "opendkim" "postfix" "dovecot" "nginx")
    
    for service in "${services[@]}"; do
        print_message "Restarting $service..."
        systemctl restart $service || print_error "Failed to restart $service"
        systemctl enable $service
    done
}

# Main menu function
main_menu() {
    print_header "$INSTALLER_NAME v$INSTALLER_VERSION"
    print_message "Optimized for commercial bulk mailing with multiple IP addresses"
    print_message "Current Date and Time (UTC): $(date -u '+%Y-%m-%d %H:%M:%S')"
    print_message "Current User: $(whoami)"
    echo
    
    echo "Please select an option:"
    echo "1) Install Multi-IP Bulk Mail Server with MailWizz optimization"
    echo "2) Add additional IP to existing installation"
    echo "3) View current IP configuration"
    echo "4) Run diagnostics"
    echo "5) Update installer"
    echo "6) Exit"
    echo
    
    read -p "Enter your choice [1-6]: " choice
    
    case $choice in
        1)
            first_time_installation_multi_ip
            ;;
        2)
            print_message "Add additional IP feature not implemented yet."
            ;;
        3)
            print_message "View IP configuration feature not implemented yet."
            ;;
        4)
            print_message "Diagnostics feature not implemented yet."
            ;;
        5)
            print_message "Update installer feature not implemented yet."
            ;;
        6)
            print_message "Exiting installer. No changes were made."
            exit 0
            ;;
        *)
            print_error "Invalid option. Exiting."
            exit 1
            ;;
    esac
}

# Export functions to make them available in other scripts
export -f fix_mysql_config restart_all_services setup_email_aliases main_menu
