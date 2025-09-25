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

# Export functions to make them available in other scripts
export -f fix_mysql_config restart_all_services setup_email_aliases
