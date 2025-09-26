#!/bin/bash

# =================================================================
# MAIN INSTALLER MODULE - PART 2
# Supporting functions and utilities with proper permissions
# =================================================================

# Fix Postfix MySQL configuration issues with complete cleanup
fix_mysql_config() {
    print_message "Fixing MySQL configuration issues..."
    
    # Stop postfix temporarily to ensure clean configuration
    systemctl stop postfix 2>/dev/null || true
    
    # Check if directory exists
    if [ ! -d /etc/postfix/dynamicmaps.cf.d ]; then
        mkdir -p /etc/postfix/dynamicmaps.cf.d
    fi
    
    # Remove ALL existing mysql-related entries to prevent any duplicates
    rm -f /etc/postfix/dynamicmaps.cf.d/mysql* 2>/dev/null
    rm -f /etc/postfix/dynamicmaps.cf.d/*mysql* 2>/dev/null
    
    # Clean up any duplicate entries from the main dynamicmaps.cf file
    if [ -f /etc/postfix/dynamicmaps.cf ]; then
        # Remove any lines containing mysql to start fresh
        grep -v "mysql" /etc/postfix/dynamicmaps.cf > /tmp/dynamicmaps.cf.tmp 2>/dev/null || true
        if [ -s /tmp/dynamicmaps.cf.tmp ]; then
            mv /tmp/dynamicmaps.cf.tmp /etc/postfix/dynamicmaps.cf
        fi
    fi
    
    # Find the correct MySQL library path
    local mysql_lib=""
    local possible_paths=(
        "/usr/lib/postfix/postfix-mysql.so"
        "/usr/lib/postfix/dict_mysql.so"
        "/usr/lib/x86_64-linux-gnu/postfix/dict_mysql.so"
        "/usr/lib/postfix/postfix-mysql.so.1.0.1"
    )
    
    for path in "${possible_paths[@]}"; do
        if [ -f "$path" ]; then
            mysql_lib="$path"
            print_message "Found MySQL library at: $mysql_lib"
            break
        fi
    done
    
    if [ -z "$mysql_lib" ]; then
        # Use the most common default
        mysql_lib="postfix-mysql.so.1.0.1"
        print_warning "Could not find MySQL library, using default: $mysql_lib"
    fi
    
    # Create a single, clean mysql configuration file
    cat > /etc/postfix/dynamicmaps.cf.d/mysql <<EOF
mysql	${mysql_lib}	dict_mysql_open
EOF
    
    # Fix permissions for all critical files
    if [ -f /etc/postfix/dynamicmaps.cf ]; then
        chown root:root /etc/postfix/dynamicmaps.cf
        chmod 644 /etc/postfix/dynamicmaps.cf
    fi
    
    chown root:root /etc/postfix/dynamicmaps.cf.d/mysql
    chmod 644 /etc/postfix/dynamicmaps.cf.d/mysql
    
    # Regenerate the main dynamicmaps.cf file to ensure consistency
    if command -v postconf >/dev/null 2>&1; then
        # Force regeneration of dynamic maps
        postconf -e "mysql = yes" 2>/dev/null || true
    fi
    
    # Clear Postfix's internal cache
    rm -f /var/lib/postfix/dynamicmaps.cf.db 2>/dev/null
    rm -f /var/spool/postfix/etc/dynamicmaps.cf.db 2>/dev/null
    
    print_message "MySQL configuration fixed"
}

# Setup email aliases with improved duplicate handling
setup_email_aliases() {
    print_message "Setting up email aliases for postmaster..."
    
    # First, ensure MySQL config is completely clean
    fix_mysql_config
    
    # Create a clean aliases file if it doesn't exist
    if [ ! -f /etc/aliases ]; then
        touch /etc/aliases
    fi
    
    # Remove any existing postmaster, abuse, webmaster, hostmaster entries to avoid duplicates
    local temp_aliases=$(mktemp)
    grep -v "^postmaster:" /etc/aliases | \
    grep -v "^abuse:" | \
    grep -v "^webmaster:" | \
    grep -v "^hostmaster:" | \
    grep -v "^mailer-daemon:" > "$temp_aliases" 2>/dev/null || true
    
    # Move cleaned file back
    if [ -s "$temp_aliases" ]; then
        mv "$temp_aliases" /etc/aliases
    else
        # If file is empty, start fresh
        echo "" > /etc/aliases
    fi
    
    # Ensure root alias exists
    if ! grep -q "^root:" /etc/aliases; then
        echo "root: $ADMIN_EMAIL" >> /etc/aliases
    fi
    
    # Add required aliases (only once, they're already removed above)
    cat >> /etc/aliases <<EOF
postmaster: root
abuse: root
webmaster: root
hostmaster: root
mailer-daemon: root
EOF
    
    # Apply aliases with clean MySQL config
    newaliases 2>&1 | grep -v "warning.*duplicate" || true
    
    print_message "Email aliases configured"
}

# Restart all services with proper MySQL cleanup
restart_all_services() {
    print_message "Restarting all services..."
    
    # Fix configuration before restarting services
    fix_mysql_config
    
    local services=("mysql" "opendkim" "postfix" "dovecot" "nginx")
    
    for service in "${services[@]}"; do
        print_message "Restarting $service..."
        systemctl restart $service 2>&1 | grep -v "warning.*duplicate" || print_error "Failed to restart $service"
        systemctl enable $service
    done
}

# Clean Postfix warnings from output
clean_postfix_output() {
    # This function filters out the duplicate mysql warnings from command output
    grep -v "warning.*dynamicmaps.cf.d/mysql.*duplicate" | grep -v "ignoring duplicate entry for \"mysql\""
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
export -f fix_mysql_config restart_all_services setup_email_aliases main_menu clean_postfix_output
