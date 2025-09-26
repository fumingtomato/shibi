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
    
    # Complete cleanup of all MySQL-related configurations
    print_message "Performing complete MySQL configuration cleanup..."
    
    # 1. Remove ALL mysql entries from dynamicmaps files
    if [ -f /etc/postfix/dynamicmaps.cf ]; then
        # Create a clean version without any mysql entries
        grep -v "mysql" /etc/postfix/dynamicmaps.cf > /tmp/dynamicmaps.cf.clean 2>/dev/null || true
        mv /tmp/dynamicmaps.cf.clean /etc/postfix/dynamicmaps.cf
    fi
    
    # 2. Remove ALL files from dynamicmaps.cf.d that contain mysql
    if [ -d /etc/postfix/dynamicmaps.cf.d ]; then
        find /etc/postfix/dynamicmaps.cf.d -type f -name "*mysql*" -delete 2>/dev/null || true
        # Also check file contents for mysql references
        for file in /etc/postfix/dynamicmaps.cf.d/*; do
            if [ -f "$file" ] && grep -q "mysql" "$file" 2>/dev/null; then
                rm -f "$file"
            fi
        done
    else
        mkdir -p /etc/postfix/dynamicmaps.cf.d
    fi
    
    # 3. Clear ALL Postfix cache databases
    rm -f /var/lib/postfix/dynamicmaps.cf.db 2>/dev/null
    rm -f /var/spool/postfix/etc/dynamicmaps.cf.db 2>/dev/null
    rm -f /etc/postfix/dynamicmaps.cf.db 2>/dev/null
    
    # 4. Clean postfix chroot environment
    if [ -d /var/spool/postfix/etc/postfix ]; then
        rm -f /var/spool/postfix/etc/postfix/dynamicmaps.cf* 2>/dev/null
        rm -rf /var/spool/postfix/etc/postfix/dynamicmaps.cf.d 2>/dev/null
    fi
    
    # 5. Find the correct MySQL library path
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
        mysql_lib="postfix-mysql.so.1.0.1"
        print_warning "Could not find MySQL library, using default: $mysql_lib"
    fi
    
    # 6. Create a single, authoritative mysql configuration file
    cat > /etc/postfix/dynamicmaps.cf.d/mysql <<EOF
mysql	${mysql_lib}	dict_mysql_open
EOF
    
    # 7. Set proper permissions
    chown root:root /etc/postfix/dynamicmaps.cf.d/mysql
    chmod 644 /etc/postfix/dynamicmaps.cf.d/mysql
    
    if [ -f /etc/postfix/dynamicmaps.cf ]; then
        chown root:root /etc/postfix/dynamicmaps.cf
        chmod 644 /etc/postfix/dynamicmaps.cf
    fi
    
    # 8. Update postfix to recognize the change
    postconf -e "readme_directory = /usr/share/doc/postfix" 2>/dev/null || true
    
    print_message "MySQL configuration cleanup completed"
}

# Wrapper function to suppress duplicate warnings in command output
suppress_mysql_warnings() {
    "$@" 2>&1 | grep -v "warning.*duplicate.*mysql" | grep -v "dynamicmaps.*duplicate" || true
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
    
    # Create a temporary clean aliases file
    local temp_aliases=$(mktemp)
    
    # Copy all non-system aliases to temp file
    grep -v "^postmaster:" /etc/aliases | \
    grep -v "^abuse:" | \
    grep -v "^webmaster:" | \
    grep -v "^hostmaster:" | \
    grep -v "^mailer-daemon:" | \
    grep -v "^nobody:" | \
    grep -v "^root:" > "$temp_aliases" 2>/dev/null || true
    
    # Add root alias if admin email is set
    if [ ! -z "$ADMIN_EMAIL" ]; then
        echo "root: $ADMIN_EMAIL" >> "$temp_aliases"
    fi
    
    # Add required system aliases
    cat >> "$temp_aliases" <<EOF
postmaster: root
abuse: root
webmaster: root
hostmaster: root
mailer-daemon: root
nobody: root
EOF
    
    # Move the clean file back
    mv "$temp_aliases" /etc/aliases
    
    # Apply aliases with warning suppression
    suppress_mysql_warnings newaliases
    
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
        
        # Stop the service
        systemctl stop $service 2>/dev/null || true
        sleep 1
        
        # Start the service with warning suppression
        if suppress_mysql_warnings systemctl start $service; then
            print_message "✓ $service started successfully"
            systemctl enable $service 2>/dev/null
        else
            print_error "Failed to restart $service"
        fi
    done
}

# Initialize MySQL configuration early in the installation
init_mysql_postfix_config() {
    print_message "Initializing MySQL-Postfix configuration..."
    
    # Ensure clean state from the beginning
    fix_mysql_config
    
    # Pre-create necessary directories
    mkdir -p /etc/postfix/dynamicmaps.cf.d
    mkdir -p /var/spool/postfix/etc/postfix
    
    # Ensure postfix user can read MySQL configs
    if id "postfix" &>/dev/null; then
        usermod -a -G postfix postfix 2>/dev/null || true
    fi
}

# Postfix check wrapper
postfix_check_clean() {
    suppress_mysql_warnings postfix check
}

# Postmap wrapper
postmap_clean() {
    suppress_mysql_warnings postmap "$@"
}

# Main menu function - THIS IS THE CRITICAL FUNCTION
main_menu() {
    print_header "$INSTALLER_NAME v$INSTALLER_VERSION"
    print_message "Optimized for commercial bulk mailing with multiple IP addresses"
    print_message "Current Date and Time (UTC): $(date -u '+%Y-%m-%d %H:%M:%S')"
    print_message "Current User: $(whoami)"
    echo
    
    # Initialize MySQL config early to prevent warnings
    init_mysql_postfix_config
    
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
            # Check if first_time_installation_multi_ip function exists
            if type first_time_installation_multi_ip &>/dev/null; then
                first_time_installation_multi_ip
            else
                print_error "Installation function not found. Please check module loading."
                exit 1
            fi
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

# Clean Postfix output wrapper
clean_postfix_output() {
    # This function filters out the duplicate mysql warnings from command output
    grep -v "warning.*dynamicmaps.cf.d/mysql.*duplicate" | grep -v "ignoring duplicate entry for \"mysql\""
}

# Export ALL functions to make them available in other scripts
export -f fix_mysql_config
export -f suppress_mysql_warnings
export -f setup_email_aliases
export -f restart_all_services
export -f init_mysql_postfix_config
export -f postfix_check_clean
export -f postmap_clean
export -f main_menu
export -f clean_postfix_output
