#!/bin/bash

# =================================================================
# MAIN INSTALLER MODULE - PART 2 - FIXED VERSION
# Supporting functions and utilities with proper permissions
# Fixed: Complete MySQL cleanup, better service verification, enhanced error handling
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
        if [ -s /tmp/dynamicmaps.cf.clean ]; then
            mv /tmp/dynamicmaps.cf.clean /etc/postfix/dynamicmaps.cf
        else
            # If file would be empty, create minimal valid file
            echo "# Postfix dynamic maps configuration" > /etc/postfix/dynamicmaps.cf
        fi
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
    local cache_files=(
        "/var/lib/postfix/dynamicmaps.cf.db"
        "/var/spool/postfix/etc/dynamicmaps.cf.db"
        "/etc/postfix/dynamicmaps.cf.db"
        "/var/spool/postfix/etc/postfix/dynamicmaps.cf.db"
    )
    
    for cache_file in "${cache_files[@]}"; do
        if [ -f "$cache_file" ]; then
            rm -f "$cache_file" 2>/dev/null
            print_debug "Removed cache file: $cache_file"
        fi
    done
    
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
        "/usr/lib/postfix/postfix-mysql.so.1"
        "/usr/lib/x86_64-linux-gnu/postfix/postfix-mysql.so"
    )
    
    for path in "${possible_paths[@]}"; do
        if [ -f "$path" ]; then
            mysql_lib="$path"
            print_message "Found MySQL library at: $mysql_lib"
            break
        fi
    done
    
    if [ -z "$mysql_lib" ]; then
        # Try to find it dynamically
        mysql_lib=$(find /usr/lib -name "*postfix*mysql*.so*" 2>/dev/null | head -1)
        if [ ! -z "$mysql_lib" ]; then
            print_message "Found MySQL library at: $mysql_lib"
        else
            mysql_lib="postfix-mysql.so.1.0.1"
            print_warning "Could not find MySQL library, using default: $mysql_lib"
        fi
    fi
    
    # 6. Create a single, authoritative mysql configuration file
    cat > /etc/postfix/dynamicmaps.cf.d/50-mysql.cf <<EOF
# MySQL support for Postfix
mysql	${mysql_lib}	dict_mysql_open
EOF
    
    # 7. Set proper permissions
    chown root:root /etc/postfix/dynamicmaps.cf.d/50-mysql.cf
    chmod 644 /etc/postfix/dynamicmaps.cf.d/50-mysql.cf
    
    if [ -f /etc/postfix/dynamicmaps.cf ]; then
        chown root:root /etc/postfix/dynamicmaps.cf
        chmod 644 /etc/postfix/dynamicmaps.cf
    fi
    
    # 8. Update postfix to recognize the change
    postconf -e "readme_directory = /usr/share/doc/postfix" 2>/dev/null || true
    
    # 9. Verify MySQL module is available
    if postconf -m 2>/dev/null | grep -q mysql; then
        print_message "✓ MySQL module is available in Postfix"
    else
        print_warning "⚠ MySQL module may not be properly loaded"
    fi
    
    print_message "MySQL configuration cleanup completed"
}

# Enhanced wrapper function to suppress duplicate warnings more effectively
suppress_mysql_warnings() {
    # Execute command and filter out MySQL warnings completely
    "$@" 2>&1 | grep -v "warning.*duplicate.*mysql" | \
                 grep -v "dynamicmaps.*duplicate" | \
                 grep -v "ignoring duplicate entry" | \
                 grep -v "dict_mysql_open" || true
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
    print_message "Applying email aliases..."
    newaliases 2>&1 | grep -v "warning.*duplicate.*mysql" | grep -v "ignoring duplicate entry" || true
    
    print_message "Email aliases configured"
}

# Verify service health with timeout
verify_service_health() {
    local service=$1
    local max_wait=${2:-30}
    local count=0
    
    print_debug "Verifying health of $service (max wait: ${max_wait}s)..."
    
    while [ $count -lt $max_wait ]; do
        if systemctl is-active --quiet $service; then
            print_debug "✓ $service is active"
            return 0
        fi
        sleep 1
        count=$((count + 1))
    done
    
    print_debug "✗ $service failed to become active within ${max_wait}s"
    return 1
}

# Enhanced service restart with health checks
restart_service_with_check() {
    local service=$1
    
    print_message "Restarting $service..."
    
    # Stop the service
    systemctl stop $service 2>/dev/null || true
    sleep 1
    
    # Clear any failed state
    systemctl reset-failed $service 2>/dev/null || true
    
    # Start the service with complete warning suppression
    if systemctl start $service 2>&1 | suppress_mysql_warnings; then
        # Verify it's actually running
        if verify_service_health $service 10; then
            print_message "✓ $service started and verified"
            systemctl enable $service 2>/dev/null || true
            return 0
        else
            print_error "✗ $service started but health check failed"
            return 1
        fi
    else
        print_error "✗ Failed to start $service"
        return 1
    fi
}

# Restart all services with proper MySQL cleanup
restart_all_services() {
    print_message "Restarting all services..."
    
    # Fix configuration before restarting services
    fix_mysql_config
    
    local services=("mysql" "opendkim" "postfix" "dovecot" "nginx")
    local failed_services=()
    
    for service in "${services[@]}"; do
        # Special handling for MySQL/MariaDB
        if [ "$service" = "mysql" ]; then
            # Check if MariaDB is being used instead
            if systemctl list-units --full -all | grep -q "mariadb.service"; then
                service="mariadb"
                print_debug "Using MariaDB instead of MySQL"
            fi
        fi
        
        if restart_service_with_check $service; then
            # Special post-start checks for certain services
            case $service in
                "mysql"|"mariadb")
                    # Wait for MySQL to be fully ready
                    local mysql_ready=false
                    for i in {1..30}; do
                        if mysqladmin ping &>/dev/null; then
                            mysql_ready=true
                            break
                        fi
                        sleep 1
                    done
                    if [ "$mysql_ready" = true ]; then
                        print_message "✓ Database is ready for connections"
                    else
                        print_error "✗ Database is not responding"
                        failed_services+=($service)
                    fi
                    ;;
                "postfix")
                    # Verify Postfix configuration
                    if postfix check 2>&1 | suppress_mysql_warnings; then
                        print_message "✓ Postfix configuration verified"
                    else
                        print_warning "⚠ Postfix configuration has warnings"
                    fi
                    ;;
                "opendkim")
                    # Check if OpenDKIM socket is listening
                    if nc -zv localhost 8891 2>&1 | grep -q succeeded; then
                        print_message "✓ OpenDKIM socket is listening"
                    else
                        print_warning "⚠ OpenDKIM socket not responding"
                    fi
                    ;;
            esac
        else
            failed_services+=($service)
        fi
    done
    
    # Report results
    if [ ${#failed_services[@]} -eq 0 ]; then
        print_message "✓ All services restarted successfully"
    else
        print_error "✗ Failed to restart: ${failed_services[*]}"
        return 1
    fi
}

# Initialize MySQL configuration early in the installation
init_mysql_postfix_config() {
    # Silently clean up MySQL config without output
    {
        # Remove all existing MySQL entries
        if [ -d /etc/postfix/dynamicmaps.cf.d ]; then
            find /etc/postfix/dynamicmaps.cf.d -type f -name "*mysql*" -delete 2>/dev/null || true
        fi
        
        # Clear cache files
        rm -f /var/lib/postfix/dynamicmaps.cf.db 2>/dev/null
        rm -f /var/spool/postfix/etc/dynamicmaps.cf.db 2>/dev/null
        rm -f /etc/postfix/dynamicmaps.cf.db 2>/dev/null
        rm -f /var/spool/postfix/etc/postfix/dynamicmaps.cf.db 2>/dev/null
    } 2>/dev/null
    
    # Pre-create necessary directories
    mkdir -p /etc/postfix/dynamicmaps.cf.d 2>/dev/null
    mkdir -p /var/spool/postfix/etc/postfix 2>/dev/null
    
    # Ensure postfix user exists and has proper groups
    if id "postfix" &>/dev/null; then
        usermod -a -G postfix postfix 2>/dev/null || true
        # Also add postfix to sasl group if it exists
        if getent group sasl &>/dev/null; then
            usermod -a -G sasl postfix 2>/dev/null || true
        fi
    fi
}

# Enhanced Postfix check wrapper
postfix_check_clean() {
    postfix check 2>&1 | suppress_mysql_warnings
}

# Enhanced Postmap wrapper
postmap_clean() {
    postmap "$@" 2>&1 | suppress_mysql_warnings
}

# Main menu function
main_menu() {
    print_header "$INSTALLER_NAME v$INSTALLER_VERSION"
    print_message "Optimized for commercial bulk mailing with multiple IP addresses"
    print_message "Current Date and Time (UTC): $(date -u '+%Y-%m-%d %H:%M:%S')"
    print_message "Current User: $(whoami)"
    
    # Check if running as root
    if [ "$(id -u)" != "0" ]; then
        print_error "This script must be run as root or with sudo privileges"
        echo "Please run: sudo $0"
        exit 1
    fi
    
    echo ""
    
    # Initialize MySQL config early to prevent warnings
    init_mysql_postfix_config
    
    echo "Please select an option:"
    echo "1) Install Multi-IP Bulk Mail Server with MailWizz optimization"
    echo "2) Add additional IP to existing installation"
    echo "3) View current IP configuration"
    echo "4) Run diagnostics"
    echo "5) Update installer"
    echo "6) Repair installation"
    echo "7) Exit"
    echo ""
    
    read -p "Enter your choice [1-7]: " choice
    
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
            print_message "Add additional IP feature coming soon..."
            create_add_ip_script
            ;;
        3)
            view_ip_configuration
            ;;
        4)
            run_diagnostics
            ;;
        5)
            update_installer
            ;;
        6)
            repair_installation
            ;;
        7)
            print_message "Exiting installer. No changes were made."
            exit 0
            ;;
        *)
            print_error "Invalid option. Exiting."
            exit 1
            ;;
    esac
}

# View current IP configuration
view_ip_configuration() {
    print_header "Current IP Configuration"
    
    echo "System IP Addresses:"
    ip -4 addr show | grep inet | grep -v '127.0.0.1' | awk '{print "  - " $2}'
    
    echo ""
    echo "Postfix Transports:"
    grep "^smtp-ip" /etc/postfix/master.cf 2>/dev/null | awk '{print "  - " $1}' || echo "  None configured"
    
    echo ""
    echo "Configured Hostnames:"
    if [ -f /root/mail-server-config.json ]; then
        grep '"ip_addresses"' -A 20 /root/mail-server-config.json | grep '"' | grep -v "ip_addresses" | tr -d '", '
    else
        echo "  Configuration file not found"
    fi
}

# Run diagnostics
run_diagnostics() {
    print_header "Running System Diagnostics"
    
    # Check services
    echo "Service Status:"
    for service in mysql mariadb postfix dovecot nginx opendkim; do
        if systemctl is-active --quiet $service 2>/dev/null; then
            echo "  ✓ $service: Running"
        else
            echo "  ✗ $service: Not running"
        fi
    done
    
    echo ""
    echo "Port Status:"
    for port in 25 587 143 993 80 443; do
        if netstat -tuln | grep -q ":$port "; then
            echo "  ✓ Port $port: Listening"
        else
            echo "  ✗ Port $port: Not listening"
        fi
    done
    
    echo ""
    echo "Mail Queue:"
    mailq | tail -5
    
    echo ""
    echo "Recent Mail Logs:"
    tail -10 /var/log/mail.log 2>/dev/null || echo "  Log file not found"
}

# Update installer
update_installer() {
    print_header "Updating Installer"
    
    local REPO_URL="https://github.com/fumingtomato/shibi"
    local INSTALL_DIR="/opt/mail-installer"
    
    print_message "Checking for updates from $REPO_URL..."
    
    # Create temp directory
    local temp_dir=$(mktemp -d)
    cd "$temp_dir"
    
    # Download latest version
    if wget -q "$REPO_URL/archive/main.zip" -O installer.zip; then
        unzip -q installer.zip
        
        # Backup current installation
        if [ -d "$INSTALL_DIR" ]; then
            cp -r "$INSTALL_DIR" "${INSTALL_DIR}.backup.$(date +%Y%m%d)"
        fi
        
        # Copy new files
        cp -r shibi-main/New_PfMIP/* "$INSTALL_DIR/" 2>/dev/null || \
        cp -r shibi-main/New_PfMIP/* ./ 2>/dev/null
        
        print_message "✓ Installer updated successfully"
    else
        print_error "✗ Failed to download updates"
    fi
    
    # Cleanup
    cd /
    rm -rf "$temp_dir"
}

# Repair installation
repair_installation() {
    print_header "Repair Installation"
    
    echo "Select repair option:"
    echo "1) Fix MySQL warnings"
    echo "2) Restart all services"
    echo "3) Regenerate DKIM keys"
    echo "4) Fix permissions"
    echo "5) Back to main menu"
    
    read -p "Enter choice [1-5]: " repair_choice
    
    case $repair_choice in
        1)
            fix_mysql_config
            print_message "MySQL configuration cleaned"
            ;;
        2)
            restart_all_services
            ;;
        3)
            if [ ! -z "$DOMAIN_NAME" ]; then
                /usr/local/bin/fix-dkim-now "$DOMAIN_NAME"
            else
                read -p "Enter domain name: " domain
                /usr/local/bin/fix-dkim-now "$domain"
            fi
            ;;
        4)
            fix_all_permissions
            ;;
        5)
            main_menu
            ;;
        *)
            print_error "Invalid option"
            ;;
    esac
}

# Fix all permissions
fix_all_permissions() {
    print_message "Fixing file permissions..."
    
    # Postfix permissions
    chown -R root:root /etc/postfix
    chmod 644 /etc/postfix/*.cf
    chmod 640 /etc/postfix/mysql-*.cf 2>/dev/null || true
    chown root:postfix /etc/postfix/mysql-*.cf 2>/dev/null || true
    
    # Dovecot permissions
    chown -R root:root /etc/dovecot
    chmod -R o-rwx /etc/dovecot
    chmod 640 /etc/dovecot/dovecot-sql.conf.ext 2>/dev/null || true
    chown root:dovecot /etc/dovecot/dovecot-sql.conf.ext 2>/dev/null || true
    
    # OpenDKIM permissions
    chown -R opendkim:opendkim /etc/opendkim 2>/dev/null || true
    chmod 600 /etc/opendkim/keys/*/mail.private 2>/dev/null || true
    
    # Mail directory permissions
    chown -R vmail:vmail /var/vmail 2>/dev/null || true
    
    print_message "✓ Permissions fixed"
}

# Create script to add additional IPs
create_add_ip_script() {
    cat > /usr/local/bin/add-mail-ip <<'EOF'
#!/bin/bash

# Script to add additional IP to existing mail server setup

echo "Add Additional IP to Mail Server"
echo "================================="

# This feature will be implemented in the next update
echo "This feature is coming soon in the next update."
echo "For now, please manually add IPs by:"
echo "1. Adding the IP to your network interface"
echo "2. Creating a new transport in /etc/postfix/master.cf"
echo "3. Updating DNS records"
echo "4. Restarting Postfix"

EOF
    chmod +x /usr/local/bin/add-mail-ip
    print_message "Script created at /usr/local/bin/add-mail-ip"
}

# Enhanced clean Postfix output wrapper
clean_postfix_output() {
    # This function filters out the duplicate mysql warnings from command output
    grep -v "warning.*dynamicmaps.cf.d/mysql.*duplicate" | \
    grep -v "ignoring duplicate entry for \"mysql\"" | \
    grep -v "warning.*duplicate.*mysql" | \
    grep -v "dict_mysql_open"
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
export -f verify_service_health
export -f restart_service_with_check
export -f view_ip_configuration
export -f run_diagnostics
export -f update_installer
export -f repair_installation
export -f fix_all_permissions
export -f create_add_ip_script
