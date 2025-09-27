#!/bin/bash

# =================================================================
# MULTI-IP BULK MAIL SERVER INSTALLER - MODULE VERSION (FIXED)
# Version: 16.0.1
# Author: fumingtomato
# Repository: https://github.com/fumingtomato/shibi
# Date: 2025-09-27
# Fixed: Path detection when loaded as a module
# =================================================================

# Note: When this file is loaded as a module by install.sh,
# it should NOT try to detect paths or load other modules
# as they are already loaded by the main installer

# Check if we're being loaded as a module or run directly
if [ -z "$INSTALLER_MODULE_MODE" ]; then
    # Being run directly (standalone mode)
    set -e
    set -o pipefail
    
    # Script directory detection for standalone mode
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    
    # Set modules directory
    if [[ "$(basename "$SCRIPT_DIR")" == "modules" ]]; then
        MODULES_DIR="${SCRIPT_DIR}"
        SCRIPT_DIR="$(dirname "$SCRIPT_DIR")"
    else
        MODULES_DIR="${SCRIPT_DIR}/modules"
    fi
    
    # Installation log
    LOG_DIR="/var/log"
    LOG_FILE="${LOG_DIR}/mail-installer-$(date +%Y%m%d-%H%M%S).log"
    
    # Create log file
    touch "$LOG_FILE"
    chmod 640 "$LOG_FILE"
    
    # Redirect output
    exec > >(tee -a "$LOG_FILE")
    exec 2>&1
    
    # Show header
    clear
    cat << "EOF"
╔══════════════════════════════════════════════════════════════╗
║     MULTI-IP BULK MAIL SERVER INSTALLER v16.0.1             ║
║                                                              ║
║     Professional Mail Server with Multi-IP Support          ║
║     Repository: https://github.com/fumingtomato/shibi       ║
╚══════════════════════════════════════════════════════════════╝

EOF
    
    echo "Installation started at: $(date)"
    echo "Log file: $LOG_FILE"
    echo ""
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        echo "Error: This script must be run as root or with sudo privileges"
        echo "Please run: sudo $0"
        exit 1
    fi
    
    # Check modules directory
    if [ ! -d "$MODULES_DIR" ]; then
        echo ""
        echo "ERROR: Modules directory not found at $MODULES_DIR"
        echo ""
        echo "Please ensure the following structure exists:"
        echo "  $SCRIPT_DIR/"
        echo "  ├── main-installer.sh (or install.sh)"
        echo "  └── modules/"
        echo "      ├── core-functions.sh"
        echo "      ├── packages-system.sh"
        echo "      └── ... (other modules)"
        echo ""
        echo "You can download all modules from:"
        echo "https://github.com/fumingtomato/shibi"
        exit 1
    fi
    
    # Load modules in standalone mode
    echo "Loading installer modules..."
    
    CORE_MODULES=(
        "core-functions.sh"
        "packages-system.sh"
    )
    
    FEATURE_MODULES=(
        "mysql-dovecot.sh"
        "multiip-config.sh"
        "postfix-setup.sh"
        "dkim-spf.sh"
        "dns-ssl.sh"
        "sticky-ip.sh"
        "monitoring-scripts.sh"
        "security-hardening.sh"
        "utility-scripts.sh"
        "mailwizz-integration.sh"
        "main-installer-part2.sh"
    )
    
    LOADED_MODULES=0
    FAILED_MODULES=0
    
    # Load core modules
    for module in "${CORE_MODULES[@]}"; do
        module_file="${MODULES_DIR}/${module}"
        if [ -f "$module_file" ]; then
            echo "  ✓ Loading: $module"
            source "$module_file"
            LOADED_MODULES=$((LOADED_MODULES + 1))
        else
            echo "  ✗ Required module not found: $module"
            FAILED_MODULES=$((FAILED_MODULES + 1))
        fi
    done
    
    if [ $FAILED_MODULES -gt 0 ]; then
        echo ""
        echo "ERROR: Core modules are missing. Cannot continue."
        exit 1
    fi
    
    # Load feature modules
    for module in "${FEATURE_MODULES[@]}"; do
        module_file="${MODULES_DIR}/${module}"
        if [ -f "$module_file" ]; then
            echo "  ✓ Loading: $module"
            source "$module_file"
            LOADED_MODULES=$((LOADED_MODULES + 1))
        else
            echo "  ⚠ Optional module not found: $module"
        fi
    done
    
    echo ""
    echo "✓ Loaded $LOADED_MODULES modules successfully"
    echo ""
fi

# =================================================================
# MAIN INSTALLER FUNCTIONS
# These functions are available whether loaded as module or standalone
# =================================================================

# Installation mode selection
select_installation_mode() {
    echo "SELECT INSTALLATION MODE"
    echo "========================"
    echo ""
    echo "1. Express Installation (Recommended for new servers)"
    echo "   - Automatic configuration with sensible defaults"
    echo "   - Single or multi-IP support"
    echo "   - Quick setup wizard"
    echo ""
    echo "2. Custom Installation (Advanced)"
    echo "   - Full control over all settings"
    echo "   - Component selection"
    echo "   - Manual configuration"
    echo ""
    echo "3. Repair/Update Existing Installation"
    echo "   - Fix configuration issues"
    echo "   - Update components"
    echo "   - Reconfigure services"
    echo ""
    
    read -p "Select mode (1-3): " INSTALL_MODE
    
    case $INSTALL_MODE in
        1) express_installation ;;
        2) custom_installation ;;
        3) repair_installation ;;
        *) 
            echo "Invalid selection. Starting express installation..."
            express_installation
            ;;
    esac
}

# Express installation
express_installation() {
    print_header "Express Installation"
    
    # Gather basic information
    gather_basic_info
    
    # Perform installation
    perform_express_installation
}

# Gather basic information
gather_basic_info() {
    print_header "Basic Configuration"
    
    # Get domain name
    read -p "Enter your domain name (e.g., example.com): " DOMAIN_NAME
    while ! validate_domain "$DOMAIN_NAME"; do
        read -p "Invalid domain. Please enter a valid domain: " DOMAIN_NAME
    done
    export DOMAIN_NAME
    
    # Get hostname
    default_hostname="mail.$DOMAIN_NAME"
    read -p "Enter mail server hostname [$default_hostname]: " HOSTNAME
    HOSTNAME=${HOSTNAME:-$default_hostname}
    export HOSTNAME
    
    # Get admin email
    read -p "Enter admin email address: " ADMIN_EMAIL
    while ! validate_email "$ADMIN_EMAIL"; do
        read -p "Invalid email. Please enter a valid email: " ADMIN_EMAIL
    done
    export ADMIN_EMAIL
    
    # Multi-IP configuration
    echo ""
    read -p "Configure multiple IP addresses? (y/n) [n]: " MULTI_IP
    MULTI_IP=${MULTI_IP:-n}
    
    if [[ "$MULTI_IP" =~ ^[Yy]$ ]]; then
        configure_multiple_ips
    else
        # Single IP configuration
        PRIMARY_IP=$(get_public_ip)
        export PRIMARY_IP
        export IP_ADDRESSES=("$PRIMARY_IP")
        export HOSTNAMES=("$HOSTNAME")
        print_message "Using single IP: $PRIMARY_IP"
    fi
    
    # Sticky IP configuration
    echo ""
    read -p "Enable sticky IP mapping? (y/n) [n]: " ENABLE_STICKY_IP
    export ENABLE_STICKY_IP=${ENABLE_STICKY_IP:-n}
    
    # Brand name
    echo ""
    read -p "Enter your brand/company name [Mail Server]: " BRAND_NAME
    export BRAND_NAME=${BRAND_NAME:-"Mail Server"}
}

# Configure multiple IPs
configure_multiple_ips() {
    print_header "Multi-IP Configuration"
    
    IP_ADDRESSES=()
    HOSTNAMES=()
    IP_DOMAINS=()
    
    echo "Enter IP addresses (one per line, empty line to finish):"
    local count=0
    while true; do
        read -p "IP $((count + 1)): " ip
        if [ -z "$ip" ]; then
            if [ $count -eq 0 ]; then
                echo "At least one IP is required"
                continue
            fi
            break
        fi
        
        if validate_ip_address "$ip"; then
            IP_ADDRESSES+=("$ip")
            
            # Get hostname for this IP
            default_host="mail-$count.$DOMAIN_NAME"
            read -p "  Hostname for $ip [$default_host]: " host
            host=${host:-$default_host}
            HOSTNAMES+=("$host")
            
            # Get domain for this IP
            read -p "  Domain for $ip [$DOMAIN_NAME]: " domain
            domain=${domain:-$DOMAIN_NAME}
            IP_DOMAINS+=("$domain")
            
            count=$((count + 1))
        else
            echo "Invalid IP address format"
        fi
    done
    
    PRIMARY_IP="${IP_ADDRESSES[0]}"
    IP_COUNT=${#IP_ADDRESSES[@]}
    
    export PRIMARY_IP
    export IP_ADDRESSES
    export HOSTNAMES
    export IP_DOMAINS
    export IP_COUNT
    
    print_message "Configured $IP_COUNT IP addresses"
}

# Perform express installation
perform_express_installation() {
    print_header "Starting Express Installation"
    
    # Update system
    print_message "Updating system packages..."
    update_system_packages
    
    # Install required packages
    print_message "Installing required packages..."
    install_all_packages
    
    # Setup MySQL
    print_message "Setting up MySQL database..."
    setup_mysql
    
    # Setup Postfix
    print_message "Setting up Postfix..."
    setup_postfix_multi_ip "$DOMAIN_NAME" "$HOSTNAME"
    
    # Setup Dovecot
    print_message "Setting up Dovecot..."
    setup_dovecot "$DOMAIN_NAME" "$HOSTNAME"
    
    # Setup DKIM/SPF
    print_message "Setting up DKIM and SPF..."
    setup_opendkim "$DOMAIN_NAME"
    setup_spf "$DOMAIN_NAME" "$HOSTNAME"
    
    # Configure multi-IP if needed
    if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
        print_message "Configuring multiple IPs..."
        setup_multiple_ips
    fi
    
    # Setup sticky IP if enabled
    if [[ "$ENABLE_STICKY_IP" =~ ^[Yy]$ ]]; then
        print_message "Setting up sticky IP..."
        setup_sticky_ip
    fi
    
    # Setup monitoring
    print_message "Setting up monitoring..."
    init_monitoring
    create_monitoring_scripts
    
    # Setup security
    print_message "Applying security hardening..."
    setup_security_hardening
    
    # Create utilities
    print_message "Creating utility scripts..."
    create_all_utilities
    
    # Generate DNS records
    print_message "Generating DNS records..."
    generate_dns_records "$DOMAIN_NAME" "$HOSTNAME"
    
    # Final configuration
    print_message "Finalizing configuration..."
    finalize_installation
}

# Custom installation
custom_installation() {
    print_header "Custom Installation"
    
    echo "Component Selection:"
    echo "1. MySQL Database"
    echo "2. Postfix Mail Server"
    echo "3. Dovecot IMAP/POP3"
    echo "4. DKIM/SPF/DMARC"
    echo "5. Multi-IP Configuration"
    echo "6. Sticky IP"
    echo "7. Monitoring Tools"
    echo "8. Security Hardening"
    echo "9. Utility Scripts"
    echo "10. All Components"
    echo ""
    
    read -p "Select components to install (comma-separated): " components
    
    # Process component selection
    IFS=',' read -ra SELECTED <<< "$components"
    
    gather_basic_info
    
    for component in "${SELECTED[@]}"; do
        case $component in
            1) setup_mysql ;;
            2) setup_postfix_multi_ip "$DOMAIN_NAME" "$HOSTNAME" ;;
            3) setup_dovecot "$DOMAIN_NAME" "$HOSTNAME" ;;
            4) 
                setup_opendkim "$DOMAIN_NAME"
                setup_spf "$DOMAIN_NAME" "$HOSTNAME"
                setup_dmarc "$DOMAIN_NAME"
                ;;
            5) setup_multiple_ips ;;
            6) setup_sticky_ip ;;
            7) 
                init_monitoring
                create_monitoring_scripts
                ;;
            8) setup_security_hardening ;;
            9) create_all_utilities ;;
            10) perform_express_installation ;;
        esac
    done
    
    finalize_installation
}

# Repair installation
repair_installation() {
    print_header "Repair/Update Installation"
    
    echo "Repair Options:"
    echo "1. Fix MySQL connection issues"
    echo "2. Repair Postfix configuration"
    echo "3. Fix Dovecot authentication"
    echo "4. Regenerate DKIM keys"
    echo "5. Update DNS records"
    echo "6. Fix permissions"
    echo "7. Restart all services"
    echo "8. Run full diagnostic"
    echo ""
    
    read -p "Select repair option: " repair_option
    
    case $repair_option in
        1) 
            fix_mysql_config
            test_database_connection
            ;;
        2)
            test_postfix_config
            postfix check
            systemctl restart postfix
            ;;
        3)
            systemctl restart dovecot
            doveadm auth test testuser@example.com testpass
            ;;
        4)
            read -p "Enter domain: " domain
            generate_dkim_keys "$domain"
            display_dkim_record "$domain"
            ;;
        5)
            read -p "Enter domain: " domain
            generate_dns_records "$domain" "mail.$domain"
            ;;
        6)
            fix_permissions
            ;;
        7)
            systemctl restart postfix dovecot mysql opendkim
            ;;
        8)
            mail-diagnostic
            ;;
    esac
}

# Finalize installation
finalize_installation() {
    print_header "Finalizing Installation"
    
    # Create admin user
    print_message "Creating admin email account..."
    add_email_user "$ADMIN_EMAIL" "ChangeMeNow123!"
    
    # Start services
    print_message "Starting services..."
    systemctl start postfix dovecot opendkim mysql
    systemctl enable postfix dovecot opendkim mysql
    
    # Show completion message
    show_completion_message
}

# Fix permissions
fix_permissions() {
    print_message "Fixing file permissions..."
    
    # Postfix
    chown -R root:postfix /etc/postfix
    chmod 644 /etc/postfix/*.cf
    chmod 640 /etc/postfix/mysql-*.cf
    
    # Dovecot
    chown -R root:dovecot /etc/dovecot
    chmod 644 /etc/dovecot/*.conf
    chmod 640 /etc/dovecot/dovecot-sql.conf.ext
    
    # Mail storage
    chown -R vmail:vmail /var/vmail
    chmod 770 /var/vmail
    
    # OpenDKIM
    chown -R opendkim:opendkim /etc/opendkim
    chmod 750 /etc/opendkim
    chmod 600 /etc/opendkim/keys/*/mail.private
    
    print_message "✓ Permissions fixed"
}

# First time installation for multi-IP
first_time_installation_multi_ip() {
    print_header "First Time Multi-IP Mail Server Installation"
    
    gather_basic_info
    perform_express_installation
}

# Main menu (for module mode)
main_menu() {
    clear
    cat << "EOF"
╔══════════════════════════════════════════════════════════════╗
║     MULTI-IP BULK MAIL SERVER INSTALLER                     ║
║                                                              ║
║     Professional Mail Server with Multi-IP Support          ║
╚══════════════════════════════════════════════════════════════╝

EOF
    
    echo "MAIN MENU"
    echo "========="
    echo ""
    echo "1. New Installation"
    echo "2. Custom Installation"
    echo "3. Repair/Update"
    echo "4. System Information"
    echo "5. Exit"
    echo ""
    
    read -p "Select option (1-5): " menu_choice
    
    case $menu_choice in
        1) express_installation ;;
        2) custom_installation ;;
        3) repair_installation ;;
        4) mail-info 2>/dev/null || echo "System info not available" ;;
        5) exit 0 ;;
        *) 
            echo "Invalid selection"
            sleep 2
            main_menu
            ;;
    esac
}

# Export functions for module mode
export -f select_installation_mode express_installation custom_installation
export -f repair_installation gather_basic_info configure_multiple_ips
export -f perform_express_installation finalize_installation fix_permissions
export -f first_time_installation_multi_ip main_menu

# If running standalone (not as module), execute main
if [ -z "$INSTALLER_MODULE_MODE" ] && [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    # Show warning
    echo "⚠ WARNING: This installer will modify system configuration files."
    echo "It is recommended to run this on a fresh server installation."
    echo ""
    read -p "Continue with installation? (y/n): " CONTINUE
    
    if [[ ! "$CONTINUE" =~ ^[Yy]$ ]]; then
        echo "Installation cancelled."
        exit 0
    fi
    
    # Start installation
    select_installation_mode
fi
