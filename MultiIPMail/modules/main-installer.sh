#!/bin/bash

# =================================================================
# MULTI-IP BULK MAIL SERVER INSTALLER - MAIN SCRIPT (FIXED VERSION)
# Version: 16.0.1
# Author: fumingtomato
# Repository: https://github.com/fumingtomato/shibi
# Date: 2025-09-27
# =================================================================

set -e  # Exit on error
set -o pipefail  # Pipe failures are errors

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULES_DIR="${SCRIPT_DIR}/modules"

# Installation log
LOG_DIR="/var/log"
LOG_FILE="${LOG_DIR}/mail-installer-$(date +%Y%m%d-%H%M%S).log"

# Create log file
touch "$LOG_FILE"
chmod 640 "$LOG_FILE"

# Redirect all output to log file while displaying on screen
exec > >(tee -a "$LOG_FILE")
exec 2>&1

# Clear screen and show header
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
    exit 1
fi

# Check modules directory
if [ ! -d "$MODULES_DIR" ]; then
    echo "Error: Modules directory not found at $MODULES_DIR"
    echo "Please ensure all installer files are in the correct location"
    exit 1
fi

# Load all modules
echo "Loading installer modules..."

# Core modules that must be loaded first
CORE_MODULES=(
    "core-functions.sh"
    "packages-system.sh"
)

# Feature modules
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

# Load core modules first
for module in "${CORE_MODULES[@]}"; do
    module_file="${MODULES_DIR}/${module}"
    if [ -f "$module_file" ]; then
        echo "  Loading: $module"
        source "$module_file"
    else
        echo "Error: Required module not found: $module"
        exit 1
    fi
done

# Load feature modules
for module in "${FEATURE_MODULES[@]}"; do
    module_file="${MODULES_DIR}/${module}"
    if [ -f "$module_file" ]; then
        echo "  Loading: $module"
        source "$module_file"
    else
        echo "Warning: Module not found: $module"
    fi
done

echo "✓ All modules loaded successfully"
echo ""

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
    print_header "EXPRESS INSTALLATION"
    
    # Check system requirements
    check_root
    check_system_requirements
    
    # Get basic configuration
    echo ""
    read -p "Enter your domain name (e.g., example.com): " DOMAIN_NAME
    while ! validate_domain "$DOMAIN_NAME"; do
        read -p "Invalid domain. Please enter a valid domain name: " DOMAIN_NAME
    done
    export DOMAIN_NAME
    
    # Set hostname
    export HOSTNAME="mail.$DOMAIN_NAME"
    read -p "Mail server hostname (default: $HOSTNAME): " custom_hostname
    if [ ! -z "$custom_hostname" ]; then
        HOSTNAME="$custom_hostname"
    fi
    
    # Admin email
    export ADMIN_EMAIL="admin@$DOMAIN_NAME"
    read -p "Administrator email (default: $ADMIN_EMAIL): " custom_email
    if [ ! -z "$custom_email" ]; then
        while ! validate_email "$custom_email"; do
            read -p "Invalid email. Please enter a valid email address: " custom_email
        done
        ADMIN_EMAIL="$custom_email"
    fi
    
    # Get public IP
    export PRIMARY_IP=$(get_public_ip)
    echo ""
    echo "Detected public IP: $PRIMARY_IP"
    
    # Multi-IP configuration
    echo ""
    read -p "Do you want to configure multiple IP addresses? (y/n): " MULTI_IP
    
    if [[ "$MULTI_IP" =~ ^[Yy]$ ]]; then
        configure_multiple_ips_interactive
    else
        IP_ADDRESSES=("$PRIMARY_IP")
        IP_DOMAINS=("$DOMAIN_NAME")
        HOSTNAMES=("$HOSTNAME")
    fi
    
    # Sticky IP feature
    echo ""
    read -p "Enable sticky IP (sender-to-IP mapping)? (y/n): " ENABLE_STICKY_IP
    export ENABLE_STICKY_IP
    
    # Proceed with installation
    echo ""
    echo "Configuration Summary:"
    echo "====================="
    echo "Domain: $DOMAIN_NAME"
    echo "Hostname: $HOSTNAME"
    echo "Admin Email: $ADMIN_EMAIL"
    echo "Primary IP: $PRIMARY_IP"
    echo "Total IPs: ${#IP_ADDRESSES[@]}"
    echo "Sticky IP: $ENABLE_STICKY_IP"
    echo ""
    
    read -p "Proceed with installation? (y/n): " CONFIRM
    if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
        echo "Installation cancelled."
        exit 0
    fi
    
    # Run installation
    run_full_installation
}

# Custom installation
custom_installation() {
    print_header "CUSTOM INSTALLATION"
    
    # Check system
    check_root
    check_system_requirements
    
    # Detailed configuration collection
    collect_detailed_configuration
    
    # Component selection
    select_components_to_install
    
    # Run selected installation
    run_custom_installation
}

# Repair installation
repair_installation() {
    print_header "REPAIR/UPDATE INSTALLATION"
    
    check_root
    
    echo "Select repair option:"
    echo "1. Fix MySQL/database issues"
    echo "2. Repair Postfix configuration"
    echo "3. Fix DKIM/SPF/DMARC"
    echo "4. Repair SSL certificates"
    echo "5. Fix permissions"
    echo "6. Update all components"
    echo "7. Full reconfiguration"
    
    read -p "Select option (1-7): " REPAIR_OPTION
    
    case $REPAIR_OPTION in
        1) 
            fix_mysql_config
            setup_mysql
            ;;
        2)
            init_postfix_config "$DOMAIN_NAME" "$HOSTNAME"
            ;;
        3)
            setup_opendkim "$DOMAIN_NAME"
            setup_spf "$DOMAIN_NAME" "$HOSTNAME"
            setup_dmarc "$DOMAIN_NAME"
            ;;
        4)
            setup_ssl_certificate "$DOMAIN_NAME" "$HOSTNAME"
            ;;
        5)
            fix_all_permissions
            ;;
        6)
            update_all_components
            ;;
        7)
            collect_detailed_configuration
            run_full_installation
            ;;
    esac
}

# Configure multiple IPs interactively
configure_multiple_ips_interactive() {
    echo ""
    echo "MULTI-IP CONFIGURATION"
    echo "======================"
    echo "Enter additional IP addresses (one per line, empty line to finish):"
    echo "Format: IP_ADDRESS [DOMAIN] [HOSTNAME]"
    echo "Example: 192.168.1.2 mail2.example.com"
    echo ""
    
    IP_ADDRESSES=()
    IP_DOMAINS=()
    HOSTNAMES=()
    
    # Add primary IP first
    IP_ADDRESSES+=("$PRIMARY_IP")
    IP_DOMAINS+=("$DOMAIN_NAME")
    HOSTNAMES+=("$HOSTNAME")
    
    local count=1
    while true; do
        read -p "IP #$((count+1)): " ip_entry
        
        if [ -z "$ip_entry" ]; then
            break
        fi
        
        # Parse entry
        local parts=($ip_entry)
        local ip="${parts[0]}"
        local domain="${parts[1]:-$DOMAIN_NAME}"
        local hostname="${parts[2]:-mail-$count.$DOMAIN_NAME}"
        
        if validate_ip_address "$ip"; then
            IP_ADDRESSES+=("$ip")
            IP_DOMAINS+=("$domain")
            HOSTNAMES+=("$hostname")
            count=$((count+1))
            echo "  Added: $ip -> $hostname"
        else
            echo "  Invalid IP address: $ip"
        fi
    done
    
    export IP_ADDRESSES
    export IP_DOMAINS
    export HOSTNAMES
    export IP_COUNT=${#IP_ADDRESSES[@]}
    
    echo ""
    echo "Configured ${#IP_ADDRESSES[@]} IP addresses"
}

# Collect detailed configuration
collect_detailed_configuration() {
    # Domain configuration
    read -p "Primary domain name: " DOMAIN_NAME
    validate_domain "$DOMAIN_NAME" || exit 1
    
    read -p "Mail server hostname (default: mail.$DOMAIN_NAME): " HOSTNAME
    HOSTNAME=${HOSTNAME:-mail.$DOMAIN_NAME}
    
    read -p "Administrator email: " ADMIN_EMAIL
    validate_email "$ADMIN_EMAIL" || exit 1
    
    # Database configuration
    read -p "MySQL root password (leave empty to generate): " MYSQL_ROOT_PASS
    if [ -z "$MYSQL_ROOT_PASS" ]; then
        MYSQL_ROOT_PASS=$(openssl rand -base64 32)
        echo "Generated MySQL root password: $MYSQL_ROOT_PASS"
    fi
    
    # SSL configuration
    read -p "Use Let's Encrypt for SSL? (y/n): " USE_LETSENCRYPT
    if [[ "$USE_LETSENCRYPT" =~ ^[Yy]$ ]]; then
        read -p "Email for Let's Encrypt notifications: " SSL_EMAIL
        SSL_EMAIL=${SSL_EMAIL:-$ADMIN_EMAIL}
    fi
    
    # MailWizz integration
    read -p "Configure MailWizz integration? (y/n): " CONFIGURE_MAILWIZZ
    if [[ "$CONFIGURE_MAILWIZZ" =~ ^[Yy]$ ]]; then
        read -p "MailWizz API URL: " MAILWIZZ_API_URL
        read -p "MailWizz Public Key: " MAILWIZZ_PUBLIC_KEY
        read -p "MailWizz Private Key: " MAILWIZZ_PRIVATE_KEY
    fi
    
    # Export all variables
    export DOMAIN_NAME HOSTNAME ADMIN_EMAIL
    export MYSQL_ROOT_PASS USE_LETSENCRYPT SSL_EMAIL
    export CONFIGURE_MAILWIZZ MAILWIZZ_API_URL MAILWIZZ_PUBLIC_KEY MAILWIZZ_PRIVATE_KEY
}

# Select components to install
select_components_to_install() {
    echo ""
    echo "SELECT COMPONENTS TO INSTALL"
    echo "============================"
    echo ""
    
    INSTALL_POSTFIX=true
    INSTALL_DOVECOT=true
    INSTALL_MYSQL=true
    INSTALL_DKIM=true
    INSTALL_SPAMASSASSIN=false
    INSTALL_CLAMAV=false
    INSTALL_WEBMAIL=false
    INSTALL_MONITORING=true
    INSTALL_SECURITY=true
    
    echo "Default components will be installed:"
    echo "  ✓ Postfix (SMTP)"
    echo "  ✓ Dovecot (IMAP/POP3)"
    echo "  ✓ MySQL/MariaDB"
    echo "  ✓ OpenDKIM"
    echo "  ✓ Monitoring tools"
    echo "  ✓ Security hardening"
    echo ""
    
    read -p "Install SpamAssassin? (y/n): " SPAM
    [[ "$SPAM" =~ ^[Yy]$ ]] && INSTALL_SPAMASSASSIN=true
    
    read -p "Install ClamAV antivirus? (y/n): " CLAM
    [[ "$CLAM" =~ ^[Yy]$ ]] && INSTALL_CLAMAV=true
    
    read -p "Install Roundcube webmail? (y/n): " WEBMAIL
    [[ "$WEBMAIL" =~ ^[Yy]$ ]] && INSTALL_WEBMAIL=true
    
    export INSTALL_POSTFIX INSTALL_DOVECOT INSTALL_MYSQL INSTALL_DKIM
    export INSTALL_SPAMASSASSIN INSTALL_CLAMAV INSTALL_WEBMAIL
    export INSTALL_MONITORING INSTALL_SECURITY
}

# Run full installation
run_full_installation() {
    print_header "STARTING INSTALLATION"
    
    # Phase 1: System preparation
    print_header "Phase 1: System Preparation"
    setup_timezone
    update_system_packages
    install_required_packages
    
    # Phase 2: Core services
    print_header "Phase 2: Core Services Installation"
    install_mail_packages
    install_database_packages
    install_web_packages
    
    # Phase 3: Configuration
    print_header "Phase 3: Service Configuration"
    
    # MySQL/Database setup
    init_mysql_postfix_config
    setup_mysql
    
    # Postfix configuration
    setup_postfix_multi_ip "$DOMAIN_NAME" "$HOSTNAME"
    
    # Dovecot configuration
    setup_dovecot "$DOMAIN_NAME" "$HOSTNAME"
    
    # Multi-IP configuration
    if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
        setup_multiple_ips
    fi
    
    # Phase 4: Email authentication
    print_header "Phase 4: Email Authentication"
    setup_opendkim "$DOMAIN_NAME"
    setup_spf "$DOMAIN_NAME" "$HOSTNAME"
    setup_dmarc "$DOMAIN_NAME" "$ADMIN_EMAIL"
    
    # Phase 5: DNS and SSL
    print_header "Phase 5: DNS and SSL Configuration"
    generate_dns_records "$DOMAIN_NAME" "$HOSTNAME"
    
    if [[ "$USE_LETSENCRYPT" =~ ^[Yy]$ ]]; then
        setup_ssl_certificate "$DOMAIN_NAME" "$HOSTNAME" "$SSL_EMAIL"
    fi
    
    # Phase 6: Security
    print_header "Phase 6: Security Hardening"
    setup_security_hardening
    
    # Phase 7: Monitoring and utilities
    print_header "Phase 7: Monitoring and Utilities"
    init_monitoring
    create_ip_warmup_scripts
    create_monitoring_scripts
    create_all_utilities
    
    # Phase 8: Optional features
    if [[ "$ENABLE_STICKY_IP" =~ ^[Yy]$ ]]; then
        print_header "Phase 8: Sticky IP Configuration"
        setup_sticky_ip
    fi
    
    if [[ "$CONFIGURE_MAILWIZZ" =~ ^[Yy]$ ]]; then
        print_header "Phase 8: MailWizz Integration"
        setup_mailwizz_complete
    fi
    
    # Phase 9: Final setup
    print_header "Phase 9: Final Setup"
    
    # Create management scripts
    create_add_ip_script
    create_control_panel
    create_system_info_script
    create_quick_setup_wizard
    
    # Initialize IP monitoring
    if [ ${#IP_ADDRESSES[@]} -gt 0 ]; then
        init_ip_monitoring
    fi
    
    # Create first email account
    echo ""
    read -p "Create first email account? (y/n): " CREATE_ACCOUNT
    if [[ "$CREATE_ACCOUNT" =~ ^[Yy]$ ]]; then
        read -p "Email address: " FIRST_EMAIL
        read -s -p "Password: " FIRST_PASS
        echo ""
        add_email_user "$FIRST_EMAIL" "$FIRST_PASS"
    fi
    
    # Start all services
    print_header "Starting Services"
    systemctl restart mysql 2>/dev/null || systemctl restart mariadb 2>/dev/null
    systemctl restart postfix
    systemctl restart dovecot
    systemctl restart opendkim
    systemctl restart fail2ban
    
    # Final tests
    print_header "Running Final Tests"
    test_postfix_config
    test_sticky_ip
    test_security
    
    # Show completion message
    show_completion_message
}

# Run custom installation
run_custom_installation() {
    print_header "RUNNING CUSTOM INSTALLATION"
    
    # Install only selected components
    if [ "$INSTALL_POSTFIX" = true ]; then
        install_mail_packages
        setup_postfix_multi_ip "$DOMAIN_NAME" "$HOSTNAME"
    fi
    
    if [ "$INSTALL_DOVECOT" = true ]; then
        setup_dovecot "$DOMAIN_NAME" "$HOSTNAME"
    fi
    
    if [ "$INSTALL_MYSQL" = true ]; then
        install_database_packages
        setup_mysql
    fi
    
    if [ "$INSTALL_DKIM" = true ]; then
        setup_opendkim "$DOMAIN_NAME"
    fi
    
    if [ "$INSTALL_SECURITY" = true ]; then
        setup_security_hardening
    fi
    
    if [ "$INSTALL_MONITORING" = true ]; then
        init_monitoring
        create_monitoring_scripts
    fi
    
    # Create utilities
    create_all_utilities
    
    # Show completion
    show_completion_message
}

# Fix all permissions
fix_all_permissions() {
    print_header "Fixing File Permissions"
    
    # Mail directories
    chown -R vmail:vmail /var/vmail 2>/dev/null || true
    chmod 770 /var/vmail 2>/dev/null || true
    
    # Postfix
    chown -R root:postfix /etc/postfix
    chmod 755 /etc/postfix
    chmod 644 /etc/postfix/*.cf
    chmod 640 /etc/postfix/mysql-*.cf 2>/dev/null || true
    
    # Dovecot
    chown -R root:dovecot /etc/dovecot
    chmod 755 /etc/dovecot
    chmod 644 /etc/dovecot/dovecot.conf
    chmod 600 /etc/dovecot/dovecot-sql.conf.ext 2>/dev/null || true
    
    # OpenDKIM
    chown -R opendkim:opendkim /etc/opendkim
    chmod 755 /etc/opendkim
    chmod 600 /etc/opendkim/keys/*/*.private 2>/dev/null || true
    
    # Logs
    chmod 640 /var/log/mail.log 2>/dev/null || true
    chmod 640 /var/log/mail.err 2>/dev/null || true
    
    print_message "✓ Permissions fixed"
}

# Update all components
update_all_components() {
    print_header "Updating All Components"
    
    apt-get update
    apt-get upgrade -y postfix dovecot-core opendkim mysql-server
    
    # Update scripts
    for script in /usr/local/bin/mail-*; do
        if [ -f "$script" ]; then
            chmod +x "$script"
        fi
    done
    
    print_message "✓ Components updated"
}

# Error handler
handle_error() {
    local line_no=$1
    local exit_code=$2
    
    echo ""
    echo "ERROR: Installation failed at line $line_no with exit code $exit_code"
    echo "Check the log file for details: $LOG_FILE"
    echo ""
    echo "To retry installation, run: $0"
    echo "For help, visit: https://github.com/fumingtomato/shibi"
    
    exit $exit_code
}

# Set error trap
trap 'handle_error $LINENO $?' ERR

# Main execution
main() {
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
}

# Run main function
main "$@"

# End of installation
echo ""
echo "Installation completed at: $(date)"
echo "Log file: $LOG_FILE"
