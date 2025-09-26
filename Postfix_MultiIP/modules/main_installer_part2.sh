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

# Save configuration for future reference
save_configuration() {
    print_message "Saving configuration details..."
    
    local config_file="/root/mail-server-config.txt"
    
    cat > "$config_file" <<EOF
=================================================
Multi-IP Mail Server Configuration
=================================================
Installation Date: $(date)
Installer Version: $INSTALLER_VERSION

Domain: $DOMAIN_NAME
Hostname: $HOSTNAME
Admin Email: $ADMIN_EMAIL

IP Addresses:
$(for ip in "${IP_ADDRESSES[@]}"; do echo "- $ip"; done)

=================================================
EOF
    
    chmod 600 "$config_file"
    print_message "Configuration saved to $config_file"
}

# Create final documentation
create_final_documentation() {
    print_message "Creating final documentation..."
    
    local doc_file="/root/mail-server-multiip-info.txt"
    
    cat > "$doc_file" <<EOF
=================================================
Multi-IP Bulk Mail Server - Complete Guide
=================================================
Installation Date: $(date)
Installer Version: $INSTALLER_VERSION

SYSTEM OVERVIEW:
---------------
Primary Domain: $DOMAIN_NAME
Hostname: $HOSTNAME
Admin Email: $ADMIN_EMAIL

IP ADDRESSES:
-----------
$(for i in $(seq 0 $((${#IP_ADDRESSES[@]}-1))); do 
    echo "IP #$((i+1)): ${IP_ADDRESSES[$i]} (Transport: smtp-ip$((i+1)))"
done)

SERVER MANAGEMENT:
----------------
1. Monitor mail logs: tail -f /var/log/mail.log
2. Check mail queue: /usr/local/bin/manage-mail-queue status
3. Monitor IP statistics: /usr/local/bin/mail-stats overall
4. Check security status: /usr/local/bin/check-mail-security

IP WARMUP MANAGEMENT:
-------------------
IP warmup scripts are located at: /usr/local/bin/ip-warmup-manager

Commands:
- Check status: ip-warmup-manager status
- Set limits: ip-warmup-manager limit [IP]
- Update counts: ip-warmup-manager update [IP] [count]

MailWizz integration guide: /root/mailwizz-multi-ip-guide.txt
PTR record setup instructions: /root/ptr-records-setup.txt
IP assignments: /root/postfix-ip-assignments.txt

BACKUP INFORMATION:
-----------------
Database password: Saved in /root/.mail_db_password
SSL certificates: /etc/letsencrypt/live/
Configuration files: /etc/postfix/, /etc/dovecot/

FOR SUPPORT:
----------
For additional help, please contact the system administrator.
EOF
    
    chmod 600 "$doc_file"
    print_message "Complete documentation created at $doc_file"
}

# Install required packages
install_required_packages() {
    print_header "Installing Required Packages"
    
    # Update package lists
    apt-get update
    
    # Install essential packages
    print_message "Installing essential packages..."
    apt-get install -y curl wget gnupg ca-certificates lsb-release apt-transport-https
    
    # Install mail server packages
    print_message "Installing mail server packages..."
    apt-get install -y postfix postfix-mysql dovecot-core dovecot-imapd dovecot-pop3d dovecot-lmtpd dovecot-mysql
    
    # Install web server
    print_message "Installing web server packages..."
    apt-get install -y nginx
    
    # Install Let's Encrypt
    print_message "Installing Let's Encrypt (certbot)..."
    apt-get install -y certbot
    
    # Install utility packages
    print_message "Installing utility packages..."
    apt-get install -y bsd-mailx mailutils openssl ssl-cert rsyslog logrotate fail2ban
    
    print_message "Required packages installed successfully"
}

# Configure hostname
configure_hostname() {
    print_header "Configuring Hostname"
    
    # Set hostname
    hostnamectl set-hostname "$HOSTNAME"
    
    # Update /etc/hosts
    if ! grep -q "$HOSTNAME" /etc/hosts; then
        echo "$PRIMARY_IP $HOSTNAME $DOMAIN_NAME" >> /etc/hosts
    fi
    
    print_message "Hostname configured successfully: $HOSTNAME"
}

# Create a basic website with server information
setup_website() {
    local domain=$1
    local email=$2
    local brand=$3
    
    print_header "Setting Up Basic Website"
    
    # Create web directory if it doesn't exist
    mkdir -p /var/www/html
    
    # Create a simple index page
    cat > /var/www/html/index.html <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${brand} Mail Server</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
            max-width: 800px;
            margin: 0 auto;
        }
        h1 {
            color: #2c3e50;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }
        footer {
            margin-top: 30px;
            font-size: 0.9em;
            color: #7f8c8d;
            border-top: 1px solid #eee;
            padding-top: 20px;
        }
    </style>
</head>
<body>
    <h1>${brand} Mail Server</h1>
    
    <p>This is the mail server for ${domain}.</p>
    
    <h2>Server Information</h2>
    <ul>
        <li>Domain: ${domain}</li>
        <li>Mail Server: mail.${domain}</li>
        <li>IMAP: mail.${domain}:993 (SSL/TLS)</li>
        <li>SMTP: mail.${domain}:587 (STARTTLS)</li>
    </ul>
    
    <p>For support, please contact <a href="mailto:${email}">${email}</a>.</p>
    
    <footer>
        &copy; $(date +%Y) ${brand}. All rights reserved.
    </footer>
</body>
</html>
EOF
    
    # Set proper ownership and permissions
    chown -R www-data:www-data /var/www/html
    chmod -R 755 /var/www/html
    
    print_message "Basic website setup completed"
}

# Define main menu function
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
            add_additional_ip
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
            print_message "Exiting installer. No changes were made."
            exit 0
            ;;
        *)
            print_error "Invalid option. Exiting."
            exit 1
            ;;
    esac
}

# Add placeholder functions that will be properly implemented later
add_additional_ip() {
    print_message "This feature is not yet implemented."
    print_message "Please run the full installation to configure IPs."
}

view_ip_configuration() {
    print_message "Checking current IP configuration..."
    if [ -f "/root/postfix-ip-assignments.txt" ]; then
        cat "/root/postfix-ip-assignments.txt"
    else
        print_error "IP configuration file not found. Has the server been configured?"
    fi
}

run_diagnostics() {
    print_message "Running system diagnostics..."
    if [ -f "/usr/local/bin/check-mail-security" ]; then
        /usr/local/bin/check-mail-security
    else
        print_error "Diagnostic tools not found. Has the server been configured?"
    fi
}

update_installer() {
    print_message "This feature will be available in a future version."
}

# Export functions to make them available in other scripts
export -f fix_mysql_config restart_all_services setup_email_aliases
export -f save_configuration create_final_documentation main_menu
export -f install_required_packages configure_hostname setup_website
