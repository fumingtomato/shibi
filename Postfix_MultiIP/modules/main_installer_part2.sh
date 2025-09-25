#!/bin/bash

# =================================================================
# MAIN INSTALLER MODULE - PART 2
# Supporting functions and utilities
# =================================================================

# Install required packages
install_required_packages() {
    print_message "Updating package repositories..."
    apt update
    
    print_message "Installing required packages..."
    apt install -y \
        postfix postfix-mysql \
        dovecot-core dovecot-imapd dovecot-lmtpd dovecot-mysql \
        mysql-server \
        opendkim opendkim-tools \
        certbot python3-certbot-nginx \
        nginx \
        mailutils \
        curl dnsutils openssl bc python3 net-tools \
        ufw fail2ban \
        logwatch rkhunter \
        unattended-upgrades apt-listchanges
}

# Configure hostname
configure_hostname() {
    print_message "Configuring hostname..."
    hostnamectl set-hostname $HOSTNAME
    echo "$PRIMARY_IP $HOSTNAME" >> /etc/hosts
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
    
    newaliases
    print_message "Email aliases configured"
}

# Restart all services
restart_all_services() {
    print_message "Restarting all services..."
    
    local services=("mysql" "opendkim" "postfix" "dovecot" "nginx")
    
    for service in "${services[@]}"; do
        print_message "Restarting $service..."
        systemctl restart $service || print_error "Failed to restart $service"
        systemctl enable $service
    done
}

# Save configuration for future reference
save_configuration() {
    print_message "Saving configuration..."
    
    cat > /etc/mail-server-config.conf <<EOF
# Mail Server Configuration - Multi-IP Edition
# Generated: $(date)
INSTALLER_VERSION="$INSTALLER_VERSION"
DOMAIN_NAME="$DOMAIN_NAME"
BRAND_NAME="$BRAND_NAME"
HOSTNAME="$HOSTNAME"
PRIMARY_IP="$PRIMARY_IP"
IP_COUNT="${#IP_ADDRESSES[@]}"
IP_ADDRESSES=(${IP_ADDRESSES[@]})
CF_API_TOKEN="$CF_API_TOKEN"
CF_ZONE_ID="$CF_ZONE_ID"
ADMIN_EMAIL="$ADMIN_EMAIL"
EOF
    
    chmod 600 /etc/mail-server-config.conf
}

# Create final documentation
create_final_documentation() {
    print_message "Creating documentation..."
    
    cat > /root/mail-server-multiip-info.txt <<EOF
======================================================
   Multi-IP Bulk Mail Server Installation Complete!
======================================================
Generated: $(date)
Installer Version: $INSTALLER_VERSION

BASIC CONFIGURATION:
-------------------
Brand Name: $BRAND_NAME
Primary Domain: $DOMAIN_NAME
Primary Hostname: $HOSTNAME
Admin Email: $ADMIN_EMAIL
Mail Account: $MAIL_USERNAME@$DOMAIN_NAME

IP CONFIGURATION:
----------------
Number of IPs: ${#IP_ADDRESSES[@]}
Primary IP: $PRIMARY_IP
EOF
    
    local ip_idx=1
    for ip in "${IP_ADDRESSES[@]}"; do
        echo "IP #${ip_idx}: $ip (Transport: smtp-ip${ip_idx})" >> /root/mail-server-multiip-info.txt
        ip_idx=$((ip_idx + 1))
    done
    
    cat >> /root/mail-server-multiip-info.txt <<'EOF'

TESTING COMMANDS:
----------------
# Send test email through specific IP:
echo "Test" | sendmail -f sender@domain.com -t recipient@example.com

# Check mail queue:
mailq

# Monitor specific transport:
postqueue -p | grep smtp-ip1

# View statistics:
/usr/local/bin/mail-stats overall

# Check IP warmup status:
/usr/local/bin/ip-warmup-manager status

MAILWIZZ INTEGRATION:
--------------------
See detailed guide: /root/mailwizz-multi-ip-guide.txt

IMPORTANT FILES:
---------------
- Configuration: /etc/mail-server-config.conf
- MailWizz Guide: /root/mailwizz-multi-ip-guide.txt
- PTR Setup: /root/ptr-records-setup.txt
- Logs: /var/log/mail.log
- Stats: /var/log/mail-stats/

MONITORING:
----------
- Daily stats: /usr/local/bin/mail-stats report
- Live monitoring: /usr/local/bin/mail-stats live
- IP reputation: /usr/local/bin/ip-warmup-manager check [IP]

MANAGEMENT URLS:
---------------
- Website: https://YOUR_DOMAIN
- Privacy Policy: https://YOUR_DOMAIN/privacy-policy.html
- Unsubscribe: https://YOUR_DOMAIN/unsubscribe.html

For support and updates, visit:
https://github.com/fumingtomato/maileristhegame
EOF
}

# Main menu function
main_menu() {
    # Source part 2 if needed
    if [ -f "/tmp/multiip-installer-$$/main_installer_part2.sh" ]; then
        source "/tmp/multiip-installer-$$/main_installer_part2.sh"
    fi
    
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

# Add additional IP to existing installation
add_additional_ip() {
    print_header "Add Additional IP Address"
    
    if [ ! -f /etc/mail-server-config.conf ]; then
        print_error "No existing installation found. Please run installation first."
        return
    fi
    
    source /etc/mail-server-config.conf
    
    print_message "Current IPs: ${IP_ADDRESSES[@]}"
    
    read -p "Enter new IP address to add: " new_ip
    
    if [[ ! $new_ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        print_error "Invalid IP format"
        return
    fi
    
    print_message "IP $new_ip will be added to configuration"
    print_warning "Please manually update Postfix master.cf and restart services"
}

# View current IP configuration
view_ip_configuration() {
    print_header "Current IP Configuration"
    
    if [ ! -f /etc/mail-server-config.conf ]; then
        print_error "No configuration found. Please run installation first."
        return
    fi
    
    source /etc/mail-server-config.conf
    
    echo "Configured IPs: ${IP_ADDRESSES[@]}"
    echo ""
    echo "Transport mappings:"
    if [ -f /etc/postfix/sender_dependent_default_transport_maps ]; then
        cat /etc/postfix/sender_dependent_default_transport_maps
    fi
}

# Run diagnostics
run_diagnostics() {
    print_header "Running System Diagnostics"
    
    print_message "Checking services..."
    for service in postfix dovecot mysql nginx opendkim; do
        if systemctl is-active --quiet $service; then
            print_message "✓ $service is running"
        else
            print_error "✗ $service is not running"
        fi
    done
    
    print_message "\nChecking mail queue..."
    mailq | tail -5
    
    print_message "\nChecking disk space..."
    df -h /
    
    print_message "\nChecking recent mail logs..."
    tail -20 /var/log/mail.log | grep -E "(error|warning|fatal)" || echo "No recent errors found"
    
    print_message "\nDiagnostics complete."
}

# Update installer
update_installer() {
    print_header "Updating Installer"
    
    print_message "Checking for updates..."
    
    local update_url="https://raw.githubusercontent.com/fumingtomato/maileristhegame/main/version.txt"
    local remote_version=$(curl -s "$update_url" 2>/dev/null || echo "$INSTALLER_VERSION")
    
    if [ "$remote_version" != "$INSTALLER_VERSION" ]; then
        print_message "New version available: $remote_version"
        read -p "Update now? (y/n): " update_now
        
        if [[ "$update_now" == "y" ]]; then
            print_message "Downloading update..."
            wget -O /tmp/install_new.sh https://raw.githubusercontent.com/fumingtomato/maileristhegame/main/install.sh
            chmod +x /tmp/install_new.sh
            print_message "Update downloaded. Run: /tmp/install_new.sh"
        fi
    else
        print_message "You have the latest version: $INSTALLER_VERSION"
    fi
}

export -f first_time_installation_multi_ip install_required_packages
export -f configure_hostname restart_all_services save_configuration
export -f create_final_documentation main_menu setup_email_aliases
export -f add_additional_ip view_ip_configuration run_diagnostics update_installer
