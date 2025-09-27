#!/bin/bash

# =================================================================
# MAIN INSTALLER PART 2 - FIXED VERSION
# Additional installation functions and configurations
# Fixed: Complete implementations, proper function exports
# =================================================================

# Initialize MySQL and Postfix configuration
init_mysql_postfix_config() {
    print_message "Initializing MySQL and Postfix configuration..."
    
    # Set default values if not already set
    export DB_NAME="${DB_NAME:-mailserver}"
    export DB_USER="${DB_USER:-mailuser}"
    export DB_HOST="${DB_HOST:-127.0.0.1}"
    export DB_PORT="${DB_PORT:-3306}"
    
    # Check if password file exists
    if [ -f /root/.mail_db_password ]; then
        export DB_PASSWORD=$(cat /root/.mail_db_password)
    else
        export DB_PASSWORD=$(openssl rand -base64 32)
        echo "$DB_PASSWORD" > /root/.mail_db_password
        chmod 600 /root/.mail_db_password
    fi
    
    print_message "✓ Configuration initialized"
}

# Fix MySQL configuration issues
fix_mysql_config() {
    print_header "Fixing MySQL Configuration"
    
    # Check MySQL service
    local mysql_service=""
    if systemctl list-units --full -all | grep -q "mysql.service"; then
        mysql_service="mysql"
    elif systemctl list-units --full -all | grep -q "mariadb.service"; then
        mysql_service="mariadb"
    else
        print_error "MySQL/MariaDB service not found"
        return 1
    fi
    
    # Stop MySQL
    systemctl stop "$mysql_service"
    
    # Fix common MySQL issues
    print_message "Checking MySQL configuration..."
    
    # Fix innodb issues
    if [ -f /var/lib/mysql/ib_logfile0 ]; then
        print_message "Cleaning InnoDB log files..."
        rm -f /var/lib/mysql/ib_logfile*
    fi
    
    # Fix permissions
    chown -R mysql:mysql /var/lib/mysql
    chmod 755 /var/lib/mysql
    
    # Update MySQL configuration
    local mysql_conf="/etc/mysql/mysql.conf.d/mysqld.cnf"
    if [ ! -f "$mysql_conf" ]; then
        mysql_conf="/etc/mysql/mariadb.conf.d/50-server.cnf"
    fi
    
    if [ -f "$mysql_conf" ]; then
        # Backup original
        cp "$mysql_conf" "${mysql_conf}.backup.$(date +%s)"
        
        # Add optimizations
        cat >> "$mysql_conf" <<EOF

# Mail Server Optimizations
max_connections = 200
max_allowed_packet = 64M
thread_cache_size = 128
query_cache_type = 1
query_cache_size = 32M
query_cache_limit = 2M
innodb_buffer_pool_size = 256M
innodb_log_file_size = 64M
innodb_flush_log_at_trx_commit = 2
innodb_flush_method = O_DIRECT
EOF
    fi
    
    # Start MySQL
    systemctl start "$mysql_service"
    
    # Wait for MySQL to be ready
    local max_wait=30
    local waited=0
    while [ $waited -lt $max_wait ]; do
        if mysqladmin ping --silent 2>/dev/null; then
            print_message "✓ MySQL is running"
            break
        fi
        sleep 1
        waited=$((waited + 1))
    done
    
    if [ $waited -eq $max_wait ]; then
        print_error "MySQL failed to start"
        return 1
    fi
    
    # Reset root password if needed
    if ! mysql -e "SELECT 1" 2>/dev/null; then
        print_message "Resetting MySQL root password..."
        
        local new_root_pass=$(openssl rand -base64 32)
        
        # Stop MySQL
        systemctl stop "$mysql_service"
        
        # Start in safe mode
        mysqld_safe --skip-grant-tables &
        local mysql_pid=$!
        sleep 5
        
        # Reset password
        mysql -e "UPDATE mysql.user SET authentication_string=PASSWORD('$new_root_pass') WHERE User='root';"
        mysql -e "UPDATE mysql.user SET plugin='mysql_native_password' WHERE User='root';"
        mysql -e "FLUSH PRIVILEGES;"
        
        # Kill safe mode
        kill $mysql_pid 2>/dev/null
        sleep 2
        
        # Update credentials file
        cat > /root/.my.cnf <<EOF
[client]
user=root
password=$new_root_pass
EOF
        chmod 600 /root/.my.cnf
        
        # Start MySQL normally
        systemctl start "$mysql_service"
        
        print_message "✓ MySQL root password reset"
    fi
    
    print_message "✓ MySQL configuration fixed"
    return 0
}

# Create IP management script
create_add_ip_script() {
    print_message "Creating IP management script..."
    
    cat > /usr/local/bin/add-mail-ip <<'EOF'
#!/bin/bash

# IP Management Script for Multi-IP Mail Server
show_usage() {
    echo "IP Management for Mail Server"
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  add <ip> [hostname]      Add new IP to mail server"
    echo "  remove <ip>              Remove IP from mail server"
    echo "  list                     List configured IPs"
    echo "  test <ip>                Test IP configuration"
    echo "  rotate                   Enable IP rotation"
    echo "  warmup <ip>              Start IP warmup"
    exit 1
}

add_ip() {
    local ip=$1
    local hostname=${2:-mail-$(date +%s).$(hostname -d)}
    
    echo "Adding IP: $ip"
    echo "Hostname: $hostname"
    
    # Validate IP
    if ! [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        echo "Error: Invalid IP address format"
        exit 1
    fi
    
    # Get primary interface
    local interface=$(ip route | grep '^default' | awk '{print $5}' | head -1)
    
    if [ -z "$interface" ]; then
        echo "Error: Could not detect network interface"
        exit 1
    fi
    
    echo "Interface: $interface"
    
    # Add IP to interface
    echo "Adding IP to interface..."
    ip addr add "$ip/24" dev "$interface"
    
    if [ $? -ne 0 ]; then
        echo "Error: Failed to add IP to interface"
        exit 1
    fi
    
    # Make persistent
    echo "Making configuration persistent..."
    
    # For Ubuntu/Debian with Netplan
    if [ -d /etc/netplan ]; then
        local netplan_file="/etc/netplan/60-additional-ips.yaml"
        
        if [ ! -f "$netplan_file" ]; then
            cat > "$netplan_file" <<YAML
network:
  version: 2
  ethernets:
    $interface:
      addresses:
        - $ip/24
YAML
        else
            # Add to existing file
            sed -i "/addresses:/a\\        - $ip/24" "$netplan_file"
        fi
        
        netplan apply
    
    # For older systems with interfaces file
    elif [ -f /etc/network/interfaces ]; then
        cat >> /etc/network/interfaces <<INTERFACES

auto ${interface}:${ip//\./_}
iface ${interface}:${ip//\./_} inet static
    address $ip
    netmask 255.255.255.0
INTERFACES
    fi
    
    # Update Postfix configuration
    echo "Updating Postfix configuration..."
    
    # Add to transport map
    echo "$hostname smtp:[$ip]" >> /etc/postfix/transport
    postmap /etc/postfix/transport
    
    # Add to sender transport
    echo "@$hostname [$ip]:25" >> /etc/postfix/sender_transport
    postmap /etc/postfix/sender_transport
    
    # Reload Postfix
    postfix reload
    
    # Add to IP pool for rotation
    echo "$ip" >> /etc/postfix/ip_pool
    
    # Initialize IP warmup
    if command -v ip-warmup-manager &>/dev/null; then
        ip-warmup-manager init "$ip" "$hostname"
    fi
    
    echo ""
    echo "✓ IP $ip successfully added"
    echo ""
    echo "Next steps:"
    echo "1. Configure reverse DNS: $ip -> $hostname"
    echo "2. Update SPF record to include: ip4:$ip"
    echo "3. Start warmup process: ip-warmup-manager status $ip"
    echo ""
    echo "DNS Records to add:"
    echo "  A record: $hostname -> $ip"
    echo "  PTR record: $ip -> $hostname (contact your provider)"
}

remove_ip() {
    local ip=$1
    
    echo "Removing IP: $ip"
    
    # Get interface
    local interface=$(ip addr show | grep "$ip" | awk '{print $NF}')
    
    if [ -z "$interface" ]; then
        echo "IP not found on any interface"
        exit 1
    fi
    
    # Remove from interface
    ip addr del "$ip/24" dev "$interface"
    
    # Remove from persistent config
    if [ -d /etc/netplan ]; then
        sed -i "/$ip/d" /etc/netplan/60-additional-ips.yaml
        netplan apply
    elif [ -f /etc/network/interfaces ]; then
        sed -i "/${ip//\./\\.}/,+3d" /etc/network/interfaces
    fi
    
    # Remove from Postfix
    sed -i "/$ip/d" /etc/postfix/transport
    sed -i "/$ip/d" /etc/postfix/sender_transport
    sed -i "/$ip/d" /etc/postfix/ip_pool
    
    postmap /etc/postfix/transport
    postmap /etc/postfix/sender_transport
    postfix reload
    
    echo "✓ IP $ip removed"
}

list_ips() {
    echo "CONFIGURED IP ADDRESSES"
    echo "======================="
    echo ""
    
    echo "System IPs:"
    ip -4 addr show | grep inet | grep -v "127.0.0.1" | awk '{print "  " $2 " on " $NF}'
    echo ""
    
    if [ -f /etc/postfix/ip_pool ]; then
        echo "Mail Server IP Pool:"
        cat /etc/postfix/ip_pool | while read ip; do
            echo "  $ip"
        done
        echo ""
    fi
    
    if command -v ip-warmup-manager &>/dev/null; then
        echo "IP Warmup Status:"
        ip-warmup-manager status
    fi
}

test_ip() {
    local ip=$1
    
    echo "Testing IP: $ip"
    echo ""
    
    # Check if IP is configured
    echo -n "1. IP configured on interface: "
    ip addr show | grep -q "inet $ip/" && echo "✓" || echo "✗"
    
    # Check outbound connectivity
    echo -n "2. Outbound connectivity: "
    curl --interface "$ip" -s -o /dev/null -w "%{http_code}" https://www.google.com | grep -q "200" && echo "✓" || echo "✗"
    
    # Check Postfix configuration
    echo -n "3. Postfix transport configured: "
    grep -q "$ip" /etc/postfix/transport && echo "✓" || echo "✗"
    
    # Check DNS
    echo -n "4. Reverse DNS: "
    dig +short -x "$ip" || echo "Not configured"
    
    # Send test email
    echo ""
    read -p "Send test email from this IP? (y/n): " send_test
    
    if [ "$send_test" = "y" ]; then
        echo "Test email from $ip" | mail -s "Test from $ip" check-auth@verifier.port25.com
        echo "Test email sent to check-auth@verifier.port25.com"
    fi
}

# Main execution
case "$1" in
    add)
        [ -z "$2" ] && show_usage
        add_ip "$2" "$3"
        ;;
    remove)
        [ -z "$2" ] && show_usage
        remove_ip "$2"
        ;;
    list)
        list_ips
        ;;
    test)
        [ -z "$2" ] && show_usage
        test_ip "$2"
        ;;
    rotate)
        systemctl enable ip-rotation.timer
        systemctl start ip-rotation.timer
        echo "✓ IP rotation enabled"
        ;;
    warmup)
        [ -z "$2" ] && show_usage
        ip-warmup-manager init "$2"
        ;;
    *)
        show_usage
        ;;
esac
EOF
    
    chmod +x /usr/local/bin/add-mail-ip
    print_message "✓ IP management script created"
}

# Create mail server control panel
create_control_panel() {
    print_message "Creating mail server control panel..."
    
    cat > /usr/local/bin/mail-control <<'EOF'
#!/bin/bash

# Mail Server Control Panel
clear

show_menu() {
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║           MAIL SERVER CONTROL PANEL                          ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    echo "  1. Service Management"
    echo "  2. IP Configuration"
    echo "  3. Email Accounts"
    echo "  4. Queue Management"
    echo "  5. Security & Firewall"
    echo "  6. Monitoring & Stats"
    echo "  7. Backup & Restore"
    echo "  8. DNS & SSL"
    echo "  9. MailWizz Integration"
    echo " 10. Diagnostics"
    echo " 11. Documentation"
    echo "  0. Exit"
    echo ""
    echo -n "Select option: "
}

service_management() {
    clear
    echo "SERVICE MANAGEMENT"
    echo "=================="
    echo ""
    echo "1. Start all services"
    echo "2. Stop all services"
    echo "3. Restart all services"
    echo "4. Service status"
    echo "5. View logs"
    echo "0. Back"
    echo ""
    echo -n "Select: "
    read choice
    
    case $choice in
        1)
            systemctl start postfix dovecot opendkim mysql
            echo "Services started"
            ;;
        2)
            systemctl stop postfix dovecot opendkim
            echo "Services stopped"
            ;;
        3)
            systemctl restart postfix dovecot opendkim mysql
            echo "Services restarted"
            ;;
        4)
            systemctl status postfix dovecot opendkim mysql --no-pager
            ;;
        5)
            tail -f /var/log/mail.log
            ;;
    esac
    
    echo ""
    read -p "Press Enter to continue..."
}

ip_configuration() {
    clear
    echo "IP CONFIGURATION"
    echo "================"
    echo ""
    echo "1. List configured IPs"
    echo "2. Add new IP"
    echo "3. Remove IP"
    echo "4. Test IP"
    echo "5. IP warmup status"
    echo "6. Enable rotation"
    echo "0. Back"
    echo ""
    echo -n "Select: "
    read choice
    
    case $choice in
        1) add-mail-ip list ;;
        2) 
            read -p "Enter IP address: " ip
            read -p "Enter hostname (optional): " hostname
            add-mail-ip add "$ip" "$hostname"
            ;;
        3)
            read -p "Enter IP to remove: " ip
            add-mail-ip remove "$ip"
            ;;
        4)
            read -p "Enter IP to test: " ip
            add-mail-ip test "$ip"
            ;;
        5) ip-warmup-manager status ;;
        6) add-mail-ip rotate ;;
    esac
    
    echo ""
    read -p "Press Enter to continue..."
}

email_accounts() {
    clear
    echo "EMAIL ACCOUNT MANAGEMENT"
    echo "========================"
    echo ""
    echo "1. List accounts"
    echo "2. Add account"
    echo "3. Delete account"
    echo "4. Change password"
    echo "5. Set quota"
    echo "6. Account info"
    echo "0. Back"
    echo ""
    echo -n "Select: "
    read choice
    
    case $choice in
        1) mail-account list ;;
        2)
            read -p "Email address: " email
            read -s -p "Password: " password
            echo ""
            mail-account add "$email" "$password"
            ;;
        3)
            read -p "Email to delete: " email
            mail-account delete "$email"
            ;;
        4)
            read -p "Email address: " email
            read -s -p "New password: " password
            echo ""
            mail-account password "$email" "$password"
            ;;
        5)
            read -p "Email address: " email
            read -p "Quota (e.g., 1G): " quota
            mail-account quota "$email" "$quota"
            ;;
        6)
            read -p "Email address: " email
            mail-account info "$email"
            ;;
    esac
    
    echo ""
    read -p "Press Enter to continue..."
}

monitoring_stats() {
    clear
    mail-stats dashboard
    echo ""
    read -p "Press Enter to continue..."
}

show_documentation() {
    clear
    echo "MAIL SERVER DOCUMENTATION"
    echo "========================="
    echo ""
    echo "Configuration Files:"
    echo "  /etc/postfix/main.cf         - Postfix main configuration"
    echo "  /etc/postfix/master.cf       - Postfix process configuration"
    echo "  /etc/dovecot/dovecot.conf    - Dovecot configuration"
    echo "  /etc/opendkim/opendkim.conf  - OpenDKIM configuration"
    echo ""
    echo "Log Files:"
    echo "  /var/log/mail.log            - Main mail log"
    echo "  /var/log/mail.err            - Mail errors"
    echo "  /var/log/mail-monitoring.log - Monitoring log"
    echo ""
    echo "Utilities:"
    echo "  mail-account    - Manage email accounts"
    echo "  mail-backup     - Backup server"
    echo "  mail-queue      - Queue management"
    echo "  mail-diagnostic - Run diagnostics"
    echo "  mail-stats      - View statistics"
    echo "  test-email      - Send test emails"
    echo "  add-mail-ip     - IP management"
    echo ""
    echo "Support:"
    echo "  GitHub: https://github.com/fumingtomato/shibi"
    echo "  Logs: /var/log/mail-installer-*.log"
    echo ""
    read -p "Press Enter to continue..."
}

# Main loop
while true; do
    clear
    show_menu
    read choice
    
    case $choice in
        1) service_management ;;
        2) ip_configuration ;;
        3) email_accounts ;;
        4) mail-queue status; read -p "Press Enter..." ;;
        5) mail-security-audit; read -p "Press Enter..." ;;
        6) monitoring_stats ;;
        7) 
            echo "1. Backup  2. Restore"
            read -n1 br_choice
            case $br_choice in
                1) mail-backup full ;;
                2) mail-restore ;;
            esac
            read -p "Press Enter..."
            ;;
        8) verify-dns; verify-ssl; read -p "Press Enter..." ;;
        9) mailwizz-campaign-stats; read -p "Press Enter..." ;;
        10) mail-diagnostic; read -p "Press Enter..." ;;
        11) show_documentation ;;
        0) exit 0 ;;
        *) echo "Invalid option" ;;
    esac
done
EOF
    
    chmod +x /usr/local/bin/mail-control
    print_message "✓ Control panel created"
    
    # Create desktop shortcut if GUI is available
    if [ -n "$DISPLAY" ] && [ -d ~/Desktop ]; then
        cat > ~/Desktop/mail-control.desktop <<EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=Mail Server Control
Comment=Mail Server Control Panel
Exec=gnome-terminal -- /usr/local/bin/mail-control
Icon=utilities-terminal
Terminal=false
Categories=System;
EOF
        chmod +x ~/Desktop/mail-control.desktop
    fi
}

# Create system information script
create_system_info_script() {
    cat > /usr/local/bin/mail-info <<'EOF'
#!/bin/bash

# Mail Server Information Script
echo "MAIL SERVER INFORMATION"
echo "======================="
echo ""

# Server details
echo "Server Details:"
echo "  Hostname: $(hostname -f)"
echo "  Primary IP: $(hostname -I | awk '{print $1}')"
echo "  OS: $(lsb_release -d | cut -f2)"
echo "  Kernel: $(uname -r)"
echo "  Uptime: $(uptime -p)"
echo ""

# Mail configuration
echo "Mail Configuration:"
echo "  Postfix Version: $(postconf -d mail_version | cut -d' ' -f3)"
echo "  Dovecot Version: $(dovecot --version 2>/dev/null | head -1)"
echo "  OpenDKIM Version: $(opendkim -V 2>&1 | head -1)"
echo ""

# IP configuration
echo "IP Addresses:"
ip -4 addr show | grep inet | grep -v "127.0.0.1" | awk '{print "  " $2 " on " $NF}'
echo ""

# DNS configuration
DOMAIN=$(hostname -d)
echo "DNS Configuration:"
echo "  Domain: $DOMAIN"
echo -n "  MX Record: "
dig +short MX "$DOMAIN" | head -1 || echo "Not configured"
echo -n "  SPF Record: "
dig +short TXT "$DOMAIN" | grep "v=spf1" | head -1 || echo "Not configured"
echo ""

# Statistics
echo "Statistics:"
echo "  Total emails in queue: $(mailq | grep -c '^[A-F0-9]' || echo 0)"

if [ -f /var/lib/mail-monitoring/mail_stats.db ]; then
    TODAY_SENT=$(sqlite3 /var/lib/mail-monitoring/mail_stats.db \
        "SELECT COALESCE(SUM(emails_sent), 0) FROM mail_stats WHERE date(timestamp) = date('now')" 2>/dev/null || echo 0)
    echo "  Emails sent today: $TODAY_SENT"
fi

if [ -f /var/lib/postfix/sticky_ip.db ]; then
    ACTIVE_SENDERS=$(sqlite3 /var/lib/postfix/sticky_ip.db \
        "SELECT COUNT(*) FROM sticky_mappings" 2>/dev/null || echo 0)
    echo "  Active senders: $ACTIVE_SENDERS"
fi

echo ""

# Storage
echo "Storage Usage:"
df -h / /var/vmail 2>/dev/null | grep -v Filesystem
echo ""

# Services
echo "Service Status:"
for service in postfix dovecot mysql opendkim; do
    printf "  %-10s: " "$service"
    systemctl is-active "$service" || echo "stopped"
done
EOF
    
    chmod +x /usr/local/bin/mail-info
    print_message "✓ System info script created"
}

# Create quick setup wizard
create_quick_setup_wizard() {
    cat > /usr/local/bin/mail-quick-setup <<'EOF'
#!/bin/bash

# Quick Setup Wizard for Mail Server
echo "MAIL SERVER QUICK SETUP WIZARD"
echo "=============================="
echo ""

# Collect information
read -p "Primary domain name: " DOMAIN
read -p "Admin email address: " ADMIN_EMAIL
read -p "Primary hostname (default: mail.$DOMAIN): " HOSTNAME
HOSTNAME=${HOSTNAME:-mail.$DOMAIN}

echo ""
echo "IP Configuration:"
echo "1. Single IP"
echo "2. Multiple IPs"
read -p "Select (1-2): " IP_CHOICE

IPS=()
if [ "$IP_CHOICE" = "2" ]; then
    echo "Enter IP addresses (one per line, empty to finish):"
    while true; do
        read -p "IP: " IP
        [ -z "$IP" ] && break
        IPS+=("$IP")
    done
else
    PUBLIC_IP=$(curl -s https://ipinfo.io/ip)
    echo "Using public IP: $PUBLIC_IP"
    IPS=("$PUBLIC_IP")
fi

echo ""
echo "Configuration Summary:"
echo "  Domain: $DOMAIN"
echo "  Hostname: $HOSTNAME"
echo "  Admin: $ADMIN_EMAIL"
echo "  IPs: ${IPS[*]}"
echo ""
read -p "Proceed with setup? (y/n): " PROCEED

if [ "$PROCEED" != "y" ]; then
    echo "Setup cancelled"
    exit 0
fi

echo ""
echo "Starting setup..."

# Update system
echo "1. Updating system packages..."
apt-get update && apt-get upgrade -y

# Set hostname
echo "2. Setting hostname..."
hostnamectl set-hostname "$HOSTNAME"
echo "$HOSTNAME" > /etc/hostname

# Install mail server
echo "3. Installing mail server components..."
apt-get install -y postfix postfix-mysql dovecot-core dovecot-imapd \
    dovecot-mysql opendkim opendkim-tools mysql-server

# Configure MySQL
echo "4. Setting up database..."
MYSQL_PASS=$(openssl rand -base64 32)
mysql -e "CREATE DATABASE IF NOT EXISTS mailserver;"
mysql -e "CREATE USER IF NOT EXISTS 'mailuser'@'localhost' IDENTIFIED BY '$MYSQL_PASS';"
mysql -e "GRANT ALL PRIVILEGES ON mailserver.* TO 'mailuser'@'localhost';"
mysql -e "FLUSH PRIVILEGES;"

echo "$MYSQL_PASS" > /root/.mail_db_password
chmod 600 /root/.mail_db_password

# Basic Postfix configuration
echo "5. Configuring Postfix..."
postconf -e "myhostname = $HOSTNAME"
postconf -e "mydomain = $DOMAIN"
postconf -e "myorigin = \$mydomain"
postconf -e "mydestination = "
postconf -e "virtual_transport = lmtp:unix:private/dovecot-lmtp"

# Setup DKIM
echo "6. Setting up DKIM..."
mkdir -p /etc/opendkim/keys/$DOMAIN
cd /etc/opendkim/keys/$DOMAIN
opendkim-genkey -s mail -d $DOMAIN
chown -R opendkim:opendkim /etc/opendkim

# Configure IPs
echo "7. Configuring IP addresses..."
for IP in "${IPS[@]}"; do
    add-mail-ip add "$IP" "mail-${IP//\./-}.$DOMAIN" 2>/dev/null || true
done

# Create admin account
echo "8. Creating admin email account..."
read -s -p "Admin password: " ADMIN_PASS
echo ""
mail-account add "$ADMIN_EMAIL" "$ADMIN_PASS" 2>/dev/null || true

# Start services
echo "9. Starting services..."
systemctl restart postfix dovecot opendkim mysql

echo ""
echo "✓ Quick setup complete!"
echo ""
echo "Next steps:"
echo "1. Add DNS records (check /root/dns-records.txt)"
echo "2. Configure SSL: certbot certonly --standalone -d $HOSTNAME"
echo "3. Test email: test-email $ADMIN_EMAIL"
echo "4. Access control panel: mail-control"
echo ""
echo "DKIM Record:"
cat /etc/opendkim/keys/$DOMAIN/mail.txt
EOF
    
    chmod +x /usr/local/bin/mail-quick-setup
    print_message "✓ Quick setup wizard created"
}

# Export all functions from part 2
export -f init_mysql_postfix_config
export -f fix_mysql_config
export -f create_add_ip_script
export -f create_control_panel
export -f create_system_info_script
export -f create_quick_setup_wizard

# Create completion message function
show_completion_message() {
    clear
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║         MAIL SERVER INSTALLATION COMPLETE!                   ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    echo "Server Information:"
    echo "  Domain: ${DOMAIN_NAME}"
    echo "  Hostname: ${HOSTNAME}"
    echo "  Primary IP: ${PRIMARY_IP}"
    echo "  Admin Email: ${ADMIN_EMAIL}"
    echo ""
    echo "Quick Commands:"
    echo "  mail-control     - Open control panel"
    echo "  mail-info        - Show server information"
    echo "  mail-account     - Manage email accounts"
    echo "  mail-diagnostic  - Run diagnostics"
    echo "  test-email       - Send test email"
    echo ""
    echo "Configuration Files:"
    echo "  DNS Records: /root/dns-records.txt"
    echo "  DKIM Record: /root/dkim-record-${DOMAIN_NAME}.txt"
    echo "  SPF Record: /root/spf-record-${DOMAIN_NAME}.txt"
    echo ""
    echo "Next Steps:"
    echo "  1. Configure DNS records as shown in the files above"
    echo "  2. Set up SSL certificate: certbot certonly --standalone -d ${HOSTNAME}"
    echo "  3. Test email delivery: test-email check-auth@verifier.port25.com"
    echo "  4. Monitor IP warmup: ip-warmup-manager status"
    echo ""
    echo "Support:"
    echo "  GitHub: https://github.com/fumingtomato/shibi"
    echo "  Logs: /var/log/mail-installer-*.log"
    echo ""
    echo "Thank you for using the Multi-IP Mail Server Installer!"
    echo ""
}

export -f show_completion_message
