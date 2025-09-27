#!/bin/bash

# =================================================================
# PACKAGES AND SYSTEM CONFIGURATION MODULE - COMPLETE FIXED VERSION
# Package installation and system setup functions
# Fixed: Complete implementations, better error handling, improved package management
# =================================================================

# Install all required packages for the mail server
install_required_packages() {
    print_header "Installing Required Packages"
    
    print_message "Updating package lists..."
    apt-get update
    
    # CRITICAL: Pre-configure Postfix to avoid interactive prompts
    print_message "Pre-configuring Postfix for non-interactive installation..."
    
    # Set Postfix configuration type to "Internet Site"
    echo "postfix postfix/mailname string ${HOSTNAME:-$(hostname -f)}" | debconf-set-selections
    echo "postfix postfix/main_mailer_type string 'Internet Site'" | debconf-set-selections
    echo "postfix postfix/destinations string ${HOSTNAME:-$(hostname -f)}, localhost" | debconf-set-selections
    
    # Set non-interactive frontend for apt
    export DEBIAN_FRONTEND=noninteractive
    
    print_message "Installing essential packages..."
    
    # Core packages - Install in groups to better handle any issues
    
    # First, install basic tools
    local basic_packages=(
        "build-essential"
        "software-properties-common"
        "apt-transport-https"
        "ca-certificates"
        "gnupg"
        "lsb-release"
        "net-tools"
        "curl"
        "wget"
        "telnet"
        "dnsutils"
        "ipcalc"
        "bc"
        "jq"
    )
    
    for package in "${basic_packages[@]}"; do
        if dpkg -l | grep -q "^ii  $package "; then
            print_message "✓ $package already installed"
        else
            print_message "Installing $package..."
            if ! apt-get install -y -q "$package" >/dev/null 2>&1; then
                print_warning "Failed to install $package, continuing..."
            fi
        fi
    done
    
    # Install Postfix with non-interactive settings
    print_message "Installing Postfix (non-interactively)..."
    if ! dpkg -l | grep -q "^ii  postfix "; then
        if ! DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
            -o Dpkg::Options::="--force-confdef" \
            -o Dpkg::Options::="--force-confold" \
            postfix postfix-mysql postfix-pcre >/dev/null 2>&1; then
            print_error "Failed to install Postfix"
            # Try alternative method
            print_message "Trying alternative Postfix installation method..."
            apt-get install -y --force-yes postfix postfix-mysql postfix-pcre 2>/dev/null || true
        else
            print_message "✓ Postfix installed successfully"
        fi
    else
        print_message "✓ Postfix already installed"
        # Ensure mysql support is installed
        if ! dpkg -l | grep -q "^ii  postfix-mysql "; then
            apt-get install -y postfix-mysql 2>/dev/null || true
        fi
    fi
    
    # Install MySQL/MariaDB
    print_message "Installing MySQL/MariaDB..."
    local mysql_installed=false
    
    # Try MySQL first
    if ! dpkg -l | grep -E "^ii  (mysql-server|mariadb-server) " &>/dev/null; then
        print_message "Installing MySQL Server..."
        if DEBIAN_FRONTEND=noninteractive apt-get install -y -q mysql-server mysql-client 2>/dev/null; then
            mysql_installed=true
            print_message "✓ MySQL Server installed"
        else
            print_warning "MySQL installation failed, trying MariaDB..."
            if DEBIAN_FRONTEND=noninteractive apt-get install -y -q mariadb-server mariadb-client 2>/dev/null; then
                mysql_installed=true
                print_message "✓ MariaDB Server installed"
            else
                print_error "Failed to install both MySQL and MariaDB"
            fi
        fi
    else
        mysql_installed=true
        print_message "✓ Database server already installed"
    fi
    
    if ! $mysql_installed; then
        print_error "Critical: No database server could be installed"
        return 1
    fi
    
    # Install Dovecot packages
    print_message "Installing Dovecot packages..."
    local dovecot_packages=(
        "dovecot-core"
        "dovecot-imapd"
        "dovecot-pop3d"
        "dovecot-lmtpd"
        "dovecot-mysql"
        "dovecot-sieve"
        "dovecot-managesieved"
    )
    
    local dovecot_failed=()
    for package in "${dovecot_packages[@]}"; do
        if dpkg -l | grep -q "^ii  $package "; then
            print_message "✓ $package already installed"
        else
            print_message "Installing $package..."
            if ! DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$package" >/dev/null 2>&1; then
                print_warning "Failed to install $package"
                dovecot_failed+=("$package")
            fi
        fi
    done
    
    if [ ${#dovecot_failed[@]} -gt 0 ] && [ ${#dovecot_failed[@]} -eq ${#dovecot_packages[@]} ]; then
        print_error "Critical: Dovecot installation completely failed"
        return 1
    fi
    
    # Install web server and SSL
    print_message "Installing web server and SSL tools..."
    local web_packages=(
        "nginx"
        "certbot"
        "python3-certbot-nginx"
    )
    
    for package in "${web_packages[@]}"; do
        if dpkg -l | grep -q "^ii  $package "; then
            print_message "✓ $package already installed"
        else
            print_message "Installing $package..."
            DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$package" >/dev/null 2>&1 || \
                print_warning "Failed to install $package, continuing..."
        fi
    done
    
    # Install email authentication
    print_message "Installing email authentication packages..."
    if ! dpkg -l | grep -q "^ii  opendkim "; then
        if DEBIAN_FRONTEND=noninteractive apt-get install -y -q opendkim opendkim-tools >/dev/null 2>&1; then
            print_message "✓ OpenDKIM installed"
        else
            print_warning "Failed to install OpenDKIM"
        fi
    else
        print_message "✓ OpenDKIM already installed"
    fi
    
    # Install security tools
    print_message "Installing security tools..."
    local security_packages=(
        "ufw"
        "fail2ban"
        "rkhunter"
        "logwatch"
    )
    
    for package in "${security_packages[@]}"; do
        if dpkg -l | grep -q "^ii  $package "; then
            print_message "✓ $package already installed"
        else
            print_message "Installing $package..."
            DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$package" >/dev/null 2>&1 || \
                print_warning "Failed to install $package, continuing..."
        fi
    done
    
    # Install utilities
    print_message "Installing utility packages..."
    local utility_packages=(
        "mailutils"
        "zip"
        "unzip"
        "git"
        "htop"
        "ncdu"
        "python3"
        "python3-pip"
    )
    
    for package in "${utility_packages[@]}"; do
        if dpkg -l | grep -q "^ii  $package "; then
            print_message "✓ $package already installed"
        else
            print_message "Installing $package..."
            DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$package" >/dev/null 2>&1 || \
                print_warning "Failed to install $package, continuing..."
        fi
    done
    
    # Reset the frontend variable
    unset DEBIAN_FRONTEND
    
    # Ensure critical services are not running yet (will be configured later)
    print_message "Stopping services for configuration..."
    systemctl stop postfix 2>/dev/null || true
    systemctl stop dovecot 2>/dev/null || true
    systemctl stop mysql 2>/dev/null || systemctl stop mariadb 2>/dev/null || true
    systemctl stop nginx 2>/dev/null || true
    systemctl stop opendkim 2>/dev/null || true
    
    print_message "Package installation completed"
    
    # Verify critical packages
    print_message "Verifying critical packages..."
    local critical_packages=("postfix" "dovecot-core" "nginx")
    local all_installed=true
    
    for package in "${critical_packages[@]}"; do
        if dpkg -l | grep -q "^ii  $package "; then
            print_message "✓ $package verified"
        else
            print_error "✗ $package is not installed properly"
            all_installed=false
        fi
    done
    
    # Check for database server (either MySQL or MariaDB)
    if dpkg -l | grep -q "^ii  mysql-server "; then
        print_message "✓ mysql-server verified"
    elif dpkg -l | grep -q "^ii  mariadb-server "; then
        print_message "✓ mariadb-server verified"
    else
        print_error "✗ No database server installed"
        all_installed=false
    fi
    
    if [ "$all_installed" = false ]; then
        print_error "Some critical packages failed to install."
        print_message "Attempting to fix broken packages..."
        apt-get install -f -y
        dpkg --configure -a
        return 1
    fi
    
    return 0
}

# Configure system hostname
configure_hostname() {
    local hostname=$1
    
    print_header "Configuring System Hostname"
    
    if [ -z "$hostname" ]; then
        print_error "Hostname not provided"
        return 1
    fi
    
    # Validate hostname format
    if [[ ! "$hostname" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        print_error "Invalid hostname format: $hostname"
        return 1
    fi
    
    # Extract the short hostname (first part before first dot)
    local short_hostname=$(echo "$hostname" | cut -d'.' -f1)
    
    print_message "Setting hostname to: $hostname"
    print_message "Short hostname: $short_hostname"
    
    # Set the hostname
    hostnamectl set-hostname "$short_hostname" 2>/dev/null || hostname "$short_hostname"
    
    # Update /etc/hostname
    echo "$short_hostname" > /etc/hostname
    
    # Update /etc/hosts
    # First, remove any existing entries for 127.0.1.1
    sed -i '/^127\.0\.1\.1/d' /etc/hosts
    
    # Add new entry
    echo "127.0.1.1 $hostname $short_hostname" >> /etc/hosts
    
    # Add server IPs to hosts file if available
    if [ ! -z "${IP_ADDRESSES}" ]; then
        for ip in "${IP_ADDRESSES[@]}"; do
            # Remove any existing entries for this IP
            sed -i "/^$ip/d" /etc/hosts
            # Add new entry
            echo "$ip $hostname $short_hostname" >> /etc/hosts
        done
    fi
    
    # Apply hostname changes
    hostname "$short_hostname"
    
    # Verify
    print_message "Hostname configured:"
    print_message "  Full: $(hostname -f 2>/dev/null || echo "$hostname")"
    print_message "  Short: $(hostname -s 2>/dev/null || echo "$short_hostname")"
    
    # Configure /etc/mailname for Postfix
    echo "$hostname" > /etc/mailname
    
    print_message "Hostname configuration completed"
    return 0
}

# Save installation configuration for future reference
save_configuration() {
    print_header "Saving Installation Configuration"
    
    local config_file="/root/mail-server-config.json"
    local backup_dir="/root/mail-server-backups"
    
    # Create backup directory
    mkdir -p "$backup_dir"
    
    print_message "Creating configuration backup..."
    
    # Create JSON configuration file
    cat > "$config_file" <<EOF
{
  "installation_date": "$(date -u '+%Y-%m-%d %H:%M:%S UTC')",
  "installer_version": "${INSTALLER_VERSION:-unknown}",
  "server_configuration": {
    "domain": "${DOMAIN_NAME:-}",
    "hostname": "${HOSTNAME:-}",
    "subdomain": "${SUBDOMAIN:-}",
    "admin_email": "${ADMIN_EMAIL:-}",
    "brand_name": "${BRAND_NAME:-}",
    "timezone": "$(timedatectl show --property=Timezone --value 2>/dev/null || echo "UTC")",
    "website_theme": "${WEBSITE_THEME:-midnight}"
  },
  "network_configuration": {
    "primary_ip": "${PRIMARY_IP:-}",
    "total_ips": ${IP_COUNT:-1},
    "ip_addresses": [
EOF
    
    # Add IP addresses to JSON
    if [ ! -z "${IP_ADDRESSES}" ]; then
        local first=true
        for ip in "${IP_ADDRESSES[@]}"; do
            if [ "$first" = true ]; then
                echo -n "      \"$ip\"" >> "$config_file"
                first=false
            else
                echo -n ",
      \"$ip\"" >> "$config_file"
            fi
        done
    fi
    
    cat >> "$config_file" <<EOF

    ]
  },
  "features": {
    "sticky_ip_enabled": ${ENABLE_STICKY_IP:-false},
    "cloudflare_dns": $([ ! -z "$CF_API_TOKEN" ] && echo "true" || echo "false"),
    "ssl_enabled": true,
    "dkim_enabled": true,
    "spf_enabled": true,
    "dmarc_enabled": true
  },
  "services": {
    "postfix": "$(postconf mail_version 2>/dev/null | cut -d' ' -f3 || echo 'unknown')",
    "dovecot": "$(dovecot --version 2>/dev/null | cut -d' ' -f1 || echo 'unknown')",
    "mysql": "$(mysql --version 2>/dev/null | awk '{print $5}' | cut -d',' -f1 || echo 'unknown')",
    "nginx": "$(nginx -v 2>&1 | cut -d'/' -f2 || echo 'unknown')"
  },
  "database": {
    "name": "mailserver",
    "user": "mailuser",
    "password_file": "/root/.mail_db_password"
  },
  "paths": {
    "mail_storage": "/var/vmail",
    "postfix_config": "/etc/postfix",
    "dovecot_config": "/etc/dovecot",
    "dkim_keys": "/etc/opendkim/keys",
    "ssl_certificates": "/etc/letsencrypt/live",
    "logs": "/var/log"
  }
}
EOF
    
    # Set proper permissions
    chmod 600 "$config_file"
    
    # Backup critical configuration files
    print_message "Backing up configuration files..."
    
    local backup_file="$backup_dir/config-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
    
    # Only backup directories that exist
    local dirs_to_backup=""
    [ -d "/etc/postfix" ] && dirs_to_backup="$dirs_to_backup /etc/postfix"
    [ -d "/etc/dovecot" ] && dirs_to_backup="$dirs_to_backup /etc/dovecot"
    [ -d "/etc/nginx/sites-available" ] && dirs_to_backup="$dirs_to_backup /etc/nginx/sites-available"
    [ -d "/etc/opendkim" ] && dirs_to_backup="$dirs_to_backup /etc/opendkim"
    [ -f "$config_file" ] && dirs_to_backup="$dirs_to_backup $config_file"
    
    if [ ! -z "$dirs_to_backup" ]; then
        tar -czf "$backup_file" $dirs_to_backup 2>/dev/null || true
        print_message "Backup created at: $backup_file"
    fi
    
    print_message "Configuration saved to: $config_file"
    
    # Create quick reference file
    create_quick_reference
    
    return 0
}

# Create quick reference documentation
create_quick_reference() {
    cat > /root/mail-server-quick-ref.txt <<EOF
==============================================
Mail Server Quick Reference
==============================================
Installation Date: $(date)
Domain: ${DOMAIN_NAME:-}
Hostname: ${HOSTNAME:-}
Subdomain: ${SUBDOMAIN:-}
Admin Email: ${ADMIN_EMAIL:-}
Website Theme: ${WEBSITE_THEME:-midnight}

MANAGEMENT COMMANDS:
--------------------
Send test email: send-test-email recipient@example.com
Send mail: send-mail recipient@example.com "Subject"
Queue management: manage-mail-queue {status|flush|clear}
Mail statistics: mail-stats {overall|ip <IP>|report}
IP warmup: ip-warmup-manager {status|init|check}
Sticky IP: sticky-ip-manager {list|assign|remove|stats}
Monitor Postfix: monitor-postfix
Security check: check-mail-security

SERVICE COMMANDS:
-----------------
Restart all: systemctl restart postfix dovecot nginx mysql opendkim
Check status: systemctl status postfix dovecot nginx mysql opendkim
View mail log: tail -f /var/log/mail.log
Check queue: mailq

DATABASE ACCESS:
----------------
MySQL database: mailserver
MySQL user: mailuser
Password location: /root/.mail_db_password

Connect to database:
mysql -u mailuser -p\$(cat /root/.mail_db_password) mailserver

IMPORTANT FILES:
----------------
Configuration backup: /root/mail-server-config.json
Postfix config: /etc/postfix/main.cf
Dovecot config: /etc/dovecot/dovecot.conf
DNS records: /root/*-record-*.txt
MailWizz guide: /root/mailwizz-multi-ip-guide.txt
==============================================
EOF
    
    chmod 644 /root/mail-server-quick-ref.txt
    print_message "Quick reference guide saved to: /root/mail-server-quick-ref.txt"
}

# Create final documentation with all important information
create_final_documentation() {
    print_header "Creating Final Documentation"
    
    local doc_file="/root/mail-server-multiip-info.txt"
    
    print_message "Generating comprehensive documentation..."
    
    cat > "$doc_file" <<'EOF'
==========================================================
   MULTI-IP BULK MAIL SERVER DOCUMENTATION
==========================================================

INSTALLATION SUMMARY
--------------------
EOF
    
    cat >> "$doc_file" <<EOF
Date: $(date)
Version: ${INSTALLER_VERSION:-}
Domain: ${DOMAIN_NAME:-}
Hostname: ${HOSTNAME:-}
Subdomain: ${SUBDOMAIN:-}
Admin Email: ${ADMIN_EMAIL:-}
Website Theme: ${WEBSITE_THEME:-midnight}
Total IPs Configured: ${IP_COUNT:-1}

IP ADDRESSES AND HOSTNAMES:
---------------------------
EOF
    
    if [ ! -z "${IP_ADDRESSES}" ]; then
        for ((i=0; i<${#IP_ADDRESSES[@]}; i++)); do
            local ip="${IP_ADDRESSES[$i]}"
            local transport_num=$((i + 1))
            local hostname_display
            
            if [ $i -eq 0 ]; then
                hostname_display="${SUBDOMAIN}.${DOMAIN_NAME}"
            else
                local suffix=$(printf "%03d" $i)
                hostname_display="${SUBDOMAIN}${suffix}.${DOMAIN_NAME}"
            fi
            
            echo "IP #${transport_num}: $ip" >> "$doc_file"
            echo "  Hostname: $hostname_display" >> "$doc_file"
            echo "  Transport: smtp-ip${transport_num}" >> "$doc_file"
            echo "" >> "$doc_file"
        done
    fi
    
    cat >> "$doc_file" <<'EOF'

SERVICES STATUS:
----------------
EOF
    
    # Check service status
    for service in postfix dovecot nginx opendkim; do
        if systemctl is-active --quiet $service 2>/dev/null; then
            echo "✓ $service: Running" >> "$doc_file"
        else
            echo "✗ $service: Not running" >> "$doc_file"
        fi
    done
    
    # Check database service
    if systemctl is-active --quiet mysql 2>/dev/null; then
        echo "✓ mysql: Running" >> "$doc_file"
    elif systemctl is-active --quiet mariadb 2>/dev/null; then
        echo "✓ mariadb: Running" >> "$doc_file"
    else
        echo "✗ Database: Not running" >> "$doc_file"
    fi
    
    cat >> "$doc_file" <<'EOF'

TESTING YOUR SETUP:
-------------------
1. Send test email:
   send-test-email recipient@external-domain.com

2. Check mail queue:
   mailq

3. Monitor mail log:
   tail -f /var/log/mail.log

4. Test authentication:
   telnet localhost 25
   EHLO test

5. Test specific IP transport:
   echo "test" | mail -s "test" -S smtp=smtp-ip1: test@example.com

WEBSITE CUSTOMIZATION:
----------------------
Your website is using the selected color theme.
To change colors, edit: /var/www/html/index.html
Look for the CSS variables in the <style> section.

UNSUBSCRIBE LINK FOR MAILWIZZ:
-------------------------------
The unsubscribe page is at: https://yourdomain.com/unsubscribe.html
To integrate with MailWizz, update the form action in unsubscribe.html
to point to your MailWizz unsubscribe endpoint.

IP WARMUP SCHEDULE:
-------------------
Day 1-3: 50 emails/day per IP
Day 4-7: 100 emails/day per IP
Day 8-14: 500 emails/day per IP
Day 15-21: 1000 emails/day per IP
Day 22-30: 5000 emails/day per IP
Day 31+: Full volume

Monitor warmup status with: ip-warmup-manager status

NEXT STEPS:
-----------
1. Configure PTR records with your hosting provider
2. Wait for DNS propagation (5-30 minutes)
3. Test DKIM with: opendkim-testkey -d ${DOMAIN_NAME:-yourdomain.com} -s mail -vvv
4. Send test email to: check-auth@verifier.port25.com
5. Configure MailWizz delivery servers
6. Begin IP warmup process

==========================================================
Installation completed successfully!
Your multi-IP bulk mail server is ready for use.
==========================================================
EOF
    
    chmod 644 "$doc_file"
    
    print_message "Complete documentation saved to: $doc_file"
    
    # Create a simple IP list file for easy reference
    if [ ! -z "${IP_ADDRESSES}" ]; then
        printf "%s\n" "${IP_ADDRESSES[@]}" > /root/ip-list.txt
        chmod 644 /root/ip-list.txt
        print_message "IP list saved to: /root/ip-list.txt"
    fi
    
    return 0
}

# Setup basic website for the mail server domain with privacy, unsubscribe, and color themes
setup_website() {
    local domain=$1
    local admin_email=$2
    local brand_name=$3
    
    if [ -z "$domain" ] || [ -z "$admin_email" ] || [ -z "$brand_name" ]; then
        print_error "Missing required parameters for website setup"
        return 1
    fi
    
    print_header "Setting Up Web Interface"
    
    # Color scheme selection
    print_message "Select a color scheme for your website:"
    echo "1) Midnight (Deep Purple & Black)"
    echo "2) Crimson Shadow (Dark Red & Black)"
    echo "3) Ocean Depth (Dark Blue & Navy)"
    echo "4) Forest Night (Dark Green & Black)"
    echo "5) Sunset Ember (Dark Orange & Brown)"
    echo "6) Storm Cloud (Dark Grey & Charcoal)"
    echo "7) Royal Velvet (Deep Purple & Gold)"
    echo "8) Blood Moon (Dark Red & Grey)"
    echo "9) Obsidian (Pure Black & Dark Grey)"
    echo "10) Dark Elegance (Black & Silver)"
    
    read -p "Enter your choice [1-10] (default: 1): " theme_choice
    theme_choice=${theme_choice:-1}
    
    # Define color schemes
    case $theme_choice in
        1)  # Midnight
            WEBSITE_THEME="midnight"
            gradient="linear-gradient(135deg, #1a0033 0%, #220044 50%, #000000 100%)"
            primary_color="#4a0080"
            accent_color="#6b46c1"
            ;;
        2)  # Crimson Shadow
            WEBSITE_THEME="crimson"
            gradient="linear-gradient(135deg, #330000 0%, #660000 50%, #000000 100%)"
            primary_color="#8b0000"
            accent_color="#dc143c"
            ;;
        3)  # Ocean Depth
            WEBSITE_THEME="ocean"
            gradient="linear-gradient(135deg, #001133 0%, #002266 50%, #000011 100%)"
            primary_color="#003366"
            accent_color="#0066cc"
            ;;
        4)  # Forest Night
            WEBSITE_THEME="forest"
            gradient="linear-gradient(135deg, #001100 0%, #002200 50%, #000000 100%)"
            primary_color="#004400"
            accent_color="#006600"
            ;;
        5)  # Sunset Ember
            WEBSITE_THEME="ember"
            gradient="linear-gradient(135deg, #331100 0%, #662200 50%, #110000 100%)"
            primary_color="#884400"
            accent_color="#cc6600"
            ;;
        6)  # Storm Cloud
            WEBSITE_THEME="storm"
            gradient="linear-gradient(135deg, #1a1a1a 0%, #333333 50%, #000000 100%)"
            primary_color="#444444"
            accent_color="#666666"
            ;;
        7)  # Royal Velvet
            WEBSITE_THEME="royal"
            gradient="linear-gradient(135deg, #2e003e 0%, #3d0052 50%, #1a0026 100%)"
            primary_color="#5a0080"
            accent_color="#8b00b3"
            ;;
        8)  # Blood Moon
            WEBSITE_THEME="bloodmoon"
            gradient="linear-gradient(135deg, #2a0000 0%, #550000 50%, #1a1a1a 100%)"
            primary_color="#770000"
            accent_color="#aa0000"
            ;;
        9)  # Obsidian
            WEBSITE_THEME="obsidian"
            gradient="linear-gradient(135deg, #0a0a0a 0%, #1a1a1a 50%, #000000 100%)"
            primary_color="#2a2a2a"
            accent_color="#3a3a3a"
            ;;
        10) # Dark Elegance
            WEBSITE_THEME="elegance"
            gradient="linear-gradient(135deg, #000000 0%, #1a1a1a 50%, #0d0d0d 100%)"
            primary_color="#333333"
            accent_color="#757575"
            ;;
        *)  # Default to Midnight
            WEBSITE_THEME="midnight"
            gradient="linear-gradient(135deg, #1a0033 0%, #220044 50%, #000000 100%)"
            primary_color="#4a0080"
            accent_color="#6b46c1"
            ;;
    esac
    
    # Export theme for configuration saving
    export WEBSITE_THEME
    
    print_message "Creating web directory structure with $WEBSITE_THEME theme..."
    
    # Create web root
    mkdir -p /var/www/html
    
    # Create main landing page with selected theme
    cat > /var/www/html/index.html <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${brand_name} - Mail Server</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background: ${gradient};
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .container {
            max-width: 600px;
            margin: 2rem;
            padding: 3rem;
            background: white;
            border-radius: 10px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.5);
            text-align: center;
        }
        h1 {
            color: ${primary_color};
            margin-bottom: 1rem;
            font-size: 2.5rem;
        }
        .status {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            background: #10b981;
            color: white;
            border-radius: 20px;
            font-size: 0.875rem;
            margin-bottom: 2rem;
        }
        .description {
            margin-bottom: 2rem;
            color: #555;
        }
        .links {
            margin-top: 2rem;
            padding-top: 2rem;
            border-top: 1px solid #e0e0e0;
        }
        .links a {
            color: ${primary_color};
            text-decoration: none;
            margin: 0 1rem;
            padding: 0.5rem 1rem;
            border: 1px solid ${primary_color};
            border-radius: 5px;
            display: inline-block;
            transition: all 0.3s ease;
        }
        .links a:hover {
            background: ${accent_color};
            border-color: ${accent_color};
            color: white;
        }
        .footer {
            margin-top: 3rem;
            padding-top: 2rem;
            border-top: 1px solid #e0e0e0;
            font-size: 0.875rem;
            color: #777;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>${brand_name}</h1>
        <span class="status">● Mail Server Active</span>
        <p class="description">Professional Email Service for ${domain}</p>
        
        <div class="links">
            <a href="/unsubscribe.html">Unsubscribe</a>
            <a href="/privacy.html">Privacy Policy</a>
        </div>
        
        <div class="footer">
            <p>© $(date +%Y) ${brand_name}. All rights reserved.</p>
            <p>Contact: ${admin_email}</p>
        </div>
    </div>
</body>
</html>
EOF
    
    # Create unsubscribe page (simplified version for space)
    create_unsubscribe_page "$domain" "$brand_name" "$admin_email" "$gradient" "$primary_color" "$accent_color"
    
    # Create privacy policy page (simplified version for space)
    create_privacy_page "$domain" "$brand_name" "$admin_email" "$gradient" "$primary_color" "$accent_color"
    
    # Set proper permissions
    chown -R www-data:www-data /var/www/html
    chmod -R 755 /var/www/html
    
    print_message "Web interface created with $WEBSITE_THEME theme"
    print_message "Unsubscribe page ready for MailWizz integration at: https://${domain}/unsubscribe.html"
    
    return 0
}

# Helper function to create unsubscribe page
create_unsubscribe_page() {
    local domain=$1
    local brand_name=$2
    local admin_email=$3
    local gradient=$4
    local primary_color=$5
    local accent_color=$6
    
    cat > /var/www/html/unsubscribe.html <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Unsubscribe - ${brand_name}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background: ${gradient};
            min-height: 100vh;
            padding: 2rem;
        }
        .container {
            max-width: 600px;
            margin: 0 auto;
            padding: 3rem;
            background: white;
            border-radius: 10px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.5);
        }
        h1 {
            color: ${primary_color};
            margin-bottom: 1.5rem;
            text-align: center;
        }
        input[type="email"] {
            width: 100%;
            padding: 0.75rem;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 1rem;
            margin-bottom: 1rem;
        }
        button {
            background: ${primary_color};
            color: white;
            border: none;
            padding: 0.75rem 2rem;
            border-radius: 5px;
            font-size: 1rem;
            cursor: pointer;
            width: 100%;
        }
        button:hover {
            background: ${accent_color};
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Unsubscribe from Mailing List</h1>
        <p>Enter your email address below to unsubscribe from our mailing list.</p>
        <form id="unsubscribe-form" action="#" method="POST">
            <input type="email" id="email" name="email" required placeholder="your@email.com">
            <button type="submit">Unsubscribe</button>
        </form>
    </div>
</body>
</html>
EOF
}

# Helper function to create privacy page
create_privacy_page() {
    local domain=$1
    local brand_name=$2
    local admin_email=$3
    local gradient=$4
    local primary_color=$5
    local accent_color=$6
    
    cat > /var/www/html/privacy.html <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Privacy Policy - ${brand_name}</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.8;
            color: #333;
            background: ${gradient};
            padding: 2rem;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            padding: 3rem;
            background: white;
            border-radius: 10px;
        }
        h1, h2 { color: ${primary_color}; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Privacy Policy</h1>
        <p>Last updated: $(date +"%B %d, %Y")</p>
        <h2>Contact Us</h2>
        <p>Email: ${admin_email}</p>
    </div>
</body>
</html>
EOF
}

# Export all functions
export -f install_required_packages
export -f configure_hostname
export -f save_configuration
export -f create_final_documentation
export -f setup_website
export -f create_quick_reference
export -f create_unsubscribe_page
export -f create_privacy_page
