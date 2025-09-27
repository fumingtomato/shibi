#!/bin/bash

# =================================================================
# PACKAGES AND SYSTEM CONFIGURATION MODULE
# Package installation and system setup functions
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
    fi
    
    # Install MySQL/MariaDB
    print_message "Installing MySQL/MariaDB..."
    local mysql_packages=(
        "mysql-server"
        "mysql-client"
    )
    
    for package in "${mysql_packages[@]}"; do
        if dpkg -l | grep -q "^ii  $package "; then
            print_message "✓ $package already installed"
        else
            print_message "Installing $package..."
            if ! DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$package" >/dev/null 2>&1; then
                print_warning "Failed to install $package, trying mariadb..."
                # Try MariaDB as alternative
                if [ "$package" = "mysql-server" ]; then
                    DEBIAN_FRONTEND=noninteractive apt-get install -y -q mariadb-server >/dev/null 2>&1 || true
                elif [ "$package" = "mysql-client" ]; then
                    DEBIAN_FRONTEND=noninteractive apt-get install -y -q mariadb-client >/dev/null 2>&1 || true
                fi
            fi
        fi
    done
    
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
    
    for package in "${dovecot_packages[@]}"; do
        if dpkg -l | grep -q "^ii  $package "; then
            print_message "✓ $package already installed"
        else
            print_message "Installing $package..."
            DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$package" >/dev/null 2>&1 || \
                print_warning "Failed to install $package, continuing..."
        fi
    done
    
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
        DEBIAN_FRONTEND=noninteractive apt-get install -y -q opendkim opendkim-tools >/dev/null 2>&1 || \
            print_warning "Failed to install OpenDKIM"
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
        "bc"
        "jq"
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
    systemctl stop mysql 2>/dev/null || true
    systemctl stop nginx 2>/dev/null || true
    
    print_message "Package installation completed"
    
    # Verify critical packages
    print_message "Verifying critical packages..."
    local critical_packages=("postfix" "mysql-server" "dovecot-core" "nginx")
    local all_installed=true
    
    for package in "${critical_packages[@]}"; do
        # Check for package or alternatives
        if dpkg -l | grep -q "^ii  $package "; then
            print_message "✓ $package verified"
        elif [ "$package" = "mysql-server" ] && dpkg -l | grep -q "^ii  mariadb-server "; then
            print_message "✓ mariadb-server verified (alternative to mysql-server)"
        else
            print_error "✗ $package is not installed properly"
            all_installed=false
        fi
    done
    
    if [ "$all_installed" = false ]; then
        print_error "Some critical packages failed to install."
        print_message "Attempting to fix broken packages..."
        apt-get install -f -y
        dpkg --configure -a
    fi
}

# Configure system hostname
configure_hostname() {
    local hostname=$1
    
    print_header "Configuring System Hostname"
    
    if [ -z "$hostname" ]; then
        print_error "Hostname not provided"
        return 1
    fi
    
    # Extract the short hostname (first part before first dot)
    local short_hostname=$(echo "$hostname" | cut -d'.' -f1)
    
    print_message "Setting hostname to: $hostname"
    print_message "Short hostname: $short_hostname"
    
    # Set the hostname
    hostnamectl set-hostname "$short_hostname"
    
    # Update /etc/hostname
    echo "$short_hostname" > /etc/hostname
    
    # Update /etc/hosts
    if ! grep -q "127.0.1.1" /etc/hosts; then
        echo "127.0.1.1 $hostname $short_hostname" >> /etc/hosts
    else
        sed -i "s/127.0.1.1.*/127.0.1.1 $hostname $short_hostname/" /etc/hosts
    fi
    
    # Add server IPs to hosts file if available
    if [ ! -z "${IP_ADDRESSES}" ]; then
        for ip in "${IP_ADDRESSES[@]}"; do
            if ! grep -q "$ip" /etc/hosts; then
                echo "$ip $hostname $short_hostname" >> /etc/hosts
            fi
        done
    fi
    
    # Apply hostname changes
    hostname "$short_hostname"
    
    # Verify
    print_message "Hostname configured:"
    print_message "  Full: $(hostname -f)"
    print_message "  Short: $(hostname -s)"
    
    # Configure /etc/mailname for Postfix
    echo "$hostname" > /etc/mailname
    
    print_message "Hostname configuration completed"
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
  "installer_version": "$INSTALLER_VERSION",
  "server_configuration": {
    "domain": "${DOMAIN_NAME:-}",
    "hostname": "${HOSTNAME:-}",
    "admin_email": "${ADMIN_EMAIL:-}",
    "brand_name": "${BRAND_NAME:-}",
    "timezone": "$(timedatectl | grep 'Time zone' | awk '{print $3}')",
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
    cat > /root/mail-server-quick-ref.txt <<EOF
==============================================
Mail Server Quick Reference
==============================================
Installation Date: $(date)
Domain: ${DOMAIN_NAME:-}
Hostname: ${HOSTNAME:-}
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
Configuration backup: $config_file
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
Version: $INSTALLER_VERSION
Domain: ${DOMAIN_NAME:-}
Hostname: ${HOSTNAME:-}
Admin Email: ${ADMIN_EMAIL:-}
Website Theme: ${WEBSITE_THEME:-midnight}
Total IPs Configured: ${IP_COUNT:-1}

IP ADDRESSES:
-------------
EOF
    
    if [ ! -z "${IP_ADDRESSES}" ]; then
        local idx=1
        for ip in "${IP_ADDRESSES[@]}"; do
            echo "$idx. $ip (Transport: smtp-ip${idx})" >> "$doc_file"
            idx=$((idx + 1))
        done
    fi
    
    cat >> "$doc_file" <<'EOF'

SERVICES STATUS:
----------------
EOF
    
    # Check service status
    for service in postfix dovecot mysql nginx opendkim; do
        if systemctl is-active --quiet $service 2>/dev/null; then
            echo "✓ $service: Running" >> "$doc_file"
        elif systemctl is-active --quiet mariadb 2>/dev/null && [ "$service" = "mysql" ]; then
            echo "✓ mariadb: Running (MySQL alternative)" >> "$doc_file"
        else
            echo "✗ $service: Not running" >> "$doc_file"
        fi
    done
    
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

==========================================================
Installation completed!
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
}

# Setup basic website for the mail server domain with privacy, unsubscribe, and color themes
setup_website() {
    local domain=$1
    local admin_email=$2
    local brand_name=$3
    
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
    
    # Create unsubscribe page with MailWizz integration placeholder
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
        .content {
            margin-bottom: 2rem;
        }
        .form-group {
            margin-bottom: 1.5rem;
        }
        label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 500;
        }
        input[type="email"] {
            width: 100%;
            padding: 0.75rem;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 1rem;
        }
        button {
            background: ${primary_color};
            color: white;
            border: none;
            padding: 0.75rem 2rem;
            border-radius: 5px;
            font-size: 1rem;
            cursor: pointer;
            transition: background 0.3s ease;
            width: 100%;
        }
        button:hover {
            background: ${accent_color};
        }
        .info {
            background: #f7f7f7;
            padding: 1rem;
            border-radius: 5px;
            margin-top: 2rem;
            font-size: 0.875rem;
            color: #666;
        }
        .back-link {
            text-align: center;
            margin-top: 2rem;
        }
        .back-link a {
            color: ${primary_color};
            text-decoration: none;
        }
        .back-link a:hover {
            color: ${accent_color};
        }
        .mailwizz-note {
            background: #fff3cd;
            border: 1px solid #ffc107;
            padding: 1rem;
            border-radius: 5px;
            margin-bottom: 2rem;
        }
        .success-message {
            background: #d4edda;
            border: 1px solid #28a745;
            color: #155724;
            padding: 1rem;
            border-radius: 5px;
            margin-bottom: 1rem;
            display: none;
        }
        .error-message {
            background: #f8d7da;
            border: 1px solid #dc3545;
            color: #721c24;
            padding: 1rem;
            border-radius: 5px;
            margin-bottom: 1rem;
            display: none;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Unsubscribe from Mailing List</h1>
        
        <div class="mailwizz-note">
            <strong>Note:</strong> If you received an email with an unsubscribe link, please use that link for instant removal. 
            The form below is for manual unsubscribe requests.
        </div>
        
        <div class="success-message" id="success-msg">
            You have been successfully unsubscribed from our mailing list.
        </div>
        
        <div class="error-message" id="error-msg">
            An error occurred. Please try again or contact support.
        </div>
        
        <div class="content">
            <p>We're sorry to see you go. Please enter your email address below to unsubscribe from our mailing list.</p>
        </div>
        
        <form id="unsubscribe-form" action="#" method="POST">
            <div class="form-group">
                <label for="email">Email Address:</label>
                <input type="email" id="email" name="email" required placeholder="your@email.com">
            </div>
            
            <button type="submit">Unsubscribe</button>
        </form>
        
        <div class="info">
            <p><strong>What happens when you unsubscribe:</strong></p>
            <ul style="margin-left: 1.5rem; margin-top: 0.5rem;">
                <li>You will be immediately removed from our mailing list</li>
                <li>You will receive a confirmation email</li>
                <li>You will no longer receive any promotional emails from us</li>
                <li>Your data will be retained for record-keeping as per our privacy policy</li>
            </ul>
        </div>
        
        <div class="back-link">
            <a href="/">← Back to Home</a>
        </div>
    </div>
    
    <script>
    // MAILWIZZ INTEGRATION INSTRUCTIONS:
    // =====================================
    // To integrate with MailWizz, replace 'YOUR_MAILWIZZ_URL' below with your actual MailWizz installation URL
    // You can either:
    // 1. Redirect to MailWizz unsubscribe page
    // 2. Use MailWizz API to process unsubscribe
    // 3. Submit to a custom webhook that connects to MailWizz
    
    document.getElementById('unsubscribe-form').addEventListener('submit', function(e) {
        e.preventDefault();
        
        var email = document.getElementById('email').value;
        
        // OPTION 1: Redirect to MailWizz unsubscribe search page
        // Uncomment the following line and add your MailWizz URL:
        // window.location.href = 'YOUR_MAILWIZZ_URL/lists/unsubscribe-search?email=' + encodeURIComponent(email);
        
        // OPTION 2: Submit to MailWizz API endpoint
        // Uncomment and configure the following:
        /*
        fetch('YOUR_MAILWIZZ_URL/api/lists/subscribers/unsubscribe', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-API-KEY': 'YOUR_API_KEY'
            },
            body: JSON.stringify({
                email: email
            })
        })
        .then(response => response.json())
        .then(data => {
            document.getElementById('success-msg').style.display = 'block';
            document.getElementById('unsubscribe-form').style.display = 'none';
        })
        .catch(error => {
            document.getElementById('error-msg').style.display = 'block';
        });
        */
        
        // OPTION 3: Temporary success message (remove when MailWizz is integrated)
        document.getElementById('success-msg').style.display = 'block';
        document.getElementById('unsubscribe-form').style.display = 'none';
        
        // Log for debugging (remove in production)
        console.log('Unsubscribe request for:', email);
        console.log('Remember to integrate with MailWizz!');
    });
    </script>
</body>
</html>
EOF
    
    # Create privacy policy page with matching theme
    cat > /var/www/html/privacy.html <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Privacy Policy - ${brand_name}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            line-height: 1.8;
            color: #333;
            background: ${gradient};
            min-height: 100vh;
            padding: 2rem;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            padding: 3rem;
            background: white;
            border-radius: 10px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.5);
        }
        h1 {
            color: ${primary_color};
            margin-bottom: 2rem;
            text-align: center;
        }
        h2 {
            color: ${primary_color};
            margin-top: 2rem;
            margin-bottom: 1rem;
            font-size: 1.4rem;
        }
        p {
            margin-bottom: 1rem;
            text-align: justify;
        }
        ul {
            margin-left: 2rem;
            margin-bottom: 1rem;
        }
        .last-updated {
            text-align: center;
            color: #666;
            font-style: italic;
            margin-bottom: 2rem;
        }
        .contact-section {
            background: #f7f7f7;
            padding: 1.5rem;
            border-radius: 5px;
            margin-top: 2rem;
        }
        .back-link {
            text-align: center;
            margin-top: 2rem;
        }
        .back-link a {
            color: ${primary_color};
            text-decoration: none;
            padding: 0.5rem 1rem;
            border: 1px solid ${primary_color};
            border-radius: 5px;
            display: inline-block;
            transition: all 0.3s ease;
        }
        .back-link a:hover {
            background: ${accent_color};
            border-color: ${accent_color};
            color: white;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Privacy Policy</h1>
        <p class="last-updated">Last updated: $(date +"%B %d, %Y")</p>
        
        <h2>1. Introduction</h2>
        <p>
            ${brand_name} ("we", "our", or "us") respects your privacy and is committed to protecting your personal data. 
            This privacy policy explains how we collect, use, and safeguard your information when you interact with our email services.
        </p>
        
        <h2>2. Information We Collect</h2>
        <p>We may collect the following types of information:</p>
        <ul>
            <li><strong>Email Address:</strong> Required for sending you communications you've subscribed to</li>
            <li><strong>Name:</strong> Used for personalization of communications</li>
            <li><strong>Subscription Preferences:</strong> Your choices regarding which communications you wish to receive</li>
            <li><strong>Engagement Data:</strong> Whether you open emails or click on links (for improving our service)</li>
            <li><strong>Technical Data:</strong> IP address, browser type, and device information for security and analytics</li>
        </ul>
        
        <h2>3. How We Use Your Information</h2>
        <p>Your information is used to:</p>
        <ul>
            <li>Send you emails you've subscribed to receive</li>
            <li>Personalize your experience</li>
            <li>Improve our email content and delivery</li>
            <li>Comply with legal obligations</li>
            <li>Protect against fraud and abuse</li>
        </ul>
        
        <h2>4. Data Retention</h2>
        <p>
            We retain your personal information only for as long as necessary to fulfill the purposes for which it was collected. 
            When you unsubscribe, we maintain a record of your email address solely to ensure you don't receive future communications.
        </p>
        
        <h2>5. Your Rights</h2>
        <p>You have the right to:</p>
        <ul>
            <li><strong>Access:</strong> Request a copy of your personal data</li>
            <li><strong>Correction:</strong> Request correction of inaccurate data</li>
            <li><strong>Deletion:</strong> Request deletion of your data (subject to legal requirements)</li>
            <li><strong>Opt-out:</strong> Unsubscribe from our communications at any time</li>
            <li><strong>Portability:</strong> Request your data in a machine-readable format</li>
        </ul>
        
        <h2>6. Email Communications</h2>
        <p>
            All marketing emails we send include an unsubscribe link. You can also manage your preferences or unsubscribe 
            via our <a href="/unsubscribe.html" style="color: ${primary_color};">unsubscribe page</a>.
        </p>
        
        <h2>7. Data Security</h2>
        <p>
            We implement appropriate technical and organizational measures to protect your personal data against unauthorized access, 
            alteration, disclosure, or destruction. This includes encryption, secure servers, and regular security assessments.
        </p>
        
        <h2>8. Third-Party Services</h2>
        <p>
            We may use third-party services for email delivery and analytics. These services are bound by their own privacy policies 
            and we ensure they meet our security standards.
        </p>
        
        <h2>9. Cookies and Tracking</h2>
        <p>
            Our emails may contain tracking pixels to help us understand email engagement. This helps us improve our service 
            and send more relevant content.
        </p>
        
        <h2>10. International Transfers</h2>
        <p>
            Your information may be transferred to and processed in countries other than your own. We ensure appropriate 
            safeguards are in place for such transfers.
        </p>
        
        <h2>11. Children's Privacy</h2>
        <p>
            Our services are not directed to individuals under 16 years of age. We do not knowingly collect personal 
            information from children.
        </p>
        
        <h2>12. Changes to This Policy</h2>
        <p>
            We may update this privacy policy from time to time. We will notify you of any material changes by posting 
            the new policy on this page and updating the "Last updated" date.
        </p>
        
        <div class="contact-section">
            <h2>13. Contact Us</h2>
            <p>
                If you have any questions about this privacy policy or our data practices, please contact us at:
            </p>
            <p>
                <strong>Email:</strong> ${admin_email}<br>
                <strong>Website:</strong> ${domain}<br>
                <strong>Data Protection Officer:</strong> ${admin_email}
            </p>
        </div>
        
        <div class="back-link">
            <a href="/">← Back to Home</a>
        </div>
    </div>
</body>
</html>
EOF
    
    # Create a configuration file with MailWizz integration instructions
    cat > /var/www/html/mailwizz-integration.txt <<EOF
========================================================
MAILWIZZ UNSUBSCRIBE INTEGRATION INSTRUCTIONS
========================================================

To connect the unsubscribe form to MailWizz:

1. OPTION 1 - Direct Redirect Method:
   - Edit /var/www/html/unsubscribe.html
   - Find the line: // window.location.href = 'YOUR_MAILWIZZ_URL/lists/unsubscribe-search?email='
   - Replace YOUR_MAILWIZZ_URL with your actual MailWizz URL
   - Uncomment the line by removing the //

2. OPTION 2 - API Integration:
   - Get your MailWizz API key from Backend > API Keys
   - Edit /var/www/html/unsubscribe.html
   - Find the API integration section (OPTION 2)
   - Replace YOUR_MAILWIZZ_URL with your MailWizz URL
   - Replace YOUR_API_KEY with your actual API key
   - Uncomment the fetch() block

3. OPTION 3 - Webhook Method:
   - Create a webhook endpoint in MailWizz
   - Configure it to handle unsubscribe requests
   - Update the form action in unsubscribe.html

4. For MailWizz Campaign Links:
   - In your MailWizz campaigns, use the tag: [UNSUBSCRIBE_URL]
   - This will automatically generate unique unsubscribe links

Your selected website theme: ${WEBSITE_THEME}
Primary color: ${primary_color}
Accent color: ${accent_color}

To change colors later, edit the CSS in:
- /var/www/html/index.html
- /var/www/html/unsubscribe.html
- /var/www/html/privacy.html

========================================================
EOF
    
    # Set proper permissions
    chown -R www-data:www-data /var/www/html
    chmod -R 755 /var/www/html
    chmod 644 /var/www/html/*.txt
    
    print_message "Web interface created with $WEBSITE_THEME theme"
    print_message "Unsubscribe page ready for MailWizz integration at: https://${domain}/unsubscribe.html"
    print_message "Integration instructions saved at: /var/www/html/mailwizz-integration.txt"
}

# Export all functions
export -f install_required_packages
export -f configure_hostname
export -f save_configuration
export -f create_final_documentation
export -f setup_website
