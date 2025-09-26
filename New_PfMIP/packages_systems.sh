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
    
    print_message "Installing essential packages..."
    
    # Core packages
    local packages=(
        # Build tools
        "build-essential"
        "software-properties-common"
        "apt-transport-https"
        "ca-certificates"
        "gnupg"
        "lsb-release"
        
        # Network tools
        "net-tools"
        "curl"
        "wget"
        "telnet"
        "dnsutils"
        "ipcalc"
        
        # Mail server packages
        "postfix"
        "postfix-mysql"
        "postfix-pcre"
        "dovecot-core"
        "dovecot-imapd"
        "dovecot-pop3d"
        "dovecot-lmtpd"
        "dovecot-mysql"
        "dovecot-sieve"
        "dovecot-managesieved"
        
        # Database
        "mysql-server"
        "mysql-client"
        
        # Web server
        "nginx"
        "certbot"
        "python3-certbot-nginx"
        
        # Email authentication
        "opendkim"
        "opendkim-tools"
        
        # Security tools
        "ufw"
        "fail2ban"
        "rkhunter"
        "logwatch"
        
        # Utilities
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
    
    # Install packages with error handling
    for package in "${packages[@]}"; do
        if dpkg -l | grep -q "^ii  $package "; then
            print_message "✓ $package already installed"
        else
            print_message "Installing $package..."
            if ! apt-get install -y "$package" >/dev/null 2>&1; then
                print_warning "Failed to install $package, continuing..."
            fi
        fi
    done
    
    print_message "Package installation completed"
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
    "timezone": "$(timedatectl | grep 'Time zone' | awk '{print $3}')"
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
    
    tar -czf "$backup_file" \
        /etc/postfix/ \
        /etc/dovecot/ \
        /etc/nginx/sites-available/ \
        /etc/opendkim/ \
        "$config_file" \
        2>/dev/null || true
    
    print_message "Configuration saved to: $config_file"
    print_message "Backup created at: $backup_file"
    
    # Create quick reference file
    cat > /root/mail-server-quick-ref.txt <<EOF
==============================================
Mail Server Quick Reference
==============================================
Installation Date: $(date)
Domain: ${DOMAIN_NAME:-}
Hostname: ${HOSTNAME:-}
Admin Email: ${ADMIN_EMAIL:-}

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
        if systemctl is-active --quiet $service; then
            echo "✓ $service: Running" >> "$doc_file"
        else
            echo "✗ $service: Not running" >> "$doc_file"
        fi
    done
    
    cat >> "$doc_file" <<'EOF'

PORTS AND FIREWALL:
-------------------
Port 22   (SSH)        - Administrative access
Port 25   (SMTP)       - Incoming mail
Port 80   (HTTP)       - Web redirect
Port 143  (IMAP)       - Mail retrieval
Port 443  (HTTPS)      - Secure web
Port 465  (SMTPS)      - Secure SMTP
Port 587  (Submission) - Mail submission
Port 993  (IMAPS)      - Secure IMAP

DNS RECORDS REQUIRED:
---------------------
1. A Records:
   - Set A record for hostname pointing to each IP
   
2. MX Record:
   - Set MX record for domain pointing to mail hostname
   
3. PTR Records (Reverse DNS):
   - Must be set with hosting provider for each IP
   
4. SPF Record:
   - Check /root/spf-record-*.txt for exact record
   
5. DKIM Record:
   - Check /root/dkim-record-*.txt for exact record
   
6. DMARC Record:
   - Check /root/dmarc-record-*.txt for exact record

MAIL ACCOUNTS:
--------------
EOF
    
    echo "Primary account: ${MAIL_USERNAME}@${DOMAIN_NAME}" >> "$doc_file"
    
    cat >> "$doc_file" <<'EOF'

To add more email accounts:
1. MySQL method:
   mysql -u mailuser -p$(cat /root/.mail_db_password) mailserver
   Then use add_email_user function

2. Command line:
   echo "INSERT INTO virtual_users (domain_id, email, password) VALUES (1, 'user@domain', ENCRYPT('password', CONCAT('$6$', SUBSTRING(SHA(RAND()), -16))));" | mysql mailserver

TESTING YOUR SETUP:
-------------------
1. Send test email:
   send-test-email recipient@external-domain.com

2. Check mail queue:
   mailq

3. Monitor mail log:
   tail -f /var/log/mail.log

4. Check specific IP sending:
   grep "smtp-ip1" /var/log/mail.log | tail

5. Test authentication:
   telnet localhost 25
   EHLO test
   AUTH LOGIN
   (provide base64 encoded credentials)

TROUBLESHOOTING:
----------------
1. Mail not sending:
   - Check: systemctl status postfix
   - Check: tail -f /var/log/mail.log
   - Verify: postfix check

2. Authentication failing:
   - Check: systemctl status dovecot
   - Test: doveadm auth test user@domain
   - Verify MySQL: mysql -u mailuser -p

3. SSL issues:
   - Check certificates: ls -la /etc/letsencrypt/live/
   - Test: openssl s_client -connect hostname:993

4. DNS issues:
   - Test SPF: dig txt domain.com
   - Test DKIM: dig txt mail._domainkey.domain.com
   - Test MX: dig mx domain.com

5. IP rotation not working:
   - Check: grep "smtp-ip" /etc/postfix/master.cf
   - Verify: postconf transport_maps

PERFORMANCE OPTIMIZATION:
-------------------------
1. Adjust Postfix settings in /etc/postfix/main.cf:
   - default_process_limit = 100-200
   - qmgr_message_active_limit = 20000-40000
   - smtp_destination_concurrency_limit = 20-50

2. MySQL tuning in /etc/mysql/mysql.conf.d/mysqld.cnf:
   - max_connections = 200
   - innodb_buffer_pool_size = 256M

3. Monitor server resources:
   - htop (CPU and memory)
   - iostat -x 1 (disk I/O)
   - netstat -an | grep :25 | wc -l (SMTP connections)

SECURITY RECOMMENDATIONS:
--------------------------
1. Regular updates:
   apt update && apt upgrade

2. Monitor logs:
   /usr/local/bin/check-mail-security

3. Check blacklists regularly:
   for ip in $(cat /root/ip-list.txt); do
     host $ip.zen.spamhaus.org
   done

4. Backup regularly:
   - Database: mysqldump mailserver > backup.sql
   - Config: tar -czf mail-config.tar.gz /etc/postfix /etc/dovecot

MAILWIZZ INTEGRATION:
---------------------
See /root/mailwizz-multi-ip-guide.txt for detailed MailWizz setup

Key points:
1. Create separate delivery server for each IP
2. Set appropriate hourly/daily limits per IP
3. Configure webhook for engagement tracking (if sticky IP enabled)
4. Use delivery server groups for load balancing

MAINTENANCE TASKS:
------------------
Daily:
- Check mail queue: mailq
- Review logs: grep error /var/log/mail.log
- Monitor reputation: check blacklists

Weekly:
- Update IP warmup status: ip-warmup-manager status
- Review statistics: mail-stats report
- Check disk space: df -h

Monthly:
- Update software: apt update && apt upgrade
- Review security: rkhunter --check
- Optimize database: mysqlcheck -o mailserver

SUPPORT RESOURCES:
------------------
- Documentation: /root/mail-server-multiip-info.txt
- Quick reference: /root/mail-server-quick-ref.txt
- MailWizz guide: /root/mailwizz-multi-ip-guide.txt
- Configuration: /root/mail-server-config.json
- Logs: /var/log/mail.log

For issues, check:
1. This documentation
2. System logs in /var/log/
3. Service status with systemctl status

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
}

# Setup basic website for the mail server domain
setup_website() {
    local domain=$1
    local admin_email=$2
    local brand_name=$3
    
    print_header "Setting Up Web Interface"
    
    print_message "Creating web directory structure..."
    
    # Create web root
    mkdir -p /var/www/html
    
    # Create a simple landing page
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
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
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
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        h1 {
            color: #764ba2;
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
        .info {
            background: #f3f4f6;
            padding: 1.5rem;
            border-radius: 8px;
            margin: 2rem 0;
        }
        .info h2 {
            color: #4b5563;
            font-size: 1.25rem;
            margin-bottom: 1rem;
        }
        .info p {
            color: #6b7280;
            margin-bottom: 0.5rem;
        }
        .contact {
            margin-top: 2rem;
            padding-top: 2rem;
            border-top: 1px solid #e5e7eb;
        }
        .contact a {
            color: #764ba2;
            text-decoration: none;
            font-weight: 500;
        }
        .contact a:hover {
            text-decoration: underline;
        }
        .features {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 1rem;
            margin: 2rem 0;
        }
        .feature {
            display: flex;
            align-items: center;
            color: #4b5563;
        }
        .feature::before {
            content: "✓";
            display: inline-block;
            width: 24px;
            height: 24px;
            background: #10b981;
            color: white;
            border-radius: 50%;
            text-align: center;
            line-height: 24px;
            margin-right: 0.5rem;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>${brand_name}</h1>
        <span class="status">● Mail Server Active</span>
        
        <div class="info">
            <h2>Professional Email Service</h2>
            <p>This is a private mail server for ${domain}.</p>
            <p>Authorized users can access their email using standard mail clients.</p>
        </div>
        
        <div class="features">
            <div class="feature">IMAP/SMTP Support</div>
            <div class="feature">SSL/TLS Security</div>
            <div class="feature">Spam Protection</div>
            <div class="feature">Multi-IP Delivery</div>
        </div>
        
        <div class="info">
            <h2>Mail Client Configuration</h2>
            <p><strong>Incoming Server (IMAP):</strong></p>
            <p>Server: ${domain}</p>
            <p>Port: 993 (SSL/TLS)</p>
            <p>Security: SSL/TLS</p>
            <br>
            <p><strong>Outgoing Server (SMTP):</strong></p>
            <p>Server: ${domain}</p>
            <p>Port: 587 (STARTTLS) or 465 (SSL/TLS)</p>
            <p>Security: STARTTLS or SSL/TLS</p>
            <p>Authentication: Required</p>
        </div>
        
        <div class="contact">
            <p>For support, contact: <a href="mailto:${admin_email}">${admin_email}</a></p>
        </div>
    </div>
</body>
</html>
EOF
    
    # Create robots.txt to prevent indexing
    cat > /var/www/html/robots.txt <<EOF
User-agent: *
Disallow: /
EOF
    
    # Create a simple 404 page
    cat > /var/www/html/404.html <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>404 - Page Not Found</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            margin: 0;
            background: #f3f4f6;
        }
        .error-container {
            text-align: center;
            padding: 2rem;
        }
        h1 {
            font-size: 6rem;
            margin: 0;
            color: #764ba2;
        }
        p {
            font-size: 1.25rem;
            color: #6b7280;
        }
        a {
            color: #764ba2;
            text-decoration: none;
        }
        a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="error-container">
        <h1>404</h1>
        <p>Page not found</p>
        <p><a href="/">Return to homepage</a></p>
    </div>
</body>
</html>
EOF
    
    # Set proper permissions
    chown -R www-data:www-data /var/www/html
    chmod -R 755 /var/www/html
    
    print_message "Web interface setup completed"
}

# Export all functions
export -f install_required_packages
export -f configure_hostname
export -f save_configuration
export -f create_final_documentation
export -f setup_website
