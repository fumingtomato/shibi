#!/bin/bash

# =================================================================
# SECURITY HARDENING MODULE
# System security, firewall configuration, and hardening measures
# =================================================================

# Apply server hardening measures
harden_server() {
    local domain=$1
    local hostname=$2
    
    print_header "Applying Server Hardening Measures"
    
    # System Updates
    print_message "Ensuring system is up to date..."
    apt update
    apt upgrade -y
    
    # SSH Hardening
    print_message "Hardening SSH configuration..."
    sed -i 's/#PermitRootLogin yes/PermitRootLogin prohibit-password/g' /etc/ssh/sshd_config
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config
    
    # Check for both possible SSH service names (ssh and sshd)
    if systemctl is-active --quiet sshd; then
        print_message "Restarting sshd service..."
        systemctl restart sshd
    elif systemctl is-active --quiet ssh; then
        print_message "Restarting ssh service..."
        systemctl restart ssh
    else
        print_warning "SSH service not found. Please restart SSH manually."
    fi
    
    # Firewall Configuration with UFW
    print_message "Setting up firewall..."
    apt install -y ufw
    
    # SSH access
    ufw allow ssh
    
    # Email services
    ufw allow 22/tcp comment 'SSH'
    ufw allow 25/tcp comment 'SMTP'
    ufw allow 587/tcp comment 'Submission'
    ufw allow 465/tcp comment 'SMTPS'
    ufw allow 143/tcp comment 'IMAP'
    ufw allow 993/tcp comment 'IMAPS'
    
    # Web services
    ufw allow 80/tcp comment 'HTTP'
    ufw allow 443/tcp comment 'HTTPS'
    
    # Enable firewall
    echo "y" | ufw enable
    
    # Fail2Ban Installation
    print_message "Installing and configuring Fail2Ban..."
    apt install -y fail2ban >/dev/null 2>&1
    
    # Create Fail2Ban configuration for mail services
    cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3

[postfix]
enabled = true
port = smtp,submission
filter = postfix
logpath = /var/log/mail.log
maxretry = 5

[dovecot]
enabled = true
port = imap,imaps
filter = dovecot
logpath = /var/log/mail.log
maxretry = 5
EOF
    
    systemctl enable fail2ban
    systemctl restart fail2ban
    
    # Check if rate limiting is already configured
    print_message "Configuring Postfix rate limits for bulk mail..."
    
    # Check if rate limiting is already configured in main.cf
    if grep -q "smtpd_client_message_rate_limit" /etc/postfix/main.cf; then
        print_message "Rate limiting is already configured in main.cf"
    else
        # Update main.cf with rate limiting
        cat >> /etc/postfix/main.cf <<EOF

# Rate limiting configuration
smtpd_client_message_rate_limit = 1000
smtpd_client_event_limit_exceptions = \$mynetworks
smtpd_client_connection_count_limit = 50
anvil_rate_time_unit = 60s
EOF
    fi
    
    # Secure Postfix configurations
    postconf -e "smtpd_helo_required = yes"
    postconf -e "disable_vrfy_command = yes"
    
    # Secure memory allocation
    print_message "Securing memory allocations..."
    cat > /etc/sysctl.d/50-security-hardening.conf <<EOF
# Kernel hardening
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.sysrq = 0
kernel.dmesg_restrict = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
EOF
    
    sysctl -p /etc/sysctl.d/50-security-hardening.conf
    
    # Setup Logwatch for log monitoring
    print_message "Setting up log monitoring..."
    apt install -y logwatch
    
    # Configure logwatch to send daily reports
    cat > /etc/cron.daily/00logwatch <<EOF
#!/bin/bash
/usr/sbin/logwatch --output mail --mailto $ADMIN_EMAIL --detail high
EOF
    
    chmod +x /etc/cron.daily/00logwatch
    
    # Setup Rootkit detection
    print_message "Installing rootkit detection..."
    apt install -y rkhunter
    
    # Configure rkhunter
    sed -i 's/CRON_DAILY_RUN=""/CRON_DAILY_RUN="yes"/g' /etc/default/rkhunter
    sed -i 's/REPORT_EMAIL="root"/REPORT_EMAIL="'$ADMIN_EMAIL'"/g' /etc/default/rkhunter
    
    # Create custom script for checking mail server security
    print_message "Creating mail server security check script..."
    
    cat > /usr/local/bin/check-mail-security <<EOF
#!/bin/bash
# Mail Server Security Check Script

# Check open ports
echo "=== Open Ports ==="
netstat -tuln | grep LISTEN

# Check Postfix queue
echo -e "\n=== Mail Queue ==="
mailq | tail -n 1

# Check recent authentication failures
echo -e "\n=== Recent Auth Failures ==="
grep "authentication failure\|Failed password" /var/log/auth.log | tail -n 10

# Check mail logs for errors
echo -e "\n=== Recent Mail Errors ==="
grep "error\|warning" /var/log/mail.log | tail -n 20

# Check Fail2Ban status
echo -e "\n=== Fail2Ban Status ==="
fail2ban-client status | grep "Jail list"

# Check disk space
echo -e "\n=== Disk Space ==="
df -h

# Check load average
echo -e "\n=== System Load ==="
uptime

# Check for large files in mail directories
echo -e "\n=== Large Files in Mail Directories ==="
find /var/mail -type f -size +50M -exec ls -lh {} \;
EOF
    
    chmod +x /usr/local/bin/check-mail-security
    
    # Setup unattended security updates
    print_message "Configuring unattended security updates..."
    apt install -y unattended-upgrades apt-listchanges
    
    cat > /etc/apt/apt.conf.d/50unattended-upgrades <<EOF
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}";
    "\${distro_id}:\${distro_codename}-security";
    "\${distro_id}ESMApps:\${distro_codename}-apps-security";
    "\${distro_id}ESM:\${distro_codename}-infra-security";
};
Unattended-Upgrade::Package-Blacklist {
};
Unattended-Upgrade::DevRelease "false";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF
    
    cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
    
    # Create script to purge old mail logs
    print_message "Creating mail log rotation optimization..."
    
    cat > /etc/logrotate.d/mail-enhanced <<EOF
/var/log/mail.log
/var/log/mail.err
/var/log/mail.warn
{
    rotate 14
    daily
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    postrotate
        invoke-rc.d rsyslog rotate >/dev/null 2>&1 || true
    endscript
}
EOF
    
    # Create emergency mail purge script
    cat > /usr/local/bin/purge-mail-queue <<EOF
#!/bin/bash
# Emergency script to purge mail queue in case of attack or queue flood

echo "WARNING: This will purge the entire mail queue!"
echo "Press Ctrl+C now to abort, or Enter to continue."
read

# Stop mail service
systemctl stop postfix

# Backup the queue (just in case)
tar -czf /root/postfix-queue-backup-\$(date +%Y%m%d%H%M%S).tar.gz /var/spool/postfix

# Purge the queue
rm -rf /var/spool/postfix/deferred/*
rm -rf /var/spool/postfix/active/*
rm -rf /var/spool/postfix/incoming/*
rm -rf /var/spool/postfix/hold/*

# Restart mail service
systemctl start postfix

echo "Mail queue has been purged."
EOF
    
    chmod +x /usr/local/bin/purge-mail-queue
    
    # Set up daily security checks
    cat > /etc/cron.daily/security-checks <<EOF
#!/bin/bash
/usr/local/bin/check-mail-security > /root/security-report-\$(date +%Y%m%d).txt
EOF
    
    chmod +x /etc/cron.daily/security-checks
    
    print_message "Server hardening completed."
    
    # Create hardening documentation
    print_message "Creating hardening documentation..."
    
    cat > /root/server-hardening-info.txt <<EOF
======================================================
   Mail Server Hardening Documentation
======================================================

Security measures implemented on this mail server:

SYSTEM SECURITY:
- Automatic security updates enabled
- SSH hardened (root login restricted, password authentication disabled)
- Kernel parameters hardened for security
- Rootkit detection (rkhunter) installed and running daily
- Daily security checks configured

NETWORK SECURITY:
- Firewall (UFW) enabled with specific rules for mail services
- Only necessary ports opened (SSH, SMTP, IMAP, HTTP/S)
- Fail2Ban installed to protect against brute force attacks
- Rate limiting implemented for connection attempts

MAIL SERVICE SECURITY:
- Postfix configured with rate limits for bulk sending
- VRFY command disabled to prevent user enumeration
- HELO/EHLO checks enforced
- Queue management tools installed

MONITORING & LOGGING:
- Enhanced log rotation for mail logs
- Daily security reports via Logwatch
- Automated security checks with /usr/local/bin/check-mail-security
- Suspicious activity alerts

BULK MAIL SPECIFIC PROTECTIONS:
- Queue rate management optimized for bulk sending
- Emergency queue purge script available (/usr/local/bin/purge-mail-queue)
- Connection count limits configured for fair resource allocation

ADDITIONAL SECURITY TOOLS:
- Run '/usr/local/bin/check-mail-security' to get a current security status
- Check daily reports in /root/security-report-*.txt
- Monitor '/var/log/mail.log' for delivery issues

In case of emergency or suspected compromise:
1. Run: systemctl stop postfix dovecot
2. Check logs for unauthorized activity
3. Contact your security team
4. Only when safe, restart with: systemctl start postfix dovecot

EOF
    
    chmod 600 /root/server-hardening-info.txt
}

export -f harden_server
