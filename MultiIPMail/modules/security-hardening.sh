#!/bin/bash

# =================================================================
# SECURITY HARDENING MODULE - FIXED VERSION
# Firewall rules, fail2ban, security configurations, and hardening
# Fixed: Complete implementations, proper rule management, security checks
# =================================================================

# Global security variables
export SECURITY_DIR="/etc/mail-security"
export FIREWALL_RULES_FILE="${SECURITY_DIR}/firewall-rules.sh"
export FAIL2BAN_DIR="/etc/fail2ban"
export SECURITY_LOG="/var/log/mail-security.log"
export ALLOWED_PORTS="22 25 80 110 143 443 465 587 993 995"

# Initialize security configuration
init_security() {
    print_header "Initializing Security Configuration"
    
    # Create security directories
    mkdir -p "$SECURITY_DIR"
    chmod 700 "$SECURITY_DIR"
    
    # Initialize security log
    touch "$SECURITY_LOG"
    chmod 640 "$SECURITY_LOG"
    
    # Check for required tools
    check_security_tools
    
    print_message "✓ Security initialization complete"
}

# Check and install security tools
check_security_tools() {
    print_message "Checking security tools..."
    
    local missing_tools=()
    
    # Check for UFW
    if ! command -v ufw &>/dev/null; then
        missing_tools+=("ufw")
    fi
    
    # Check for fail2ban
    if ! command -v fail2ban-client &>/dev/null; then
        missing_tools+=("fail2ban")
    fi
    
    # Check for rkhunter
    if ! command -v rkhunter &>/dev/null; then
        missing_tools+=("rkhunter")
    fi
    
    # Check for ClamAV
    if ! command -v clamscan &>/dev/null; then
        missing_tools+=("clamav clamav-daemon")
    fi
    
    # Install missing tools
    if [ ${#missing_tools[@]} -gt 0 ]; then
        print_message "Installing security tools: ${missing_tools[*]}"
        apt-get update
        apt-get install -y ${missing_tools[@]}
    fi
    
    print_message "✓ Security tools ready"
}

# Setup firewall rules for mail server
setup_firewall() {
    print_header "Setting up Firewall Rules"
    
    # Check if UFW is installed
    if ! command -v ufw &>/dev/null; then
        print_error "UFW not installed"
        return 1
    fi
    
    # Disable UFW temporarily
    ufw --force disable
    
    # Reset UFW to defaults
    echo "y" | ufw --force reset
    
    # Set default policies
    ufw default deny incoming
    ufw default allow outgoing
    ufw default deny routed
    
    # Allow SSH (rate limited)
    ufw limit 22/tcp comment 'SSH rate limited'
    
    # Mail server ports
    ufw allow 25/tcp comment 'SMTP'
    ufw allow 465/tcp comment 'SMTPS'
    ufw allow 587/tcp comment 'Submission'
    
    # IMAP/POP3 ports
    ufw allow 110/tcp comment 'POP3'
    ufw allow 143/tcp comment 'IMAP'
    ufw allow 993/tcp comment 'IMAPS'
    ufw allow 995/tcp comment 'POP3S'
    
    # Web ports (for webmail/admin)
    ufw allow 80/tcp comment 'HTTP'
    ufw allow 443/tcp comment 'HTTPS'
    
    # Allow established connections
    ufw allow established
    
    # Create custom firewall script
    create_custom_firewall_rules
    
    # Enable UFW
    echo "y" | ufw enable
    
    # Show status
    ufw status verbose
    
    print_message "✓ Firewall configured and enabled"
}

# Create custom firewall rules script
create_custom_firewall_rules() {
    print_message "Creating custom firewall rules..."
    
    cat > "$FIREWALL_RULES_FILE" <<'EOF'
#!/bin/bash

# Custom Firewall Rules for Mail Server
# This script is called after UFW rules are loaded

# Enable logging
iptables -A INPUT -j LOG --log-prefix "FW-DROP: " --log-level 4

# Protection against port scanning
iptables -N port-scanning
iptables -A port-scanning -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j RETURN
iptables -A port-scanning -j DROP

# Protection against SYN flood
iptables -N syn-flood
iptables -A INPUT -p tcp --syn -j syn-flood
iptables -A syn-flood -m limit --limit 1/s --limit-burst 3 -j RETURN
iptables -A syn-flood -j DROP

# Drop invalid packets
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

# Block specific attacks
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP # XMAS packets
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP # NULL packets
iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP # SYN-FIN packets

# Rate limiting for mail ports
iptables -A INPUT -p tcp --dport 25 -m connlimit --connlimit-above 10 -j REJECT
iptables -A INPUT -p tcp --dport 587 -m connlimit --connlimit-above 10 -j REJECT
iptables -A INPUT -p tcp --dport 465 -m connlimit --connlimit-above 10 -j REJECT

# Country-based blocking (optional - requires xtables-addons)
# Uncomment and modify as needed
# iptables -A INPUT -m geoip --src-cc CN,RU,KP -j DROP

# Brute force protection for mail services
iptables -N MAIL_BRUTE
iptables -A INPUT -p tcp -m multiport --dports 25,465,587,110,143,993,995 -m state --state NEW -j MAIL_BRUTE
iptables -A MAIL_BRUTE -m recent --set --name MAIL
iptables -A MAIL_BRUTE -m recent --update --seconds 60 --hitcount 10 --name MAIL -j DROP

# Log accepted connections (for debugging)
# iptables -A INPUT -j LOG --log-prefix "FW-ACCEPT: " --log-level 6

echo "Custom firewall rules loaded at $(date)" >> /var/log/mail-security.log
EOF
    
    chmod +x "$FIREWALL_RULES_FILE"
    
    # Add to UFW after rules
    if [ -d /etc/ufw ]; then
        echo "$FIREWALL_RULES_FILE" > /etc/ufw/after.rules.d/mail-custom
    fi
    
    print_message "✓ Custom firewall rules created"
}

# Setup fail2ban for mail services
setup_fail2ban() {
    print_header "Setting up Fail2ban"
    
    # Ensure fail2ban is installed
    if ! command -v fail2ban-client &>/dev/null; then
        apt-get update
        apt-get install -y fail2ban
    fi
    
    # Stop fail2ban during configuration
    systemctl stop fail2ban 2>/dev/null || true
    
    # Create local jail configuration
    cat > "${FAIL2BAN_DIR}/jail.local" <<'EOF'
[DEFAULT]
# Ban time and retry settings
bantime = 3600
findtime = 600
maxretry = 5
destemail = root@localhost
sender = root@localhost
action = %(action_mwl)s

# Whitelist local networks
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3

[postfix]
enabled = true
port = smtp,465,submission
filter = postfix[mode=aggressive]
logpath = /var/log/mail.log
maxretry = 3

[postfix-sasl]
enabled = true
port = smtp,465,submission,imap,imaps,pop3,pop3s
filter = postfix-sasl
logpath = /var/log/mail.log
maxretry = 2

[dovecot]
enabled = true
port = smtp,465,submission,imap,imaps,pop3,pop3s
filter = dovecot
logpath = /var/log/mail.log
maxretry = 3

[postfix-ratelimit]
enabled = true
port = smtp,465,submission
filter = postfix-ratelimit
logpath = /var/log/mail.log
maxretry = 10
findtime = 60
bantime = 300

[mail-flood]
enabled = true
port = smtp,465,submission
filter = mail-flood
logpath = /var/log/mail.log
maxretry = 50
findtime = 60
bantime = 1800
EOF
    
    # Create custom filters
    create_fail2ban_filters
    
    # Start and enable fail2ban
    systemctl start fail2ban
    systemctl enable fail2ban
    
    # Show status
    fail2ban-client status
    
    print_message "✓ Fail2ban configured and started"
}

# Create custom fail2ban filters
create_fail2ban_filters() {
    print_message "Creating fail2ban filters..."
    
    # Postfix rate limit filter
    cat > "${FAIL2BAN_DIR}/filter.d/postfix-ratelimit.conf" <<'EOF'
[Definition]
failregex = ^.*postfix/smtpd\[\d+\]: warning: \[<HOST>\]: too many connections
            ^.*postfix/anvil\[\d+\]: statistics: max connection rate .* for \(smtp:<HOST>\)
ignoreregex =
EOF
    
    # Mail flood filter
    cat > "${FAIL2BAN_DIR}/filter.d/mail-flood.conf" <<'EOF'
[Definition]
failregex = ^.*postfix/smtpd\[\d+\]: NOQUEUE: reject: RCPT from .*\[<HOST>\]
            ^.*postfix/cleanup\[\d+\]: warning: .*\[<HOST>\]: Message exceeded
ignoreregex =
EOF
    
    # Enhanced Postfix SASL filter
    cat > "${FAIL2BAN_DIR}/filter.d/postfix-sasl.conf" <<'EOF'
[Definition]
failregex = ^.*postfix/smtpd\[\d+\]: warning: .*\[<HOST>\]: SASL .* authentication failed
            ^.*postfix/smtpd\[\d+\]: warning: .*\[<HOST>\]: SASL LOGIN authentication failed
            ^.*postfix/smtpd\[\d+\]: warning: .*\[<HOST>\]: SASL PLAIN authentication failed
ignoreregex =
EOF
    
    print_message "✓ Fail2ban filters created"
}

# Harden mail server configuration
harden_mail_config() {
    print_header "Hardening Mail Server Configuration"
    
    # Harden Postfix
    harden_postfix
    
    # Harden Dovecot
    harden_dovecot
    
    # Harden SSH
    harden_ssh
    
    # System hardening
    harden_system
    
    print_message "✓ Mail server hardening complete"
}

# Harden Postfix configuration
harden_postfix() {
    print_message "Hardening Postfix..."
    
    # Security settings
    postconf -e "disable_vrfy_command = yes"
    postconf -e "smtpd_banner = \$myhostname ESMTP"
    postconf -e "smtpd_helo_required = yes"
    postconf -e "strict_rfc821_envelopes = yes"
    postconf -e "show_user_unknown_table_name = no"
    
    # Rate limiting
    postconf -e "smtpd_error_sleep_time = 5s"
    postconf -e "smtpd_soft_error_limit = 10"
    postconf -e "smtpd_hard_error_limit = 20"
    postconf -e "smtpd_client_connection_count_limit = 10"
    postconf -e "smtpd_client_connection_rate_limit = 30"
    postconf -e "anvil_rate_time_unit = 60s"
    
    # Reject parameters
    postconf -e "smtpd_delay_reject = yes"
    postconf -e "smtpd_recipient_limit = 100"
    postconf -e "smtpd_timeout = 30s"
    
    # TLS hardening
    postconf -e "smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1"
    postconf -e "smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1"
    postconf -e "smtpd_tls_mandatory_ciphers = high"
    postconf -e "smtpd_tls_exclude_ciphers = aNULL, MD5, DES, 3DES, RC4"
    postconf -e "tls_high_cipherlist = ECDHE+AESGCM:ECDHE+RSA+AESGCM:ECDHE+RSA+SHA256:ECDHE+RSA+SHA384"
    
    systemctl reload postfix
    print_message "✓ Postfix hardened"
}

# Harden Dovecot configuration
harden_dovecot() {
    print_message "Hardening Dovecot..."
    
    # Create security configuration
    cat > /etc/dovecot/conf.d/99-security.conf <<'EOF'
# Dovecot Security Configuration

# Disable plaintext authentication
disable_plaintext_auth = yes

# SSL/TLS configuration
ssl = required
ssl_min_protocol = TLSv1.2
ssl_cipher_list = ECDHE+AESGCM:ECDHE+RSA+AESGCM:ECDHE+RSA+SHA256:ECDHE+RSA+SHA384
ssl_prefer_server_ciphers = yes

# Authentication settings
auth_mechanisms = plain login
auth_failure_delay = 2 secs
auth_cache_size = 10M
auth_cache_ttl = 1 hour
auth_cache_negative_ttl = 1 hour

# Login process
login_trusted_networks = 127.0.0.0/8
login_access_sockets = 

# Mail process limits
mail_max_userip_connections = 10
first_valid_uid = 1000
last_valid_uid = 60000

# Protocol limits
protocol imap {
  mail_max_userip_connections = 10
  imap_client_workarounds = 
}

protocol pop3 {
  mail_max_userip_connections = 3
  pop3_client_workarounds = 
}
EOF
    
    systemctl reload dovecot
    print_message "✓ Dovecot hardened"
}

# Harden SSH configuration
harden_ssh() {
    print_message "Hardening SSH..."
    
    # Backup original config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%s)
    
    # Apply hardening settings
    cat >> /etc/ssh/sshd_config.d/99-hardening.conf <<'EOF'
# SSH Hardening Configuration
Protocol 2
Port 22
PermitRootLogin prohibit-password
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
Compression no
ClientAliveInterval 300
ClientAliveCountMax 2
UseDNS no
MaxAuthTries 3
MaxSessions 10
LoginGraceTime 30
StrictModes yes
IgnoreRhosts yes
HostbasedAuthentication no
AllowUsers *@*
DenyUsers nobody
LogLevel VERBOSE
EOF
    
    # Test configuration
    if sshd -t; then
        systemctl reload sshd
        print_message "✓ SSH hardened"
    else
        print_error "SSH configuration error - check settings"
    fi
}

# System-wide hardening
harden_system() {
    print_message "Applying system hardening..."
    
    # Kernel parameters
    cat > /etc/sysctl.d/99-mail-security.conf <<'EOF'
# Mail Server Security - Kernel Parameters

# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0

# Ignore ICMP ping requests
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Log Martians
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Ignore Directed pings
net.ipv4.icmp_echo_ignore_all = 0

# Accept source route
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# SYN flood protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_max_syn_backlog = 4096

# Increase system file descriptor limit
fs.file-max = 100000

# Increase system IP port limits
net.ipv4.ip_local_port_range = 1024 65535

# TCP optimization
net.core.somaxconn = 4096
net.ipv4.tcp_fin_timeout = 20
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15

# Memory optimization
net.core.rmem_default = 31457280
net.core.rmem_max = 67108864
net.core.wmem_default = 31457280
net.core.wmem_max = 67108864
net.core.netdev_max_backlog = 65536
net.core.optmem_max = 25165824
EOF
    
    # Apply sysctl settings
    sysctl -p /etc/sysctl.d/99-mail-security.conf
    
    # Set file permissions
    chmod 644 /etc/passwd
    chmod 640 /etc/shadow
    chmod 644 /etc/group
    chmod 640 /etc/gshadow
    
    # Disable unnecessary services
    local unnecessary_services=("bluetooth" "cups" "avahi-daemon")
    for service in "${unnecessary_services[@]}"; do
        if systemctl list-unit-files | grep -q "$service"; then
            systemctl disable "$service" 2>/dev/null || true
            systemctl stop "$service" 2>/dev/null || true
        fi
    done
    
    print_message "✓ System hardening applied"
}

# Setup intrusion detection
setup_intrusion_detection() {
    print_header "Setting up Intrusion Detection"
    
    # Install and configure rkhunter
    if command -v rkhunter &>/dev/null; then
        print_message "Configuring rkhunter..."
        
        # Update rkhunter database
        rkhunter --update
        rkhunter --propupd
        
        # Configure rkhunter
        sed -i 's/MAIL-ON-WARNING=""/MAIL-ON-WARNING="root@localhost"/' /etc/rkhunter.conf
        
        # Add to cron
        if ! crontab -l 2>/dev/null | grep -q "rkhunter"; then
            (crontab -l 2>/dev/null; echo "0 3 * * * /usr/bin/rkhunter --check --skip-keypress") | crontab -
        fi
        
        print_message "✓ Rkhunter configured"
    fi
    
    # Setup file integrity monitoring
    create_file_integrity_monitor
    
    print_message "✓ Intrusion detection configured"
}

# Create file integrity monitoring script
create_file_integrity_monitor() {
    cat > /usr/local/bin/file-integrity-check <<'EOF'
#!/bin/bash

# File Integrity Monitoring
BASELINE_DIR="/var/lib/mail-security/baselines"
ALERT_EMAIL="root@localhost"

# Create baseline directory
mkdir -p "$BASELINE_DIR"

# Files to monitor
MONITOR_FILES=(
    "/etc/passwd"
    "/etc/shadow"
    "/etc/group"
    "/etc/postfix/main.cf"
    "/etc/postfix/master.cf"
    "/etc/dovecot/dovecot.conf"
    "/etc/ssh/sshd_config"
)

# Generate or check baselines
for file in "${MONITOR_FILES[@]}"; do
    baseline_file="$BASELINE_DIR/$(echo $file | tr / _).sha256"
    
    if [ ! -f "$baseline_file" ]; then
        # Generate baseline
        sha256sum "$file" > "$baseline_file"
        echo "Baseline created for $file"
    else
        # Check integrity
        current_hash=$(sha256sum "$file" | cut -d' ' -f1)
        baseline_hash=$(cut -d' ' -f1 "$baseline_file")
        
        if [ "$current_hash" != "$baseline_hash" ]; then
            echo "ALERT: File modified: $file" | mail -s "Security Alert: File Integrity" "$ALERT_EMAIL"
            echo "[$(date)] File modified: $file" >> /var/log/mail-security.log
            
            # Update baseline
            sha256sum "$file" > "$baseline_file"
        fi
    fi
done
EOF
    
    chmod +x /usr/local/bin/file-integrity-check
    
    # Add to cron
    if ! crontab -l 2>/dev/null | grep -q "file-integrity-check"; then
        (crontab -l 2>/dev/null; echo "0 * * * * /usr/local/bin/file-integrity-check") | crontab -
    fi
}

# Create security audit script
create_security_audit_script() {
    cat > /usr/local/bin/mail-security-audit <<'EOF'
#!/bin/bash

# Mail Server Security Audit
echo "MAIL SERVER SECURITY AUDIT"
echo "=========================="
echo "Date: $(date)"
echo ""

# Check services
echo "SERVICE STATUS:"
echo "--------------"
for service in postfix dovecot opendkim fail2ban ufw; do
    printf "%-15s: " "$service"
    systemctl is-active "$service" || echo "NOT RUNNING"
done
echo ""

# Check open ports
echo "OPEN PORTS:"
echo "-----------"
netstat -tuln | grep LISTEN
echo ""

# Check failed login attempts
echo "FAILED LOGIN ATTEMPTS (Last 24 hours):"
echo "--------------------------------------"
grep "authentication failed" /var/log/mail.log | grep "$(date -d '1 day ago' '+%b %e')" | wc -l
echo ""

# Check fail2ban status
echo "FAIL2BAN JAILS:"
echo "--------------"
fail2ban-client status | grep "Jail list" | cut -d':' -f2 | tr ',' '\n' | while read jail; do
    if [ ! -z "$jail" ]; then
        jail=$(echo $jail | tr -d ' ')
        echo -n "$jail: "
        fail2ban-client status "$jail" | grep "Currently banned" | cut -d':' -f2
    fi
done
echo ""

# Check firewall rules
echo "FIREWALL STATUS:"
echo "---------------"
ufw status numbered | head -20
echo ""

# Check for suspicious processes
echo "SUSPICIOUS PROCESSES:"
echo "--------------------"
ps aux | grep -E "(nc|netcat|perl|python|ruby|bash)" | grep -v grep | head -10
echo ""

# Check for large mail queue
echo "MAIL QUEUE:"
echo "----------"
mailq | tail -1
echo ""

# Security recommendations
echo "RECOMMENDATIONS:"
echo "---------------"
echo "1. Review failed login attempts regularly"
echo "2. Keep all software updated"
echo "3. Monitor mail logs for anomalies"
echo "4. Check blacklist status regularly"
echo "5. Review firewall rules monthly"
EOF
    
    chmod +x /usr/local/bin/mail-security-audit
    print_message "✓ Security audit script created"
}

# Test security configuration
test_security() {
    print_header "Testing Security Configuration"
    
    local all_good=true
    
    # Check firewall
    if ufw status | grep -q "Status: active"; then
        print_message "✓ Firewall is active"
    else
        print_error "✗ Firewall is not active"
        all_good=false
    fi
    
    # Check fail2ban
    if systemctl is-active --quiet fail2ban; then
        print_message "✓ Fail2ban is running"
        
        # Check jails
        local jail_count=$(fail2ban-client status | grep "Number of jail" | cut -d':' -f2 | tr -d ' ')
        print_message "  Active jails: $jail_count"
    else
        print_error "✗ Fail2ban is not running"
        all_good=false
    fi
    
    # Check SSH hardening
    if sshd -T | grep -q "permitrootlogin prohibit-password"; then
        print_message "✓ SSH root login restricted"
    else
        print_warning "⚠ SSH root login may not be properly restricted"
    fi
    
    # Check Postfix hardening
    if postconf -n | grep -q "disable_vrfy_command = yes"; then
        print_message "✓ Postfix VRFY command disabled"
    else
        print_warning "⚠ Postfix VRFY command not disabled"
    fi
    
    if [ "$all_good" = true ]; then
        print_message "✓ Security test passed"
        return 0
    else
        print_error "Security test failed - review configuration"
        return 1
    fi
}

# Main security setup function
setup_security_hardening() {
    print_header "Security Hardening Setup"
    
    # Initialize security
    init_security
    
    # Setup firewall
    setup_firewall
    
    # Setup fail2ban
    setup_fail2ban
    
    # Harden configurations
    harden_mail_config
    
    # Setup intrusion detection
    setup_intrusion_detection
    
    # Create audit script
    create_security_audit_script
    
    # Test security
    test_security
    
    print_message "✓ Security hardening complete"
    print_message ""
    print_message "Security tools available:"
    print_message "  mail-security-audit - Run security audit"
    print_message "  file-integrity-check - Check file integrity"
    print_message "  fail2ban-client status - Check fail2ban status"
    print_message "  ufw status - Check firewall status"
}

# Export functions
export -f init_security check_security_tools setup_firewall
export -f create_custom_firewall_rules setup_fail2ban create_fail2ban_filters
export -f harden_mail_config harden_postfix harden_dovecot harden_ssh
export -f harden_system setup_intrusion_detection create_file_integrity_monitor
export -f create_security_audit_script test_security setup_security_hardening

# Export variables
export SECURITY_DIR FIREWALL_RULES_FILE FAIL2BAN_DIR SECURITY_LOG ALLOWED_PORTS
