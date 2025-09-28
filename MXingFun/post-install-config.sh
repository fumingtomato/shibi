#!/bin/bash

# =================================================================
# MAIL SERVER POST-INSTALLATION CONFIGURATION
# Version: 16.0.3
# Configures SSL (Let's Encrypt only), firewall, and final optimizations
# =================================================================

# Colors
GREEN='\033[38;5;208m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[1;33m'
NC='\033[0m'

print_message() {
    echo -e "${GREEN}$1${NC}"
}

print_error() {
    echo -e "${RED}$1${NC}" >&2
}

print_warning() {
    echo -e "${YELLOW}$1${NC}"
}

print_header() {
    echo -e "${BLUE}==================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}==================================================${NC}"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    print_error "This script must be run as root"
    exit 1
fi

print_header "Mail Server Post-Installation Configuration"
echo ""

# Load configuration from installer
if [ -f "$(pwd)/install.conf" ]; then
    source "$(pwd)/install.conf"
elif [ -f "/root/mail-installer/install.conf" ]; then
    source "/root/mail-installer/install.conf"
fi

# Get domain info from environment or Postfix
if [ -z "$DOMAIN_NAME" ]; then
    if [ -f /etc/postfix/main.cf ]; then
        HOSTNAME=$(postconf -h myhostname 2>/dev/null || hostname -f)
        DOMAIN_NAME=$(postconf -h mydomain 2>/dev/null || hostname -d)
    else
        HOSTNAME=$(hostname -f)
        DOMAIN_NAME=$(hostname -d)
    fi
else
    # Use values from installer
    HOSTNAME=${HOSTNAME:-"mail.$DOMAIN_NAME"}
fi

# Validate we have proper domain
if [[ "$DOMAIN_NAME" == "localdomain" ]] || [ -z "$DOMAIN_NAME" ] || [[ "$DOMAIN_NAME" == "localhost"* ]]; then
    print_error "Invalid domain detected: $DOMAIN_NAME"
    read -p "Please enter your actual domain name (e.g., example.com): " DOMAIN_NAME
    while [[ ! "$DOMAIN_NAME" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; do
        echo "Invalid domain format. Please use format: example.com"
        read -p "Enter your domain name: " DOMAIN_NAME
    done
    HOSTNAME="mail.$DOMAIN_NAME"
fi

# Get admin email if not set
if [ -z "$ADMIN_EMAIL" ] || [[ "$ADMIN_EMAIL" == *"localdomain"* ]]; then
    ADMIN_EMAIL="admin@$DOMAIN_NAME"
fi

# Get primary IP if not set
if [ -z "$PRIMARY_IP" ]; then
    PRIMARY_IP=$(curl -s --max-time 5 https://ipinfo.io/ip 2>/dev/null || hostname -I | awk '{print $1}')
fi

echo "Configuration:"
echo "  Domain: $DOMAIN_NAME"
echo "  Hostname: $HOSTNAME"
echo "  Admin Email: $ADMIN_EMAIL"
echo "  Primary IP: $PRIMARY_IP"
echo ""

# ===================================================================
# 1. SSL/TLS CONFIGURATION - AUTOMATED FOR LET'S ENCRYPT
# ===================================================================

print_header "SSL/TLS Configuration (Let's Encrypt)"

# Check if certbot is installed
if ! command -v certbot &> /dev/null; then
    echo "Installing Certbot..."
    apt-get update
    apt-get install -y certbot
fi

# Check if certificate already exists
if [ -d "/etc/letsencrypt/live/$HOSTNAME" ]; then
    print_message "SSL certificate already exists for $HOSTNAME"
    echo "Certificate expiry:"
    certbot certificates 2>/dev/null | grep -A2 "$HOSTNAME" | grep "Expiry"
else
    print_message "Requesting Let's Encrypt certificate for $HOSTNAME..."
    
    # Check if DNS is resolving first
    echo -n "Checking DNS resolution for $HOSTNAME... "
    if host "$HOSTNAME" 8.8.8.8 > /dev/null 2>&1; then
        print_message "✓ DNS is resolving"
        
        # Stop services that might be using port 80
        systemctl stop nginx 2>/dev/null || true
        systemctl stop apache2 2>/dev/null || true
        
        # Get certificate
        certbot certonly --standalone \
            -d "$HOSTNAME" \
            --non-interactive \
            --agree-tos \
            --email "$ADMIN_EMAIL" \
            --no-eff-email \
            --force-renewal
        
        if [ $? -eq 0 ]; then
            print_message "✓ SSL certificate obtained successfully"
            
            # Update Postfix configuration
            postconf -e "smtpd_tls_cert_file = /etc/letsencrypt/live/$HOSTNAME/fullchain.pem"
            postconf -e "smtpd_tls_key_file = /etc/letsencrypt/live/$HOSTNAME/privkey.pem"
            
            # Update Dovecot configuration
            cat > /etc/dovecot/conf.d/10-ssl.conf <<EOF
ssl = required
ssl_cert = </etc/letsencrypt/live/$HOSTNAME/fullchain.pem
ssl_key = </etc/letsencrypt/live/$HOSTNAME/privkey.pem
ssl_min_protocol = TLSv1.2
ssl_cipher_list = ECDHE+AESGCM:ECDHE+RSA+AESGCM:DHE+RSA+AESGCM
ssl_prefer_server_ciphers = yes
ssl_dh = </etc/dovecot/dh.pem
EOF
            
            # Setup auto-renewal
            cat > /etc/cron.d/certbot-renewal <<EOF
0 2 * * * root certbot renew --quiet --post-hook "systemctl reload postfix dovecot"
EOF
            
            print_message "✓ Auto-renewal configured"
            
        else
            print_error "Failed to obtain Let's Encrypt certificate"
            echo ""
            echo "Possible reasons:"
            echo "1. DNS records not yet propagated (wait 5-30 minutes)"
            echo "2. Port 80 is blocked by firewall"
            echo "3. Domain doesn't point to this server ($PRIMARY_IP)"
            echo ""
            echo "You can retry later with:"
            echo "  certbot certonly --standalone -d $HOSTNAME"
            echo ""
            
            # Use temporary self-signed certificate
            print_warning "Creating temporary self-signed certificate..."
            
            openssl req -new -x509 -days 365 -nodes \
                -out /etc/ssl/certs/mailserver-temp.crt \
                -keyout /etc/ssl/private/mailserver-temp.key \
                -subj "/C=US/ST=State/L=City/O=TempCert/CN=$HOSTNAME" 2>/dev/null
            
            chmod 600 /etc/ssl/private/mailserver-temp.key
            
            postconf -e "smtpd_tls_cert_file = /etc/ssl/certs/mailserver-temp.crt"
            postconf -e "smtpd_tls_key_file = /etc/ssl/private/mailserver-temp.key"
            
            cat > /etc/dovecot/conf.d/10-ssl.conf <<EOF
ssl = required
ssl_cert = </etc/ssl/certs/mailserver-temp.crt
ssl_key = </etc/ssl/private/mailserver-temp.key
ssl_min_protocol = TLSv1.2
EOF
            
            print_warning "Temporary certificate created. Replace with Let's Encrypt when DNS is ready."
        fi
    else
        print_warning "✗ DNS not resolving yet"
        echo ""
        echo "DNS is not resolving for $HOSTNAME"
        echo "This is normal if you just added DNS records."
        echo ""
        echo "Creating temporary self-signed certificate..."
        
        openssl req -new -x509 -days 365 -nodes \
            -out /etc/ssl/certs/mailserver-temp.crt \
            -keyout /etc/ssl/private/mailserver-temp.key \
            -subj "/C=US/ST=State/L=City/O=TempCert/CN=$HOSTNAME" 2>/dev/null
        
        chmod 600 /etc/ssl/private/mailserver-temp.key
        
        postconf -e "smtpd_tls_cert_file = /etc/ssl/certs/mailserver-temp.crt"
        postconf -e "smtpd_tls_key_file = /etc/ssl/private/mailserver-temp.key"
        
        print_message "Temporary certificate created."
        echo ""
        echo "To get Let's Encrypt certificate after DNS propagates:"
        echo "  certbot certonly --standalone -d $HOSTNAME"
        echo ""
        echo "Then update Postfix and Dovecot to use the new certificate."
    fi
fi

# Generate DH parameters for Dovecot if not exists
if [ ! -f /etc/dovecot/dh.pem ]; then
    print_message "Generating DH parameters (this may take a minute)..."
    openssl dhparam -out /etc/dovecot/dh.pem 2048 2>/dev/null
fi

# ===================================================================
# 2. FIREWALL CONFIGURATION
# ===================================================================

print_header "Firewall Configuration"

if command -v ufw &> /dev/null; then
    print_message "Configuring UFW firewall..."
    
    # Default policies
    ufw --force disable
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow SSH (important!)
    ufw allow 22/tcp comment 'SSH'
    
    # Mail server ports
    ufw allow 25/tcp comment 'SMTP'
    ufw allow 587/tcp comment 'Submission'
    ufw allow 465/tcp comment 'SMTPS'
    ufw allow 143/tcp comment 'IMAP'
    ufw allow 993/tcp comment 'IMAPS'
    ufw allow 110/tcp comment 'POP3'
    ufw allow 995/tcp comment 'POP3S'
    
    # Web ports (for webmail and certbot)
    ufw allow 80/tcp comment 'HTTP'
    ufw allow 443/tcp comment 'HTTPS'
    
    # Enable firewall
    ufw --force enable
    
    print_message "✓ Firewall configured and enabled"
    
    # Show status
    ufw status numbered
else
    print_warning "UFW not installed, skipping firewall configuration"
    echo "Install with: apt-get install -y ufw"
fi

# ===================================================================
# 3. FAIL2BAN CONFIGURATION
# ===================================================================

print_header "Fail2ban Configuration"

if ! command -v fail2ban-client &> /dev/null; then
    print_message "Installing Fail2ban..."
    apt-get install -y fail2ban
fi

# Create jail configuration for mail services
cat > /etc/fail2ban/jail.local <<'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
destemail = root@localhost
action = %(action_mwl)s

[sshd]
enabled = true

[postfix]
enabled = true
port = smtp,submission,smtps
filter = postfix
logpath = /var/log/mail.log
maxretry = 3

[postfix-sasl]
enabled = true
port = smtp,submission,smtps
filter = postfix[mode=auth]
logpath = /var/log/mail.log
maxretry = 3

[dovecot]
enabled = true
port = pop3,pop3s,imap,imaps,submission,sieve
filter = dovecot
logpath = /var/log/mail.log
maxretry = 3
EOF

# Create custom filters
cat > /etc/fail2ban/filter.d/postfix-custom.conf <<'EOF'
[Definition]
failregex = ^.*postfix/smtpd.*: NOQUEUE: reject:.*from\s+\[<HOST>\].*$
            ^.*postfix/smtpd.*:.*\[<HOST>\]: Relay access denied.*$
            ^.*postfix/smtpd.*: warning:.*\[<HOST>\]: SASL.*authentication failed.*$
ignoreregex =
EOF

# Restart fail2ban
systemctl restart fail2ban
systemctl enable fail2ban

print_message "✓ Fail2ban configured"

# ===================================================================
# 4. POSTFIX OPTIMIZATION
# ===================================================================

print_header "Optimizing Postfix Configuration"

# Performance tuning
postconf -e "default_process_limit = 100"
postconf -e "smtp_connection_cache_on_demand = yes"
postconf -e "smtp_connection_cache_time_limit = 2s"
postconf -e "smtp_connection_reuse_time_limit = 300s"

# Security settings
postconf -e "disable_vrfy_command = yes"
postconf -e "smtpd_helo_required = yes"
postconf -e "strict_rfc821_envelopes = yes"
postconf -e "invalid_hostname_reject_code = 550"
postconf -e "non_fqdn_reject_code = 550"
postconf -e "unknown_address_reject_code = 550"
postconf -e "unknown_client_reject_code = 550"
postconf -e "unknown_hostname_reject_code = 550"

# Anti-spam settings
postconf -e "smtpd_recipient_limit = 100"
postconf -e "smtpd_client_message_rate_limit = 60"
postconf -e "anvil_rate_time_unit = 60s"

# TLS settings
postconf -e "smtpd_tls_security_level = may"
postconf -e "smtpd_tls_auth_only = yes"
postconf -e "smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1"
postconf -e "smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1"
postconf -e "smtpd_tls_mandatory_ciphers = medium"

# Update master.cf for submission port
if ! grep -q "^submission" /etc/postfix/master.cf; then
    cat >> /etc/postfix/master.cf <<'EOF'

# Submission port with STARTTLS
submission inet n       -       y       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_sasl_type=dovecot
  -o smtpd_sasl_path=private/auth
  -o smtpd_reject_unlisted_recipient=no
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING

# SMTPS port (465)
smtps inet n       -       y       -       -       smtpd
  -o syslog_name=postfix/smtps
  -o smtpd_tls_wrappermode=yes
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_sasl_type=dovecot
  -o smtpd_sasl_path=private/auth
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING
EOF
fi

print_message "✓ Postfix optimized"

# ===================================================================
# 5. SYSTEM OPTIMIZATION
# ===================================================================

print_header "System Optimization"

# Increase file descriptors
if ! grep -q "# Mail server limits" /etc/security/limits.conf; then
    cat >> /etc/security/limits.conf <<EOF

# Mail server limits
* soft nofile 65536
* hard nofile 65536
* soft nproc 32768
* hard nproc 32768
EOF
fi

# Kernel parameters for mail server
cat > /etc/sysctl.d/99-mailserver.conf <<EOF
# Mail Server Optimization
net.ipv4.tcp_fin_timeout = 20
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.ip_local_port_range = 10000 65000
net.core.rmem_default = 31457280
net.core.rmem_max = 67108864
net.core.wmem_default = 31457280
net.core.wmem_max = 67108864
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_congestion_control = htcp
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_window_scaling = 1
EOF

sysctl -p /etc/sysctl.d/99-mailserver.conf 2>/dev/null

print_message "✓ System optimized"

# ===================================================================
# 6. LOG ROTATION
# ===================================================================

print_header "Configuring Log Rotation"

cat > /etc/logrotate.d/mailserver <<EOF
/var/log/mail.log
/var/log/mail.err
/var/log/mail.warn
{
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    sharedscripts
    postrotate
        /usr/bin/doveadm log reopen 2>/dev/null || true
        /usr/sbin/postfix reload 2>/dev/null || true
    endscript
}
EOF

print_message "✓ Log rotation configured"

# ===================================================================
# 7. SERVICES RESTART
# ===================================================================

print_header "Restarting Services"

services=(postfix dovecot opendkim mysql fail2ban)

for service in "${services[@]}"; do
    echo -n "Restarting $service... "
    if systemctl restart $service 2>/dev/null; then
        echo "✓"
    else
        echo "✗ (might not be installed)"
    fi
done

# ===================================================================
# 8. CREATE SSL HELPER SCRIPT
# ===================================================================

print_header "Creating SSL Helper Script"

cat > /usr/local/bin/get-ssl-cert << EOF
#!/bin/bash

# SSL Certificate Helper Script
# Attempts to get Let's Encrypt certificate

HOSTNAME="$HOSTNAME"
ADMIN_EMAIL="$ADMIN_EMAIL"

echo "SSL Certificate Setup for: \$HOSTNAME"
echo "===================================="
echo ""

# Check DNS
echo -n "Checking DNS resolution... "
if host "\$HOSTNAME" 8.8.8.8 > /dev/null 2>&1; then
    echo "✓ DNS is resolving"
    
    # Stop services using port 80
    systemctl stop nginx 2>/dev/null || true
    systemctl stop apache2 2>/dev/null || true
    
    # Get certificate
    certbot certonly --standalone \\
        -d "\$HOSTNAME" \\
        --non-interactive \\
        --agree-tos \\
        --email "\$ADMIN_EMAIL" \\
        --no-eff-email \\
        --force-renewal
    
    if [ \$? -eq 0 ]; then
        echo ""
        echo "✓ Certificate obtained successfully!"
        echo ""
        echo "Updating mail server configuration..."
        
        # Update Postfix
        postconf -e "smtpd_tls_cert_file = /etc/letsencrypt/live/\$HOSTNAME/fullchain.pem"
        postconf -e "smtpd_tls_key_file = /etc/letsencrypt/live/\$HOSTNAME/privkey.pem"
        
        # Update Dovecot
        sed -i "s|ssl_cert = .*|ssl_cert = </etc/letsencrypt/live/\$HOSTNAME/fullchain.pem|" /etc/dovecot/conf.d/10-ssl.conf
        sed -i "s|ssl_key = .*|ssl_key = </etc/letsencrypt/live/\$HOSTNAME/privkey.pem|" /etc/dovecot/conf.d/10-ssl.conf
        
        # Restart services
        systemctl reload postfix
        systemctl reload dovecot
        
        echo "✓ Services updated with new certificate"
    else
        echo ""
        echo "✗ Failed to obtain certificate"
        echo "Check that port 80 is accessible and DNS is correct"
    fi
else
    echo "✗ DNS not resolving"
    echo ""
    echo "Please ensure DNS records are set up:"
    echo "  A record: \$HOSTNAME -> \$(curl -s https://ipinfo.io/ip)"
    echo ""
    echo "Then run this script again."
fi
EOF

chmod +x /usr/local/bin/get-ssl-cert

# ===================================================================
# 9. CREATE QUICK TEST SCRIPT
# ===================================================================

cat > /usr/local/bin/mail-test << 'EOF'
#!/bin/bash

echo "MAIL SERVER QUICK TEST"
echo "====================="
echo ""

# Check services
echo "1. Service Status:"
for service in postfix dovecot opendkim mysql; do
    printf "   %-10s: " "$service"
    systemctl is-active $service || echo "NOT RUNNING"
done
echo ""

# Check ports
echo "2. Open Ports:"
netstat -tlnp 2>/dev/null | grep -E ":(25|587|465|143|993|110|995) " | awk '{print "   Port", $4}'
echo ""

# Check SSL
echo "3. SSL Certificate:"
HOSTNAME=$(postconf -h myhostname)
if [ -f /etc/letsencrypt/live/$HOSTNAME/fullchain.pem ]; then
    echo "   ✓ Let's Encrypt certificate found"
    echo "   Expires: $(openssl x509 -in /etc/letsencrypt/live/$HOSTNAME/fullchain.pem -noout -enddate | cut -d= -f2)"
elif [ -f /etc/ssl/certs/mailserver-temp.crt ]; then
    echo "   ⚠ Using temporary self-signed certificate"
    echo "   Run 'get-ssl-cert' after DNS propagates to get Let's Encrypt certificate"
else
    echo "   ✗ No SSL certificate found"
fi
echo ""

# Check DNS
DOMAIN=$(postconf -h mydomain)
echo "4. DNS Quick Check:"
echo -n "   MX Record: "
dig +short MX $DOMAIN @8.8.8.8 | head -1 || echo "NOT SET"
echo ""

# Test email
echo "5. Send Test Email:"
echo "   Use: test-email recipient@example.com"
echo ""

echo "For full DNS check: check-dns $DOMAIN"
echo "For server status: mail-status"
echo "To get SSL certificate: get-ssl-cert"
EOF

chmod +x /usr/local/bin/mail-test

# ===================================================================
# COMPLETION
# ===================================================================

print_header "Post-Installation Complete!"
echo ""
echo "✓ SSL/TLS configured"
echo "✓ Firewall configured"
echo "✓ Fail2ban configured"
echo "✓ Services optimized"
echo "✓ Log rotation configured"
echo ""

# SSL status
if [ -f "/etc/letsencrypt/live/$HOSTNAME/fullchain.pem" ]; then
    print_message "✓ Let's Encrypt SSL certificate is active"
else
    print_warning "⚠ Temporary certificate in use"
    echo "  Run 'get-ssl-cert' after DNS propagates to get Let's Encrypt certificate"
fi
echo ""

echo "Quick Commands:"
echo "  mail-test      - Run quick test"
echo "  mail-status    - Check server status"
echo "  check-dns      - Verify DNS records"
echo "  test-email     - Send test email"
echo "  get-ssl-cert   - Get/renew Let's Encrypt certificate"
echo ""

# Run quick test
echo "Running quick test..."
echo ""
/usr/local/bin/mail-test

echo ""
print_message "✓ Post-installation configuration completed!"
print_message ""
print_message "Your mail server is now ready to use!"

# Save configuration summary
cat > /root/mail-server-config.txt <<EOF
Mail Server Configuration Summary
Generated: $(date)
================================================================================

Domain: $DOMAIN_NAME
Hostname: $HOSTNAME
Admin Email: $ADMIN_EMAIL
Primary IP: $PRIMARY_IP

SSL Certificate:
$(if [ -f "/etc/letsencrypt/live/$HOSTNAME/fullchain.pem" ]; then
    echo "  Type: Let's Encrypt"
    echo "  Location: /etc/letsencrypt/live/$HOSTNAME/"
    certbot certificates 2>/dev/null | grep -A2 "$HOSTNAME"
else
    echo "  Type: Temporary self-signed"
    echo "  Run 'get-ssl-cert' to obtain Let's Encrypt certificate"
fi)

Services:
  Postfix (SMTP): $(systemctl is-active postfix)
  Dovecot (IMAP): $(systemctl is-active dovecot)
  OpenDKIM: $(systemctl is-active opendkim)
  MySQL: $(systemctl is-active mysql || systemctl is-active mariadb)
  Fail2ban: $(systemctl is-active fail2ban)

Ports:
  25  - SMTP
  587 - Submission (STARTTLS)
  465 - SMTPS
  143 - IMAP
  993 - IMAPS
  110 - POP3
  995 - POP3S

Management Commands:
  mail-account   - Manage email accounts
  mail-queue     - Manage mail queue
  mail-status    - Check server status
  mail-backup    - Backup mail server
  mail-log       - View mail logs
  test-email     - Send test email
  check-dns      - Verify DNS records
  get-ssl-cert   - Get/renew SSL certificate

================================================================================
EOF

echo "Configuration saved to: /root/mail-server-config.txt"
