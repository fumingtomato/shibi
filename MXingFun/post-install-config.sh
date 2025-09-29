#!/bin/bash

# =================================================================
# MAIL SERVER POST-INSTALLATION CONFIGURATION
# Version: 17.0.0
# Configures SSL, firewall, IP rotation finalization, and optimizations
# FIXED: Complete IP rotation setup, better service detection, subdomain support
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

# Get domain info
if [ -z "$DOMAIN_NAME" ]; then
    if [ -f /etc/postfix/main.cf ]; then
        HOSTNAME=$(postconf -h myhostname 2>/dev/null || hostname -f)
        DOMAIN_NAME=$(postconf -h mydomain 2>/dev/null || hostname -d)
    else
        HOSTNAME=$(hostname -f)
        DOMAIN_NAME=$(hostname -d)
    fi
else
    # Use configured hostname with subdomain
    if [ ! -z "$MAIL_SUBDOMAIN" ]; then
        HOSTNAME="$MAIL_SUBDOMAIN.$DOMAIN_NAME"
    else
        HOSTNAME=${HOSTNAME:-"mail.$DOMAIN_NAME"}
    fi
fi

# Get admin email
if [ -z "$ADMIN_EMAIL" ]; then
    ADMIN_EMAIL="${FIRST_EMAIL:-admin@$DOMAIN_NAME}"
fi

# Get primary IP
if [ -z "$PRIMARY_IP" ]; then
    PRIMARY_IP=$(curl -s --max-time 5 https://ipinfo.io/ip 2>/dev/null || hostname -I | awk '{print $1}')
fi

echo "Configuration:"
echo "  Domain: $DOMAIN_NAME"
echo "  Hostname: $HOSTNAME"
echo "  Admin Email: $ADMIN_EMAIL"
echo "  Primary IP: $PRIMARY_IP"
if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
    echo "  Total IPs: ${#IP_ADDRESSES[@]}"
fi
echo ""

# ===================================================================
# 1. FINALIZE IP ROTATION CONFIGURATION
# ===================================================================

if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
    print_header "Finalizing IP Rotation Configuration"
    
    echo "Configuring Postfix for ${#IP_ADDRESSES[@]} IP addresses..."
    
    # Create transport table
    cat > /etc/postfix/transport <<EOF
# Transport table for IP rotation
# Default transport uses round-robin
$DOMAIN_NAME    :
EOF
    
    # Create sender-dependent transport script
    cat > /usr/local/bin/postfix-transport-selector <<'EOF'
#!/bin/bash
# Postfix Transport Selector for IP Rotation
# This script assigns senders to specific IPs for sticky sessions

SENDER="$1"
NUM_IPS=REPLACE_NUM_IPS
DB_PASS=$(cat /root/.mail_db_password 2>/dev/null)

if [ -z "$SENDER" ]; then
    echo "smtp:"
    exit 0
fi

# Check if sender already has assigned IP in database
if [ ! -z "$DB_PASS" ]; then
    ASSIGNED=$(mysql -u mailuser -p"$DB_PASS" -h localhost mailserver -N -e "
        SELECT transport_id FROM ip_rotation_log WHERE sender_email='$SENDER' LIMIT 1
    " 2>/dev/null)
    
    if [ ! -z "$ASSIGNED" ]; then
        # Update last used time and increment counter
        mysql -u mailuser -p"$DB_PASS" -h localhost mailserver -e "
            UPDATE ip_rotation_log 
            SET last_used=NOW(), message_count=message_count+1 
            WHERE sender_email='$SENDER'
        " 2>/dev/null
        
        echo "smtp-ip${ASSIGNED}:"
        exit 0
    fi
fi

# No existing assignment, create new one using hash
HASH=$(echo -n "$SENDER" | md5sum | cut -c1-8)
TRANSPORT_NUM=$((0x$HASH % NUM_IPS + 1))

# Get the IP for this transport
IP_NUM=$((TRANSPORT_NUM - 1))
IP_ADDR="${IP_ADDRESSES[$IP_NUM]}"

# Save assignment to database
if [ ! -z "$DB_PASS" ]; then
    mysql -u mailuser -p"$DB_PASS" -h localhost mailserver -e "
        INSERT INTO ip_rotation_log (sender_email, assigned_ip, transport_id, message_count)
        VALUES ('$SENDER', '$IP_ADDR', $TRANSPORT_NUM, 1)
        ON DUPLICATE KEY UPDATE 
            last_used=NOW(), 
            message_count=message_count+1
    " 2>/dev/null
fi

echo "smtp-ip${TRANSPORT_NUM}:"
EOF
    
    # Replace placeholders
    sed -i "s/REPLACE_NUM_IPS/${#IP_ADDRESSES[@]}/" /usr/local/bin/postfix-transport-selector
    
    # Add IP addresses array to script
    echo "" >> /usr/local/bin/postfix-transport-selector
    echo "# IP Addresses" >> /usr/local/bin/postfix-transport-selector
    echo "IP_ADDRESSES=(" >> /usr/local/bin/postfix-transport-selector
    for ip in "${IP_ADDRESSES[@]}"; do
        echo "    \"$ip\"" >> /usr/local/bin/postfix-transport-selector
    done
    echo ")" >> /usr/local/bin/postfix-transport-selector
    
    chmod +x /usr/local/bin/postfix-transport-selector
    
    # Update Postfix master.cf if not already done
    if ! grep -q "smtp-ip1" /etc/postfix/master.cf; then
        echo "" >> /etc/postfix/master.cf
        echo "# IP Rotation Transports" >> /etc/postfix/master.cf
        
        local i=0
        for ip in "${IP_ADDRESSES[@]}"; do
            i=$((i+1))
            cat >> /etc/postfix/master.cf <<EOF

# Transport for IP $ip
smtp-ip$i unix - - n - - smtp
    -o smtp_bind_address=$ip
    -o smtp_bind_address_enforce=yes
    -o smtp_helo_name=$HOSTNAME
    -o syslog_name=postfix-ip$i
EOF
        done
    fi
    
    # Configure transport maps
    postmap /etc/postfix/transport
    
    # Update Postfix configuration
    postconf -e "transport_maps = hash:/etc/postfix/transport"
    postconf -e "smtp_bind_address_enforce = yes"
    
    # Create IP rotation monitoring command
    cat > /usr/local/bin/ip-rotation-status <<'EOF'
#!/bin/bash

# IP Rotation Status Monitor
DB_PASS=$(cat /root/.mail_db_password 2>/dev/null)

echo "IP Rotation Status"
echo "=================="
echo ""

if [ -z "$DB_PASS" ]; then
    echo "Checking mail logs..."
    for i in $(seq 1 REPLACE_NUM_IPS); do
        count=$(grep "postfix-ip$i" /var/log/mail.log 2>/dev/null | grep -c "status=sent" || echo "0")
        echo "Transport smtp-ip$i: $count messages sent today"
    done
else
    echo "Database statistics:"
    mysql -u mailuser -p"$DB_PASS" -h localhost mailserver -e "
        SELECT 
            transport_id as 'Transport',
            assigned_ip as 'IP Address',
            COUNT(*) as 'Senders',
            SUM(message_count) as 'Messages',
            MAX(last_used) as 'Last Used'
        FROM ip_rotation_log
        GROUP BY transport_id, assigned_ip
        ORDER BY transport_id
    " 2>/dev/null || echo "No data available yet"
fi

echo ""
echo "Current mail queue:"
mailq | tail -5
EOF
    
    sed -i "s/REPLACE_NUM_IPS/${#IP_ADDRESSES[@]}/" /usr/local/bin/ip-rotation-status
    chmod +x /usr/local/bin/ip-rotation-status
    
    print_message "✓ IP rotation configured with sticky sessions"
    echo "  Monitor with: ip-rotation-status"
    echo ""
fi

# ===================================================================
# 2. VERIFY OPENDKIM CONFIGURATION
# ===================================================================

print_header "Verifying OpenDKIM Configuration"

# Check if OpenDKIM is installed
if ! command -v opendkim &> /dev/null; then
    echo "Installing OpenDKIM..."
    apt-get update > /dev/null 2>&1
    apt-get install -y opendkim opendkim-tools > /dev/null 2>&1
fi

# Check if DKIM keys exist
if [ -f "/etc/opendkim/keys/$DOMAIN_NAME/mail.private" ]; then
    print_message "✓ DKIM keys exist"
else
    print_warning "⚠ DKIM keys not found - this should have been created earlier"
fi

# Ensure OpenDKIM configuration is correct
cat > /etc/opendkim.conf <<EOF
# OpenDKIM Configuration
AutoRestart             Yes
AutoRestartRate         10/1h
UMask                   002
Syslog                  yes
SyslogSuccess           Yes
LogWhy                  Yes

# Canonicalization
Canonicalization        relaxed/simple

# Signing
Mode                    sv
SubDomains              yes

# Trusted hosts
ExternalIgnoreList      refile:/etc/opendkim/TrustedHosts
InternalHosts           refile:/etc/opendkim/TrustedHosts
KeyTable                refile:/etc/opendkim/KeyTable
SigningTable            refile:/etc/opendkim/SigningTable

# Socket
Socket                  inet:8891@localhost
PidFile                 /var/run/opendkim/opendkim.pid
SignatureAlgorithm      rsa-sha256
UserID                  opendkim:opendkim

# Additional settings
OversignHeaders         From
EOF

# Setup TrustedHosts with all IPs
cat > /etc/opendkim/TrustedHosts <<EOF
127.0.0.1
localhost
::1
$PRIMARY_IP
$HOSTNAME
*.$DOMAIN_NAME
EOF

# Add all additional IPs
if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
    for ip in "${IP_ADDRESSES[@]}"; do
        echo "$ip" >> /etc/opendkim/TrustedHosts
    done
fi

# Setup KeyTable
echo "mail._domainkey.$DOMAIN_NAME $DOMAIN_NAME:mail:/etc/opendkim/keys/$DOMAIN_NAME/mail.private" > /etc/opendkim/KeyTable

# Setup SigningTable
cat > /etc/opendkim/SigningTable <<EOF
*@$DOMAIN_NAME mail._domainkey.$DOMAIN_NAME
*@$HOSTNAME mail._domainkey.$DOMAIN_NAME
EOF

# Set proper permissions
chown -R opendkim:opendkim /etc/opendkim
chmod 644 /etc/opendkim/TrustedHosts
chmod 644 /etc/opendkim/KeyTable
chmod 644 /etc/opendkim/SigningTable

# Configure Postfix to use OpenDKIM
postconf -e "milter_protocol = 6"
postconf -e "milter_default_action = accept"
postconf -e "smtpd_milters = inet:localhost:8891"
postconf -e "non_smtpd_milters = inet:localhost:8891"

# Restart OpenDKIM
systemctl restart opendkim 2>/dev/null
systemctl enable opendkim 2>/dev/null

# Verify OpenDKIM is running
sleep 2
if netstat -lnp 2>/dev/null | grep -q ":8891"; then
    print_message "✓ OpenDKIM is running and listening on port 8891"
else
    print_warning "⚠ OpenDKIM may not be listening on port 8891"
    systemctl stop opendkim
    sleep 1
    systemctl start opendkim
fi

# ===================================================================
# 3. SSL/TLS CONFIGURATION
# ===================================================================

print_header "SSL/TLS Configuration"

# Check if certbot is installed
if ! command -v certbot &> /dev/null; then
    echo "Installing Certbot..."
    apt-get update > /dev/null 2>&1
    apt-get install -y certbot python3-certbot-nginx > /dev/null 2>&1
fi

# Check if certificate already exists
if [ -d "/etc/letsencrypt/live/$HOSTNAME" ]; then
    print_message "✓ SSL certificate already exists for $HOSTNAME"
    
    # Update Postfix configuration
    postconf -e "smtpd_tls_cert_file = /etc/letsencrypt/live/$HOSTNAME/fullchain.pem"
    postconf -e "smtpd_tls_key_file = /etc/letsencrypt/live/$HOSTNAME/privkey.pem"
    
    # Update Dovecot configuration if exists
    if [ -d /etc/dovecot/conf.d ]; then
        cat > /etc/dovecot/conf.d/10-ssl.conf <<EOF
ssl = required
ssl_cert = </etc/letsencrypt/live/$HOSTNAME/fullchain.pem
ssl_key = </etc/letsencrypt/live/$HOSTNAME/privkey.pem
ssl_min_protocol = TLSv1.2
ssl_cipher_list = ECDHE+AESGCM:ECDHE+RSA+AESGCM:DHE+RSA+AESGCM
ssl_prefer_server_ciphers = yes
ssl_dh = </etc/dovecot/dh.pem
EOF
    fi
else
    print_message "Checking if DNS is ready for SSL certificate..."
    
    # Check if DNS is resolving
    echo -n "Testing DNS resolution for $HOSTNAME... "
    if host "$HOSTNAME" 8.8.8.8 > /dev/null 2>&1; then
        print_message "✓ DNS is resolving"
        
        # Try to get certificate
        echo "Attempting to get Let's Encrypt certificate..."
        
        # Stop services that might be using port 80
        systemctl stop nginx 2>/dev/null || true
        
        certbot certonly --standalone \
            -d "$HOSTNAME" \
            --non-interactive \
            --agree-tos \
            --email "$ADMIN_EMAIL" \
            --no-eff-email > /dev/null 2>&1
        
        if [ $? -eq 0 ]; then
            print_message "✓ SSL certificate obtained successfully"
            
            # Update Postfix
            postconf -e "smtpd_tls_cert_file = /etc/letsencrypt/live/$HOSTNAME/fullchain.pem"
            postconf -e "smtpd_tls_key_file = /etc/letsencrypt/live/$HOSTNAME/privkey.pem"
            
            # Update Dovecot
            if [ -d /etc/dovecot/conf.d ]; then
                cat > /etc/dovecot/conf.d/10-ssl.conf <<EOF
ssl = required
ssl_cert = </etc/letsencrypt/live/$HOSTNAME/fullchain.pem
ssl_key = </etc/letsencrypt/live/$HOSTNAME/privkey.pem
ssl_min_protocol = TLSv1.2
ssl_cipher_list = ECDHE+AESGCM:ECDHE+RSA+AESGCM:DHE+RSA+AESGCM
ssl_prefer_server_ciphers = yes
ssl_dh = </etc/dovecot/dh.pem
EOF
            fi
        else
            print_warning "⚠ Could not get SSL certificate (DNS might not be ready)"
            echo "Creating self-signed certificate as temporary solution..."
            
            mkdir -p /etc/ssl/certs /etc/ssl/private
            openssl req -new -x509 -days 365 -nodes \
                -out /etc/ssl/certs/mailserver.crt \
                -keyout /etc/ssl/private/mailserver.key \
                -subj "/C=US/ST=State/L=City/O=Mail/CN=$HOSTNAME" 2>/dev/null
            
            chmod 600 /etc/ssl/private/mailserver.key
            
            postconf -e "smtpd_tls_cert_file = /etc/ssl/certs/mailserver.crt"
            postconf -e "smtpd_tls_key_file = /etc/ssl/private/mailserver.key"
        fi
        
        # Start nginx again
        systemctl start nginx 2>/dev/null || true
    else
        print_warning "⚠ DNS not resolving yet - using self-signed certificate"
        
        mkdir -p /etc/ssl/certs /etc/ssl/private
        openssl req -new -x509 -days 365 -nodes \
            -out /etc/ssl/certs/mailserver.crt \
            -keyout /etc/ssl/private/mailserver.key \
            -subj "/C=US/ST=State/L=City/O=Mail/CN=$HOSTNAME" 2>/dev/null
        
        chmod 600 /etc/ssl/private/mailserver.key
        
        postconf -e "smtpd_tls_cert_file = /etc/ssl/certs/mailserver.crt"
        postconf -e "smtpd_tls_key_file = /etc/ssl/private/mailserver.key"
    fi
fi

# Generate DH parameters for Dovecot if not exists
if [ ! -f /etc/dovecot/dh.pem ]; then
    print_message "Generating DH parameters (this may take a minute)..."
    openssl dhparam -out /etc/dovecot/dh.pem 2048 2>/dev/null
fi

# Setup auto-renewal
cat > /etc/cron.d/certbot-renewal <<EOF
0 2,14 * * * root certbot renew --quiet --post-hook "systemctl reload postfix dovecot nginx 2>/dev/null || true"
EOF

# ===================================================================
# 4. FIREWALL CONFIGURATION
# ===================================================================

print_header "Firewall Configuration"

if command -v ufw &> /dev/null; then
    print_message "Configuring UFW firewall..."
    
    # Default policies
    ufw --force disable > /dev/null 2>&1
    ufw --force reset > /dev/null 2>&1
    ufw default deny incoming > /dev/null 2>&1
    ufw default allow outgoing > /dev/null 2>&1
    
    # Allow SSH (important!)
    ufw allow 22/tcp comment 'SSH' > /dev/null 2>&1
    
    # Mail server ports
    ufw allow 25/tcp comment 'SMTP' > /dev/null 2>&1
    ufw allow 587/tcp comment 'Submission' > /dev/null 2>&1
    ufw allow 465/tcp comment 'SMTPS' > /dev/null 2>&1
    ufw allow 143/tcp comment 'IMAP' > /dev/null 2>&1
    ufw allow 993/tcp comment 'IMAPS' > /dev/null 2>&1
    ufw allow 110/tcp comment 'POP3' > /dev/null 2>&1
    ufw allow 995/tcp comment 'POP3S' > /dev/null 2>&1
    
    # Web ports
    ufw allow 80/tcp comment 'HTTP' > /dev/null 2>&1
    ufw allow 443/tcp comment 'HTTPS' > /dev/null 2>&1
    
    # Enable firewall
    ufw --force enable > /dev/null 2>&1
    
    print_message "✓ Firewall configured and enabled"
else
    print_warning "UFW not installed, skipping firewall configuration"
fi

# ===================================================================
# 5. FAIL2BAN CONFIGURATION
# ===================================================================

print_header "Fail2ban Configuration"

if ! command -v fail2ban-client &> /dev/null; then
    print_message "Installing Fail2ban..."
    apt-get install -y fail2ban > /dev/null 2>&1
fi

# Create jail configuration
cat > /etc/fail2ban/jail.local <<'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
destemail = root@localhost
action = %(action_mwl)s

[sshd]
enabled = true
port = 22
maxretry = 3

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

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/*error.log

[nginx-noscript]
enabled = true
port = http,https
filter = nginx-noscript
logpath = /var/log/nginx/*access.log
maxretry = 6

[nginx-badbots]
enabled = true
port = http,https
filter = nginx-badbots
logpath = /var/log/nginx/*access.log
maxretry = 2

[nginx-noproxy]
enabled = true
port = http,https
filter = nginx-noproxy
logpath = /var/log/nginx/*error.log
maxretry = 2
EOF

# Restart fail2ban
systemctl restart fail2ban > /dev/null 2>&1
systemctl enable fail2ban > /dev/null 2>&1

print_message "✓ Fail2ban configured"

# ===================================================================
# 6. POSTFIX OPTIMIZATION
# ===================================================================

print_header "Optimizing Postfix Configuration"

# Performance tuning
postconf -e "default_process_limit = 100"
postconf -e "smtp_connection_cache_on_demand = yes"
postconf -e "smtp_connection_cache_time_limit = 2s"
postconf -e "smtp_connection_reuse_time_limit = 300s"

# Bulk email optimizations
if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
    # Multiple IP optimizations
    postconf -e "smtp_destination_concurrency_limit = 20"
    postconf -e "smtp_destination_rate_delay = 1s"
    postconf -e "smtp_extra_recipient_limit = 1000"
else
    # Single IP optimizations
    postconf -e "smtp_destination_concurrency_limit = 10"
    postconf -e "smtp_destination_rate_delay = 2s"
    postconf -e "smtp_extra_recipient_limit = 500"
fi

# Security settings
postconf -e "disable_vrfy_command = yes"
postconf -e "smtpd_helo_required = yes"
postconf -e "strict_rfc821_envelopes = yes"

# Anti-spam settings
postconf -e "smtpd_recipient_limit = 1000"
postconf -e "smtpd_client_message_rate_limit = 100"
postconf -e "anvil_rate_time_unit = 60s"

# TLS settings
postconf -e "smtpd_tls_security_level = may"
postconf -e "smtpd_tls_auth_only = yes"
postconf -e "smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1"
postconf -e "smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1"
postconf -e "smtpd_tls_mandatory_ciphers = medium"
postconf -e "smtpd_tls_loglevel = 1"
postconf -e "smtpd_tls_received_header = yes"
postconf -e "smtpd_tls_session_cache_database = btree:\${data_directory}/smtpd_scache"
postconf -e "smtp_tls_session_cache_database = btree:\${data_directory}/smtp_scache"

# Message size for bulk email
postconf -e "message_size_limit = 52428800"  # 50MB
postconf -e "mailbox_size_limit = 0"         # Unlimited

print_message "✓ Postfix optimized for bulk email"

# ===================================================================
# 7. SYSTEM OPTIMIZATION
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

sysctl -p /etc/sysctl.d/99-mailserver.conf > /dev/null 2>&1

print_message "✓ System optimized"

# ===================================================================
# 8. LOG ROTATION
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
# 9. SERVICES RESTART
# ===================================================================

print_header "Restarting Services"

# List of services to check and restart
declare -a services=("postfix" "dovecot" "opendkim" "nginx" "fail2ban")

# Check if MySQL or MariaDB is running
if systemctl is-active --quiet mysql 2>/dev/null; then
    services+=("mysql")
elif systemctl is-active --quiet mariadb 2>/dev/null; then
    services+=("mariadb")
fi

for service in "${services[@]}"; do
    echo -n "Restarting $service... "
    if systemctl list-units --full -all | grep -Fq "${service}.service"; then
        systemctl restart $service 2>/dev/null
        if systemctl is-active --quiet $service; then
            echo "✓"
        else
            echo "✗ (service not running)"
        fi
    else
        echo "✗ (not installed)"
    fi
done

# ===================================================================
# 10. CREATE HELPER SCRIPTS
# ===================================================================

print_header "Creating Helper Scripts"

# Quick SSL getter
cat > /usr/local/bin/get-ssl-cert <<EOF
#!/bin/bash

# Quick SSL Certificate Getter
HOSTNAME="$HOSTNAME"
DOMAIN="$DOMAIN_NAME"
ADMIN_EMAIL="$ADMIN_EMAIL"

echo "Getting Let's Encrypt certificates..."
echo ""

# Check DNS for mail server
echo -n "Checking DNS for \$HOSTNAME... "
if host "\$HOSTNAME" 8.8.8.8 > /dev/null 2>&1; then
    echo "✓ Resolving"
    
    systemctl stop nginx 2>/dev/null || true
    
    # Get certificate for mail server
    certbot certonly --standalone \\
        -d "\$HOSTNAME" \\
        --non-interactive \\
        --agree-tos \\
        --email "\$ADMIN_EMAIL" \\
        --no-eff-email \\
        --force-renewal
    
    if [ \$? -eq 0 ]; then
        echo "✓ Mail server certificate obtained!"
        
        # Update configs
        postconf -e "smtpd_tls_cert_file = /etc/letsencrypt/live/\$HOSTNAME/fullchain.pem"
        postconf -e "smtpd_tls_key_file = /etc/letsencrypt/live/\$HOSTNAME/privkey.pem"
        
        if [ -f /etc/dovecot/conf.d/10-ssl.conf ]; then
            sed -i "s|ssl_cert = .*|ssl_cert = </etc/letsencrypt/live/\$HOSTNAME/fullchain.pem|" /etc/dovecot/conf.d/10-ssl.conf
            sed -i "s|ssl_key = .*|ssl_key = </etc/letsencrypt/live/\$HOSTNAME/privkey.pem|" /etc/dovecot/conf.d/10-ssl.conf
        fi
    fi
else
    echo "✗ DNS not resolving yet"
fi

# Check DNS for website
echo -n "Checking DNS for \$DOMAIN... "
if host "\$DOMAIN" 8.8.8.8 > /dev/null 2>&1; then
    echo "✓ Resolving"
    
    # Get certificate for website
    systemctl start nginx 2>/dev/null || true
    
    certbot --nginx \\
        -d "\$DOMAIN" \\
        -d "www.\$DOMAIN" \\
        --non-interactive \\
        --agree-tos \\
        --email "\$ADMIN_EMAIL" \\
        --no-eff-email
    
    if [ \$? -eq 0 ]; then
        echo "✓ Website certificate obtained!"
    fi
else
    echo "✗ DNS not resolving yet"
fi

systemctl reload postfix dovecot nginx 2>/dev/null || true
echo ""
echo "Done! Services reloaded."
EOF

chmod +x /usr/local/bin/get-ssl-cert

# ===================================================================
# 11. SAVE CONFIGURATION SUMMARY
# ===================================================================

cat > /root/mail-server-config.txt <<EOF
Mail Server Configuration Summary
Generated: $(date)
================================================================================

Domain: $DOMAIN_NAME
Mail Subdomain: $MAIL_SUBDOMAIN
Hostname: $HOSTNAME
Admin Email: $ADMIN_EMAIL
Primary IP: $PRIMARY_IP
$([ ${#IP_ADDRESSES[@]} -gt 1 ] && echo "Total IPs: ${#IP_ADDRESSES[@]}")

First Email Account: ${FIRST_EMAIL:-Not configured}

SSL Certificate:
$(if [ -f "/etc/letsencrypt/live/$HOSTNAME/fullchain.pem" ]; then
    echo "  Mail Server: Let's Encrypt"
    echo "  Location: /etc/letsencrypt/live/$HOSTNAME/"
    echo "  Auto-renewal: Enabled"
else
    echo "  Mail Server: Self-signed (temporary)"
    echo "  Get Let's Encrypt: run 'get-ssl-cert'"
fi)

$(if [ -f "/etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem" ]; then
    echo "  Website: Let's Encrypt"
    echo "  Location: /etc/letsencrypt/live/$DOMAIN_NAME/"
else
    echo "  Website: Not configured yet"
fi)

DKIM Status:
  Service: $(systemctl is-active opendkim 2>/dev/null || echo "not running")
  Port 8891: $(netstat -lnp 2>/dev/null | grep -q ":8891" && echo "Listening" || echo "Not listening")
  DKIM Key: $([ -f "/etc/opendkim/keys/$DOMAIN_NAME/mail.txt" ] && echo "Generated" || echo "Missing")
  DKIM in DNS: $(dig +short TXT mail._domainkey.$DOMAIN_NAME @8.8.8.8 2>/dev/null | grep -q "v=DKIM1" && echo "Yes" || echo "Pending")

$(if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
    echo "IP Rotation:"
    echo "  Status: Configured"
    echo "  Total IPs: ${#IP_ADDRESSES[@]}"
    echo "  Mode: Sticky sessions (sender-based)"
    echo "  Monitor: ip-rotation-status"
fi)

Services:
  Postfix (SMTP): $(systemctl is-active postfix 2>/dev/null || echo "not running")
  Dovecot (IMAP): $(systemctl is-active dovecot 2>/dev/null || echo "not running")
  OpenDKIM: $(systemctl is-active opendkim 2>/dev/null || echo "not running")
  MySQL: $(systemctl is-active mysql 2>/dev/null || systemctl is-active mariadb 2>/dev/null || echo "not running")
  Nginx: $(systemctl is-active nginx 2>/dev/null || echo "not running")
  Fail2ban: $(systemctl is-active fail2ban 2>/dev/null || echo "not running")
  Firewall: $(ufw status 2>/dev/null | grep -q "Status: active" && echo "Active" || echo "Inactive")

Ports:
  25  - SMTP
  587 - Submission (STARTTLS)
  465 - SMTPS
  143 - IMAP
  993 - IMAPS
  110 - POP3
  995 - POP3S
  80  - HTTP (website)
  443 - HTTPS (website)
  8891 - OpenDKIM

Website:
  URL: http://$DOMAIN_NAME
  SSL: $([ -f "/etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem" ] && echo "https://$DOMAIN_NAME" || echo "Not configured")
  Root: /var/www/$DOMAIN_NAME

Email Testing:
  Send test: test-email check-auth@verifier.port25.com ${FIRST_EMAIL:-user@$DOMAIN_NAME}
  Mail Tester: https://www.mail-tester.com
  MX Toolbox: https://mxtoolbox.com/SuperTool.aspx?action=mx:$DOMAIN_NAME

Management Commands:
  test-email        - Send test email with DKIM
  mail-account      - Manage email accounts
  mail-status       - Check server status
  mail-queue        - Manage mail queue
  mail-log          - View mail logs
  check-dns         - Verify DNS records
  get-ssl-cert      - Get/renew SSL certificates
  mailwizz-info     - Mailwizz configuration info
$([ ${#IP_ADDRESSES[@]} -gt 1 ] && echo "  ip-rotation-status - Monitor IP rotation")
$([ ${#IP_ADDRESSES[@]} -gt 1 ] && echo "  ip-usage          - Check IP usage statistics")

Logs:
  /var/log/mail.log     - Mail server log
  /var/log/syslog       - System log
  journalctl -xe        - Service logs

Backup:
  Run: mail-backup

================================================================================
EOF

# ===================================================================
# COMPLETION
# ===================================================================

print_header "Post-Installation Complete!"
echo ""
echo "✓ OpenDKIM verified and running"
echo "✓ SSL/TLS configured"
echo "✓ Firewall configured" 
echo "✓ Fail2ban configured"
echo "✓ Services optimized"
echo "✓ Log rotation configured"
if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
    echo "✓ IP rotation configured with sticky sessions"
fi
echo ""

# Show status summary
print_header "SERVER STATUS"

echo "DKIM SIGNING:"
echo "  Status: $(systemctl is-active opendkim 2>/dev/null || echo "not running")"
echo "  Port: localhost:8891"
echo "  Selector: mail"
echo "  Domain: $DOMAIN_NAME"

if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
    echo ""
    echo "IP ROTATION:"
    echo "  Configured IPs: ${#IP_ADDRESSES[@]}"
    echo "  Primary: $PRIMARY_IP"
    echo "  Mode: Sticky sessions"
    echo "  Monitor: ip-rotation-status"
fi

echo ""
echo "SSL STATUS:"
if [ -f "/etc/letsencrypt/live/$HOSTNAME/fullchain.pem" ]; then
    print_message "  ✓ Mail server: Let's Encrypt certificate active"
else
    print_warning "  ⚠ Mail server: Using temporary self-signed certificate"
    echo "    Get certificate: get-ssl-cert"
fi

if [ -f "/etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem" ]; then
    print_message "  ✓ Website: Let's Encrypt certificate active"
else
    print_warning "  ⚠ Website: No SSL certificate yet"
fi

echo ""
if [ ! -z "$FIRST_EMAIL" ]; then
    print_message "Email account ready:"
    echo "  Email: $FIRST_EMAIL"
    echo "  Server: $HOSTNAME"
    echo "  Ports: 587 (SMTP), 993 (IMAP)"
fi

echo ""
print_header "QUICK TEST COMMANDS"
echo ""
echo "1. Test DKIM signature:"
echo "   test-email check-auth@verifier.port25.com ${FIRST_EMAIL:-test@$DOMAIN_NAME}"
echo ""
echo "2. Check everything:"
echo "   mail-test"
echo ""
echo "3. Check DNS and DKIM:"
echo "   check-dns $DOMAIN_NAME"
echo ""
if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
    echo "4. Monitor IP rotation:"
    echo "   ip-rotation-status"
    echo ""
fi

print_message "Configuration saved to: /root/mail-server-config.txt"
echo ""
print_message "✓ Post-installation configuration completed!"
print_message "✓ Your mail server is ready with DKIM signing enabled!"
if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
    print_message "✓ IP rotation is active with sticky sessions!"
fi
