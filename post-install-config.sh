#!/bin/bash

# =================================================================
# MAIL SERVER POST-INSTALLATION CONFIGURATION
# Version: 17.1.0 - Fixed hostname generation and IP rotation
# Configures SSL, firewall, IP rotation finalization, and optimizations
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
    # FIX 1: Use configured hostname with custom subdomain
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
echo "  Mail Subdomain: ${MAIL_SUBDOMAIN:-mail}"
echo "  Admin Email: $ADMIN_EMAIL"
echo "  Primary IP: $PRIMARY_IP"
if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
    echo "  Total IPs: ${#IP_ADDRESSES[@]}"
fi
echo ""

# ===================================================================
# 1. FINALIZE IP ROTATION CONFIGURATION (FIX 2)
# ===================================================================

if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
    print_header "Finalizing IP Rotation Configuration"
    
    echo "Finalizing configuration for ${#IP_ADDRESSES[@]} IP addresses..."
    
    # Ensure MySQL directory exists
    mkdir -p /etc/postfix/mysql
    
    # Get database password
    if [ -f /root/.mail_db_password ]; then
        DB_PASS=$(cat /root/.mail_db_password)
    else
        print_error "Database password not found"
        exit 1
    fi
    
    # Create sender transport lookup
    cat > /etc/postfix/mysql/sender-transports.cf <<EOF
user = mailuser
password = $DB_PASS
hosts = 127.0.0.1
dbname = mailserver
query = SELECT CONCAT('smtp-ip', transport_id, ':') FROM ip_rotation_advanced WHERE sender_email='%s'
EOF
    
    # Set permissions
    chmod 640 /etc/postfix/mysql/sender-transports.cf
    chown root:postfix /etc/postfix/mysql/sender-transports.cf
    
    # Create hash-based sender transports file
    touch /etc/postfix/sender_transports
    postmap /etc/postfix/sender_transports
    
    # Configure Postfix for sender-dependent transport
    postconf -e "sender_dependent_default_transport_maps = hash:/etc/postfix/sender_transports, mysql:/etc/postfix/mysql/sender-transports.cf"
    postconf -e "smtp_sender_dependent_authentication = yes"
    postconf -e "smtp_bind_address_enforce = yes"
    postconf -e "default_transport = smtp"
    
    # Verify transport configurations in master.cf
    echo "Verifying transport configurations..."
    for i in "${!IP_ADDRESSES[@]}"; do
        if grep -q "smtp-ip$i" /etc/postfix/master.cf; then
            echo "  ✓ Transport smtp-ip$i configured"
        else
            print_warning "  ⚠ Transport smtp-ip$i missing - adding"
            
            # FIX 2: Add missing transport configuration
            cat >> /etc/postfix/master.cf <<EOF

# Transport for IP ${IP_ADDRESSES[$i]} (index $i)
smtp-ip$i unix - - n - - smtp
  -o smtp_bind_address=${IP_ADDRESSES[$i]}
  -o smtp_helo_name=${MAIL_SUBDOMAIN}$i.$DOMAIN_NAME
  -o syslog_name=postfix-ip$i
EOF
        fi
    done
    
    print_message "✓ IP rotation finalized with ${#IP_ADDRESSES[@]} addresses"
    echo ""
fi

# ===================================================================
# 2. VERIFY DKIM IS PROPERLY CONFIGURED (1024-bit)
# ===================================================================

print_header "Verifying DKIM Configuration"

# Check if OpenDKIM is installed
if ! command -v opendkim &> /dev/null; then
    echo "Installing OpenDKIM..."
    apt-get update > /dev/null 2>&1
    apt-get install -y opendkim opendkim-tools > /dev/null 2>&1
fi

# Check DKIM key size
if [ -f "/etc/opendkim/keys/$DOMAIN_NAME/mail.private" ]; then
    # Extract key bits properly
    KEY_BITS=$(openssl rsa -in "/etc/opendkim/keys/$DOMAIN_NAME/mail.private" -text -noout 2>/dev/null | grep "Private-Key:" | head -1 | grep -oP '\d+' | head -1 || echo "0")
    
    # Ensure KEY_BITS is numeric
    if ! [[ "$KEY_BITS" =~ ^[0-9]+$ ]]; then
        KEY_BITS=0
    fi
    
    if [ "$KEY_BITS" -eq 1024 ]; then
        print_message "✓ DKIM key is 1024-bit (DNS compatible)"
    elif [ "$KEY_BITS" -eq 2048 ]; then
        print_warning "⚠ DKIM key is 2048-bit - regenerating as 1024-bit for DNS compatibility"
        
        cd /etc/opendkim/keys/$DOMAIN_NAME
        mv mail.private mail.private.backup
        mv mail.txt mail.txt.backup
        
        opendkim-genkey -s mail -d $DOMAIN_NAME -b 1024
        chown opendkim:opendkim mail.private mail.txt
        chmod 600 mail.private
        chmod 644 mail.txt
        
        print_message "✓ Regenerated as 1024-bit key"
    elif [ "$KEY_BITS" -eq 0 ]; then
        print_warning "⚠ Could not determine DKIM key size - regenerating"
        
        cd /etc/opendkim/keys/$DOMAIN_NAME
        [ -f mail.private ] && mv mail.private mail.private.backup
        [ -f mail.txt ] && mv mail.txt mail.txt.backup
        
        opendkim-genkey -s mail -d $DOMAIN_NAME -b 1024
        chown opendkim:opendkim mail.private mail.txt
        chmod 600 mail.private
        chmod 644 mail.txt
        
        print_message "✓ Generated new 1024-bit key"
    else
        print_warning "⚠ Unexpected key size: $KEY_BITS bits"
    fi
    
    # Display key info
    if [ -f "/etc/opendkim/keys/$DOMAIN_NAME/mail.txt" ]; then
        DKIM_KEY=$(cat /etc/opendkim/keys/$DOMAIN_NAME/mail.txt | grep -v "(" | grep -v ")" | sed 's/.*"p=//' | sed 's/".*//' | tr -d '\n\t\r ')
        echo "DKIM public key length: ${#DKIM_KEY} characters"
        if [ ${#DKIM_KEY} -gt 250 ]; then
            print_warning "⚠ Key seems too long for 1024-bit (should be ~215 chars)"
        elif [ ${#DKIM_KEY} -eq 0 ]; then
            print_warning "⚠ Could not extract DKIM key from file"
        fi
    fi
else
    print_warning "⚠ DKIM keys not found - generating now"
    mkdir -p /etc/opendkim/keys/$DOMAIN_NAME
    cd /etc/opendkim/keys/$DOMAIN_NAME
    opendkim-genkey -s mail -d $DOMAIN_NAME -b 1024
    chown -R opendkim:opendkim /etc/opendkim
    chmod 600 mail.private
    chmod 644 mail.txt
    print_message "✓ Generated 1024-bit DKIM key"
fi

# Ensure OpenDKIM is properly configured for signing
cat > /etc/opendkim.conf <<EOF
# OpenDKIM Configuration - SIGNING ENABLED
AutoRestart             Yes
AutoRestartRate         10/1h
UMask                   002
Syslog                  yes
SyslogSuccess           Yes
LogWhy                  Yes

# CRITICAL: Set to signing mode
Mode                    sv
Domain                  $DOMAIN_NAME
Selector                mail
MinimumKeyBits          1024
SubDomains              yes
AlwaysAddARHeader       yes

# Canonicalization
Canonicalization        relaxed/simple

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
TemporaryDirectory      /var/tmp

# Additional signing settings
OversignHeaders         From
EOF

# Setup TrustedHosts with all IPs and hostnames
cat > /etc/opendkim/TrustedHosts <<EOF
127.0.0.1
localhost
::1
$PRIMARY_IP
$HOSTNAME
*.$DOMAIN_NAME
$DOMAIN_NAME
EOF

# Add all additional IPs and their hostnames
if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
    for i in "${!IP_ADDRESSES[@]}"; do
        echo "${IP_ADDRESSES[$i]}" >> /etc/opendkim/TrustedHosts
        if [ $i -ne 0 ]; then
            echo "${MAIL_SUBDOMAIN}${i}.$DOMAIN_NAME" >> /etc/opendkim/TrustedHosts
        fi
    done
fi

# Setup KeyTable
echo "mail._domainkey.$DOMAIN_NAME $DOMAIN_NAME:mail:/etc/opendkim/keys/$DOMAIN_NAME/mail.private" > /etc/opendkim/KeyTable

# Setup comprehensive SigningTable
cat > /etc/opendkim/SigningTable <<EOF
*@$DOMAIN_NAME mail._domainkey.$DOMAIN_NAME
*@$HOSTNAME mail._domainkey.$DOMAIN_NAME
$DOMAIN_NAME mail._domainkey.$DOMAIN_NAME
*@localhost mail._domainkey.$DOMAIN_NAME
*@localhost.localdomain mail._domainkey.$DOMAIN_NAME
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

# Create systemd directory if needed
if [ ! -d /var/run/opendkim ]; then
    mkdir -p /var/run/opendkim
    chown opendkim:opendkim /var/run/opendkim
fi

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
# 3. AUTOMATIC SSL/TLS CONFIGURATION
# ===================================================================

print_header "SSL/TLS Configuration"

# Check if certbot is installed
if ! command -v certbot &> /dev/null; then
    echo "Installing Certbot..."
    apt-get update > /dev/null 2>&1
    apt-get install -y certbot python3-certbot-nginx > /dev/null 2>&1
fi

# Build list of ALL domains for SSL
SSL_DOMAINS="$DOMAIN_NAME www.$DOMAIN_NAME $HOSTNAME"

# FIX 1: Add numbered subdomains with correct prefix if multiple IPs
if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
    for i in "${!IP_ADDRESSES[@]}"; do
        if [ $i -ne 0 ]; then
            SSL_DOMAINS="$SSL_DOMAINS ${MAIL_SUBDOMAIN}${i}.$DOMAIN_NAME"
        fi
    done
fi

# Check if certificate already exists
if [ -d "/etc/letsencrypt/live/$DOMAIN_NAME" ]; then
    print_message "✓ SSL certificate already exists for $DOMAIN_NAME"
    
    # Update Postfix configuration
    postconf -e "smtpd_tls_cert_file = /etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem"
    postconf -e "smtpd_tls_key_file = /etc/letsencrypt/live/$DOMAIN_NAME/privkey.pem"
    
    # Update Dovecot configuration if exists
    if [ -d /etc/dovecot/conf.d ]; then
        cat > /etc/dovecot/conf.d/10-ssl.conf <<EOF
ssl = required
ssl_cert = </etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem
ssl_key = </etc/letsencrypt/live/$DOMAIN_NAME/privkey.pem
ssl_min_protocol = TLSv1.2
ssl_cipher_list = ECDHE+AESGCM:ECDHE+RSA+AESGCM:DHE+RSA+AESGCM
ssl_prefer_server_ciphers = yes
ssl_dh = </etc/dovecot/dh.pem
EOF
    fi
else
    print_message "Attempting to get SSL certificate for all domains..."
    
    # Check if DNS is resolving
    if host "$DOMAIN_NAME" 8.8.8.8 > /dev/null 2>&1; then
        print_message "DNS is resolving for $DOMAIN_NAME"
        
        # Build certbot domain arguments
        CERT_ARGS=""
        for domain in $SSL_DOMAINS; do
            CERT_ARGS="$CERT_ARGS -d $domain"
        done
        
        # Try to get certificate with nginx plugin
        certbot --nginx \
            $CERT_ARGS \
            --non-interactive \
            --agree-tos \
            --email "$ADMIN_EMAIL" \
            --no-eff-email 2>/dev/null
        
        if [ $? -eq 0 ]; then
            print_message "✓ SSL certificate obtained for all domains"
            
            # Update Postfix
            postconf -e "smtpd_tls_cert_file = /etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem"
            postconf -e "smtpd_tls_key_file = /etc/letsencrypt/live/$DOMAIN_NAME/privkey.pem"
            
            # Update Dovecot
            if [ -d /etc/dovecot/conf.d ]; then
                cat > /etc/dovecot/conf.d/10-ssl.conf <<EOF
ssl = required
ssl_cert = </etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem
ssl_key = </etc/letsencrypt/live/$DOMAIN_NAME/privkey.pem
ssl_min_protocol = TLSv1.2
ssl_cipher_list = ECDHE+AESGCM:ECDHE+RSA+AESGCM:DHE+RSA+AESGCM
ssl_prefer_server_ciphers = yes
ssl_dh = </etc/dovecot/dh.pem
EOF
            fi
        else
            print_warning "⚠ Could not get SSL certificate (DNS might not be ready)"
            print_message "Using self-signed certificate temporarily"
            
            # Create self-signed certificate
            mkdir -p /etc/ssl/certs /etc/ssl/private
            openssl req -new -x509 -days 365 -nodes \
                -out /etc/ssl/certs/mailserver.crt \
                -keyout /etc/ssl/private/mailserver.key \
                -subj "/C=US/ST=State/L=City/O=Mail/CN=$HOSTNAME" 2>/dev/null
            
            chmod 600 /etc/ssl/private/mailserver.key
            
            postconf -e "smtpd_tls_cert_file = /etc/ssl/certs/mailserver.crt"
            postconf -e "smtpd_tls_key_file = /etc/ssl/private/mailserver.key"
        fi
    else
        print_warning "⚠ DNS not resolving yet for $DOMAIN_NAME"
        print_message "Using self-signed certificate temporarily"
        
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

# Setup auto-retry for certificates
cat > /usr/local/bin/ssl-auto-retry <<'EOF'
#!/bin/bash
# Auto-retry SSL certificates if they don't exist yet

if [ -f /root/mail-installer/install.conf ]; then
    source /root/mail-installer/install.conf
fi

# Check if cert exists
if [ ! -d "/etc/letsencrypt/live/$DOMAIN_NAME" ]; then
    if host "$DOMAIN_NAME" 8.8.8.8 > /dev/null 2>&1; then
        # Build domain list
        CERT_ARGS="-d $DOMAIN_NAME -d www.$DOMAIN_NAME -d $HOSTNAME"
        if [ ! -z "$MAIL_SUBDOMAIN" ] && [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
            for i in "${!IP_ADDRESSES[@]}"; do
                if [ $i -ne 0 ]; then
                    CERT_ARGS="$CERT_ARGS -d ${MAIL_SUBDOMAIN}${i}.$DOMAIN_NAME"
                fi
            done
        fi
        
        certbot --nginx $CERT_ARGS \
            --non-interactive --agree-tos --email "$ADMIN_EMAIL" \
            --no-eff-email 2>/dev/null && \
        systemctl reload postfix dovecot nginx 2>/dev/null
    fi
fi
EOF

chmod +x /usr/local/bin/ssl-auto-retry

# Add to cron to retry getting certs
echo "*/30 * * * * root /usr/local/bin/ssl-auto-retry" >> /etc/cron.d/ssl-retry

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
# 5. POSTFIX OPTIMIZATION
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
# 6. SERVICES RESTART
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
# 7. CREATE HELPER SCRIPT FOR SSL
# ===================================================================

print_header "Creating Helper Scripts"

# Quick SSL getter with ALL domains
cat > /usr/local/bin/get-ssl-cert <<EOF
#!/bin/bash

# Quick SSL Certificate Getter
HOSTNAME="$HOSTNAME"
DOMAIN="$DOMAIN_NAME"
ADMIN_EMAIL="$ADMIN_EMAIL"
MAIL_SUBDOMAIN="${MAIL_SUBDOMAIN:-mail}"

GREEN='\033[38;5;208m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo "Getting Let's Encrypt certificates automatically..."
echo ""

# Check DNS for domain
echo -n "Checking DNS for \$DOMAIN... "
if host "\$DOMAIN" 8.8.8.8 > /dev/null 2>&1; then
    echo -e "\${GREEN}✓ Resolving\${NC}"
    
    # Build complete domain list
    CERT_ARGS="-d \$DOMAIN -d www.\$DOMAIN -d \$HOSTNAME"
    
    # Add numbered subdomains if they exist
    if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
        for i in {1..$((${#IP_ADDRESSES[@]}-1))}; do
            SUB="\${MAIL_SUBDOMAIN}\${i}.\$DOMAIN"
            if host "\$SUB" 8.8.8.8 > /dev/null 2>&1; then
                CERT_ARGS="\$CERT_ARGS -d \$SUB"
            fi
        done
    fi
    
    echo "Requesting certificate for all domains..."
    
    # Get certificate with nginx plugin
    certbot --nginx \\
        \$CERT_ARGS \\
        --non-interactive \\
        --agree-tos \\
        --email "\$ADMIN_EMAIL" \\
        --no-eff-email \\
        --redirect
    
    if [ \$? -eq 0 ]; then
        echo -e "\${GREEN}✓ SSL certificates obtained for all domains!\${NC}"
        
        # Update configs
        postconf -e "smtpd_tls_cert_file = /etc/letsencrypt/live/\$DOMAIN/fullchain.pem"
        postconf -e "smtpd_tls_key_file = /etc/letsencrypt/live/\$DOMAIN/privkey.pem"
        
        if [ -f /etc/dovecot/conf.d/10-ssl.conf ]; then
            sed -i "s|ssl_cert = .*|ssl_cert = </etc/letsencrypt/live/\$DOMAIN/fullchain.pem|" /etc/dovecot/conf.d/10-ssl.conf
            sed -i "s|ssl_key = .*|ssl_key = </etc/letsencrypt/live/\$DOMAIN/privkey.pem|" /etc/dovecot/conf.d/10-ssl.conf
        fi
    else
        echo -e "\${YELLOW}✗ Failed (DNS may not be ready)\${NC}"
    fi
else
    echo -e "\${RED}✗ DNS not resolving yet\${NC}"
fi

systemctl reload postfix dovecot nginx 2>/dev/null || true
echo ""
echo -e "\${GREEN}Done! Services reloaded.\${NC}"
echo ""
echo "Certificate status:"
certbot certificates
EOF

chmod +x /usr/local/bin/get-ssl-cert

# ===================================================================
# COMPLETION
# ===================================================================

print_header "Post-Installation Complete!"
echo ""
echo "✓ OpenDKIM configured with 1024-bit key and signing enabled"
echo "✓ SSL/TLS configured (auto-retry enabled for all domains)"
echo "✓ Firewall configured" 
echo "✓ Services optimized"
if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
    echo "✓ IP rotation configured with ${#IP_ADDRESSES[@]} addresses"
    echo "✓ Custom mail subdomain: $MAIL_SUBDOMAIN"
fi
echo ""

# Show status summary
print_header "SERVER STATUS"

echo "DKIM SIGNING:"
echo "  Status: $(systemctl is-active opendkim 2>/dev/null || echo "not running")"
echo "  Port: localhost:8891"
echo "  Selector: mail"
echo "  Domain: $DOMAIN_NAME"
echo "  Mode: SIGNING ENABLED (sv)"
echo "  Key Size: 1024-bit"

if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
    echo ""
    echo "IP ROTATION:"
    echo "  Configured IPs: ${#IP_ADDRESSES[@]}"
    echo "  Primary: $PRIMARY_IP ($HOSTNAME)"
    for i in "${!IP_ADDRESSES[@]}"; do
        if [ $i -ne 0 ]; then
            echo "  Additional: ${IP_ADDRESSES[$i]} (${MAIL_SUBDOMAIN}${i}.$DOMAIN_NAME)"
        fi
    done
    echo "  Mode: Database-backed with bulk-ip-manage"
fi

echo ""
echo "SSL STATUS:"
if [ -f "/etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem" ]; then
    print_message "  ✓ SSL certificates active for all domains"
else
    print_warning "  ⚠ SSL pending (auto-retry every 30 minutes)"
    echo "    Run manually: get-ssl-cert"
fi

echo ""
print_message "✓ Post-installation configuration completed!"
print_message "✓ Mail subdomain: $MAIL_SUBDOMAIN"
print_message "✓ Hostname: $HOSTNAME"
if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
    print_message "✓ IP rotation active with bulk-ip-manage command!"
fi
