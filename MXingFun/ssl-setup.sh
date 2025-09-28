#!/bin/bash

# =================================================================
# LET'S ENCRYPT SSL SETUP - FOR MAIL SERVER AND WEBSITE
# Version: 16.1.0
# Gets SSL certificates for both mail.domain.com and domain.com
# =================================================================

# Load configuration
if [ -f "$(pwd)/install.conf" ]; then
    source "$(pwd)/install.conf"
elif [ -f "/root/mail-installer/install.conf" ]; then
    source "/root/mail-installer/install.conf"
fi

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

print_header "Let's Encrypt SSL Certificate Setup"
echo ""
echo "Domain: $DOMAIN_NAME"
echo "Mail Hostname: $HOSTNAME"
echo "Admin Email: $ADMIN_EMAIL"
echo ""

# Ensure certbot is installed
if ! command -v certbot &> /dev/null; then
    echo "Installing Certbot..."
    apt-get update > /dev/null 2>&1
    apt-get install -y certbot > /dev/null 2>&1
fi

# ===================================================================
# 1. GET SSL FOR MAIL SERVER (mail.domain.com)
# ===================================================================

print_header "Mail Server SSL Certificate"

echo -n "Checking DNS for $HOSTNAME... "

DNS_IP=$(dig +short A $HOSTNAME @8.8.8.8 2>/dev/null | head -1)
if [ -z "$DNS_IP" ]; then
    print_error "✗ DNS not found"
    echo ""
    echo "DNS A record for $HOSTNAME is not resolving."
    echo "Skipping mail server SSL for now."
    MAIL_SSL_SUCCESS=false
elif [ "$DNS_IP" != "$PRIMARY_IP" ]; then
    print_warning "⚠ DNS points to $DNS_IP, expected $PRIMARY_IP"
    echo "This might cause certificate validation to fail."
    read -p "Continue anyway? (y/n): " cont
    if [[ "${cont,,}" != "y" ]]; then
        MAIL_SSL_SUCCESS=false
    else
        MAIL_SSL_SUCCESS=pending
    fi
else
    print_message "✓ DNS is correct ($DNS_IP)"
    MAIL_SSL_SUCCESS=pending
fi

if [ "$MAIL_SSL_SUCCESS" == "pending" ]; then
    # Check if certificate already exists
    if [ -d "/etc/letsencrypt/live/$HOSTNAME" ]; then
        print_warning "Certificate already exists for $HOSTNAME"
        echo "Certificate expiry:"
        certbot certificates 2>/dev/null | grep -A2 "$HOSTNAME" | grep "Expiry"
        MAIL_SSL_SUCCESS=true
    else
        # Stop services that might use port 80
        echo "Preparing for certificate request..."
        systemctl stop nginx 2>/dev/null || true
        systemctl stop apache2 2>/dev/null || true
        
        # Request certificate for mail server
        echo "Requesting certificate for mail server..."
        
        certbot certonly --standalone \
            -d "$HOSTNAME" \
            --non-interactive \
            --agree-tos \
            --email "$ADMIN_EMAIL" \
            --no-eff-email
        
        if [ $? -eq 0 ]; then
            print_message "✓ Mail server SSL certificate obtained!"
            MAIL_SSL_SUCCESS=true
            
            # Configure Postfix
            echo "Configuring Postfix SSL..."
            postconf -e "smtpd_tls_cert_file = /etc/letsencrypt/live/$HOSTNAME/fullchain.pem"
            postconf -e "smtpd_tls_key_file = /etc/letsencrypt/live/$HOSTNAME/privkey.pem"
            postconf -e "smtpd_use_tls = yes"
            postconf -e "smtpd_tls_auth_only = yes"
            postconf -e "smtpd_tls_security_level = may"
            postconf -e "smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1"
            postconf -e "smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1"
            
            # Configure Dovecot
            echo "Configuring Dovecot SSL..."
            
            # Generate DH parameters if not exists
            if [ ! -f /etc/dovecot/dh.pem ]; then
                echo "Generating DH parameters..."
                openssl dhparam -out /etc/dovecot/dh.pem 2048 2>/dev/null
            fi
            
            cat > /etc/dovecot/conf.d/10-ssl.conf <<EOF
ssl = required
ssl_cert = </etc/letsencrypt/live/$HOSTNAME/fullchain.pem
ssl_key = </etc/letsencrypt/live/$HOSTNAME/privkey.pem
ssl_min_protocol = TLSv1.2
ssl_cipher_list = ECDHE+AESGCM:ECDHE+RSA+AESGCM:DHE+RSA+AESGCM
ssl_prefer_server_ciphers = yes
ssl_dh = </etc/dovecot/dh.pem
EOF
            
            # Restart mail services
            systemctl restart postfix
            systemctl restart dovecot
            
        else
            print_error "✗ Failed to obtain mail server SSL certificate"
            MAIL_SSL_SUCCESS=false
        fi
    fi
fi

echo ""

# ===================================================================
# 2. GET SSL FOR WEBSITE (domain.com and www.domain.com)
# ===================================================================

print_header "Website SSL Certificate"

echo -n "Checking DNS for $DOMAIN_NAME... "

DNS_IP=$(dig +short A $DOMAIN_NAME @8.8.8.8 2>/dev/null | head -1)
if [ -z "$DNS_IP" ]; then
    print_error "✗ DNS not found"
    echo ""
    echo "DNS A record for $DOMAIN_NAME is not resolving."
    echo "Skipping website SSL for now."
    WEBSITE_SSL_SUCCESS=false
elif [ "$DNS_IP" != "$PRIMARY_IP" ]; then
    print_warning "⚠ DNS points to $DNS_IP, expected $PRIMARY_IP"
    echo "This might cause certificate validation to fail."
    read -p "Continue anyway? (y/n): " cont
    if [[ "${cont,,}" != "y" ]]; then
        WEBSITE_SSL_SUCCESS=false
    else
        WEBSITE_SSL_SUCCESS=pending
    fi
else
    print_message "✓ DNS is correct ($DNS_IP)"
    WEBSITE_SSL_SUCCESS=pending
fi

if [ "$WEBSITE_SSL_SUCCESS" == "pending" ]; then
    # Check if certificate already exists
    if [ -d "/etc/letsencrypt/live/$DOMAIN_NAME" ]; then
        print_warning "Certificate already exists for $DOMAIN_NAME"
        echo "Certificate expiry:"
        certbot certificates 2>/dev/null | grep -A2 "$DOMAIN_NAME" | grep "Expiry"
        WEBSITE_SSL_SUCCESS=true
    else
        # Ensure nginx is running for webroot verification
        systemctl start nginx 2>/dev/null || true
        
        # Create webroot if it doesn't exist
        WEB_ROOT="/var/www/$DOMAIN_NAME"
        mkdir -p "$WEB_ROOT"
        
        # Request certificate for website
        echo "Requesting certificate for website..."
        
        # First try webroot method (if nginx is configured)
        if [ -f "/etc/nginx/sites-enabled/$DOMAIN_NAME" ]; then
            certbot certonly --webroot \
                -w "$WEB_ROOT" \
                -d "$DOMAIN_NAME" \
                -d "www.$DOMAIN_NAME" \
                --non-interactive \
                --agree-tos \
                --email "$ADMIN_EMAIL" \
                --no-eff-email
            CERT_RESULT=$?
        else
            # Fall back to standalone if nginx not configured
            systemctl stop nginx 2>/dev/null || true
            certbot certonly --standalone \
                -d "$DOMAIN_NAME" \
                -d "www.$DOMAIN_NAME" \
                --non-interactive \
                --agree-tos \
                --email "$ADMIN_EMAIL" \
                --no-eff-email
            CERT_RESULT=$?
        fi
        
        if [ $CERT_RESULT -eq 0 ]; then
            print_message "✓ Website SSL certificate obtained!"
            WEBSITE_SSL_SUCCESS=true
            
            # Update Nginx configuration for SSL if exists
            if [ -f "/etc/nginx/sites-available/$DOMAIN_NAME" ]; then
                # Check if SSL server block already exists
                if ! grep -q "listen 443 ssl" "/etc/nginx/sites-available/$DOMAIN_NAME"; then
                    echo "Updating Nginx configuration for SSL..."
                    
                    cat >> /etc/nginx/sites-available/$DOMAIN_NAME <<EOF

# SSL Server Block
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $DOMAIN_NAME www.$DOMAIN_NAME;
    
    ssl_certificate /etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN_NAME/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    
    root $WEB_ROOT;
    index index.html;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    # Mailwizz unsubscribe redirect
    location /unsubscribe {
        # UPDATE THIS WITH YOUR MAILWIZZ URL
        return 302 https://your-mailwizz-domain.com/lists/unsubscribe;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN_NAME www.$DOMAIN_NAME;
    return 301 https://\$server_name\$request_uri;
}
EOF
                    
                    # Restart nginx
                    nginx -t 2>/dev/null && systemctl reload nginx
                    print_message "✓ Nginx configured for HTTPS"
                fi
            fi
        else
            print_error "✗ Failed to obtain website SSL certificate"
            WEBSITE_SSL_SUCCESS=false
        fi
    fi
fi

echo ""

# ===================================================================
# 3. SETUP AUTO-RENEWAL
# ===================================================================

print_header "Configuring Auto-Renewal"

# Setup auto-renewal cron job
cat > /etc/cron.d/certbot-renewal <<EOF
# Renew Let's Encrypt certificates twice daily
0 2,14 * * * root certbot renew --quiet --post-hook "systemctl reload postfix dovecot nginx 2>/dev/null || true"
EOF

print_message "✓ Auto-renewal configured"
echo ""

# ===================================================================
# 4. SHOW CERTIFICATE STATUS
# ===================================================================

print_header "Certificate Status"

echo "Checking all certificates..."
echo ""

if command -v certbot &> /dev/null; then
    certbot certificates
fi

echo ""

# ===================================================================
# COMPLETION
# ===================================================================

print_header "SSL Setup Summary"

if [ "$MAIL_SSL_SUCCESS" == "true" ]; then
    print_message "✓ Mail Server SSL: Active"
    echo "  Domain: $HOSTNAME"
    echo "  Certificate: /etc/letsencrypt/live/$HOSTNAME/"
    echo "  Services configured: Postfix, Dovecot"
else
    print_warning "⚠ Mail Server SSL: Not configured"
    echo "  To retry later: certbot certonly --standalone -d $HOSTNAME"
fi

echo ""

if [ "$WEBSITE_SSL_SUCCESS" == "true" ]; then
    print_message "✓ Website SSL: Active"
    echo "  Domain: $DOMAIN_NAME (and www.$DOMAIN_NAME)"
    echo "  Certificate: /etc/letsencrypt/live/$DOMAIN_NAME/"
    echo "  URL: https://$DOMAIN_NAME"
else
    print_warning "⚠ Website SSL: Not configured"
    echo "  To retry later: certbot certonly --standalone -d $DOMAIN_NAME -d www.$DOMAIN_NAME"
fi

echo ""

if [ "$MAIL_SSL_SUCCESS" == "true" ] || [ "$WEBSITE_SSL_SUCCESS" == "true" ]; then
    print_message "✓ SSL certificates obtained successfully!"
    echo ""
    echo "Auto-renewal is configured to run twice daily."
    echo "Certificates will renew automatically before expiration."
else
    print_warning "⚠ No SSL certificates were obtained"
    echo ""
    echo "Common issues:"
    echo "1. Port 80 is blocked by firewall"
    echo "2. DNS not fully propagated (wait 5-30 minutes)"
    echo "3. Domain doesn't point to this server ($PRIMARY_IP)"
    echo ""
    echo "After DNS propagates, run this script again or use:"
    echo "  For mail: certbot certonly --standalone -d $HOSTNAME"
    echo "  For website: certbot certonly --standalone -d $DOMAIN_NAME -d www.$DOMAIN_NAME"
fi

echo ""

# Create helper script for manual SSL
cat > /usr/local/bin/get-ssl << 'EOF'
#!/bin/bash

# SSL Certificate Helper Script

echo "SSL Certificate Manager"
echo "======================="
echo ""
echo "1. Get/Renew mail server certificate"
echo "2. Get/Renew website certificate"
echo "3. Get/Renew both certificates"
echo "4. Check certificate status"
echo ""
read -p "Select option (1-4): " option

case $option in
    1)
        echo "Getting mail server certificate..."
        systemctl stop nginx 2>/dev/null
        certbot certonly --standalone -d HOSTNAME_PLACEHOLDER --force-renewal
        systemctl start nginx 2>/dev/null
        systemctl reload postfix dovecot
        ;;
    2)
        echo "Getting website certificate..."
        certbot certonly --webroot -w /var/www/DOMAIN_PLACEHOLDER -d DOMAIN_PLACEHOLDER -d www.DOMAIN_PLACEHOLDER --force-renewal
        systemctl reload nginx
        ;;
    3)
        echo "Getting both certificates..."
        systemctl stop nginx 2>/dev/null
        certbot certonly --standalone -d HOSTNAME_PLACEHOLDER --force-renewal
        certbot certonly --standalone -d DOMAIN_PLACEHOLDER -d www.DOMAIN_PLACEHOLDER --force-renewal
        systemctl start nginx 2>/dev/null
        systemctl reload postfix dovecot
        ;;
    4)
        certbot certificates
        ;;
    *)
        echo "Invalid option"
        ;;
esac
EOF

# Replace placeholders in helper script
sed -i "s/HOSTNAME_PLACEHOLDER/$HOSTNAME/g" /usr/local/bin/get-ssl
sed -i "s/DOMAIN_PLACEHOLDER/$DOMAIN_NAME/g" /usr/local/bin/get-ssl
chmod +x /usr/local/bin/get-ssl

echo "Helper script created: get-ssl"
echo "Use 'get-ssl' to manage certificates manually"
echo ""

print_message "✓ SSL setup completed!"
