#!/bin/bash

# =================================================================
# LET'S ENCRYPT SSL SETUP - RUNS AFTER DNS IS CONFIGURED
# Version: 16.0.4
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
echo "Hostname: $HOSTNAME"
echo "Email: $ADMIN_EMAIL"
echo ""

# Check DNS first
echo "Verifying DNS is configured correctly..."
echo -n "Checking A record for $HOSTNAME... "

DNS_IP=$(dig +short A $HOSTNAME @8.8.8.8 2>/dev/null | head -1)
if [ -z "$DNS_IP" ]; then
    print_error "✗ DNS not found"
    echo ""
    echo "DNS A record for $HOSTNAME is not resolving."
    echo "Please ensure DNS records are configured and propagated."
    exit 1
fi

if [ "$DNS_IP" != "$PRIMARY_IP" ]; then
    print_warning "⚠ DNS points to $DNS_IP, expected $PRIMARY_IP"
    echo "This might cause certificate validation to fail."
    read -p "Continue anyway? (y/n): " cont
    if [[ "${cont,,}" != "y" ]]; then
        exit 1
    fi
else
    print_message "✓ DNS is correct ($DNS_IP)"
fi

# Check if certificate already exists
if [ -d "/etc/letsencrypt/live/$HOSTNAME" ]; then
    print_warning "Certificate already exists for $HOSTNAME"
    read -p "Renew/replace existing certificate? (y/n): " renew
    if [[ "${renew,,}" != "y" ]]; then
        echo "Using existing certificate."
        exit 0
    fi
    CERTBOT_FLAGS="--force-renewal"
else
    CERTBOT_FLAGS=""
fi

# Stop services that might use port 80
echo ""
echo "Preparing for certificate request..."
systemctl stop nginx 2>/dev/null || true
systemctl stop apache2 2>/dev/null || true

# Request certificate
echo ""
echo "Requesting Let's Encrypt certificate..."

certbot certonly --standalone \
    -d "$HOSTNAME" \
    --non-interactive \
    --agree-tos \
    --email "$ADMIN_EMAIL" \
    --no-eff-email \
    $CERTBOT_FLAGS

if [ $? -eq 0 ]; then
    print_message "✓ SSL certificate obtained successfully!"
    echo ""
    
    # Configure Postfix
    echo "Configuring Postfix..."
    postconf -e "smtpd_tls_cert_file = /etc/letsencrypt/live/$HOSTNAME/fullchain.pem"
    postconf -e "smtpd_tls_key_file = /etc/letsencrypt/live/$HOSTNAME/privkey.pem"
    postconf -e "smtpd_use_tls = yes"
    postconf -e "smtpd_tls_auth_only = yes"
    postconf -e "smtpd_tls_security_level = may"
    postconf -e "smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1"
    postconf -e "smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1"
    
    # Configure Dovecot
    echo "Configuring Dovecot..."
    
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
    
    # Setup auto-renewal
    echo "Setting up auto-renewal..."
    cat > /etc/cron.d/certbot-renewal <<EOF
# Renew Let's Encrypt certificates twice daily
0 2,14 * * * root certbot renew --quiet --post-hook "systemctl reload postfix dovecot"
EOF
    
    # Restart services
    echo "Restarting mail services..."
    systemctl restart postfix
    systemctl restart dovecot
    
    # Show certificate info
    echo ""
    print_header "Certificate Information"
    certbot certificates 2>/dev/null | grep -A3 "$HOSTNAME"
    
    echo ""
    print_message "✓ SSL setup completed successfully!"
    echo ""
    echo "Your mail server now has a valid Let's Encrypt certificate."
    echo "The certificate will auto-renew before expiration."
    
else
    print_error "✗ Failed to obtain SSL certificate"
    echo ""
    echo "Common issues:"
    echo "1. Port 80 is blocked by firewall"
    echo "2. DNS not fully propagated (wait 5-30 minutes)"
    echo "3. Domain doesn't point to this server"
    echo ""
    echo "To retry: bash ssl-setup.sh"
    exit 1
fi
