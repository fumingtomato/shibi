#!/bin/bash

# =================================================================
# DNS AND SSL CONFIGURATION MODULE - FIXED VERSION
# DNS record management and SSL certificate automation
# Fixed: Cloudflare API integration, Let's Encrypt automation, DNS validation
# =================================================================

# Global variables for DNS and SSL
export DNS_PROVIDER=""
export CF_API_TOKEN=""
export CF_ZONE_ID=""
export CF_EMAIL=""
export SSL_EMAIL=""
export SSL_CERT_PATH="/etc/letsencrypt/live"
export USE_LETSENCRYPT="yes"
export DNS_RECORDS_FILE="/root/dns-records.txt"

# Check Certbot installation
check_certbot_installation() {
    if ! command -v certbot &>/dev/null; then
        print_message "Installing Certbot..."
        
        # Add snapd for latest certbot
        apt-get update
        apt-get install -y snapd
        snap install core
        snap refresh core
        snap install --classic certbot
        ln -sf /snap/bin/certbot /usr/bin/certbot 2>/dev/null || true
    fi
    
    # Check if certbot is available
    if ! command -v certbot &>/dev/null; then
        print_warning "Certbot installation failed, falling back to apt"
        apt-get install -y certbot python3-certbot-nginx python3-certbot-apache
    fi
    
    return 0
}

# Setup Cloudflare DNS integration
setup_cloudflare_dns() {
    local domain=$1
    
    print_header "Setting up Cloudflare DNS Integration"
    
    # Check if API credentials are provided
    if [ -z "$CF_API_TOKEN" ] || [ -z "$CF_ZONE_ID" ]; then
        print_warning "Cloudflare API credentials not configured"
        print_message "Please set CF_API_TOKEN and CF_ZONE_ID to enable automatic DNS updates"
        return 1
    fi
    
    # Create Cloudflare configuration file
    cat > /root/.cloudflare.conf <<EOF
# Cloudflare API Configuration
CF_API_TOKEN="${CF_API_TOKEN}"
CF_ZONE_ID="${CF_ZONE_ID}"
CF_EMAIL="${CF_EMAIL}"
DOMAIN="${domain}"
EOF
    
    chmod 600 /root/.cloudflare.conf
    
    # Create Cloudflare DNS update script
    create_cloudflare_update_script
    
    # Test Cloudflare API connection
    test_cloudflare_api
    
    print_message "✓ Cloudflare DNS integration configured"
}

# Create Cloudflare DNS update script
create_cloudflare_update_script() {
    cat > /usr/local/bin/update-cloudflare-dns <<'EOF'
#!/bin/bash

# Cloudflare DNS Update Script
# Load configuration
source /root/.cloudflare.conf

# Function to make Cloudflare API call
cf_api() {
    local method=$1
    local endpoint=$2
    local data=$3
    
    curl -s -X "$method" \
        "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/${endpoint}" \
        -H "Authorization: Bearer ${CF_API_TOKEN}" \
        -H "Content-Type: application/json" \
        ${data:+--data "$data"}
}

# Function to create or update DNS record
update_dns_record() {
    local type=$1
    local name=$2
    local content=$3
    local ttl=${4:-1}  # 1 = Auto
    local proxied=${5:-false}
    
    echo "Updating DNS record: $name ($type) -> $content"
    
    # Check if record exists
    local record_id=$(cf_api GET "dns_records?type=${type}&name=${name}" | \
        grep -oP '"id":"[^"]+' | head -1 | cut -d'"' -f4)
    
    local data=$(cat <<JSON
{
    "type": "${type}",
    "name": "${name}",
    "content": "${content}",
    "ttl": ${ttl},
    "proxied": ${proxied}
}
JSON
)
    
    if [ -z "$record_id" ]; then
        # Create new record
        cf_api POST "dns_records" "$data"
        echo "Created new DNS record: $name"
    else
        # Update existing record
        cf_api PUT "dns_records/${record_id}" "$data"
        echo "Updated existing DNS record: $name"
    fi
}

# Function to delete DNS record
delete_dns_record() {
    local type=$1
    local name=$2
    
    echo "Deleting DNS record: $name ($type)"
    
    local record_id=$(cf_api GET "dns_records?type=${type}&name=${name}" | \
        grep -oP '"id":"[^"]+' | head -1 | cut -d'"' -f4)
    
    if [ ! -z "$record_id" ]; then
        cf_api DELETE "dns_records/${record_id}"
        echo "Deleted DNS record: $name"
    else
        echo "Record not found: $name"
    fi
}

# Main execution
case "$1" in
    add)
        update_dns_record "$2" "$3" "$4" "$5" "$6"
        ;;
    delete)
        delete_dns_record "$2" "$3"
        ;;
    list)
        cf_api GET "dns_records" | python3 -m json.tool
        ;;
    *)
        echo "Usage: $0 {add|delete|list} [args]"
        echo "  add TYPE NAME CONTENT [TTL] [PROXIED]"
        echo "  delete TYPE NAME"
        echo "  list"
        exit 1
        ;;
esac
EOF
    
    chmod +x /usr/local/bin/update-cloudflare-dns
    print_message "Cloudflare DNS update script created"
}

# Test Cloudflare API connection
test_cloudflare_api() {
    print_message "Testing Cloudflare API connection..."
    
    local response=$(curl -s -X GET \
        "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}" \
        -H "Authorization: Bearer ${CF_API_TOKEN}" \
        -H "Content-Type: application/json")
    
    if echo "$response" | grep -q '"success":true'; then
        print_message "✓ Cloudflare API connection successful"
        return 0
    else
        print_error "Cloudflare API connection failed"
        echo "Response: $response"
        return 1
    fi
}

# Generate all required DNS records
generate_dns_records() {
    local domain=$1
    local hostname=${2:-mail.$domain}
    
    print_header "Generating DNS Records"
    
    # Clear existing records file
    > "$DNS_RECORDS_FILE"
    
    # Header
    cat >> "$DNS_RECORDS_FILE" <<EOF
================================================================================
DNS RECORDS FOR: ${domain}
Generated: $(date)
Hostname: ${hostname}
================================================================================

REQUIRED DNS RECORDS:
====================

EOF
    
    # A Records for main domain and mail subdomain
    echo "A RECORDS:" >> "$DNS_RECORDS_FILE"
    echo "----------" >> "$DNS_RECORDS_FILE"
    
    if [ ! -z "$PRIMARY_IP" ]; then
        echo "Type: A" >> "$DNS_RECORDS_FILE"
        echo "Name: @" >> "$DNS_RECORDS_FILE"
        echo "Value: ${PRIMARY_IP}" >> "$DNS_RECORDS_FILE"
        echo "TTL: 3600" >> "$DNS_RECORDS_FILE"
        echo "" >> "$DNS_RECORDS_FILE"
        
        echo "Type: A" >> "$DNS_RECORDS_FILE"
        echo "Name: mail" >> "$DNS_RECORDS_FILE"
        echo "Value: ${PRIMARY_IP}" >> "$DNS_RECORDS_FILE"
        echo "TTL: 3600" >> "$DNS_RECORDS_FILE"
        echo "" >> "$DNS_RECORDS_FILE"
    fi
    
    # Additional A records for multi-IP setup
    if [ ${#IP_ADDRESSES[@]} -gt 0 ]; then
        for i in "${!IP_ADDRESSES[@]}"; do
            local ip="${IP_ADDRESSES[$i]}"
            local subdomain="mail-${i}"
            
            echo "Type: A" >> "$DNS_RECORDS_FILE"
            echo "Name: ${subdomain}" >> "$DNS_RECORDS_FILE"
            echo "Value: ${ip}" >> "$DNS_RECORDS_FILE"
            echo "TTL: 3600" >> "$DNS_RECORDS_FILE"
            echo "" >> "$DNS_RECORDS_FILE"
        done
    fi
    
    # MX Record
    echo "" >> "$DNS_RECORDS_FILE"
    echo "MX RECORD:" >> "$DNS_RECORDS_FILE"
    echo "----------" >> "$DNS_RECORDS_FILE"
    echo "Type: MX" >> "$DNS_RECORDS_FILE"
    echo "Name: @" >> "$DNS_RECORDS_FILE"
    echo "Value: ${hostname}" >> "$DNS_RECORDS_FILE"
    echo "Priority: 10" >> "$DNS_RECORDS_FILE"
    echo "TTL: 3600" >> "$DNS_RECORDS_FILE"
    echo "" >> "$DNS_RECORDS_FILE"
    
    # SPF Record
    echo "" >> "$DNS_RECORDS_FILE"
    echo "SPF RECORD:" >> "$DNS_RECORDS_FILE"
    echo "-----------" >> "$DNS_RECORDS_FILE"
    echo "Type: TXT" >> "$DNS_RECORDS_FILE"
    echo "Name: @" >> "$DNS_RECORDS_FILE"
    
    local spf_record="v=spf1"
    for ip in "${IP_ADDRESSES[@]}"; do
        spf_record="${spf_record} ip4:${ip}"
    done
    spf_record="${spf_record} mx a ~all"
    
    echo "Value: ${spf_record}" >> "$DNS_RECORDS_FILE"
    echo "TTL: 3600" >> "$DNS_RECORDS_FILE"
    echo "" >> "$DNS_RECORDS_FILE"
    
    # DKIM Record (placeholder - actual value from dkim-spf module)
    echo "" >> "$DNS_RECORDS_FILE"
    echo "DKIM RECORD:" >> "$DNS_RECORDS_FILE"
    echo "------------" >> "$DNS_RECORDS_FILE"
    echo "Type: TXT" >> "$DNS_RECORDS_FILE"
    echo "Name: ${DKIM_SELECTOR}._domainkey" >> "$DNS_RECORDS_FILE"
    
    # Get actual DKIM value if available
    local dkim_value=$(get_dkim_value "$domain" 2>/dev/null || echo "PENDING_GENERATION")
    echo "Value: v=DKIM1; k=rsa; p=${dkim_value}" >> "$DNS_RECORDS_FILE"
    echo "TTL: 3600" >> "$DNS_RECORDS_FILE"
    echo "" >> "$DNS_RECORDS_FILE"
    
    # DMARC Record
    echo "" >> "$DNS_RECORDS_FILE"
    echo "DMARC RECORD:" >> "$DNS_RECORDS_FILE"
    echo "-------------" >> "$DNS_RECORDS_FILE"
    echo "Type: TXT" >> "$DNS_RECORDS_FILE"
    echo "Name: _dmarc" >> "$DNS_RECORDS_FILE"
    echo "Value: v=DMARC1; p=none; rua=mailto:postmaster@${domain}; ruf=mailto:postmaster@${domain}; fo=1; adkim=r; aspf=r" >> "$DNS_RECORDS_FILE"
    echo "TTL: 3600" >> "$DNS_RECORDS_FILE"
    echo "" >> "$DNS_RECORDS_FILE"
    
    # PTR Records (Reverse DNS)
    echo "" >> "$DNS_RECORDS_FILE"
    echo "REVERSE DNS (PTR) RECORDS:" >> "$DNS_RECORDS_FILE"
    echo "--------------------------" >> "$DNS_RECORDS_FILE"
    echo "Note: These must be configured with your hosting provider" >> "$DNS_RECORDS_FILE"
    echo "" >> "$DNS_RECORDS_FILE"
    
    for ip in "${IP_ADDRESSES[@]}"; do
        echo "IP: ${ip} -> ${hostname}" >> "$DNS_RECORDS_FILE"
    done
    
    # Additional records for webmail/autodiscover
    cat >> "$DNS_RECORDS_FILE" <<EOF

OPTIONAL RECORDS (for webmail/autodiscover):
=============================================

Type: CNAME
Name: webmail
Value: ${hostname}
TTL: 3600

Type: CNAME
Name: autodiscover
Value: ${hostname}
TTL: 3600

Type: CNAME
Name: autoconfig
Value: ${hostname}
TTL: 3600

Type: SRV
Name: _autodiscover._tcp
Value: 0 0 443 ${hostname}
Priority: 0
Weight: 0
Port: 443
TTL: 3600

================================================================================
VERIFICATION COMMANDS:
=====================

After adding these records, verify with:

# Check A record
dig A ${domain}
dig A ${hostname}

# Check MX record
dig MX ${domain}

# Check SPF record
dig TXT ${domain}

# Check DKIM record
dig TXT ${DKIM_SELECTOR}._domainkey.${domain}

# Check DMARC record
dig TXT _dmarc.${domain}

# Check reverse DNS
dig -x ${PRIMARY_IP}

================================================================================
EOF
    
    print_message "DNS records generated and saved to: $DNS_RECORDS_FILE"
    
    # Display critical records
    echo ""
    print_message "Critical DNS records to add:"
    echo "1. A record: @ -> ${PRIMARY_IP}"
    echo "2. A record: mail -> ${PRIMARY_IP}"
    echo "3. MX record: @ -> ${hostname} (priority: 10)"
    echo "4. TXT record (SPF): @ -> ${spf_record}"
    echo "5. TXT record (DKIM): ${DKIM_SELECTOR}._domainkey -> [See DKIM setup]"
    echo "6. TXT record (DMARC): _dmarc -> v=DMARC1; p=none; rua=mailto:postmaster@${domain}"
}

# Setup SSL certificate with Let's Encrypt
setup_ssl_certificate() {
    local domain=$1
    local hostname=${2:-mail.$domain}
    local email=${3:-$SSL_EMAIL}
    
    print_header "Setting up SSL Certificate"
    
    # Check if certbot is installed
    check_certbot_installation
    
    if [ "$USE_LETSENCRYPT" != "yes" ]; then
        print_message "Using self-signed certificate..."
        generate_self_signed_cert "$hostname"
        return 0
    fi
    
    # Prepare for Let's Encrypt
    print_message "Requesting Let's Encrypt certificate..."
    
    # Stop web servers temporarily
    systemctl stop nginx 2>/dev/null || true
    systemctl stop apache2 2>/dev/null || true
    
    # Prepare domain list
    local domains="-d ${hostname} -d ${domain}"
    
    # Add webmail subdomain if needed
    domains="${domains} -d webmail.${domain}"
    
    # Add additional hostnames for multi-IP
    if [ ${#HOSTNAMES[@]} -gt 0 ]; then
        for host in "${HOSTNAMES[@]}"; do
            if [ "$host" != "$hostname" ]; then
                domains="${domains} -d ${host}"
            fi
        done
    fi
    
    # Request certificate
    print_message "Requesting certificate for: ${domains}"
    
    if certbot certonly \
        --standalone \
        --non-interactive \
        --agree-tos \
        --email "${email}" \
        --no-eff-email \
        ${domains} \
        --expand \
        --force-renewal; then
        
        print_message "✓ SSL certificate obtained successfully"
        
        # Create symlinks for easy access
        ln -sf "${SSL_CERT_PATH}/${hostname}/fullchain.pem" /etc/ssl/certs/mail-cert.pem
        ln -sf "${SSL_CERT_PATH}/${hostname}/privkey.pem" /etc/ssl/private/mail-key.pem
        
        # Configure auto-renewal
        setup_ssl_auto_renewal "$hostname"
        
        # Configure services to use the certificate
        configure_services_ssl "$hostname"
        
    else
        print_warning "Let's Encrypt certificate request failed"
        print_message "Falling back to self-signed certificate..."
        generate_self_signed_cert "$hostname"
    fi
    
    # Restart web servers
    systemctl start nginx 2>/dev/null || true
    systemctl start apache2 2>/dev/null || true
}

# Generate self-signed certificate
generate_self_signed_cert() {
    local hostname=$1
    
    print_message "Generating self-signed certificate..."
    
    openssl req -new -x509 -days 365 -nodes \
        -out /etc/ssl/certs/mail-cert.pem \
        -keyout /etc/ssl/private/mail-key.pem \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=${hostname}" \
        2>/dev/null
    
    chmod 644 /etc/ssl/certs/mail-cert.pem
    chmod 600 /etc/ssl/private/mail-key.pem
    
    print_message "✓ Self-signed certificate generated"
}

# Setup SSL auto-renewal
setup_ssl_auto_renewal() {
    local hostname=$1
    
    print_message "Setting up SSL auto-renewal..."
    
    # Create renewal hook script
    cat > /etc/letsencrypt/renewal-hooks/deploy/mail-services.sh <<'EOF'
#!/bin/bash

# Reload services after certificate renewal
systemctl reload postfix 2>/dev/null || true
systemctl reload dovecot 2>/dev/null || true
systemctl reload nginx 2>/dev/null || true
systemctl reload apache2 2>/dev/null || true

# Update certificate permissions
chmod 644 /etc/ssl/certs/mail-cert.pem 2>/dev/null || true
chmod 600 /etc/ssl/private/mail-key.pem 2>/dev/null || true

# Log renewal
echo "[$(date)] Certificate renewed and services reloaded" >> /var/log/letsencrypt/renewal.log
EOF
    
    chmod +x /etc/letsencrypt/renewal-hooks/deploy/mail-services.sh
    
    # Test renewal
    print_message "Testing certificate renewal..."
    certbot renew --dry-run
    
    # Add cron job for renewal if not exists
    if ! crontab -l 2>/dev/null | grep -q "certbot renew"; then
        (crontab -l 2>/dev/null; echo "0 0,12 * * * /usr/bin/certbot renew --quiet") | crontab -
        print_message "✓ Auto-renewal cron job added"
    fi
}

# Configure services to use SSL certificate
configure_services_ssl() {
    local hostname=$1
    
    print_message "Configuring services to use SSL certificate..."
    
    # Configure Postfix
    if [ -f /etc/postfix/main.cf ]; then
        postconf -e "smtpd_tls_cert_file = /etc/ssl/certs/mail-cert.pem"
        postconf -e "smtpd_tls_key_file = /etc/ssl/private/mail-key.pem"
        systemctl reload postfix 2>/dev/null || true
    fi
    
    # Configure Dovecot
    if [ -f /etc/dovecot/conf.d/10-ssl.conf ]; then
        sed -i "s|ssl_cert = .*|ssl_cert = </etc/ssl/certs/mail-cert.pem|" /etc/dovecot/conf.d/10-ssl.conf
        sed -i "s|ssl_key = .*|ssl_key = </etc/ssl/private/mail-key.pem|" /etc/dovecot/conf.d/10-ssl.conf
        systemctl reload dovecot 2>/dev/null || true
    fi
    
    print_message "✓ Services configured to use SSL certificate"
}

# Create DNS verification script
create_dns_verification_script() {
    cat > /usr/local/bin/verify-dns <<'EOF'
#!/bin/bash

# DNS Verification Script
DOMAIN="${1:-$(hostname -d)}"

echo "DNS Verification for $DOMAIN"
echo "============================="
echo ""

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Check function
check_record() {
    local type=$1
    local name=$2
    local expected=$3
    
    echo -n "Checking $type record for $name... "
    
    local result=$(dig +short $type $name @8.8.8.8 | head -1)
    
    if [ ! -z "$result" ]; then
        echo -e "${GREEN}✓${NC} Found: $result"
        if [ ! -z "$expected" ] && [[ "$result" != *"$expected"* ]]; then
            echo "  Warning: Expected to contain '$expected'"
        fi
        return 0
    else
        echo -e "${RED}✗${NC} Not found"
        return 1
    fi
}

# Run checks
echo "A Records:"
check_record A "$DOMAIN"
check_record A "mail.$DOMAIN"
echo ""

echo "MX Record:"
check_record MX "$DOMAIN"
echo ""

echo "TXT Records:"
check_record TXT "$DOMAIN" "v=spf1"
check_record TXT "mail._domainkey.$DOMAIN"
check_record TXT "_dmarc.$DOMAIN" "v=DMARC1"
echo ""

# Reverse DNS check
echo "Reverse DNS:"
PUBLIC_IP=$(curl -s https://ipinfo.io/ip)
if [ ! -z "$PUBLIC_IP" ]; then
    echo -n "Checking PTR for $PUBLIC_IP... "
    PTR=$(dig +short -x $PUBLIC_IP | head -1)
    if [ ! -z "$PTR" ]; then
        echo -e "${GREEN}✓${NC} $PTR"
    else
        echo -e "${RED}✗${NC} No PTR record"
    fi
fi

echo ""
echo "Full DNS propagation can take up to 48 hours"
EOF
    
    chmod +x /usr/local/bin/verify-dns
    print_message "DNS verification script created at /usr/local/bin/verify-dns"
}

# Create SSL verification script
create_ssl_verification_script() {
    cat > /usr/local/bin/verify-ssl <<'EOF'
#!/bin/bash

# SSL Certificate Verification Script
DOMAIN="${1:-$(hostname -f)}"

echo "SSL Certificate Verification"
echo "============================"
echo ""

# Check certificate files
echo "Certificate files:"
for file in /etc/ssl/certs/mail-cert.pem /etc/ssl/private/mail-key.pem; do
    if [ -f "$file" ]; then
        echo "✓ $file exists"
        if [[ "$file" == *"cert.pem" ]]; then
            echo "  Subject: $(openssl x509 -in $file -noout -subject | cut -d'=' -f2-)"
            echo "  Expires: $(openssl x509 -in $file -noout -enddate | cut -d'=' -f2)"
        fi
    else
        echo "✗ $file missing"
    fi
done
echo ""

# Test SMTP TLS
echo "Testing SMTP TLS on port 25:"
echo | openssl s_client -connect localhost:25 -starttls smtp 2>/dev/null | grep -E "subject=|issuer="
echo ""

# Test SMTPS on port 465
echo "Testing SMTPS on port 465:"
echo | openssl s_client -connect localhost:465 2>/dev/null | grep -E "subject=|issuer="
echo ""

# Test IMAPS on port 993
echo "Testing IMAPS on port 993:"
echo | openssl s_client -connect localhost:993 2>/dev/null | grep -E "subject=|issuer="
echo ""

# Check renewal status
if command -v certbot &>/dev/null; then
    echo "Certificate renewal status:"
    certbot certificates 2>/dev/null | grep -E "Certificate Name:|Expiry Date:|VALID:"
fi
EOF
    
    chmod +x /usr/local/bin/verify-ssl
    print_message "SSL verification script created at /usr/local/bin/verify-ssl"
}

# Update DNS records automatically
update_dns_records() {
    local domain=$1
    local provider=${2:-$DNS_PROVIDER}
    
    print_header "Updating DNS Records"
    
    case "$provider" in
        cloudflare)
            update_cloudflare_dns_records "$domain"
            ;;
        manual)
            print_message "Manual DNS update mode"
            print_message "Please add the records from: $DNS_RECORDS_FILE"
            ;;
        *)
            print_warning "DNS provider not configured"
            print_message "Please manually add the records from: $DNS_RECORDS_FILE"
            ;;
    esac
}

# Update Cloudflare DNS records
update_cloudflare_dns_records() {
    local domain=$1
    
    if [ ! -x /usr/local/bin/update-cloudflare-dns ]; then
        print_error "Cloudflare update script not found"
        return 1
    fi
    
    print_message "Updating Cloudflare DNS records..."
    
    # Add A records
    /usr/local/bin/update-cloudflare-dns add A "@" "$PRIMARY_IP" 1 false
    /usr/local/bin/update-cloudflare-dns add A "mail" "$PRIMARY_IP" 1 false
    
    # Add MX record
    /usr/local/bin/update-cloudflare-dns add MX "@" "mail.${domain}" 1 false
    
    # Add SPF record
    local spf_record="v=spf1"
    for ip in "${IP_ADDRESSES[@]}"; do
        spf_record="${spf_record} ip4:${ip}"
    done
    spf_record="${spf_record} mx a ~all"
    /usr/local/bin/update-cloudflare-dns add TXT "@" "${spf_record}" 1 false
    
    # Add DKIM record if available
    local dkim_value=$(get_dkim_value "$domain" 2>/dev/null)
    if [ ! -z "$dkim_value" ]; then
        /usr/local/bin/update-cloudflare-dns add TXT "${DKIM_SELECTOR}._domainkey" "v=DKIM1; k=rsa; p=${dkim_value}" 1 false
    fi
    
    # Add DMARC record
    /usr/local/bin/update-cloudflare-dns add TXT "_dmarc" "v=DMARC1; p=none; rua=mailto:postmaster@${domain}" 1 false
    
    print_message "✓ Cloudflare DNS records updated"
}

# Main DNS and SSL setup function
setup_dns_and_ssl() {
    local domain=$1
    local hostname=${2:-mail.$domain}
    
    print_header "DNS and SSL Configuration"
    
    # Generate DNS records
    generate_dns_records "$domain" "$hostname"
    
    # Setup DNS provider integration
    if [ ! -z "$CF_API_TOKEN" ]; then
        setup_cloudflare_dns "$domain"
        update_cloudflare_dns_records "$domain"
    fi
    
    # Setup SSL certificate
    setup_ssl_certificate "$domain" "$hostname" "$SSL_EMAIL"
    
    # Create verification scripts
    create_dns_verification_script
    create_ssl_verification_script
    
    print_message "✓ DNS and SSL configuration completed"
    print_message ""
    print_message "Next steps:"
    print_message "1. Add DNS records from: $DNS_RECORDS_FILE"
    print_message "2. Verify DNS with: verify-dns $domain"
    print_message "3. Verify SSL with: verify-ssl $hostname"
}

# Export functions
export -f check_certbot_installation setup_cloudflare_dns create_cloudflare_update_script
export -f test_cloudflare_api generate_dns_records setup_ssl_certificate
export -f generate_self_signed_cert setup_ssl_auto_renewal configure_services_ssl
export -f create_dns_verification_script create_ssl_verification_script
export -f update_dns_records update_cloudflare_dns_records setup_dns_and_ssl

# Export variables
export DNS_PROVIDER CF_API_TOKEN CF_ZONE_ID CF_EMAIL
export SSL_EMAIL SSL_CERT_PATH USE_LETSENCRYPT DNS_RECORDS_FILE
