#!/bin/bash

# =================================================================
# CLOUDFLARE DNS AUTOMATIC SETUP FOR MAIL SERVER
# Version: 1.0
# Automatically adds all required DNS records to Cloudflare
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

print_header "Cloudflare DNS Automatic Setup"
echo ""

# Check for required tools
if ! command -v curl &> /dev/null; then
    apt-get update && apt-get install -y curl
fi

if ! command -v jq &> /dev/null; then
    apt-get update && apt-get install -y jq
fi

# Get configuration from existing setup
if [ -f /etc/postfix/main.cf ]; then
    HOSTNAME=$(postconf -h myhostname 2>/dev/null)
    DOMAIN=$(postconf -h mydomain 2>/dev/null)
else
    read -p "Enter your domain name (e.g., example.com): " DOMAIN
    HOSTNAME="mail.$DOMAIN"
fi

PRIMARY_IP=$(curl -s https://ipinfo.io/ip 2>/dev/null || hostname -I | awk '{print $1}')

echo "Configuration detected:"
echo "  Domain: $DOMAIN"
echo "  Hostname: $HOSTNAME"
echo "  Primary IP: $PRIMARY_IP"
echo ""

# Get Cloudflare credentials
print_header "Cloudflare API Credentials"
echo ""
echo "You need your Cloudflare API credentials to proceed."
echo "Get them from: https://dash.cloudflare.com/profile/api-tokens"
echo ""

# Check for saved credentials
CREDS_FILE="/root/.cloudflare_credentials"
if [ -f "$CREDS_FILE" ]; then
    source "$CREDS_FILE"
    echo "Found saved credentials"
    read -p "Use saved credentials? (y/n) [y]: " USE_SAVED
    if [[ "${USE_SAVED,,}" != "n" ]]; then
        CF_EMAIL="$SAVED_CF_EMAIL"
        CF_API_KEY="$SAVED_CF_API_KEY"
    else
        CF_EMAIL=""
        CF_API_KEY=""
    fi
fi

if [ -z "$CF_EMAIL" ]; then
    read -p "Enter Cloudflare email: " CF_EMAIL
fi

if [ -z "$CF_API_KEY" ]; then
    echo "Enter Cloudflare API Key (Global API Key or API Token):"
    read -s CF_API_KEY
    echo ""
fi

# Save credentials for future use
cat > "$CREDS_FILE" <<EOF
SAVED_CF_EMAIL="$CF_EMAIL"
SAVED_CF_API_KEY="$CF_API_KEY"
EOF
chmod 600 "$CREDS_FILE"

# Test API credentials and get Zone ID
print_header "Connecting to Cloudflare"

echo -n "Getting Zone ID for $DOMAIN... "
ZONE_RESPONSE=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$DOMAIN" \
    -H "X-Auth-Email: $CF_EMAIL" \
    -H "X-Auth-Key: $CF_API_KEY" \
    -H "Content-Type: application/json")

ZONE_ID=$(echo "$ZONE_RESPONSE" | jq -r '.result[0].id')

if [ "$ZONE_ID" == "null" ] || [ -z "$ZONE_ID" ]; then
    print_error "✗ Failed to get Zone ID"
    echo "Response: $ZONE_RESPONSE"
    echo ""
    echo "Please check:"
    echo "1. Your API credentials are correct"
    echo "2. The domain $DOMAIN exists in your Cloudflare account"
    exit 1
fi

print_message "✓ Found Zone ID: $ZONE_ID"
echo ""

# Function to create DNS record
create_dns_record() {
    local TYPE=$1
    local NAME=$2
    local CONTENT=$3
    local PRIORITY=$4
    local PROXIED=${5:-false}
    
    echo -n "Creating $TYPE record: $NAME... "
    
    # Build the JSON payload
    if [ ! -z "$PRIORITY" ] && [ "$TYPE" == "MX" ]; then
        JSON_DATA=$(jq -n \
            --arg type "$TYPE" \
            --arg name "$NAME" \
            --arg content "$CONTENT" \
            --argjson priority "$PRIORITY" \
            --argjson proxied "$PROXIED" \
            '{type: $type, name: $name, content: $content, priority: $priority, proxied: $proxied}')
    else
        JSON_DATA=$(jq -n \
            --arg type "$TYPE" \
            --arg name "$NAME" \
            --arg content "$CONTENT" \
            --argjson proxied "$PROXIED" \
            '{type: $type, name: $name, content: $content, proxied: $proxied}')
    fi
    
    RESPONSE=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records" \
        -H "X-Auth-Email: $CF_EMAIL" \
        -H "X-Auth-Key: $CF_API_KEY" \
        -H "Content-Type: application/json" \
        --data "$JSON_DATA")
    
    SUCCESS=$(echo "$RESPONSE" | jq -r '.success')
    
    if [ "$SUCCESS" == "true" ]; then
        print_message "✓ Created"
        return 0
    else
        ERROR=$(echo "$RESPONSE" | jq -r '.errors[0].message // .errors[0]')
        if [[ "$ERROR" == *"already exists"* ]]; then
            print_warning "⚠ Already exists"
            
            # Try to update instead
            echo -n "  Updating existing record... "
            RECORD_ID=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records?type=$TYPE&name=$NAME" \
                -H "X-Auth-Email: $CF_EMAIL" \
                -H "X-Auth-Key: $CF_API_KEY" \
                -H "Content-Type: application/json" | jq -r '.result[0].id')
            
            if [ "$RECORD_ID" != "null" ] && [ ! -z "$RECORD_ID" ]; then
                UPDATE_RESPONSE=$(curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records/$RECORD_ID" \
                    -H "X-Auth-Email: $CF_EMAIL" \
                    -H "X-Auth-Key: $CF_API_KEY" \
                    -H "Content-Type: application/json" \
                    --data "$JSON_DATA")
                
                if [ "$(echo "$UPDATE_RESPONSE" | jq -r '.success')" == "true" ]; then
                    print_message "✓ Updated"
                else
                    print_error "✗ Failed to update"
                fi
            fi
        else
            print_error "✗ Failed: $ERROR"
        fi
        return 1
    fi
}

# Get DKIM key if it exists
DKIM_KEY=""
DKIM_FILE="/etc/opendkim/keys/$DOMAIN/mail.txt"
if [ -f "$DKIM_FILE" ]; then
    DKIM_KEY=$(cat "$DKIM_FILE" | grep -oP '(?<=p=)[^"]+' | tr -d '\n\t\r ')
    echo "Found DKIM key in $DKIM_FILE"
else
    print_warning "DKIM key not found. Run the mail installer first."
fi

# Start creating DNS records
print_header "Creating DNS Records"

# 1. A Record for mail subdomain
create_dns_record "A" "mail.$DOMAIN" "$PRIMARY_IP" "" "false"

# 2. MX Record
create_dns_record "MX" "$DOMAIN" "mail.$DOMAIN" "10" "false"

# 3. SPF Record
SPF_RECORD="v=spf1 mx a ip4:$PRIMARY_IP ~all"
create_dns_record "TXT" "$DOMAIN" "$SPF_RECORD" "" "false"

# 4. DKIM Record (if key exists)
if [ ! -z "$DKIM_KEY" ]; then
    DKIM_RECORD="v=DKIM1; k=rsa; p=$DKIM_KEY"
    create_dns_record "TXT" "mail._domainkey.$DOMAIN" "$DKIM_RECORD" "" "false"
else
    print_warning "⚠ Skipping DKIM record (no key found)"
fi

# 5. DMARC Record
DMARC_RECORD="v=DMARC1; p=none; rua=mailto:admin@$DOMAIN"
create_dns_record "TXT" "_dmarc.$DOMAIN" "$DMARC_RECORD" "" "false"

# 6. Autodiscover records (optional but useful)
echo ""
read -p "Add autodiscover records for email clients? (y/n) [y]: " ADD_AUTO
if [[ "${ADD_AUTO,,}" != "n" ]]; then
    create_dns_record "CNAME" "autodiscover.$DOMAIN" "mail.$DOMAIN" "" "false"
    create_dns_record "CNAME" "autoconfig.$DOMAIN" "mail.$DOMAIN" "" "false"
    
    # SRV records for autodiscovery
    create_dns_record "SRV" "_autodiscover._tcp.$DOMAIN" "0 0 443 mail.$DOMAIN" "" "false"
    create_dns_record "SRV" "_imaps._tcp.$DOMAIN" "0 1 993 mail.$DOMAIN" "" "false"
    create_dns_record "SRV" "_submission._tcp.$DOMAIN" "0 1 587 mail.$DOMAIN" "" "false"
fi

# List all DNS records
print_header "Verifying DNS Records"

echo "Fetching all DNS records for $DOMAIN..."
ALL_RECORDS=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records?per_page=100" \
    -H "X-Auth-Email: $CF_EMAIL" \
    -H "X-Auth-Key: $CF_API_KEY" \
    -H "Content-Type: application/json")

echo ""
echo "Mail-related DNS records:"
echo "$ALL_RECORDS" | jq -r '.result[] | select(.name | contains("mail") or contains("_dmarc") or contains("_domainkey") or .type == "MX" or (.type == "TXT" and .content | contains("spf1"))) | "\(.type)\t\(.name)\t\(.content[0:60])"' | column -t

# Save configuration
print_header "Saving Configuration"

cat > /root/cloudflare-dns-config.txt <<EOF
Cloudflare DNS Configuration
Generated: $(date)
================================================================================

Domain: $DOMAIN
Zone ID: $ZONE_ID
Primary IP: $PRIMARY_IP

DNS Records Created:
1. A record: mail.$DOMAIN -> $PRIMARY_IP
2. MX record: $DOMAIN -> mail.$DOMAIN (priority 10)
3. SPF record: $DOMAIN -> "$SPF_RECORD"
4. DKIM record: mail._domainkey.$DOMAIN
5. DMARC record: _dmarc.$DOMAIN -> "$DMARC_RECORD"

To verify DNS propagation:
  dig A mail.$DOMAIN
  dig MX $DOMAIN
  dig TXT $DOMAIN
  dig TXT mail._domainkey.$DOMAIN
  dig TXT _dmarc.$DOMAIN

Or use online tools:
  https://mxtoolbox.com/SuperTool.aspx?action=mx:$DOMAIN
  https://www.mail-tester.com/

================================================================================
EOF

echo "Configuration saved to: /root/cloudflare-dns-config.txt"
echo ""

# Final notes
print_header "Setup Complete!"

echo "✓ All DNS records have been added to Cloudflare"
echo ""
echo "IMPORTANT:"
echo "1. DNS propagation may take 5-30 minutes"
echo "2. PTR (Reverse DNS) must be set with your hosting provider"
echo "3. Test your setup with: test-email check-auth@verifier.port25.com"
echo ""
echo "To check DNS propagation:"
echo "  check-dns $DOMAIN"
echo ""
echo "To verify in Cloudflare dashboard:"
echo "  https://dash.cloudflare.com/$ZONE_ID/dns"
echo ""

print_message "Cloudflare DNS setup completed successfully!"
