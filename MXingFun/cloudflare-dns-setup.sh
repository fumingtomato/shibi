#!/bin/bash

# =================================================================
# CLOUDFLARE DNS AUTOMATIC SETUP FOR MAIL SERVER
# Version: 1.2
# Automatically adds all required DNS records to Cloudflare
# Works with API Token (no email needed) or Global API Key (email required)
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

# Load configuration from installer (REUSE EXISTING CONFIG!)
if [ -f "$(pwd)/install.conf" ]; then
    source "$(pwd)/install.conf"
elif [ -f "/root/mail-installer/install.conf" ]; then
    source "/root/mail-installer/install.conf"
fi

# If DOMAIN_NAME is not set from installer config, get from postfix
if [ -z "$DOMAIN_NAME" ]; then
    if [ -f /etc/postfix/main.cf ]; then
        HOSTNAME=$(postconf -h myhostname 2>/dev/null)
        DOMAIN_NAME=$(postconf -h mydomain 2>/dev/null)
    else
        print_error "Domain configuration not found!"
        exit 1
    fi
else
    HOSTNAME=${HOSTNAME:-"mail.$DOMAIN_NAME"}
fi

# Use PRIMARY_IP from installer config or detect it
if [ -z "$PRIMARY_IP" ]; then
    PRIMARY_IP=$(curl -s https://ipinfo.io/ip 2>/dev/null || hostname -I | awk '{print $1}')
fi

echo "Configuration detected:"
echo "  Domain: $DOMAIN_NAME"
echo "  Hostname: $HOSTNAME"
echo "  Primary IP: $PRIMARY_IP"
echo ""

# Get Cloudflare credentials - SIMPLIFIED!
print_header "Cloudflare API Credentials"
echo ""

# Check for saved credentials
CREDS_FILE="/root/.cloudflare_credentials"
CF_API_KEY=""

if [ -f "$CREDS_FILE" ]; then
    source "$CREDS_FILE"
    if [ ! -z "$SAVED_CF_API_KEY" ]; then
        echo "Found saved API credentials"
        read -p "Use saved credentials? (y/n) [y]: " USE_SAVED
        USE_SAVED=${USE_SAVED:-y}
        if [[ "${USE_SAVED,,}" == "y" ]]; then
            CF_API_KEY="$SAVED_CF_API_KEY"
        fi
    fi
fi

# Get API key if not set
if [ -z "$CF_API_KEY" ]; then
    echo "You need a Cloudflare API Token or Global API Key"
    echo ""
    echo "RECOMMENDED: Create a scoped API Token:"
    echo "1. Go to: https://dash.cloudflare.com/profile/api-tokens"
    echo "2. Click 'Create Token'"
    echo "3. Use template 'Edit zone DNS' or create custom token with:"
    echo "   - Zone:DNS:Edit permissions"
    echo "   - Include your specific zone"
    echo ""
    echo "OR use your Global API Key (less secure, requires email)"
    echo ""
    
    echo "Enter Cloudflare API Token or Global API Key:"
    echo "(Input will be hidden for security)"
    read -s CF_API_KEY
    echo ""
    
    # Make sure key was entered
    while [ -z "$CF_API_KEY" ]; do
        print_error "API Key cannot be empty!"
        echo "Enter Cloudflare API Token or Global API Key:"
        read -s CF_API_KEY
        echo ""
    done
fi

# Save credentials for future use (just the key)
cat > "$CREDS_FILE" <<EOF
SAVED_CF_API_KEY="$CF_API_KEY"
EOF
chmod 600 "$CREDS_FILE"

# Test API credentials and get Zone ID
print_header "Connecting to Cloudflare"

echo -n "Getting Zone ID for $DOMAIN_NAME... "

# Try API Token authentication first (no email needed)
ZONE_RESPONSE=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$DOMAIN_NAME" \
    -H "Authorization: Bearer $CF_API_KEY" \
    -H "Content-Type: application/json")

# Check if response is valid
if ! echo "$ZONE_RESPONSE" | jq empty 2>/dev/null; then
    print_error "✗ Invalid response from Cloudflare API"
    echo "Response: $ZONE_RESPONSE"
    exit 1
fi

SUCCESS=$(echo "$ZONE_RESPONSE" | jq -r '.success')

# If token auth failed, it might be a Global API Key
if [ "$SUCCESS" == "false" ]; then
    ERROR_CODE=$(echo "$ZONE_RESPONSE" | jq -r '.errors[0].code')
    
    if [ "$ERROR_CODE" == "9109" ] || [ "$ERROR_CODE" == "6003" ]; then
        # Likely a Global API Key, needs email
        echo ""
        print_warning "This appears to be a Global API Key, email required"
        read -p "Enter Cloudflare account email: " CF_EMAIL
        
        # Try again with email
        ZONE_RESPONSE=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$DOMAIN_NAME" \
            -H "X-Auth-Email: $CF_EMAIL" \
            -H "X-Auth-Key: $CF_API_KEY" \
            -H "Content-Type: application/json")
        
        SUCCESS=$(echo "$ZONE_RESPONSE" | jq -r '.success')
        
        if [ "$SUCCESS" == "true" ]; then
            # Save email for future use with Global Key
            echo "SAVED_CF_EMAIL=\"$CF_EMAIL\"" >> "$CREDS_FILE"
            AUTH_METHOD="global"
        fi
    fi
else
    AUTH_METHOD="token"
fi

if [ "$SUCCESS" != "true" ]; then
    ERROR_MSG=$(echo "$ZONE_RESPONSE" | jq -r '.errors[0].message // "Unknown error"')
    print_error "✗ API Authentication Failed"
    echo "Error: $ERROR_MSG"
    echo ""
    echo "Please check your API credentials"
    rm -f "$CREDS_FILE"
    exit 1
fi

ZONE_ID=$(echo "$ZONE_RESPONSE" | jq -r '.result[0].id // empty')

if [ -z "$ZONE_ID" ] || [ "$ZONE_ID" == "null" ]; then
    print_error "✗ Domain not found in Cloudflare account"
    echo "Please ensure $DOMAIN_NAME is added to your Cloudflare account"
    exit 1
fi

print_message "✓ Found Zone ID: $ZONE_ID"
echo "✓ Authentication method: ${AUTH_METHOD:-token}"
echo ""

# Function to create DNS record (works with both auth methods)
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
    
    # Use appropriate auth headers
    if [ "$AUTH_METHOD" == "global" ]; then
        RESPONSE=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records" \
            -H "X-Auth-Email: $CF_EMAIL" \
            -H "X-Auth-Key: $CF_API_KEY" \
            -H "Content-Type: application/json" \
            --data "$JSON_DATA")
    else
        RESPONSE=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records" \
            -H "Authorization: Bearer $CF_API_KEY" \
            -H "Content-Type: application/json" \
            --data "$JSON_DATA")
    fi
    
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
            
            if [ "$AUTH_METHOD" == "global" ]; then
                RECORD_ID=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records?type=$TYPE&name=$NAME" \
                    -H "X-Auth-Email: $CF_EMAIL" \
                    -H "X-Auth-Key: $CF_API_KEY" \
                    -H "Content-Type: application/json" | jq -r '.result[0].id')
                    
                UPDATE_RESPONSE=$(curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records/$RECORD_ID" \
                    -H "X-Auth-Email: $CF_EMAIL" \
                    -H "X-Auth-Key: $CF_API_KEY" \
                    -H "Content-Type: application/json" \
                    --data "$JSON_DATA")
            else
                RECORD_ID=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records?type=$TYPE&name=$NAME" \
                    -H "Authorization: Bearer $CF_API_KEY" \
                    -H "Content-Type: application/json" | jq -r '.result[0].id')
                    
                UPDATE_RESPONSE=$(curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records/$RECORD_ID" \
                    -H "Authorization: Bearer $CF_API_KEY" \
                    -H "Content-Type: application/json" \
                    --data "$JSON_DATA")
            fi
            
            if [ "$(echo "$UPDATE_RESPONSE" | jq -r '.success')" == "true" ]; then
                print_message "✓ Updated"
            else
                print_error "✗ Failed to update"
            fi
        else
            print_error "✗ Failed: $ERROR"
        fi
        return 1
    fi
}

# Get DKIM key if it exists
DKIM_KEY=""
DKIM_FILE="/etc/opendkim/keys/$DOMAIN_NAME/mail.txt"
if [ -f "$DKIM_FILE" ]; then
    DKIM_KEY=$(cat "$DKIM_FILE" | grep -oP '(?<=p=)[^"]+' | tr -d '\n\t\r ')
    echo "Found DKIM key in $DKIM_FILE"
else
    print_warning "DKIM key not found. It will be created during installation."
fi

# Start creating DNS records
print_header "Creating DNS Records"

# 1. A Record for mail subdomain
create_dns_record "A" "mail.$DOMAIN_NAME" "$PRIMARY_IP" "" "false"

# 2. MX Record
create_dns_record "MX" "$DOMAIN_NAME" "mail.$DOMAIN_NAME" "10" "false"

# 3. SPF Record
SPF_RECORD="v=spf1 mx a ip4:$PRIMARY_IP ~all"
create_dns_record "TXT" "$DOMAIN_NAME" "$SPF_RECORD" "" "false"

# 4. DKIM Record (if key exists)
if [ ! -z "$DKIM_KEY" ]; then
    DKIM_RECORD="v=DKIM1; k=rsa; p=$DKIM_KEY"
    create_dns_record "TXT" "mail._domainkey.$DOMAIN_NAME" "$DKIM_RECORD" "" "false"
else
    print_warning "⚠ Skipping DKIM record (will be added after key generation)"
fi

# 5. DMARC Record
DMARC_RECORD="v=DMARC1; p=none; rua=mailto:admin@$DOMAIN_NAME"
create_dns_record "TXT" "_dmarc.$DOMAIN_NAME" "$DMARC_RECORD" "" "false"

# 6. Autodiscover records - AUTO YES, NO MORE QUESTIONS!
echo ""
echo "Adding autodiscover records for email clients..."
create_dns_record "CNAME" "autodiscover.$DOMAIN_NAME" "mail.$DOMAIN_NAME" "" "false"
create_dns_record "CNAME" "autoconfig.$DOMAIN_NAME" "mail.$DOMAIN_NAME" "" "false"

# SRV records for autodiscovery
create_dns_record "SRV" "_autodiscover._tcp.$DOMAIN_NAME" "0 0 443 mail.$DOMAIN_NAME" "" "false"
create_dns_record "SRV" "_imaps._tcp.$DOMAIN_NAME" "0 1 993 mail.$DOMAIN_NAME" "" "false"
create_dns_record "SRV" "_submission._tcp.$DOMAIN_NAME" "0 1 587 mail.$DOMAIN_NAME" "" "false"

# Save configuration
print_header "Saving Configuration"

cat > /root/cloudflare-dns-config.txt <<EOF
Cloudflare DNS Configuration
Generated: $(date)
================================================================================

Domain: $DOMAIN_NAME
Zone ID: $ZONE_ID
Primary IP: $PRIMARY_IP
Auth Method: ${AUTH_METHOD:-token}

DNS Records Created:
1. A record: mail.$DOMAIN_NAME -> $PRIMARY_IP
2. MX record: $DOMAIN_NAME -> mail.$DOMAIN_NAME (priority 10)
3. SPF record: $DOMAIN_NAME -> "$SPF_RECORD"
4. DKIM record: mail._domainkey.$DOMAIN_NAME
5. DMARC record: _dmarc.$DOMAIN_NAME -> "$DMARC_RECORD"
6. Autodiscover/Autoconfig records

To verify DNS propagation:
  dig A mail.$DOMAIN_NAME
  dig MX $DOMAIN_NAME
  dig TXT $DOMAIN_NAME

Or use online tools:
  https://mxtoolbox.com/SuperTool.aspx?action=mx:$DOMAIN_NAME

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

print_message "Cloudflare DNS setup completed successfully!"
