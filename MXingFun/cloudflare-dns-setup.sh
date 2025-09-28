#!/bin/bash

# =================================================================
# CLOUDFLARE DNS AUTOMATIC SETUP FOR MAIL SERVER
# Version: 1.5
# Automatically adds all required DNS records to Cloudflare
# PREVENTS DUPLICATE RECORDS - Updates existing ones
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
    apt-get update && apt-get install -y curl > /dev/null 2>&1
fi

if ! command -v jq &> /dev/null; then
    apt-get update && apt-get install -y jq > /dev/null 2>&1
fi

# Load configuration from installer
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

# Get additional IPs if configured
ADDITIONAL_IPS=""
if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
    for ip in "${IP_ADDRESSES[@]:1}"; do
        ADDITIONAL_IPS="$ADDITIONAL_IPS ip4:$ip"
    done
fi

echo "Configuration detected:"
echo "  Domain: $DOMAIN_NAME"
echo "  Hostname: $HOSTNAME"
echo "  Primary IP: $PRIMARY_IP"
if [ ! -z "$ADDITIONAL_IPS" ]; then
    echo "  Additional IPs: $ADDITIONAL_IPS"
fi
echo ""

# Get Cloudflare credentials
print_header "Cloudflare API Credentials"
echo ""

CREDS_FILE="/root/.cloudflare_credentials"
CF_API_KEY=""
CF_EMAIL=""

if [ -f "$CREDS_FILE" ]; then
    source "$CREDS_FILE"
    if [ ! -z "$SAVED_CF_API_KEY" ]; then
        echo "Using saved API credentials"
        CF_API_KEY="$SAVED_CF_API_KEY"
        CF_EMAIL="${SAVED_CF_EMAIL:-}"
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
    
    echo "Enter Cloudflare API Token or Global API Key:"
    echo "(Input will be hidden for security)"
    read -s CF_API_KEY
    echo ""
    
    while [ -z "$CF_API_KEY" ]; do
        print_error "API Key cannot be empty!"
        echo "Enter Cloudflare API Token or Global API Key:"
        read -s CF_API_KEY
        echo ""
    done
    
    # Save for next time
    cat > "$CREDS_FILE" <<EOF
SAVED_CF_API_KEY="$CF_API_KEY"
EOF
    chmod 600 "$CREDS_FILE"
fi

# Test API credentials and get Zone ID
print_header "Connecting to Cloudflare"

echo -n "Getting Zone ID for $DOMAIN_NAME... "

# Try API Token authentication first
ZONE_RESPONSE=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$DOMAIN_NAME" \
    -H "Authorization: Bearer $CF_API_KEY" \
    -H "Content-Type: application/json")

SUCCESS=$(echo "$ZONE_RESPONSE" | jq -r '.success')

# If token auth failed, it might be a Global API Key
if [ "$SUCCESS" == "false" ]; then
    ERROR_CODE=$(echo "$ZONE_RESPONSE" | jq -r '.errors[0].code')
    
    if [ "$ERROR_CODE" == "9109" ] || [ "$ERROR_CODE" == "6003" ]; then
        echo ""
        if [ -z "$CF_EMAIL" ]; then
            print_warning "This appears to be a Global API Key, email required"
            read -p "Enter Cloudflare account email: " CF_EMAIL
            echo "SAVED_CF_EMAIL=\"$CF_EMAIL\"" >> "$CREDS_FILE"
        fi
        
        ZONE_RESPONSE=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$DOMAIN_NAME" \
            -H "X-Auth-Email: $CF_EMAIL" \
            -H "X-Auth-Key: $CF_API_KEY" \
            -H "Content-Type: application/json")
        
        SUCCESS=$(echo "$ZONE_RESPONSE" | jq -r '.success')
        AUTH_METHOD="global"
    fi
else
    AUTH_METHOD="token"
fi

if [ "$SUCCESS" != "true" ]; then
    ERROR_MSG=$(echo "$ZONE_RESPONSE" | jq -r '.errors[0].message // "Unknown error"')
    print_error "✗ API Authentication Failed"
    echo "Error: $ERROR_MSG"
    rm -f "$CREDS_FILE"
    exit 1
fi

ZONE_ID=$(echo "$ZONE_RESPONSE" | jq -r '.result[0].id // empty')

if [ -z "$ZONE_ID" ] || [ "$ZONE_ID" == "null" ]; then
    print_error "✗ Domain not found in Cloudflare account"
    exit 1
fi

print_message "✓ Found Zone ID: $ZONE_ID"
echo "✓ Authentication method: ${AUTH_METHOD:-token}"
echo ""

# CRITICAL FUNCTION: DELETE EXISTING RECORDS BEFORE CREATING NEW ONES
delete_existing_records() {
    local TYPE=$1
    local NAME=$2
    
    echo -n "Checking for existing $TYPE records for $NAME... "
    
    if [ "$AUTH_METHOD" == "global" ]; then
        EXISTING=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records?type=$TYPE&name=$NAME" \
            -H "X-Auth-Email: $CF_EMAIL" \
            -H "X-Auth-Key: $CF_API_KEY" \
            -H "Content-Type: application/json")
    else
        EXISTING=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records?type=$TYPE&name=$NAME" \
            -H "Authorization: Bearer $CF_API_KEY" \
            -H "Content-Type: application/json")
    fi
    
    RECORD_COUNT=$(echo "$EXISTING" | jq '.result | length')
    
    if [ "$RECORD_COUNT" -gt 0 ]; then
        echo "Found $RECORD_COUNT record(s)"
        
        # Delete ALL existing records of this type/name
        echo "$EXISTING" | jq -r '.result[].id' | while read RECORD_ID; do
            echo -n "  Deleting old record $RECORD_ID... "
            
            if [ "$AUTH_METHOD" == "global" ]; then
                DEL_RESPONSE=$(curl -s -X DELETE "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records/$RECORD_ID" \
                    -H "X-Auth-Email: $CF_EMAIL" \
                    -H "X-Auth-Key: $CF_API_KEY" \
                    -H "Content-Type: application/json")
            else
                DEL_RESPONSE=$(curl -s -X DELETE "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records/$RECORD_ID" \
                    -H "Authorization: Bearer $CF_API_KEY" \
                    -H "Content-Type: application/json")
            fi
            
            if [ "$(echo "$DEL_RESPONSE" | jq -r '.success')" == "true" ]; then
                print_message "✓"
            else
                print_error "✗"
            fi
        done
    else
        echo "None found"
    fi
}

# Function to create DNS record (ALWAYS DELETE OLD ONES FIRST)
create_dns_record() {
    local TYPE=$1
    local NAME=$2
    local CONTENT=$3
    local PRIORITY=$4
    local PROXIED=${5:-false}
    
    # ALWAYS delete existing records first to prevent duplicates
    delete_existing_records "$TYPE" "$NAME"
    
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
    
    # Create the new record
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
        print_error "✗ Failed: $ERROR"
        return 1
    fi
}

# Function for SRV records
create_srv_record() {
    local NAME=$1
    local PRIORITY=$2
    local WEIGHT=$3
    local PORT=$4
    local TARGET=$5
    
    delete_existing_records "SRV" "$NAME"
    
    echo -n "Creating SRV record: $NAME... "
    
    JSON_DATA=$(jq -n \
        --arg name "$NAME" \
        --argjson priority "$PRIORITY" \
        --argjson weight "$WEIGHT" \
        --argjson port "$PORT" \
        --arg target "$TARGET" \
        '{
            type: "SRV",
            name: $name,
            data: {
                priority: $priority,
                weight: $weight,
                port: $port,
                target: $target
            },
            ttl: 3600
        }')
    
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
    
    if [ "$(echo "$RESPONSE" | jq -r '.success')" == "true" ]; then
        print_message "✓ Created"
    else
        print_error "✗ Failed"
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

# 3. SPF Record - INCLUDE ALL IPs
SPF_RECORD="v=spf1 mx a ip4:$PRIMARY_IP$ADDITIONAL_IPS ~all"
create_dns_record "TXT" "$DOMAIN_NAME" "$SPF_RECORD" "" "false"

# 4. DKIM Record (if key exists)
if [ ! -z "$DKIM_KEY" ]; then
    DKIM_RECORD="v=DKIM1; k=rsa; p=$DKIM_KEY"
    create_dns_record "TXT" "mail._domainkey.$DOMAIN_NAME" "$DKIM_RECORD" "" "false"
else
    print_warning "⚠ Skipping DKIM record (will be added after key generation)"
fi

# 5. DMARC Record - USE FIRST_EMAIL or ADMIN_EMAIL
DMARC_EMAIL="${FIRST_EMAIL:-${ADMIN_EMAIL:-admin@$DOMAIN_NAME}}"
DMARC_RECORD="v=DMARC1; p=none; rua=mailto:$DMARC_EMAIL"
create_dns_record "TXT" "_dmarc.$DOMAIN_NAME" "$DMARC_RECORD" "" "false"

# 6. Autodiscover records
echo ""
echo "Adding autodiscover records for email clients..."
create_dns_record "CNAME" "autodiscover.$DOMAIN_NAME" "mail.$DOMAIN_NAME" "" "false"
create_dns_record "CNAME" "autoconfig.$DOMAIN_NAME" "mail.$DOMAIN_NAME" "" "false"

# 7. SRV records
create_srv_record "_autodiscover._tcp.$DOMAIN_NAME" 0 0 443 "mail.$DOMAIN_NAME"
create_srv_record "_imaps._tcp.$DOMAIN_NAME" 0 1 993 "mail.$DOMAIN_NAME"
create_srv_record "_submission._tcp.$DOMAIN_NAME" 0 1 587 "mail.$DOMAIN_NAME"

# Save configuration
print_header "Saving Configuration"

cat > /root/cloudflare-dns-config.txt <<EOF
Cloudflare DNS Configuration
Generated: $(date)
================================================================================

Domain: $DOMAIN_NAME
Zone ID: $ZONE_ID
Primary IP: $PRIMARY_IP
Additional IPs: $ADDITIONAL_IPS
Auth Method: ${AUTH_METHOD:-token}

DNS Records Created:
1. A record: mail.$DOMAIN_NAME -> $PRIMARY_IP
2. MX record: $DOMAIN_NAME -> mail.$DOMAIN_NAME (priority 10)
3. SPF record: $DOMAIN_NAME -> "$SPF_RECORD"
4. DKIM record: mail._domainkey.$DOMAIN_NAME
5. DMARC record: _dmarc.$DOMAIN_NAME -> "$DMARC_RECORD"
6. Autodiscover/Autoconfig CNAME records
7. SRV records for mail client autodiscovery

To verify DNS propagation:
  dig A mail.$DOMAIN_NAME
  dig MX $DOMAIN_NAME
  dig TXT $DOMAIN_NAME
  dig SRV _autodiscover._tcp.$DOMAIN_NAME

Or use online tools:
  https://mxtoolbox.com/SuperTool.aspx?action=mx:$DOMAIN_NAME

================================================================================
EOF

echo "Configuration saved to: /root/cloudflare-dns-config.txt"
echo ""

print_header "Setup Complete!"

echo "✓ All DNS records have been added to Cloudflare"
echo "✓ Old duplicate records have been removed"
echo ""
echo "IMPORTANT:"
echo "1. DNS propagation may take 5-30 minutes"
echo "2. PTR (Reverse DNS) must be set with your hosting provider"
echo "3. Test your setup with: test-email check-auth@verifier.port25.com"
echo ""

print_message "Cloudflare DNS setup completed successfully!"
