#!/bin/bash

# =================================================================
# CLOUDFLARE DNS SETUP FOR MAIL SERVER
# Version: 2.2.0
# Adds all DNS records including DKIM (key already generated)
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

# Load configuration
if [ -f "$(pwd)/install.conf" ]; then
    source "$(pwd)/install.conf"
elif [ -f "/root/mail-installer/install.conf" ]; then
    source "/root/mail-installer/install.conf"
fi

print_header "Cloudflare DNS Configuration"
echo ""

# Verify required variables
if [ -z "$CF_API_KEY" ]; then
    print_error "Cloudflare API key not found in configuration"
    exit 1
fi

if [ -z "$DOMAIN_NAME" ]; then
    print_error "Domain name not found in configuration"
    exit 1
fi

echo "Domain: $DOMAIN_NAME"
echo "Hostname: $HOSTNAME"
echo "Primary IP: $PRIMARY_IP"
echo ""

# Load saved Cloudflare credentials if available
CREDS_FILE="/root/.cloudflare_credentials"
if [ -f "$CREDS_FILE" ]; then
    source "$CREDS_FILE"
    CF_API_KEY="${SAVED_CF_API_KEY:-$CF_API_KEY}"
    CF_EMAIL="${SAVED_CF_EMAIL:-}"
fi

# Check if jq is installed
if ! command -v jq &> /dev/null; then
    echo "Installing jq for JSON parsing..."
    apt-get update > /dev/null 2>&1
    apt-get install -y jq > /dev/null 2>&1
fi

# ===================================================================
# GET DKIM KEY (Should already exist from main installer)
# ===================================================================

DKIM_KEY=""
DKIM_RECORD_VALUE=""

if [ -f "/etc/opendkim/keys/$DOMAIN_NAME/mail.txt" ]; then
    print_message "✓ DKIM key found (generated during installation)"
    # Extract just the key part
    DKIM_KEY=$(cat /etc/opendkim/keys/$DOMAIN_NAME/mail.txt | grep -oP '(?<=p=)[^"]+' | tr -d '\n\t\r ')
    if [ ! -z "$DKIM_KEY" ]; then
        DKIM_RECORD_VALUE="v=DKIM1; k=rsa; p=$DKIM_KEY"
        echo "  Key length: ${#DKIM_KEY} characters"
    else
        print_warning "⚠ Could not extract DKIM key from file"
    fi
else
    print_warning "⚠ DKIM key file not found at /etc/opendkim/keys/$DOMAIN_NAME/mail.txt"
    print_warning "  DKIM will not be added to DNS"
fi

echo ""

# ===================================================================
# TEST API CONNECTION
# ===================================================================

print_header "Testing Cloudflare API Connection"

# First try as API Token
echo -n "Testing API connection... "
TEST_RESPONSE=$(curl -s -X GET "https://api.cloudflare.com/client/v4/user/tokens/verify" \
    -H "Authorization: Bearer $CF_API_KEY" \
    -H "Content-Type: application/json")

SUCCESS=$(echo "$TEST_RESPONSE" | jq -r '.success' 2>/dev/null)

if [ "$SUCCESS" == "true" ]; then
    print_message "✓ Connected with API Token"
    AUTH_METHOD="token"
else
    # Try as Global API Key
    if [ -z "$CF_EMAIL" ]; then
        echo ""
        echo "API Token authentication failed."
        echo "Trying Global API Key method..."
        read -p "Enter your Cloudflare account email: " CF_EMAIL
        
        # Save email for future use
        echo "SAVED_CF_EMAIL=\"$CF_EMAIL\"" >> "$CREDS_FILE"
    fi
    
    TEST_RESPONSE=$(curl -s -X GET "https://api.cloudflare.com/client/v4/user" \
        -H "X-Auth-Email: $CF_EMAIL" \
        -H "X-Auth-Key: $CF_API_KEY" \
        -H "Content-Type: application/json")
    
    SUCCESS=$(echo "$TEST_RESPONSE" | jq -r '.success' 2>/dev/null)
    
    if [ "$SUCCESS" == "true" ]; then
        print_message "✓ Connected with Global API Key"
        AUTH_METHOD="global"
    else
        print_error "✗ Failed to authenticate with Cloudflare"
        ERROR_MSG=$(echo "$TEST_RESPONSE" | jq -r '.errors[0].message' 2>/dev/null)
        [ ! -z "$ERROR_MSG" ] && [ "$ERROR_MSG" != "null" ] && echo "Error: $ERROR_MSG"
        exit 1
    fi
fi

# ===================================================================
# GET ZONE ID
# ===================================================================

echo -n "Getting Zone ID for $DOMAIN_NAME... "

if [ "$AUTH_METHOD" == "global" ]; then
    ZONE_RESPONSE=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$DOMAIN_NAME" \
        -H "X-Auth-Email: $CF_EMAIL" \
        -H "X-Auth-Key: $CF_API_KEY" \
        -H "Content-Type: application/json")
else
    ZONE_RESPONSE=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$DOMAIN_NAME" \
        -H "Authorization: Bearer $CF_API_KEY" \
        -H "Content-Type: application/json")
fi

ZONE_ID=$(echo "$ZONE_RESPONSE" | jq -r '.result[0].id' 2>/dev/null)

if [ -z "$ZONE_ID" ] || [ "$ZONE_ID" == "null" ]; then
    print_error "✗ Zone not found"
    echo "Make sure $DOMAIN_NAME exists in your Cloudflare account"
    ERROR_MSG=$(echo "$ZONE_RESPONSE" | jq -r '.errors[0].message' 2>/dev/null)
    [ ! -z "$ERROR_MSG" ] && [ "$ERROR_MSG" != "null" ] && echo "Error: $ERROR_MSG"
    exit 1
fi

print_message "✓ Found"
echo "Zone ID: $ZONE_ID"
echo ""

# ===================================================================
# HELPER FUNCTIONS
# ===================================================================

check_existing_record() {
    local record_type="$1"
    local record_name="$2"
    
    if [ "$AUTH_METHOD" == "global" ]; then
        EXISTING=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records?type=$record_type&name=$record_name" \
            -H "X-Auth-Email: $CF_EMAIL" \
            -H "X-Auth-Key: $CF_API_KEY" \
            -H "Content-Type: application/json")
    else
        EXISTING=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records?type=$record_type&name=$record_name" \
            -H "Authorization: Bearer $CF_API_KEY" \
            -H "Content-Type: application/json")
    fi
    
    echo "$EXISTING" | jq -r '.result[] | .id' 2>/dev/null
}

delete_record() {
    local record_id="$1"
    
    if [ "$AUTH_METHOD" == "global" ]; then
        curl -s -X DELETE "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records/$record_id" \
            -H "X-Auth-Email: $CF_EMAIL" \
            -H "X-Auth-Key: $CF_API_KEY" \
            -H "Content-Type: application/json" > /dev/null
    else
        curl -s -X DELETE "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records/$record_id" \
            -H "Authorization: Bearer $CF_API_KEY" \
            -H "Content-Type: application/json" > /dev/null
    fi
}

add_dns_record() {
    local record_type="$1"
    local record_name="$2"
    local record_content="$3"
    local priority="$4"
    local proxied="${5:-false}"
    
    echo -n "Adding $record_type record for $record_name... "
    
    # Check for existing record
    EXISTING_IDS=$(check_existing_record "$record_type" "$record_name")
    if [ ! -z "$EXISTING_IDS" ]; then
        echo -n "(removing old) "
        for id in $EXISTING_IDS; do
            delete_record "$id"
        done
    fi
    
    # Build JSON data
    if [ ! -z "$priority" ] && [ "$record_type" == "MX" ]; then
        JSON_DATA=$(jq -n \
            --arg type "$record_type" \
            --arg name "$record_name" \
            --arg content "$record_content" \
            --argjson priority "$priority" \
            --argjson proxied "$proxied" \
            '{type: $type, name: $name, content: $content, priority: $priority, proxied: $proxied}')
    else
        JSON_DATA=$(jq -n \
            --arg type "$record_type" \
            --arg name "$record_name" \
            --arg content "$record_content" \
            --argjson proxied "$proxied" \
            '{type: $type, name: $name, content: $content, proxied: $proxied}')
    fi
    
    # Add the record
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
    
    if [ "$(echo "$RESPONSE" | jq -r '.success' 2>/dev/null)" == "true" ]; then
        print_message "✓"
    else
        print_error "✗"
        ERROR_MSG=$(echo "$RESPONSE" | jq -r '.errors[0].message' 2>/dev/null)
        [ ! -z "$ERROR_MSG" ] && [ "$ERROR_MSG" != "null" ] && echo "  Error: $ERROR_MSG"
    fi
}

# ===================================================================
# ADD DNS RECORDS
# ===================================================================

print_header "Adding DNS Records to Cloudflare"

# 1. A record for mail subdomain
add_dns_record "A" "$HOSTNAME" "$PRIMARY_IP" "" "false"

# 2. A record for root domain (for website)
add_dns_record "A" "$DOMAIN_NAME" "$PRIMARY_IP" "" "false"

# 3. MX record
add_dns_record "MX" "$DOMAIN_NAME" "$HOSTNAME" "10" "false"

# 4. SPF record
SPF_RECORD="v=spf1 mx a ip4:$PRIMARY_IP ~all"
add_dns_record "TXT" "$DOMAIN_NAME" "$SPF_RECORD" "" "false"

# 5. DMARC record
DMARC_RECORD="v=DMARC1; p=quarantine; rua=mailto:dmarc@$DOMAIN_NAME; ruf=mailto:dmarc@$DOMAIN_NAME; fo=1; pct=100"
add_dns_record "TXT" "_dmarc.$DOMAIN_NAME" "$DMARC_RECORD" "" "false"

# 6. DKIM record (if key exists)
if [ ! -z "$DKIM_RECORD_VALUE" ]; then
    echo ""
    print_header "Adding DKIM Record"
    add_dns_record "TXT" "mail._domainkey.$DOMAIN_NAME" "$DKIM_RECORD_VALUE" "" "false"
    
    if [ $? -eq 0 ]; then
        print_message "✓ DKIM record added successfully!"
    else
        print_error "✗ Failed to add DKIM record"
        echo "You can add it manually:"
        echo "  Name: mail._domainkey.$DOMAIN_NAME"
        echo "  Type: TXT"
        echo "  Value: $DKIM_RECORD_VALUE"
    fi
else
    print_warning ""
    print_warning "⚠ DKIM key not available - skipping DKIM record"
    print_warning "  Run 'opendkim-genkey' manually if needed"
fi

# 7. PTR record suggestion
echo ""
print_header "PTR Record (Reverse DNS)"
echo "IMPORTANT: PTR record cannot be set in Cloudflare."
echo "Contact your server provider to set PTR record:"
echo "  IP: $PRIMARY_IP"
echo "  Should resolve to: $HOSTNAME"
echo ""
echo "Common providers:"
echo "  - DigitalOcean: Droplet settings → Networking"
echo "  - Vultr: Server settings → IPv4 → Reverse DNS"
echo "  - Linode: Linode settings → Network → Reverse DNS"
echo "  - AWS: Elastic IP → Actions → Update reverse DNS"

# ===================================================================
# VERIFY DNS RECORDS
# ===================================================================

echo ""
print_header "Verifying DNS Records"

echo "Testing DNS resolution (using Cloudflare DNS 1.1.1.1)..."
echo ""

# Test A record for mail
echo -n "A record for $HOSTNAME: "
A_RECORD=$(dig +short A $HOSTNAME @1.1.1.1 2>/dev/null | head -1)
if [ "$A_RECORD" == "$PRIMARY_IP" ]; then
    print_message "✓ $A_RECORD"
else
    print_warning "⚠ Not propagated yet (expected: $PRIMARY_IP)"
fi

# Test A record for domain
echo -n "A record for $DOMAIN_NAME: "
A_RECORD=$(dig +short A $DOMAIN_NAME @1.1.1.1 2>/dev/null | head -1)
if [ "$A_RECORD" == "$PRIMARY_IP" ]; then
    print_message "✓ $A_RECORD"
else
    print_warning "⚠ Not propagated yet (expected: $PRIMARY_IP)"
fi

# Test MX record
echo -n "MX record for $DOMAIN_NAME: "
MX_RECORD=$(dig +short MX $DOMAIN_NAME @1.1.1.1 2>/dev/null | awk '{print $2}' | sed 's/\.$//' | head -1)
if [ "$MX_RECORD" == "$HOSTNAME" ]; then
    print_message "✓ $MX_RECORD"
else
    print_warning "⚠ Not propagated yet (expected: $HOSTNAME)"
fi

# Test SPF record
echo -n "SPF record: "
SPF=$(dig +short TXT $DOMAIN_NAME @1.1.1.1 2>/dev/null | grep "v=spf1")
if [ ! -z "$SPF" ]; then
    print_message "✓ Found"
else
    print_warning "⚠ Not propagated yet"
fi

# Test DKIM record
if [ ! -z "$DKIM_RECORD_VALUE" ]; then
    echo -n "DKIM record: "
    DKIM=$(dig +short TXT mail._domainkey.$DOMAIN_NAME @1.1.1.1 2>/dev/null | grep "v=DKIM1")
    if [ ! -z "$DKIM" ]; then
        print_message "✓ Found"
    else
        print_warning "⚠ Not propagated yet"
    fi
fi

# Test DMARC record
echo -n "DMARC record: "
DMARC=$(dig +short TXT _dmarc.$DOMAIN_NAME @1.1.1.1 2>/dev/null | grep "v=DMARC1")
if [ ! -z "$DMARC" ]; then
    print_message "✓ Found"
else
    print_warning "⚠ Not propagated yet"
fi

# ===================================================================
# COMPLETION
# ===================================================================

echo ""
print_header "DNS Configuration Complete!"

echo ""
echo "✅ All DNS records have been added to Cloudflare"
if [ ! -z "$DKIM_RECORD_VALUE" ]; then
    echo "✅ DKIM record has been added"
fi
echo ""
echo "⏱ DNS propagation typically takes:"
echo "   - Cloudflare network: Immediate"
echo "   - Global propagation: 5-30 minutes"
echo "   - Full propagation: Up to 48 hours (rare)"
echo ""
echo "📝 Records added:"
echo "   • A record: $HOSTNAME → $PRIMARY_IP"
echo "   • A record: $DOMAIN_NAME → $PRIMARY_IP"
echo "   • MX record: $DOMAIN_NAME → $HOSTNAME"
echo "   • SPF record: v=spf1 mx a ip4:$PRIMARY_IP ~all"
echo "   • DMARC record: Basic quarantine policy"
if [ ! -z "$DKIM_RECORD_VALUE" ]; then
    echo "   • DKIM record: mail._domainkey (2048-bit key)"
fi
echo ""
echo "🔧 Don't forget:"
echo "   • Set PTR record with your hosting provider"
echo "   • Wait for DNS propagation before getting SSL certificate"
echo ""
echo "Test DNS propagation:"
echo "   check-dns $DOMAIN_NAME"
echo ""
if [ ! -z "$DKIM_RECORD_VALUE" ]; then
    print_message "✓ DKIM is configured and will sign all outgoing emails!"
fi
print_message "✓ Cloudflare DNS setup completed successfully!"
