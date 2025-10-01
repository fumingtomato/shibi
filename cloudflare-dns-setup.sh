#!/bin/bash

# =================================================================
# CLOUDFLARE DNS SETUP FOR MAIL SERVER - AUTOMATIC, NO QUESTIONS
# Version: 17.1.0 - Fixed hostname generation with custom subdomain
# Adds all DNS records including DKIM automatically
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
    echo "Skipping automatic DNS setup"
    exit 0
fi

if [ -z "$DOMAIN_NAME" ]; then
    print_error "Domain name not found in configuration"
    exit 1
fi

# FIX 1: Use configured hostname with custom subdomain
if [ ! -z "$MAIL_SUBDOMAIN" ]; then
    HOSTNAME="$MAIL_SUBDOMAIN.$DOMAIN_NAME"
    MAIL_PREFIX="$MAIL_SUBDOMAIN"
else
    HOSTNAME=${HOSTNAME:-"mail.$DOMAIN_NAME"}
    MAIL_PREFIX="mail"
fi

echo "Domain: $DOMAIN_NAME"
echo "Mail Server: $HOSTNAME"
echo "Mail Subdomain: $MAIL_PREFIX"
echo "Primary IP: $PRIMARY_IP"
if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
    echo "Additional IPs: $((${#IP_ADDRESSES[@]} - 1))"
fi
echo ""

# Load saved Cloudflare credentials if available
CREDS_FILE="/root/.cloudflare_credentials"
if [ -f "$CREDS_FILE" ]; then
    source "$CREDS_FILE"
    CF_API_KEY="${SAVED_CF_API_KEY:-$CF_API_KEY}"
    CF_EMAIL="${SAVED_CF_EMAIL:-$CF_EMAIL}"
fi

# Check if jq is installed
if ! command -v jq &> /dev/null; then
    echo "Installing jq for JSON parsing..."
    apt-get update > /dev/null 2>&1
    apt-get install -y jq > /dev/null 2>&1
fi

# ===================================================================
# GET AND PREPARE DKIM KEY (FIXED EXTRACTION METHOD)
# ===================================================================

DKIM_KEY=""
DKIM_RECORD_VALUE=""

# FIXED: Better extraction method that handles the multi-line format
if [ -f "/etc/opendkim/keys/$DOMAIN_NAME/mail.txt" ]; then
    print_message "✓ DKIM key found (generated during installation)"
    
    # Extract the entire content between quotes and clean it
    RAW_FILE=$(cat /etc/opendkim/keys/$DOMAIN_NAME/mail.txt)
    
    # Method 1: Extract everything after p= and before the closing quote
    DKIM_KEY=$(cat /etc/opendkim/keys/$DOMAIN_NAME/mail.txt | tr -d '\n\r\t' | sed 's/.*"p=//' | sed 's/".*//' | tr -d ' "')
    
    # Method 2: If Method 1 fails, try grep with perl regex
    if [ -z "$DKIM_KEY" ] || [ ${#DKIM_KEY} -lt 100 ]; then
        DKIM_KEY=$(cat /etc/opendkim/keys/$DOMAIN_NAME/mail.txt | grep -Po '(?<=p=)[^"]+' | tr -d '\n\r\t ')
    fi
    
    # Method 3: If still failing, use awk
    if [ -z "$DKIM_KEY" ] || [ ${#DKIM_KEY} -lt 100 ]; then
        DKIM_KEY=$(awk -F'"' '/p=/{print $2}' /etc/opendkim/keys/$DOMAIN_NAME/mail.txt | sed 's/.*p=//' | tr -d '\n\r\t ')
    fi
    
    # Validate the key
    if [ ! -z "$DKIM_KEY" ] && [ ${#DKIM_KEY} -gt 100 ]; then
        KEY_LENGTH=${#DKIM_KEY}
        echo "  Key length: $KEY_LENGTH characters"
        
        # Extract h= value if present
        H_VALUE=$(echo "$RAW_FILE" | grep -oP 'h=\K[^;]+' | tr -d ' ' || echo "")
        
        # Build the complete DKIM record
        if [ ! -z "$H_VALUE" ]; then
            DKIM_RECORD_VALUE="v=DKIM1; h=$H_VALUE; k=rsa; p=$DKIM_KEY"
        else
            DKIM_RECORD_VALUE="v=DKIM1; k=rsa; p=$DKIM_KEY"
        fi
        
        # 1024-bit keys are ~216 characters
        if [ $KEY_LENGTH -ge 200 ] && [ $KEY_LENGTH -le 250 ]; then
            echo "  1024-bit key detected - perfect for DNS"
        elif [ $KEY_LENGTH -gt 250 ]; then
            print_warning "  WARNING: Key might be 2048-bit (${KEY_LENGTH} chars)"
        fi
        
        echo "  DKIM record prepared for DNS"
    else
        print_warning "⚠ Could not extract DKIM key from file"
        print_warning "  Key will need to be added manually"
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

# Function to make Cloudflare API requests
cf_api_request() {
    local method="$1"
    local endpoint="$2"
    local data="$3"
    
    if [ "$AUTH_METHOD" == "global" ]; then
        if [ -z "$data" ]; then
            curl -s -X "$method" "https://api.cloudflare.com/client/v4/$endpoint" \
                -H "X-Auth-Email: $CF_EMAIL" \
                -H "X-Auth-Key: $CF_API_KEY" \
                -H "Content-Type: application/json"
        else
            curl -s -X "$method" "https://api.cloudflare.com/client/v4/$endpoint" \
                -H "X-Auth-Email: $CF_EMAIL" \
                -H "X-Auth-Key: $CF_API_KEY" \
                -H "Content-Type: application/json" \
                --data "$data"
        fi
    else
        if [ -z "$data" ]; then
            curl -s -X "$method" "https://api.cloudflare.com/client/v4/$endpoint" \
                -H "Authorization: Bearer $CF_API_KEY" \
                -H "Content-Type: application/json"
        else
            curl -s -X "$method" "https://api.cloudflare.com/client/v4/$endpoint" \
                -H "Authorization: Bearer $CF_API_KEY" \
                -H "Content-Type: application/json" \
                --data "$data"
        fi
    fi
}

# First try as API Token
echo -n "Testing API connection... "
TEST_RESPONSE=$(cf_api_request "GET" "user/tokens/verify" "" 2>/dev/null || echo "{}")

SUCCESS=$(echo "$TEST_RESPONSE" | jq -r '.success' 2>/dev/null)

if [ "$SUCCESS" == "true" ]; then
    print_message "✓ Connected with API Token"
    AUTH_METHOD="token"
else
    # Try as Global API Key
    if [ -z "$CF_EMAIL" ]; then
        print_error "✗ API Token authentication failed and no email provided"
        echo "Cannot proceed with automatic DNS setup"
        exit 0
    fi
    
    AUTH_METHOD="global"
    TEST_RESPONSE=$(cf_api_request "GET" "user" "" 2>/dev/null || echo "{}")
    SUCCESS=$(echo "$TEST_RESPONSE" | jq -r '.success' 2>/dev/null)
    
    if [ "$SUCCESS" == "true" ]; then
        print_message "✓ Connected with Global API Key"
    else
        print_error "✗ Failed to authenticate with Cloudflare"
        ERROR_MSG=$(echo "$TEST_RESPONSE" | jq -r '.errors[0].message' 2>/dev/null)
        [ ! -z "$ERROR_MSG" ] && [ "$ERROR_MSG" != "null" ] && echo "Error: $ERROR_MSG"
        exit 0
    fi
fi

# ===================================================================
# GET ZONE ID
# ===================================================================

echo -n "Getting Zone ID for $DOMAIN_NAME... "

ZONE_RESPONSE=$(cf_api_request "GET" "zones?name=$DOMAIN_NAME" "")

ZONE_ID=$(echo "$ZONE_RESPONSE" | jq -r '.result[0].id' 2>/dev/null)

if [ -z "$ZONE_ID" ] || [ "$ZONE_ID" == "null" ]; then
    print_error "✗ Zone not found"
    echo "Make sure $DOMAIN_NAME exists in your Cloudflare account"
    ERROR_MSG=$(echo "$ZONE_RESPONSE" | jq -r '.errors[0].message' 2>/dev/null)
    [ ! -z "$ERROR_MSG" ] && [ "$ERROR_MSG" != "null" ] && echo "Error: $ERROR_MSG"
    exit 0
fi

print_message "✓ Found"
echo "Zone ID: $ZONE_ID"
echo ""

# ===================================================================
# HELPER FUNCTIONS (FIXED FOR PROPER DKIM HANDLING)
# ===================================================================

check_existing_record() {
    local record_type="$1"
    local record_name="$2"
    
    EXISTING=$(cf_api_request "GET" "zones/$ZONE_ID/dns_records?type=$record_type&name=$record_name" "")
    echo "$EXISTING" | jq -r '.result[] | .id' 2>/dev/null
}

delete_record() {
    local record_id="$1"
    cf_api_request "DELETE" "zones/$ZONE_ID/dns_records/$record_id" "" > /dev/null 2>&1
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
    
    # CRITICAL FIX: Properly escape the content for JSON
    # This ensures special characters don't break the JSON
    ESCAPED_CONTENT=$(echo "$record_content" | jq -Rs .)
    
    # Build JSON data based on record type
    if [ ! -z "$priority" ] && [ "$record_type" == "MX" ]; then
        JSON_DATA=$(cat <<EOF
{
  "type": "$record_type",
  "name": "$record_name",
  "content": "$record_content",
  "priority": $priority,
  "proxied": $proxied
}
EOF
)
    else
        # For TXT records (including DKIM), use the escaped content
        if [ "$record_type" == "TXT" ]; then
            JSON_DATA=$(cat <<EOF
{
  "type": "$record_type",
  "name": "$record_name",
  "content": $ESCAPED_CONTENT,
  "proxied": $proxied
}
EOF
)
        else
            JSON_DATA=$(cat <<EOF
{
  "type": "$record_type",
  "name": "$record_name",
  "content": "$record_content",
  "proxied": $proxied
}
EOF
)
        fi
    fi
    
    # Add the record
    RESPONSE=$(cf_api_request "POST" "zones/$ZONE_ID/dns_records" "$JSON_DATA")
    
    if [ "$(echo "$RESPONSE" | jq -r '.success' 2>/dev/null)" == "true" ]; then
        print_message "✓"
        return 0
    else
        print_error "✗"
        ERROR_MSG=$(echo "$RESPONSE" | jq -r '.errors[0].message' 2>/dev/null)
        [ ! -z "$ERROR_MSG" ] && [ "$ERROR_MSG" != "null" ] && echo "  Error: $ERROR_MSG"
        return 1
    fi
}

# ===================================================================
# ADD DNS RECORDS - AUTOMATIC, NO QUESTIONS
# ===================================================================

print_header "Adding DNS Records to Cloudflare"

# FIX 1: A record for mail subdomain (USING CONFIGURED SUBDOMAIN)
add_dns_record "A" "$HOSTNAME" "$PRIMARY_IP" "" "false"

# 2. A record for root domain (for website)
add_dns_record "A" "$DOMAIN_NAME" "$PRIMARY_IP" "" "false"

# 3. A record for www subdomain
add_dns_record "A" "www.$DOMAIN_NAME" "$PRIMARY_IP" "" "false"

# FIX 1: Additional IPs as A records (USING CONFIGURED SUBDOMAIN PREFIX)
if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
    echo ""
    echo "Adding additional IP addresses..."
    for i in "${!IP_ADDRESSES[@]}"; do
        if [ $i -ne 0 ]; then
            ip="${IP_ADDRESSES[$i]}"
            # Use configured subdomain prefix with number suffix
            subdomain_name="${MAIL_PREFIX}${i}.$DOMAIN_NAME"
            add_dns_record "A" "$subdomain_name" "$ip" "" "false"
        fi
    done
fi

# 5. MX record
add_dns_record "MX" "$DOMAIN_NAME" "$HOSTNAME" "10" "false"

# 6. SPF record (include all IPs)
SPF_IPS="ip4:$PRIMARY_IP"
if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
    for ip in "${IP_ADDRESSES[@]:1}"; do
        SPF_IPS="$SPF_IPS ip4:$ip"
    done
fi
SPF_RECORD="v=spf1 mx a $SPF_IPS ~all"
add_dns_record "TXT" "$DOMAIN_NAME" "$SPF_RECORD" "" "false"

# 7. DMARC record
DMARC_RECORD="v=DMARC1; p=quarantine; rua=mailto:dmarc@$DOMAIN_NAME; ruf=mailto:dmarc@$DOMAIN_NAME; fo=1; pct=100"
add_dns_record "TXT" "_dmarc.$DOMAIN_NAME" "$DMARC_RECORD" "" "false"

# 8. DKIM record (FIXED TO WORK PROPERLY)
if [ ! -z "$DKIM_RECORD_VALUE" ] && [ ! -z "$DKIM_KEY" ]; then
    echo ""
    print_header "Adding DKIM Record"
    
    echo "Adding DKIM record to Cloudflare..."
    echo "  Name: mail._domainkey.$DOMAIN_NAME"
    echo "  Type: TXT"
    echo "  Key length: ${#DKIM_KEY} characters"
    
    # Add DKIM record with proper handling
    if add_dns_record "TXT" "mail._domainkey.$DOMAIN_NAME" "$DKIM_RECORD_VALUE" "" "false"; then
        print_message "✓ DKIM record added successfully!"
        echo ""
        
        # Verify it was added correctly
        echo "Verifying DKIM record in Cloudflare..."
        sleep 3
        
        CHECK_RESPONSE=$(cf_api_request "GET" "zones/$ZONE_ID/dns_records?type=TXT&name=mail._domainkey.$DOMAIN_NAME" "")
        DKIM_IN_CF=$(echo "$CHECK_RESPONSE" | jq -r '.result[0].content' 2>/dev/null)
        
        if [[ "$DKIM_IN_CF" == *"p=$DKIM_KEY"* ]]; then
            print_message "✓ DKIM record verified in Cloudflare!"
        else
            print_warning "⚠ DKIM record may not have been added correctly"
            echo "  Please verify in Cloudflare dashboard"
        fi
    else
        print_error "✗ Failed to add DKIM record via API"
        echo ""
        echo "MANUAL ADDITION REQUIRED:"
        echo "========================="
        echo "Add this TXT record in Cloudflare dashboard:"
        echo ""
        echo "Name: mail._domainkey"
        echo "Type: TXT"
        echo "Content: $DKIM_RECORD_VALUE"
        echo ""
        echo "========================="
    fi
else
    if [ -f "/etc/opendkim/keys/$DOMAIN_NAME/mail.txt" ]; then
        print_warning "⚠ DKIM key extraction failed"
        echo ""
        echo "MANUAL ADDITION REQUIRED:"
        echo "========================="
        echo "1. Get the key from your server:"
        echo "   cat /etc/opendkim/keys/$DOMAIN_NAME/mail.txt"
        echo ""
        echo "2. Extract the p= value (everything between quotes on the p= line)"
        echo ""
        echo "3. Add TXT record in Cloudflare:"
        echo "   Name: mail._domainkey"
        echo "   Type: TXT"
        echo "   Content: v=DKIM1; k=rsa; p=[YOUR_KEY_HERE]"
        echo "========================="
    fi
fi

# 9. Additional email authentication records
echo ""
echo "Adding additional authentication records..."

# SPF for subdomains
add_dns_record "TXT" "$HOSTNAME" "v=spf1 a -all" "" "false"

# Return Path
add_dns_record "CNAME" "bounces.$DOMAIN_NAME" "$HOSTNAME" "" "false"

# Autodiscover for email clients
add_dns_record "CNAME" "autodiscover.$DOMAIN_NAME" "$HOSTNAME" "" "false"

# Mail server identification
add_dns_record "TXT" "_smtp._tcp.$DOMAIN_NAME" "v=spf1 a -all" "" "false"

# 10. PTR record suggestion
echo ""
print_header "PTR Record (Reverse DNS)"
echo "IMPORTANT: PTR record cannot be set in Cloudflare."
echo "Contact your server provider to set PTR record:"
echo "  IP: $PRIMARY_IP"
echo "  Should resolve to: $HOSTNAME"

if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
    echo ""
    echo "Additional IPs needing PTR records:"
    for i in "${!IP_ADDRESSES[@]}"; do
        if [ $i -ne 0 ]; then
            ip="${IP_ADDRESSES[$i]}"
            echo "  IP: $ip -> ${MAIL_PREFIX}${i}.$DOMAIN_NAME"
        fi
    done
fi

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

# Function to test DNS with timeout
test_dns() {
    local query_type=$1
    local domain=$2
    local nameserver=${3:-1.1.1.1}
    
    timeout 5 dig +short $query_type $domain @$nameserver 2>/dev/null
}

# Test A record for mail server
echo -n "A record for $HOSTNAME: "
A_RECORD=$(test_dns A $HOSTNAME | head -1)
if [ "$A_RECORD" == "$PRIMARY_IP" ]; then
    print_message "✓ $A_RECORD"
else
    print_warning "⚠ Not propagated yet (expected: $PRIMARY_IP)"
fi

# Test A record for domain
echo -n "A record for $DOMAIN_NAME: "
A_RECORD=$(test_dns A $DOMAIN_NAME | head -1)
if [ "$A_RECORD" == "$PRIMARY_IP" ]; then
    print_message "✓ $A_RECORD"
else
    print_warning "⚠ Not propagated yet (expected: $PRIMARY_IP)"
fi

# Test MX record
echo -n "MX record for $DOMAIN_NAME: "
MX_RECORD=$(test_dns MX $DOMAIN_NAME | awk '{print $2}' | sed 's/\.$//' | head -1)
if [ "$MX_RECORD" == "$HOSTNAME" ]; then
    print_message "✓ $MX_RECORD"
else
    print_warning "⚠ Not propagated yet (expected: $HOSTNAME)"
fi

# Test SPF record
echo -n "SPF record: "
SPF=$(test_dns TXT $DOMAIN_NAME | grep "v=spf1")
if [ ! -z "$SPF" ]; then
    print_message "✓ Found"
else
    print_warning "⚠ Not propagated yet"
fi

# Test DKIM record
if [ ! -z "$DKIM_KEY" ]; then
    echo -n "DKIM record: "
    DKIM=$(test_dns TXT mail._domainkey.$DOMAIN_NAME | grep "v=DKIM1")
    if [ ! -z "$DKIM" ]; then
        print_message "✓ Found in DNS"
        # Verify it contains our key
        if [[ "$DKIM" == *"$DKIM_KEY"* ]]; then
            print_message "  ✓ Key matches local key"
        else
            print_warning "  ⚠ Key in DNS doesn't match local key"
        fi
    else
        print_warning "⚠ Not in DNS yet (may take 5-30 minutes)"
    fi
fi

# Test DMARC record
echo -n "DMARC record: "
DMARC=$(test_dns TXT _dmarc.$DOMAIN_NAME | grep "v=DMARC1")
if [ ! -z "$DMARC" ]; then
    print_message "✓ Found"
else
    print_warning "⚠ Not propagated yet"
fi

# ===================================================================
# CREATE DNS VERIFICATION SCRIPT
# ===================================================================

cat > /usr/local/bin/verify-dns << 'EOF'
#!/bin/bash

# DNS Verification Script
DOMAIN="DOMAIN_PLACEHOLDER"
HOSTNAME="HOSTNAME_PLACEHOLDER"
PRIMARY_IP="IP_PLACEHOLDER"
MAIL_PREFIX="PREFIX_PLACEHOLDER"

GREEN='\033[38;5;208m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "DNS Propagation Check for $DOMAIN"
echo "=================================="
echo ""

# Test multiple DNS servers
DNS_SERVERS="1.1.1.1 8.8.8.8 9.9.9.9"

for server in $DNS_SERVERS; do
    echo "Testing with DNS server $server:"
    
    # A record
    echo -n "  A record for $HOSTNAME: "
    result=$(dig +short A $HOSTNAME @$server 2>/dev/null | head -1)
    if [ "$result" == "$PRIMARY_IP" ]; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${YELLOW}✗ ($result)${NC}"
    fi
    
    # MX record
    echo -n "  MX record: "
    result=$(dig +short MX $DOMAIN @$server 2>/dev/null | awk '{print $2}' | sed 's/\.$//' | head -1)
    if [ "$result" == "$HOSTNAME" ]; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${YELLOW}✗ ($result)${NC}"
    fi
    
    # DKIM
    echo -n "  DKIM record: "
    result=$(dig +short TXT mail._domainkey.$DOMAIN @$server 2>/dev/null)
    if echo "$result" | grep -q "v=DKIM1"; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${YELLOW}✗${NC}"
    fi
    
    echo ""
done

echo "Note: DNS propagation can take 5-30 minutes globally"

# Test with OpenDKIM
echo ""
echo "OpenDKIM Verification:"
opendkim-testkey -d $DOMAIN -s mail -vvv 2>&1 | tail -3
EOF

# Replace placeholders
sed -i "s/DOMAIN_PLACEHOLDER/$DOMAIN_NAME/g" /usr/local/bin/verify-dns
sed -i "s/HOSTNAME_PLACEHOLDER/$HOSTNAME/g" /usr/local/bin/verify-dns
sed -i "s/IP_PLACEHOLDER/$PRIMARY_IP/g" /usr/local/bin/verify-dns
sed -i "s/PREFIX_PLACEHOLDER/$MAIL_PREFIX/g" /usr/local/bin/verify-dns
chmod +x /usr/local/bin/verify-dns

# ===================================================================
# SAVE DNS RECORDS FILE
# ===================================================================

# Save complete DNS records to file
cat > /root/dns-records-$DOMAIN_NAME.txt <<EOF
DNS RECORDS CONFIGURED IN CLOUDFLARE
=====================================
Generated: $(date)

Domain: $DOMAIN_NAME
Mail Server: $HOSTNAME
Mail Subdomain: $MAIL_PREFIX
Primary IP: $PRIMARY_IP

RECORDS ADDED:
--------------

1. A Records:
   - $HOSTNAME → $PRIMARY_IP
   - $DOMAIN_NAME → $PRIMARY_IP
   - www.$DOMAIN_NAME → $PRIMARY_IP
$(if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
    echo "   - Additional IPs configured with ${MAIL_PREFIX}N.$DOMAIN_NAME pattern:"
    for i in "${!IP_ADDRESSES[@]}"; do
        if [ $i -ne 0 ]; then
            echo "     ${MAIL_PREFIX}${i}.$DOMAIN_NAME → ${IP_ADDRESSES[$i]}"
        fi
    done
fi)

2. MX Record:
   - $DOMAIN_NAME → $HOSTNAME (Priority: 10)

3. SPF Record:
   - $DOMAIN_NAME TXT: "$SPF_RECORD"

4. DMARC Record:
   - _dmarc.$DOMAIN_NAME TXT: "$DMARC_RECORD"

5. DKIM Record:
   - mail._domainkey.$DOMAIN_NAME TXT:
$(if [ ! -z "$DKIM_RECORD_VALUE" ]; then
    echo "     $DKIM_RECORD_VALUE"
    echo "   - Key length: ${#DKIM_KEY} characters"
else
    echo "     [MANUAL ADDITION REQUIRED - Key extraction failed]"
fi)

6. Additional Records:
   - SPF for mail: $HOSTNAME TXT: v=spf1 a -all
   - Return Path CNAME: bounces.$DOMAIN_NAME → $HOSTNAME
   - Autodiscover CNAME: autodiscover.$DOMAIN_NAME → $HOSTNAME

PTR RECORDS (MUST BE SET WITH YOUR HOSTING PROVIDER):
   - $PRIMARY_IP → $HOSTNAME
$(if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
    for i in "${!IP_ADDRESSES[@]}"; do
        if [ $i -ne 0 ]; then
            echo "   - ${IP_ADDRESSES[$i]} → ${MAIL_PREFIX}${i}.$DOMAIN_NAME"
        fi
    done
fi)

VERIFICATION COMMANDS:
   verify-dns                              - Check DNS propagation
   check-dns                               - Detailed DNS check
   opendkim-testkey -d $DOMAIN_NAME -s mail -vvv  - Test DKIM key

$(if [ -z "$DKIM_KEY" ] && [ -f "/etc/opendkim/keys/$DOMAIN_NAME/mail.txt" ]; then
    echo ""
    echo "MANUAL DKIM ADDITION REQUIRED:"
    echo "==============================="
    echo "The DKIM key could not be automatically extracted."
    echo "Please add it manually to Cloudflare:"
    echo ""
    echo "1. Get the key from: cat /etc/opendkim/keys/$DOMAIN_NAME/mail.txt"
    echo "2. Extract the p= value (everything between quotes)"
    echo "3. Add TXT record:"
    echo "   Name: mail._domainkey"
    echo "   Type: TXT"
    echo "   Content: v=DKIM1; k=rsa; p=[YOUR_KEY_HERE]"
fi)
EOF

# ===================================================================
# COMPLETION
# ===================================================================

echo ""
print_header "DNS Configuration Complete!"

echo ""
echo "✅ DNS records have been added to Cloudflare"
echo "✅ Using mail subdomain: $MAIL_PREFIX (creates $HOSTNAME)"
if [ ! -z "$DKIM_KEY" ]; then
    echo "✅ DKIM record processed (${#DKIM_KEY} characters)"
else
    echo "⚠️  DKIM record needs manual addition"
fi
if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
    echo "✅ Multiple IP addresses configured with ${MAIL_PREFIX}N pattern"
    echo "   Example: ${MAIL_PREFIX}1.$DOMAIN_NAME, ${MAIL_PREFIX}2.$DOMAIN_NAME, etc."
fi
echo ""
echo "⏱ DNS propagation typically takes:"
echo "   - Cloudflare network: Immediate"
echo "   - Global propagation: 5-30 minutes"
echo "   - Full propagation: Up to 48 hours (rare)"
echo ""
echo "📝 Configuration saved to: /root/dns-records-$DOMAIN_NAME.txt"
echo ""
echo "Test commands:"
echo "   verify-dns                     - Check propagation"
echo "   check-dns $DOMAIN_NAME         - Detailed DNS check"
echo ""

if [ ! -z "$DKIM_KEY" ]; then
    echo "DKIM Verification:"
    echo "   opendkim-testkey -d $DOMAIN_NAME -s mail -vvv"
    echo ""
    echo "After 5 minutes, test your email score at:"
    echo "   https://www.mail-tester.com"
else
    echo "⚠️  IMPORTANT: Add DKIM record manually in Cloudflare"
    echo "   See /root/dns-records-$DOMAIN_NAME.txt for details"
fi

echo ""
print_message "✓ Cloudflare DNS setup completed with $MAIL_PREFIX subdomain!"
