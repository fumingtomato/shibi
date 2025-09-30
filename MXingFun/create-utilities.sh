#!/bin/bash

# =================================================================
# CREATE MAIL SERVER MANAGEMENT UTILITIES
# Version: 17.1.0 - Enhanced with bulk IP management
# Creates all management commands for the mail server
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

print_header "Creating Management Utilities"

# ===================================================================
# 1. MAIL STATUS COMMAND
# ===================================================================

cat > /usr/local/bin/mail-status <<'EOF'
#!/bin/bash

GREEN='\033[38;5;208m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "Mail Server Status"
echo "=================="
echo ""

# Service status
echo "Services:"
for service in postfix dovecot opendkim mysql nginx; do
    echo -n "  $service: "
    if systemctl is-active --quiet $service; then
        echo -e "${GREEN}✓ Running${NC}"
    else
        echo -e "${RED}✗ Stopped${NC}"
    fi
done

echo ""
echo "Ports:"
for port in 25 587 465 993 995 143 110 80 443 8891; do
    echo -n "  Port $port: "
    if netstat -tuln 2>/dev/null | grep -q ":$port "; then
        echo -e "${GREEN}✓ Open${NC}"
    else
        echo -e "${YELLOW}✗ Closed${NC}"
    fi
done

echo ""
echo "Mail Queue:"
mailq_count=$(mailq 2>/dev/null | grep -c "^[A-F0-9]" || echo "0")
echo "  Messages in queue: $mailq_count"

echo ""
echo "Disk Usage:"
df -h / | awk 'NR==2 {print "  Used: "$3" of "$2" ("$5")"}'

echo ""
echo "Memory Usage:"
free -h | awk 'NR==2 {print "  Used: "$3" of "$2}'

echo ""
echo "DKIM Status:"
if [ -f "/etc/opendkim/keys/*/mail.txt" ]; then
    echo -e "  ${GREEN}✓ DKIM key exists${NC}"
    if netstat -lnp 2>/dev/null | grep -q ":8891"; then
        echo -e "  ${GREEN}✓ OpenDKIM listening on 8891${NC}"
    else
        echo -e "  ${RED}✗ OpenDKIM not listening${NC}"
    fi
else
    echo -e "  ${RED}✗ DKIM key not found${NC}"
fi
EOF

chmod +x /usr/local/bin/mail-status

# ===================================================================
# 2. MAIL ACCOUNT MANAGEMENT
# ===================================================================

cat > /usr/local/bin/mail-account <<'EOF'
#!/bin/bash

# Load database password
if [ -f /root/.mail_db_password ]; then
    DB_PASS=$(cat /root/.mail_db_password)
elif [ -f /etc/mail-config/db_password ]; then
    DB_PASS=$(cat /etc/mail-config/db_password)
else
    echo "Error: Database password file not found"
    exit 1
fi

# MySQL command
MYSQL_CMD="mysql -u mailuser -p$DB_PASS mailserver"

case "$1" in
    add)
        if [ -z "$2" ] || [ -z "$3" ]; then
            echo "Usage: mail-account add email@domain.com password"
            exit 1
        fi
        
        EMAIL="$2"
        PASS="$3"
        DOMAIN="${EMAIL#*@}"
        
        # Hash password
        if command -v doveadm &> /dev/null; then
            PASS_HASH=$(doveadm pw -s SHA512-CRYPT -p "$PASS")
        else
            PASS_HASH="{PLAIN}$PASS"
        fi
        
        # Add domain if not exists
        $MYSQL_CMD -e "INSERT IGNORE INTO virtual_domains (name) VALUES ('$DOMAIN')" 2>/dev/null
        
        # Add user
        $MYSQL_CMD -e "INSERT INTO virtual_users (domain_id, email, password, active) 
                      SELECT id, '$EMAIL', '$PASS_HASH', 1 
                      FROM virtual_domains WHERE name = '$DOMAIN'" 2>/dev/null
        
        if [ $? -eq 0 ]; then
            echo "✓ Account created: $EMAIL"
            
            # Create maildir
            MAIL_USER="${EMAIL%@*}"
            MAIL_DIR="/var/vmail/$DOMAIN/$MAIL_USER"
            mkdir -p "$MAIL_DIR"
            chown -R vmail:vmail /var/vmail
        else
            echo "✗ Failed to create account (may already exist)"
        fi
        ;;
        
    delete)
        if [ -z "$2" ]; then
            echo "Usage: mail-account delete email@domain.com"
            exit 1
        fi
        
        EMAIL="$2"
        $MYSQL_CMD -e "DELETE FROM virtual_users WHERE email = '$EMAIL'" 2>/dev/null
        
        if [ $? -eq 0 ]; then
            echo "✓ Account deleted: $EMAIL"
        else
            echo "✗ Failed to delete account"
        fi
        ;;
        
    list)
        echo "Email Accounts:"
        $MYSQL_CMD -e "SELECT email, active, created_at FROM virtual_users ORDER BY email" 2>/dev/null
        ;;
        
    password)
        if [ -z "$2" ] || [ -z "$3" ]; then
            echo "Usage: mail-account password email@domain.com newpassword"
            exit 1
        fi
        
        EMAIL="$2"
        PASS="$3"
        
        if command -v doveadm &> /dev/null; then
            PASS_HASH=$(doveadm pw -s SHA512-CRYPT -p "$PASS")
        else
            PASS_HASH="{PLAIN}$PASS"
        fi
        
        $MYSQL_CMD -e "UPDATE virtual_users SET password = '$PASS_HASH' WHERE email = '$EMAIL'" 2>/dev/null
        
        if [ $? -eq 0 ]; then
            echo "✓ Password updated for: $EMAIL"
        else
            echo "✗ Failed to update password"
        fi
        ;;
        
    *)
        echo "Mail Account Manager"
        echo "Usage: mail-account {add|delete|list|password}"
        echo ""
        echo "Commands:"
        echo "  add email@domain.com password  - Create new account"
        echo "  delete email@domain.com        - Delete account"
        echo "  list                           - List all accounts"
        echo "  password email@domain.com pass - Change password"
        ;;
esac
EOF

chmod +x /usr/local/bin/mail-account

# ===================================================================
# 3. BULK IP MANAGEMENT COMMAND (FIX 3)
# ===================================================================

cat > /usr/local/bin/bulk-ip-manage <<'EOF'
#!/bin/bash

# Bulk IP Management Tool for Mail Server
GREEN='\033[38;5;208m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Load database password
if [ -f /root/.mail_db_password ]; then
    DB_PASS=$(cat /root/.mail_db_password)
elif [ -f /etc/mail-config/db_password ]; then
    DB_PASS=$(cat /etc/mail-config/db_password)
else
    echo -e "${RED}Error: Database password not found${NC}"
    exit 1
fi

MYSQL_CMD="mysql -u mailuser -p$DB_PASS mailserver"

case "$1" in
    assign)
        if [ -z "$2" ] || [ -z "$3" ]; then
            echo "Usage: bulk-ip-manage assign <email> <mode>"
            echo "Modes: sticky, round-robin, least-used"
            exit 1
        fi
        
        EMAIL="$2"
        MODE="$3"
        
        # Validate mode
        if [[ ! "$MODE" =~ ^(sticky|round-robin|least-used)$ ]]; then
            echo -e "${RED}Invalid mode. Use: sticky, round-robin, or least-used${NC}"
            exit 1
        fi
        
        # Call stored procedure or assign IP
        $MYSQL_CMD -e "CALL assign_ip_to_sender('$EMAIL', '$MODE')" 2>/dev/null
        
        if [ $? -eq 0 ]; then
            # Get assigned IP
            RESULT=$($MYSQL_CMD -N -e "SELECT assigned_ip, transport_id FROM ip_rotation_advanced WHERE sender_email='$EMAIL'" 2>/dev/null)
            IP=$(echo "$RESULT" | awk '{print $1}')
            TRANSPORT=$(echo "$RESULT" | awk '{print $2}')
            echo -e "${GREEN}✓ Assigned $EMAIL to IP $IP (transport smtp-ip$TRANSPORT) using $MODE mode${NC}"
            
            # Update Postfix sender transport map
            echo "$EMAIL smtp-ip$TRANSPORT:" >> /etc/postfix/sender_transports
            postmap /etc/postfix/sender_transports
            postfix reload 2>/dev/null
        else
            echo -e "${RED}✗ Failed to assign IP${NC}"
        fi
        ;;
        
    list)
        echo "Current IP Assignments:"
        echo ""
        $MYSQL_CMD -e "
        SELECT 
            sender_email as 'Email Address', 
            assigned_ip as 'Assigned IP', 
            rotation_mode as 'Mode',
            message_count as 'Total Messages',
            messages_today as 'Today',
            DATE_FORMAT(last_used, '%Y-%m-%d %H:%i') as 'Last Used'
        FROM ip_rotation_advanced
        ORDER BY last_used DESC;" 2>/dev/null
        ;;
        
    stats)
        echo "IP Pool Statistics:"
        echo ""
        $MYSQL_CMD -e "
        SELECT 
            ip_address as 'IP Address',
            hostname as 'Hostname',
            CASE is_active WHEN 1 THEN 'Active' ELSE 'Inactive' END as 'Status',
            reputation_score as 'Score',
            messages_sent_today as 'Today',
            messages_sent_total as 'Total',
            DATE_FORMAT(last_used, '%Y-%m-%d %H:%i') as 'Last Used'
        FROM ip_pool
        ORDER BY ip_index;" 2>/dev/null
        ;;
        
    reset)
        if [ -z "$2" ]; then
            echo "Usage: bulk-ip-manage reset <email|all>"
            exit 1
        fi
        
        if [ "$2" == "all" ]; then
            # Reset all assignments
            $MYSQL_CMD -e "
            UPDATE ip_rotation_advanced SET assigned_ip = NULL, transport_id = NULL;
            UPDATE ip_pool SET messages_sent_today = 0, last_reset = CURDATE();" 2>/dev/null
            
            # Clear Postfix sender transports
            echo "# Sender transport mappings - managed by bulk-ip-manage" > /etc/postfix/sender_transports
            postmap /etc/postfix/sender_transports
            postfix reload 2>/dev/null
            
            echo -e "${GREEN}✓ Reset all IP assignments${NC}"
        else
            EMAIL="$2"
            $MYSQL_CMD -e "
            UPDATE ip_rotation_advanced 
            SET assigned_ip = NULL, transport_id = NULL 
            WHERE sender_email = '$EMAIL';" 2>/dev/null
            
            # Remove from Postfix sender transports
            grep -v "^$EMAIL " /etc/postfix/sender_transports > /tmp/sender_transports.tmp
            mv /tmp/sender_transports.tmp /etc/postfix/sender_transports
            postmap /etc/postfix/sender_transports
            postfix reload 2>/dev/null
            
            echo -e "${GREEN}✓ Reset IP assignment for $EMAIL${NC}"
        fi
        ;;
        
    activate|deactivate)
        if [ -z "$2" ]; then
            echo "Usage: bulk-ip-manage $1 <ip>"
            exit 1
        fi
        
        IP="$2"
        ACTIVE=$([ "$1" == "activate" ] && echo "1" || echo "0")
        
        $MYSQL_CMD -e "UPDATE ip_pool SET is_active = $ACTIVE WHERE ip_address = '$IP';" 2>/dev/null
        
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✓ IP $IP ${1}d${NC}"
        else
            echo -e "${RED}✗ Failed to $1 IP${NC}"
        fi
        ;;
        
    reputation)
        if [ -z "$2" ] || [ -z "$3" ]; then
            echo "Usage: bulk-ip-manage reputation <ip> <score>"
            echo "Score range: 0-100 (100 = best)"
            exit 1
        fi
        
        IP="$2"
        SCORE="$3"
        
        if ! [[ "$SCORE" =~ ^[0-9]+$ ]] || [ "$SCORE" -lt 0 ] || [ "$SCORE" -gt 100 ]; then
            echo -e "${RED}Invalid score. Use 0-100${NC}"
            exit 1
        fi
        
        $MYSQL_CMD -e "UPDATE ip_pool SET reputation_score = $SCORE WHERE ip_address = '$IP';" 2>/dev/null
        
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✓ Set reputation score for $IP to $SCORE${NC}"
        else
            echo -e "${RED}✗ Failed to update reputation${NC}"
        fi
        ;;
        
    report)
        echo "========================================="
        echo "Bulk Mail IP Rotation Report"
        echo "========================================="
        echo ""
        
        # Summary
        TOTAL_IPS=$($MYSQL_CMD -N -e "SELECT COUNT(*) FROM ip_pool" 2>/dev/null)
        ACTIVE_IPS=$($MYSQL_CMD -N -e "SELECT COUNT(*) FROM ip_pool WHERE is_active=1" 2>/dev/null)
        TOTAL_MSGS=$($MYSQL_CMD -N -e "SELECT IFNULL(SUM(messages_sent_total),0) FROM ip_pool" 2>/dev/null)
        TODAY_MSGS=$($MYSQL_CMD -N -e "SELECT IFNULL(SUM(messages_sent_today),0) FROM ip_pool" 2>/dev/null)
        
        echo "Summary:"
        echo "  Total IPs: $TOTAL_IPS (Active: $ACTIVE_IPS)"
        echo "  Messages sent today: $TODAY_MSGS"
        echo "  Messages sent total: $TOTAL_MSGS"
        echo ""
        
        # Top senders
        echo "Top 5 Senders Today:"
        $MYSQL_CMD -e "
        SELECT 
            sender_email as 'Email',
            messages_today as 'Messages',
            rotation_mode as 'Mode'
        FROM ip_rotation_advanced
        WHERE messages_today > 0
        ORDER BY messages_today DESC
        LIMIT 5;" 2>/dev/null
        echo ""
        
        # IP utilization
        echo "IP Utilization:"
        $MYSQL_CMD -e "
        SELECT 
            ip_address as 'IP',
            CONCAT(ROUND((messages_sent_today/max_daily_limit)*100,1),'%') as 'Usage',
            CONCAT(messages_sent_today,'/',max_daily_limit) as 'Messages'
        FROM ip_pool
        WHERE is_active=1
        ORDER BY (messages_sent_today/max_daily_limit) DESC;" 2>/dev/null
        ;;
        
    *)
        echo "Bulk IP Management Tool"
        echo "Usage: bulk-ip-manage {command} [options]"
        echo ""
        echo "Commands:"
        echo "  assign <email> <mode>    - Assign rotation mode to sender"
        echo "                             Modes: sticky, round-robin, least-used"
        echo "  list                     - List all sender IP assignments"
        echo "  stats                    - Show IP pool statistics"
        echo "  reset <email|all>        - Reset IP assignments"
        echo "  activate <ip>            - Activate an IP address"
        echo "  deactivate <ip>          - Deactivate an IP address"
        echo "  reputation <ip> <score>  - Set IP reputation (0-100)"
        echo "  report                   - Generate usage report"
        echo ""
        echo "Examples:"
        echo "  bulk-ip-manage assign sender@domain.com round-robin"
        echo "  bulk-ip-manage stats"
        echo "  bulk-ip-manage deactivate 192.168.1.5"
        ;;
esac
EOF

chmod +x /usr/local/bin/bulk-ip-manage

# ===================================================================
# 4. TEST EMAIL COMMAND (WITH DKIM VERIFICATION)
# ===================================================================

cat > /usr/local/bin/test-email <<'EOF'
#!/bin/bash

if [ -z "$1" ]; then
    echo "Usage: test-email recipient@example.com [from@domain.com]"
    echo ""
    echo "Special test addresses:"
    echo "  check-auth@verifier.port25.com - Full authentication test"
    echo "  test@mail-tester.com           - Get link for spam score"
    exit 1
fi

TO="$1"
FROM="${2:-postmaster@DOMAIN_PLACEHOLDER}"
SUBJECT="Test Email from HOSTNAME_PLACEHOLDER - $(date)"

# Create test email with headers that trigger DKIM signing
cat <<EMAIL | sendmail -f "$FROM" "$TO"
From: $FROM
To: $TO
Subject: $SUBJECT
Date: $(date -R)
Message-ID: <$(date +%s).$(openssl rand -hex 8)@HOSTNAME_PLACEHOLDER>
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit

This is a test email from your mail server.

Server Information:
- Hostname: HOSTNAME_PLACEHOLDER
- Domain: DOMAIN_PLACEHOLDER
- Mail Subdomain: SUBDOMAIN_PLACEHOLDER
- Timestamp: $(date)
- DKIM: Enabled (1024-bit key)
- SPF: Configured
- DMARC: Configured

This email should be signed with DKIM.
Check the headers for DKIM-Signature field.

Authentication Test Services:
- Port25: check-auth@verifier.port25.com
- Mail-Tester: https://www.mail-tester.com
- MXToolbox: https://mxtoolbox.com

---
Sent from HOSTNAME_PLACEHOLDER Mail Server
EMAIL

echo "✓ Test email sent to: $TO"
echo "  From: $FROM"
echo ""
echo "Check the recipient's inbox (and spam folder)"
echo ""

if [[ "$TO" == *"verifier.port25.com"* ]]; then
    echo "Port25 will reply with authentication results including:"
    echo "  - SPF check"
    echo "  - DKIM signature verification"
    echo "  - DMARC policy check"
elif [[ "$TO" == *"mail-tester.com"* ]]; then
    echo "Check https://www.mail-tester.com for your spam score"
fi

# Check if DKIM is working
echo ""
echo "Quick DKIM check:"
if netstat -lnp 2>/dev/null | grep -q ":8891"; then
    echo "  ✓ OpenDKIM is running"
else
    echo "  ✗ OpenDKIM not running - emails won't be signed!"
fi
EOF

# Replace placeholders
sed -i "s/DOMAIN_PLACEHOLDER/$DOMAIN_NAME/g" /usr/local/bin/test-email
sed -i "s/HOSTNAME_PLACEHOLDER/$HOSTNAME/g" /usr/local/bin/test-email
sed -i "s/SUBDOMAIN_PLACEHOLDER/${MAIL_SUBDOMAIN:-mail}/g" /usr/local/bin/test-email
chmod +x /usr/local/bin/test-email

# ===================================================================
# 5. CHECK DNS COMMAND (ENHANCED)
# ===================================================================

cat > /usr/local/bin/check-dns <<'EOF'
#!/bin/bash

DOMAIN="${1:-DOMAIN_PLACEHOLDER}"
HOSTNAME="HOSTNAME_PLACEHOLDER"
PRIMARY_IP="PRIMARY_IP_PLACEHOLDER"
MAIL_PREFIX="PREFIX_PLACEHOLDER"

GREEN='\033[38;5;208m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "DNS Records Check for $DOMAIN"
echo "=============================="
echo "Mail Subdomain: $MAIL_PREFIX"
echo ""

# Function to check DNS
check_record() {
    local type=$1
    local record=$2
    local expected=$3
    local result
    
    echo -n "$type record for $record: "
    
    if [ "$type" = "MX" ]; then
        result=$(dig +short MX "$record" @8.8.8.8 2>/dev/null | awk '{print $2}' | sed 's/\.$//' | head -1)
    elif [ "$type" = "TXT" ]; then
        result=$(dig +short TXT "$record" @8.8.8.8 2>/dev/null)
    else
        result=$(dig +short "$type" "$record" @8.8.8.8 2>/dev/null | head -1)
    fi
    
    if [ ! -z "$result" ]; then
        if [ ! -z "$expected" ] && [ "$result" = "$expected" ]; then
            echo -e "${GREEN}✓ $result${NC}"
        elif [ ! -z "$result" ]; then
            echo -e "${GREEN}✓ Found${NC}"
            echo "  Value: $result"
        fi
    else
        echo -e "${RED}✗ Not found${NC}"
        if [ ! -z "$expected" ]; then
            echo "  Expected: $expected"
        fi
    fi
}

# Check A records
check_record "A" "$HOSTNAME" "$PRIMARY_IP"
check_record "A" "$DOMAIN" "$PRIMARY_IP"
check_record "A" "www.$DOMAIN" "$PRIMARY_IP"

echo ""

# Check MX record
check_record "MX" "$DOMAIN" "$HOSTNAME"

echo ""

# Check TXT records
echo "TXT Records:"
echo -n "  SPF: "
SPF=$(dig +short TXT "$DOMAIN" @8.8.8.8 2>/dev/null | grep "v=spf1")
if [ ! -z "$SPF" ]; then
    echo -e "${GREEN}✓ Found${NC}"
    echo "    $SPF"
else
    echo -e "${RED}✗ Not found${NC}"
fi

echo -n "  DMARC: "
DMARC=$(dig +short TXT "_dmarc.$DOMAIN" @8.8.8.8 2>/dev/null | grep "v=DMARC1")
if [ ! -z "$DMARC" ]; then
    echo -e "${GREEN}✓ Found${NC}"
    echo "    $DMARC"
else
    echo -e "${RED}✗ Not found${NC}"
fi

echo -n "  DKIM: "
DKIM=$(dig +short TXT "mail._domainkey.$DOMAIN" @8.8.8.8 2>/dev/null | grep "v=DKIM1")
if [ ! -z "$DKIM" ]; then
    echo -e "${GREEN}✓ Found${NC}"
    # Extract key length
    DKIM_KEY=$(echo "$DKIM" | sed 's/.*p=//' | sed 's/".*//' | tr -d ' ')
    echo "    Key length: ${#DKIM_KEY} characters"
    
    # Verify with OpenDKIM
    echo ""
    echo "  OpenDKIM verification:"
    opendkim-testkey -d "$DOMAIN" -s mail -vvv 2>&1 | grep -E "key (OK|not secure|not found)" | sed 's/^/    /'
else
    echo -e "${RED}✗ Not found${NC}"
    echo "    Add TXT record: mail._domainkey"
    
    # Try to get local key
    if [ -f "/etc/opendkim/keys/$DOMAIN/mail.txt" ]; then
        LOCAL_KEY=$(cat /etc/opendkim/keys/$DOMAIN/mail.txt | tr -d '\n\r\t' | sed 's/.*"p=//' | sed 's/".*//' | tr -d ' "')
        if [ ! -z "$LOCAL_KEY" ]; then
            echo "    Value: v=DKIM1; k=rsa; p=$LOCAL_KEY"
        fi
    fi
fi

echo ""
echo "Reverse DNS (PTR):"
PTR=$(dig +short -x "$PRIMARY_IP" @8.8.8.8 2>/dev/null | sed 's/\.$//')
echo -n "  $PRIMARY_IP: "
if [ "$PTR" = "$HOSTNAME" ]; then
    echo -e "${GREEN}✓ $PTR${NC}"
else
    echo -e "${YELLOW}$PTR${NC}"
    echo "  Should be: $HOSTNAME"
fi
EOF

# Replace placeholders
sed -i "s/DOMAIN_PLACEHOLDER/$DOMAIN_NAME/g" /usr/local/bin/check-dns
sed -i "s/HOSTNAME_PLACEHOLDER/$HOSTNAME/g" /usr/local/bin/check-dns
sed -i "s/PRIMARY_IP_PLACEHOLDER/$PRIMARY_IP/g" /usr/local/bin/check-dns
sed -i "s/PREFIX_PLACEHOLDER/${MAIL_SUBDOMAIN:-mail}/g" /usr/local/bin/check-dns
chmod +x /usr/local/bin/check-dns

# ===================================================================
# 6. IP ROTATION STATUS (if configured)
# ===================================================================

if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
    cat > /usr/local/bin/ip-rotation-status <<'EOF'
#!/bin/bash

echo "IP Rotation Status"
echo "=================="
echo ""

# Load database password
if [ -f /root/.mail_db_password ]; then
    DB_PASS=$(cat /root/.mail_db_password)
elif [ -f /etc/mail-config/db_password ]; then
    DB_PASS=$(cat /etc/mail-config/db_password)
else
    echo "Error: Database password file not found"
    exit 1
fi

# Load configuration
if [ -f /root/mail-installer/install.conf ]; then
    source /root/mail-installer/install.conf
elif [ -f /etc/mail-config/install.conf ]; then
    source /etc/mail-config/install.conf
fi

# Show configured IPs
echo "Configured IPs:"
i=0
for ip in "${IP_ADDRESSES[@]}"; do
    if [ $i -eq 0 ]; then
        hostname="$HOSTNAME"
    else
        hostname="${MAIL_SUBDOMAIN}${i}.$DOMAIN_NAME"
    fi
    echo "  smtp-ip$i: $ip ($hostname)"
    ((i++))
done

echo ""
echo "Current Assignments:"

# Show database assignments
mysql -u mailuser -p"$DB_PASS" mailserver -e "
SELECT 
    sender_email as 'Sender',
    assigned_ip as 'IP Address',
    CONCAT('smtp-ip', transport_id) as 'Transport',
    message_count as 'Messages',
    rotation_mode as 'Mode',
    last_used as 'Last Used'
FROM ip_rotation_advanced 
ORDER BY last_used DESC 
LIMIT 20;" 2>/dev/null || echo "No data available"

echo ""
echo "IP Usage Statistics:"
mysql -u mailuser -p"$DB_PASS" mailserver -e "
SELECT 
    ip_address as 'IP Address',
    hostname as 'Hostname',
    messages_sent_today as 'Today',
    messages_sent_total as 'Total',
    reputation_score as 'Reputation'
FROM ip_pool 
WHERE is_active = 1
ORDER BY ip_index;" 2>/dev/null || echo "No statistics available"

echo ""
echo "Management Commands:"
echo "  bulk-ip-manage assign <email> <mode>  - Assign IP rotation mode"
echo "  bulk-ip-manage stats                  - Show detailed statistics"
echo "  bulk-ip-manage report                 - Generate usage report"
EOF

    chmod +x /usr/local/bin/ip-rotation-status
fi

# ===================================================================
# 7. MAILWIZZ INFO
# ===================================================================

cat > /usr/local/bin/mailwizz-info <<'EOF'
#!/bin/bash

echo "MailWizz Configuration Information"
echo "==================================="
echo ""
echo "SMTP Settings for MailWizz:"
echo "  Hostname: HOSTNAME_PLACEHOLDER"
echo "  Port: 587 (STARTTLS) or 465 (SSL)"
echo "  Encryption: TLS or SSL"
echo "  Authentication: Required"
echo ""
echo "Bounce Server (IMAP):"
echo "  Hostname: HOSTNAME_PLACEHOLDER"
echo "  Port: 993"
echo "  Encryption: SSL"
echo "  Protocol: IMAP"
echo ""
echo "FBL Server:"
echo "  Same as Bounce Server"
echo ""
echo "Email Account:"
echo "  Use any account created with: mail-account add"
echo ""
echo "Delivery Server Type:"
echo "  Choose: SMTP"
echo ""

if [ -f /root/.mail_db_password ] || [ -f /etc/mail-config/db_password ]; then
    DB_PASS=$(cat /root/.mail_db_password 2>/dev/null || cat /etc/mail-config/db_password 2>/dev/null)
    echo "Available sending accounts:"
    mysql -u mailuser -p"$DB_PASS" mailserver -e "SELECT email FROM virtual_users WHERE active=1" 2>/dev/null | tail -n +2 | sed 's/^/  /'
fi

echo ""
echo "To create a new sending account:"
echo "  mail-account add sender@DOMAIN_PLACEHOLDER password"
echo ""
echo "Website URL:"
echo "  https://DOMAIN_PLACEHOLDER"
echo ""

# Load configuration for IP rotation info
if [ -f /root/mail-installer/install.conf ]; then
    source /root/mail-installer/install.conf
elif [ -f /etc/mail-config/install.conf ]; then
    source /etc/mail-config/install.conf
fi

if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
    echo "IP Rotation Configuration:"
    echo "  Multiple IPs configured: ${#IP_ADDRESSES[@]}"
    echo "  Use bulk-ip-manage to assign rotation modes"
    echo ""
fi

echo "Remember to update nginx config for MailWizz proxy!"
EOF

sed -i "s/HOSTNAME_PLACEHOLDER/$HOSTNAME/g" /usr/local/bin/mailwizz-info
sed -i "s/DOMAIN_PLACEHOLDER/$DOMAIN_NAME/g" /usr/local/bin/mailwizz-info
chmod +x /usr/local/bin/mailwizz-info

# ===================================================================
# COMPLETION
# ===================================================================

print_header "Management Utilities Created"

echo ""
echo "✓ Created utilities:"
echo "  • mail-status       - Check server status"
echo "  • mail-account      - Manage email accounts"
echo "  • bulk-ip-manage    - Manage IP rotation (NEW)"
echo "  • test-email        - Send test emails"
echo "  • check-dns         - Verify DNS configuration"
echo "  • mailwizz-info     - MailWizz configuration guide"

if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
    echo "  • ip-rotation-status - Monitor IP rotation"
fi

echo ""
echo "Quick start:"
echo "  1. Run: mail-status"
echo "  2. Send test: test-email check-auth@verifier.port25.com"
echo "  3. Check DNS: check-dns"
if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
    echo "  4. Manage IPs: bulk-ip-manage stats"
fi
echo ""

print_message "✓ All management utilities installed successfully!"
print_message "✓ Mail subdomain: ${MAIL_SUBDOMAIN:-mail}"
print_message "✓ Hostname: $HOSTNAME"
