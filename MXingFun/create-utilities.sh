#!/bin/bash

# =================================================================
# CREATE MAIL SERVER MANAGEMENT UTILITIES
# Version: 17.0.6 - Enhanced with better DKIM verification
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
# 3. TEST EMAIL COMMAND (WITH DKIM VERIFICATION)
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
chmod +x /usr/local/bin/test-email

# ===================================================================
# 4. CHECK DNS COMMAND (ENHANCED)
# ===================================================================

cat > /usr/local/bin/check-dns <<'EOF'
#!/bin/bash

DOMAIN="${1:-DOMAIN_PLACEHOLDER}"
HOSTNAME="HOSTNAME_PLACEHOLDER"
PRIMARY_IP="PRIMARY_IP_PLACEHOLDER"

GREEN='\033[38;5;208m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "DNS Records Check for $DOMAIN"
echo "=============================="
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
chmod +x /usr/local/bin/check-dns

# ===================================================================
# 5. MAIL TEST COMPREHENSIVE
# ===================================================================

cat > /usr/local/bin/mail-test <<'EOF'
#!/bin/bash

GREEN='\033[38;5;208m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}==================================================${NC}"
echo -e "${BLUE}Comprehensive Mail Server Test${NC}"
echo -e "${BLUE}==================================================${NC}"
echo ""

# 1. Service Status
echo "1. SERVICE STATUS"
echo "-----------------"
for service in postfix dovecot opendkim mysql nginx; do
    echo -n "  $service: "
    if systemctl is-active --quiet $service; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗${NC}"
    fi
done

# 2. Port Status
echo ""
echo "2. PORT STATUS"
echo "--------------"
PORTS=(25:SMTP 587:Submission 465:SMTPS 993:IMAPS 995:POP3S 143:IMAP 110:POP3 80:HTTP 443:HTTPS 8891:OpenDKIM)
for port_info in "${PORTS[@]}"; do
    IFS=':' read -r port name <<< "$port_info"
    echo -n "  $port ($name): "
    if netstat -tuln 2>/dev/null | grep -q ":$port "; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗${NC}"
    fi
done

# 3. DNS Records
echo ""
echo "3. DNS RECORDS"
echo "--------------"
DOMAIN="DOMAIN_PLACEHOLDER"

echo -n "  A record: "
if [ "$(dig +short A $DOMAIN @8.8.8.8 2>/dev/null | head -1)" != "" ]; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}✗${NC}"
fi

echo -n "  MX record: "
if [ "$(dig +short MX $DOMAIN @8.8.8.8 2>/dev/null | head -1)" != "" ]; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}✗${NC}"
fi

echo -n "  SPF record: "
if dig +short TXT $DOMAIN @8.8.8.8 2>/dev/null | grep -q "v=spf1"; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}✗${NC}"
fi

echo -n "  DKIM record: "
if dig +short TXT mail._domainkey.$DOMAIN @8.8.8.8 2>/dev/null | grep -q "v=DKIM1"; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}✗${NC}"
fi

echo -n "  DMARC record: "
if dig +short TXT _dmarc.$DOMAIN @8.8.8.8 2>/dev/null | grep -q "v=DMARC1"; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}✗${NC}"
fi

# 4. DKIM Status
echo ""
echo "4. DKIM STATUS"
echo "--------------"

echo -n "  Key file: "
if [ -f "/etc/opendkim/keys/$DOMAIN/mail.txt" ]; then
    echo -e "${GREEN}✓${NC}"
    KEY=$(grep -oP 'p=\K[^"]+' /etc/opendkim/keys/$DOMAIN/mail.txt | tr -d '\n\t\r ')
    echo "    Length: ${#KEY} characters"
else
    echo -e "${RED}✗${NC}"
fi

echo -n "  OpenDKIM service: "
if netstat -lnp 2>/dev/null | grep -q ":8891"; then
    echo -e "${GREEN}✓ Listening${NC}"
else
    echo -e "${RED}✗ Not listening${NC}"
fi

echo -n "  DKIM validation: "
result=$(opendkim-testkey -d $DOMAIN -s mail -vvv 2>&1 | grep "key OK")
if [ ! -z "$result" ]; then
    echo -e "${GREEN}✓ Valid${NC}"
else
    echo -e "${YELLOW}⚠ Check needed${NC}"
fi

# 5. SSL Certificate
echo ""
echo "5. SSL CERTIFICATE"
echo "------------------"

echo -n "  Certificate: "
if [ -d "/etc/letsencrypt/live/$DOMAIN" ]; then
    echo -e "${GREEN}✓ Let's Encrypt${NC}"
    expiry=$(openssl x509 -enddate -noout -in /etc/letsencrypt/live/$DOMAIN/fullchain.pem 2>/dev/null | cut -d= -f2)
    echo "    Expires: $expiry"
elif [ -f "/etc/ssl/certs/mailserver.crt" ]; then
    echo -e "${YELLOW}⚠ Self-signed${NC}"
else
    echo -e "${RED}✗ Not found${NC}"
fi

# 6. Mail Queue
echo ""
echo "6. MAIL QUEUE"
echo "-------------"
queue_count=$(mailq 2>/dev/null | grep -c "^[A-F0-9]" || echo "0")
echo "  Messages in queue: $queue_count"

# 7. Database
echo ""
echo "7. DATABASE"
echo "-----------"
if [ -f /root/.mail_db_password ]; then
    DB_PASS=$(cat /root/.mail_db_password)
    user_count=$(mysql -u mailuser -p"$DB_PASS" mailserver -e "SELECT COUNT(*) FROM virtual_users" 2>/dev/null | tail -1 || echo "0")
    domain_count=$(mysql -u mailuser -p"$DB_PASS" mailserver -e "SELECT COUNT(*) FROM virtual_domains" 2>/dev/null | tail -1 || echo "0")
    echo "  Domains: $domain_count"
    echo "  Users: $user_count"
else
    echo "  ${RED}✗ Database credentials not found${NC}"
fi

# Summary
echo ""
echo -e "${BLUE}==================================================${NC}"
echo "TEST SUMMARY"
echo ""
echo "Next steps:"
echo "1. Send test email: test-email check-auth@verifier.port25.com"
echo "2. Check spam score: https://www.mail-tester.com"
echo "3. Verify DKIM: opendkim-testkey -d $DOMAIN -s mail -vvv"
echo ""

# Overall status
errors=0
[ ! -f "/etc/opendkim/keys/$DOMAIN/mail.txt" ] && ((errors++))
! netstat -lnp 2>/dev/null | grep -q ":8891" && ((errors++))
! dig +short TXT mail._domainkey.$DOMAIN @8.8.8.8 2>/dev/null | grep -q "v=DKIM1" && ((errors++))

if [ $errors -eq 0 ]; then
    echo -e "${GREEN}✓ Server appears fully configured!${NC}"
else
    echo -e "${YELLOW}⚠ Some issues need attention ($errors items)${NC}"
fi
EOF

sed -i "s/DOMAIN_PLACEHOLDER/$DOMAIN_NAME/g" /usr/local/bin/mail-test
chmod +x /usr/local/bin/mail-test

# ===================================================================
# 6. MAIL LOG VIEWER
# ===================================================================

cat > /usr/local/bin/mail-log <<'EOF'
#!/bin/bash

case "$1" in
    live)
        echo "Live mail log (Ctrl+C to stop):"
        tail -f /var/log/mail.log
        ;;
    errors)
        echo "Recent mail errors:"
        grep -i "error\|warning\|fatal\|panic" /var/log/mail.log | tail -50
        ;;
    sent)
        echo "Recently sent emails:"
        grep "status=sent" /var/log/mail.log | tail -20
        ;;
    bounced)
        echo "Recently bounced emails:"
        grep "status=bounced" /var/log/mail.log | tail -20
        ;;
    dkim)
        echo "Recent DKIM activity:"
        grep -i "dkim" /var/log/mail.log | tail -30
        ;;
    auth)
        echo "Recent authentication attempts:"
        grep -i "sasl\|auth" /var/log/mail.log | tail -30
        ;;
    search)
        if [ -z "$2" ]; then
            echo "Usage: mail-log search term"
            exit 1
        fi
        echo "Searching for: $2"
        grep -i "$2" /var/log/mail.log | tail -50
        ;;
    *)
        echo "Mail Log Viewer"
        echo "Usage: mail-log {live|errors|sent|bounced|dkim|auth|search}"
        echo ""
        echo "Commands:"
        echo "  live     - Watch live log"
        echo "  errors   - Show recent errors"
        echo "  sent     - Show sent emails"
        echo "  bounced  - Show bounced emails"
        echo "  dkim     - Show DKIM activity"
        echo "  auth     - Show authentication attempts"
        echo "  search   - Search for specific term"
        ;;
esac
EOF

chmod +x /usr/local/bin/mail-log

# ===================================================================
# 7. MAIL QUEUE MANAGEMENT
# ===================================================================

cat > /usr/local/bin/mail-queue <<'EOF'
#!/bin/bash

case "$1" in
    show)
        mailq
        ;;
    count)
        count=$(mailq 2>/dev/null | grep -c "^[A-F0-9]" || echo "0")
        echo "Messages in queue: $count"
        ;;
    flush)
        echo "Flushing mail queue..."
        postqueue -f
        echo "✓ Queue flush initiated"
        ;;
    clear)
        echo "Clearing entire queue..."
        read -p "Are you sure? This will delete ALL queued mail! (y/N): " confirm
        if [ "$confirm" = "y" ]; then
            postsuper -d ALL
            echo "✓ Queue cleared"
        else
            echo "Cancelled"
        fi
        ;;
    hold)
        echo "Putting queue on hold..."
        postsuper -h ALL
        echo "✓ Queue on hold"
        ;;
    release)
        echo "Releasing held messages..."
        postsuper -H ALL
        echo "✓ Messages released"
        ;;
    *)
        echo "Mail Queue Manager"
        echo "Usage: mail-queue {show|count|flush|clear|hold|release}"
        echo ""
        echo "Commands:"
        echo "  show    - Show queue contents"
        echo "  count   - Count messages in queue"
        echo "  flush   - Attempt to deliver queued mail"
        echo "  clear   - Delete all queued mail"
        echo "  hold    - Put queue on hold"
        echo "  release - Release held messages"
        ;;
esac
EOF

chmod +x /usr/local/bin/mail-queue

# ===================================================================
# 8. IP ROTATION STATUS (if configured)
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
else
    echo "Error: Database password file not found"
    exit 1
fi

# Show configured IPs
echo "Configured IPs:"
i=0
for ip in IP_ADDRESSES_PLACEHOLDER; do
    echo "  smtp-ip$i: $ip"
    ((i++))
done

echo ""
echo "Current Assignments:"

# Show database assignments
mysql -u mailuser -p"$DB_PASS" mailserver -e "
SELECT 
    sender_email as 'Sender',
    assigned_ip as 'IP Address',
    transport_id as 'Transport',
    message_count as 'Messages',
    last_used as 'Last Used'
FROM ip_rotation_log 
ORDER BY last_used DESC 
LIMIT 20;" 2>/dev/null || echo "No data available"

echo ""
echo "IP Usage Statistics:"
mysql -u mailuser -p"$DB_PASS" mailserver -e "
SELECT 
    assigned_ip as 'IP Address',
    COUNT(*) as 'Senders',
    SUM(message_count) as 'Total Messages'
FROM ip_rotation_log 
GROUP BY assigned_ip;" 2>/dev/null || echo "No statistics available"
EOF

    # Replace placeholder with actual IPs
    IP_LIST="${IP_ADDRESSES[@]}"
    sed -i "s/IP_ADDRESSES_PLACEHOLDER/$IP_LIST/g" /usr/local/bin/ip-rotation-status
    chmod +x /usr/local/bin/ip-rotation-status
fi

# ===================================================================
# 9. BACKUP SCRIPT
# ===================================================================

cat > /usr/local/bin/mail-backup <<'EOF'
#!/bin/bash

BACKUP_DIR="/root/mail-backups"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

echo "Creating mail server backup..."

mkdir -p "$BACKUP_DIR"

# Backup configuration files
tar czf "$BACKUP_DIR/config-$TIMESTAMP.tar.gz" \
    /etc/postfix \
    /etc/dovecot \
    /etc/opendkim \
    /etc/nginx/sites-available \
    /root/.mail_db_password \
    /root/.cloudflare_credentials \
    /root/mail-installer/install.conf \
    2>/dev/null

echo "✓ Configuration backed up"

# Backup database
if [ -f /root/.mail_db_password ]; then
    DB_PASS=$(cat /root/.mail_db_password)
    mysqldump -u mailuser -p"$DB_PASS" mailserver > "$BACKUP_DIR/mailserver-$TIMESTAMP.sql"
    echo "✓ Database backed up"
fi

# List backups
echo ""
echo "Backups in $BACKUP_DIR:"
ls -lh "$BACKUP_DIR" | tail -5

echo ""
echo "✓ Backup complete: $BACKUP_DIR/*-$TIMESTAMP.*"
EOF

chmod +x /usr/local/bin/mail-backup

# ===================================================================
# 10. MAILWIZZ INFO
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

if [ -f /root/.mail_db_password ]; then
    DB_PASS=$(cat /root/.mail_db_password)
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
echo "  • test-email        - Send test emails"
echo "  • check-dns         - Verify DNS configuration"
echo "  • mail-test         - Comprehensive server test"
echo "  • mail-log          - View mail logs"
echo "  • mail-queue        - Manage mail queue"
echo "  • mail-backup       - Backup configuration"
echo "  • mailwizz-info     - MailWizz configuration guide"

if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
    echo "  • ip-rotation-status - Monitor IP rotation"
fi

echo ""
echo "Quick start:"
echo "  1. Run: mail-test"
echo "  2. Send test: test-email check-auth@verifier.port25.com"
echo "  3. Check DNS: check-dns"
echo ""

print_message "✓ All management utilities installed successfully!"
