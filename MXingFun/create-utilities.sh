#!/bin/bash

# =================================================================
# CREATE MAIL SERVER UTILITIES - AUTOMATIC, NO QUESTIONS
# Version: 17.0.0
# Creates helper scripts for managing the mail server
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

print_header "Creating Mail Server Utilities"
echo ""

# Load configuration
if [ -f "$(pwd)/install.conf" ]; then
    source "$(pwd)/install.conf"
elif [ -f "/root/mail-installer/install.conf" ]; then
    source "/root/mail-installer/install.conf"
fi

# Get domain info
if [ -z "$DOMAIN_NAME" ]; then
    if [ -f /etc/postfix/main.cf ]; then
        DOMAIN_NAME=$(postconf -h mydomain 2>/dev/null || hostname -d)
        HOSTNAME=$(postconf -h myhostname 2>/dev/null || hostname -f)
    else
        DOMAIN_NAME=$(hostname -d)
        HOSTNAME=$(hostname -f)
    fi
else
    # Use configured hostname with subdomain
    if [ ! -z "$MAIL_SUBDOMAIN" ]; then
        HOSTNAME="$MAIL_SUBDOMAIN.$DOMAIN_NAME"
    else
        HOSTNAME=${HOSTNAME:-"mail.$DOMAIN_NAME"}
    fi
fi

# ===================================================================
# 1. MAIL ACCOUNT MANAGER
# ===================================================================

echo "Creating mail-account command..."

cat > /usr/local/bin/mail-account << 'EOF'
#!/bin/bash

# Mail Account Manager
# Version: 17.0.0

GREEN='\033[38;5;208m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Load DB password
if [ -f /root/.mail_db_password ]; then
    DB_PASS=$(cat /root/.mail_db_password)
else
    echo -e "${RED}Error: Database password file not found${NC}"
    exit 1
fi

# Test database connection
MYSQL_CMD="mysql -u mailuser -p$DB_PASS -h localhost mailserver"
if ! $MYSQL_CMD -e "SELECT 1" >/dev/null 2>&1; then
    MYSQL_CMD="mysql -u mailuser -p$DB_PASS -h 127.0.0.1 mailserver"
    if ! $MYSQL_CMD -e "SELECT 1" >/dev/null 2>&1; then
        echo -e "${RED}Error: Cannot connect to database${NC}"
        exit 1
    fi
fi

# Functions
add_account() {
    EMAIL="$1"
    PASSWORD="$2"
    
    if [ -z "$EMAIL" ] || [ -z "$PASSWORD" ]; then
        echo "Usage: mail-account add user@domain.com password"
        exit 1
    fi
    
    # Validate email format
    if ! [[ "$EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        echo -e "${RED}Invalid email format${NC}"
        exit 1
    fi
    
    # Extract domain
    DOMAIN="${EMAIL#*@}"
    MAILBOX="${EMAIL%@*}"
    
    # Hash password
    if command -v doveadm &> /dev/null; then
        PASS_HASH=$(doveadm pw -s SHA512-CRYPT -p "$PASSWORD" 2>/dev/null)
        if [ -z "$PASS_HASH" ]; then
            PASS_HASH=$(doveadm pw -s SSHA512 -p "$PASSWORD" 2>/dev/null)
        fi
    else
        PASS_HASH="{PLAIN}$PASSWORD"
    fi
    
    # Add domain if not exists
    $MYSQL_CMD <<SQL 2>/dev/null
INSERT IGNORE INTO virtual_domains (name) VALUES ('$DOMAIN');
SQL
    
    # Add user
    $MYSQL_CMD <<SQL 2>/dev/null
SET @domain_id = (SELECT id FROM virtual_domains WHERE name = '$DOMAIN');
INSERT INTO virtual_users (domain_id, email, password, quota, active)
VALUES (@domain_id, '$EMAIL', '$PASS_HASH', 0, 1)
ON DUPLICATE KEY UPDATE password = '$PASS_HASH', active = 1;
SQL
    
    if [ $? -eq 0 ]; then
        # Create maildir
        MAIL_DIR="/var/vmail/$DOMAIN/$MAILBOX"
        mkdir -p "$MAIL_DIR"
        chown -R vmail:vmail /var/vmail/
        
        echo -e "${GREEN}✓ Account created: $EMAIL${NC}"
        echo "  Maildir: $MAIL_DIR"
        echo "  IMAP/SMTP Server: $(hostname -f)"
        echo "  Ports: 587 (SMTP), 993 (IMAP)"
    else
        echo -e "${RED}✗ Failed to create account${NC}"
        exit 1
    fi
}

list_accounts() {
    echo -e "${GREEN}Email Accounts:${NC}"
    $MYSQL_CMD -e "
    SELECT 
        email as 'Email Address',
        CASE active 
            WHEN 1 THEN 'Active' 
            ELSE 'Disabled' 
        END as 'Status',
        DATE_FORMAT(created_at, '%Y-%m-%d %H:%i') as 'Created'
    FROM virtual_users 
    ORDER BY email;" 2>/dev/null
}

delete_account() {
    EMAIL="$1"
    
    if [ -z "$EMAIL" ]; then
        echo "Usage: mail-account delete user@domain.com"
        exit 1
    fi
    
    echo -n "Are you sure you want to delete $EMAIL? (y/n): "
    read CONFIRM
    
    if [ "$CONFIRM" = "y" ]; then
        $MYSQL_CMD -e "DELETE FROM virtual_users WHERE email = '$EMAIL';" 2>/dev/null
        
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✓ Account deleted: $EMAIL${NC}"
        else
            echo -e "${RED}✗ Failed to delete account${NC}"
        fi
    else
        echo "Cancelled"
    fi
}

disable_account() {
    EMAIL="$1"
    
    if [ -z "$EMAIL" ]; then
        echo "Usage: mail-account disable user@domain.com"
        exit 1
    fi
    
    $MYSQL_CMD -e "UPDATE virtual_users SET active = 0 WHERE email = '$EMAIL';" 2>/dev/null
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Account disabled: $EMAIL${NC}"
    else
        echo -e "${RED}✗ Failed to disable account${NC}"
    fi
}

enable_account() {
    EMAIL="$1"
    
    if [ -z "$EMAIL" ]; then
        echo "Usage: mail-account enable user@domain.com"
        exit 1
    fi
    
    $MYSQL_CMD -e "UPDATE virtual_users SET active = 1 WHERE email = '$EMAIL';" 2>/dev/null
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Account enabled: $EMAIL${NC}"
    else
        echo -e "${RED}✗ Failed to enable account${NC}"
    fi
}

password_change() {
    EMAIL="$1"
    PASSWORD="$2"
    
    if [ -z "$EMAIL" ] || [ -z "$PASSWORD" ]; then
        echo "Usage: mail-account password user@domain.com newpassword"
        exit 1
    fi
    
    # Hash password
    if command -v doveadm &> /dev/null; then
        PASS_HASH=$(doveadm pw -s SHA512-CRYPT -p "$PASSWORD" 2>/dev/null)
        if [ -z "$PASS_HASH" ]; then
            PASS_HASH=$(doveadm pw -s SSHA512 -p "$PASSWORD" 2>/dev/null)
        fi
    else
        PASS_HASH="{PLAIN}$PASSWORD"
    fi
    
    $MYSQL_CMD -e "UPDATE virtual_users SET password = '$PASS_HASH' WHERE email = '$EMAIL';" 2>/dev/null
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Password updated for: $EMAIL${NC}"
    else
        echo -e "${RED}✗ Failed to update password${NC}"
    fi
}

# Main command handler
case "$1" in
    add)
        add_account "$2" "$3"
        ;;
    list)
        list_accounts
        ;;
    delete)
        delete_account "$2"
        ;;
    disable)
        disable_account "$2"
        ;;
    enable)
        enable_account "$2"
        ;;
    password)
        password_change "$2" "$3"
        ;;
    *)
        echo "Mail Account Manager"
        echo "Usage: mail-account {add|list|delete|disable|enable|password} [options]"
        echo ""
        echo "Commands:"
        echo "  add user@domain.com password    - Create new email account"
        echo "  list                            - List all accounts"
        echo "  delete user@domain.com          - Delete account"
        echo "  disable user@domain.com         - Disable account"
        echo "  enable user@domain.com          - Enable account"
        echo "  password user@domain.com newpass - Change password"
        ;;
esac
EOF

chmod +x /usr/local/bin/mail-account
print_message "✓ mail-account command created"

# ===================================================================
# 2. TEST EMAIL SENDER
# ===================================================================

echo "Creating test-email command..."

cat > /usr/local/bin/test-email << 'EOF'
#!/bin/bash

# Test Email Sender with DKIM
# Version: 17.0.0

GREEN='\033[38;5;208m'
RED='\033[0;31m'
NC='\033[0m'

# Get domain info
DOMAIN=$(postconf -h mydomain 2>/dev/null || hostname -d)
HOSTNAME=$(postconf -h myhostname 2>/dev/null || hostname -f)

# Check if OpenDKIM is running
if ! systemctl is-active --quiet opendkim; then
    echo -e "${RED}Warning: OpenDKIM is not running. Starting it...${NC}"
    systemctl start opendkim
    sleep 2
fi

# Default values
TO_EMAIL="${1:-check-auth@verifier.port25.com}"
FROM_EMAIL="${2:-test@$DOMAIN}"
SUBJECT="Test Email from $HOSTNAME - $(date '+%Y-%m-%d %H:%M:%S')"

if [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
    echo "Test Email Sender"
    echo "Usage: test-email [recipient] [from_email]"
    echo ""
    echo "Examples:"
    echo "  test-email                                    # Send to Port25 verifier"
    echo "  test-email check-auth@verifier.port25.com    # Check authentication"
    echo "  test-email user@example.com                  # Send to specific address"
    echo "  test-email user@example.com sender@$DOMAIN   # Specify sender"
    echo ""
    echo "Test services:"
    echo "  check-auth@verifier.port25.com - Full authentication test"
    echo "  https://www.mail-tester.com - Get test address first"
    echo ""
    exit 0
fi

echo -e "${GREEN}Sending test email...${NC}"
echo "  From: $FROM_EMAIL"
echo "  To: $TO_EMAIL"
echo "  Subject: $SUBJECT"
echo ""

# Get server IP info
SERVER_IP=$(curl -s https://ipinfo.io/ip 2>/dev/null || hostname -I | awk '{print $1}')

# Check if multiple IPs are configured
NUM_IPS=$(postconf -h | grep -c "smtp-ip" 2>/dev/null || echo "1")

# Create test message with headers for authentication
cat <<MESSAGE | sendmail -v -f "$FROM_EMAIL" "$TO_EMAIL"
From: $FROM_EMAIL
To: $TO_EMAIL
Subject: $SUBJECT
Date: $(date -R)
Message-ID: <$(date +%s).$RANDOM@$HOSTNAME>
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit

This is a test email from your mail server at $HOSTNAME.

Server Information:
===================
Hostname: $HOSTNAME
Domain: $DOMAIN
Server IP: $SERVER_IP
Configured IPs: $NUM_IPS
Timestamp: $(date)

Authentication Tests:
====================
SPF: Should PASS (IP authorized in SPF record)
DKIM: Should PASS (Email signed with 2048-bit key)
DMARC: Should PASS (SPF and DKIM aligned)

OpenDKIM Status:
================
Service: $(systemctl is-active opendkim)
Port 8891: $(netstat -lnp 2>/dev/null | grep -q ":8891" && echo "Listening" || echo "Not listening")
DKIM Selector: mail
DKIM Domain: $DOMAIN

Email Headers:
==============
This email should contain:
- DKIM-Signature header (added by OpenDKIM)
- Return-Path header
- Received headers showing the path

Testing Instructions:
=====================
1. For Port25 verifier: Wait for the automated reply
2. For mail-tester.com: Check your score on their website
3. Check headers to verify DKIM signature is present

If this is sent to check-auth@verifier.port25.com, you will receive
a detailed report showing SPF, DKIM, and DMARC results.

---
Sent from $HOSTNAME
Mail Server Installation: https://github.com/fumingtomato/shibi
MESSAGE

if [ $? -eq 0 ]; then
    echo ""
    echo -e "${GREEN}✓ Test email sent successfully!${NC}"
    echo ""
    
    if [[ "$TO_EMAIL" == *"verifier.port25.com"* ]]; then
        echo "📧 Port25 will reply with authentication results to: $FROM_EMAIL"
        echo "   Check the inbox in a few minutes for the report."
        echo ""
        echo "Expected results:"
        echo "  ✓ SPF check: PASS"
        echo "  ✓ DKIM check: PASS"
        echo "  ✓ DMARC check: PASS"
    elif [[ "$TO_EMAIL" == *"mail-tester.com"* ]]; then
        echo "📧 Check your score at: https://www.mail-tester.com"
        echo "   Use the same testing address you got from the website."
    else
        echo "📧 Email sent to: $TO_EMAIL"
        echo "   Check the inbox and verify DKIM-Signature header is present."
    fi
    
    echo ""
    echo "To view mail log:"
    echo "  tail -n 50 /var/log/mail.log | grep -i dkim"
else
    echo -e "${RED}✗ Failed to send test email${NC}"
    echo "Check mail log: tail -f /var/log/mail.log"
fi
EOF

chmod +x /usr/local/bin/test-email
print_message "✓ test-email command created"

# ===================================================================
# 3. DNS CHECKER
# ===================================================================

echo "Creating check-dns command..."

cat > /usr/local/bin/check-dns << EOF
#!/bin/bash

# DNS Record Checker
# Version: 17.0.0

GREEN='\033[38;5;208m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

DOMAIN="\${1:-$DOMAIN_NAME}"
HOSTNAME="$HOSTNAME"
SERVER_IP=$(curl -s https://ipinfo.io/ip 2>/dev/null || hostname -I | awk '{print $1}')

echo -e "\${GREEN}DNS Record Check for \$DOMAIN\${NC}"
echo "============================================"
echo ""

# Check A record for mail subdomain
echo -n "A record for \$HOSTNAME: "
A_RECORD=\$(dig +short A \$HOSTNAME @8.8.8.8 2>/dev/null | head -1)
if [ "\$A_RECORD" == "\$SERVER_IP" ]; then
    echo -e "\${GREEN}✓ \$A_RECORD (matches server)\${NC}"
else
    if [ -z "\$A_RECORD" ]; then
        echo -e "\${RED}✗ Not found\${NC}"
    else
        echo -e "\${YELLOW}⚠ \$A_RECORD (expected: \$SERVER_IP)\${NC}"
    fi
fi

# Check A record for main domain
echo -n "A record for \$DOMAIN: "
A_RECORD=\$(dig +short A \$DOMAIN @8.8.8.8 2>/dev/null | head -1)
if [ ! -z "\$A_RECORD" ]; then
    echo -e "\${GREEN}✓ \$A_RECORD\${NC}"
else
    echo -e "\${YELLOW}⚠ Not found (needed for website)\${NC}"
fi

# Check MX record
echo -n "MX record: "
MX_RECORD=\$(dig +short MX \$DOMAIN @8.8.8.8 2>/dev/null | awk '{print \$2}' | sed 's/\\.$//' | head -1)
if [ "\$MX_RECORD" == "\$HOSTNAME" ]; then
    echo -e "\${GREEN}✓ \$MX_RECORD\${NC}"
else
    if [ -z "\$MX_RECORD" ]; then
        echo -e "\${RED}✗ Not found\${NC}"
    else
        echo -e "\${YELLOW}⚠ \$MX_RECORD (expected: \$HOSTNAME)\${NC}"
    fi
fi

# Check SPF record
echo -n "SPF record: "
SPF=\$(dig +short TXT \$DOMAIN @8.8.8.8 2>/dev/null | grep "v=spf1")
if [ ! -z "\$SPF" ]; then
    echo -e "\${GREEN}✓ Found\${NC}"
    echo "  \$SPF"
else
    echo -e "\${RED}✗ Not found\${NC}"
    echo "  Add TXT record: v=spf1 mx a ip4:\$SERVER_IP ~all"
fi

# Check DKIM record
echo -n "DKIM record (mail._domainkey): "
DKIM=\$(dig +short TXT mail._domainkey.\$DOMAIN @8.8.8.8 2>/dev/null | grep "v=DKIM1")
if [ ! -z "\$DKIM" ]; then
    echo -e "\${GREEN}✓ Found\${NC}"
    # Check if it's a valid DKIM key
    if echo "\$DKIM" | grep -q "k=rsa" && echo "\$DKIM" | grep -q "p="; then
        echo "  Key type: RSA"
        KEY_LENGTH=\$(echo "\$DKIM" | grep -oP 'p=\\K[^"]+' | tr -d ' ' | wc -c)
        echo "  Key length: ~\$((KEY_LENGTH * 6)) bits"
    fi
else
    echo -e "\${RED}✗ Not found\${NC}"
    if [ -f "/etc/opendkim/keys/\$DOMAIN/mail.txt" ]; then
        echo "  Local key exists. Add this TXT record:"
        echo "  Name: mail._domainkey"
        echo "  Value: \$(cat /etc/opendkim/keys/\$DOMAIN/mail.txt | grep -v '(' | grep -v ')' | tr -d '\\n\\t" ')"
    fi
fi

# Check DMARC record
echo -n "DMARC record: "
DMARC=\$(dig +short TXT _dmarc.\$DOMAIN @8.8.8.8 2>/dev/null | grep "v=DMARC1")
if [ ! -z "\$DMARC" ]; then
    echo -e "\${GREEN}✓ Found\${NC}"
    echo "  \$DMARC"
else
    echo -e "\${YELLOW}⚠ Not found (optional but recommended)\${NC}"
    echo "  Add TXT record _dmarc.\$DOMAIN:"
    echo "  v=DMARC1; p=quarantine; rua=mailto:dmarc@\$DOMAIN"
fi

# Check PTR record
echo -n "PTR record (Reverse DNS): "
PTR=\$(dig +short -x \$SERVER_IP @8.8.8.8 2>/dev/null | sed 's/\\.$//')
if [ "\$PTR" == "\$HOSTNAME" ]; then
    echo -e "\${GREEN}✓ \$PTR\${NC}"
else
    if [ -z "\$PTR" ]; then
        echo -e "\${RED}✗ Not configured\${NC}"
    else
        echo -e "\${YELLOW}⚠ \$PTR (expected: \$HOSTNAME)\${NC}"
    fi
    echo "  Contact your hosting provider to set PTR record"
fi

echo ""
echo "============================================"

# Summary
ISSUES=0
[ "\$A_RECORD" != "\$SERVER_IP" ] && ISSUES=\$((ISSUES + 1))
[ -z "\$MX_RECORD" ] && ISSUES=\$((ISSUES + 1))
[ -z "\$SPF" ] && ISSUES=\$((ISSUES + 1))
[ -z "\$DKIM" ] && ISSUES=\$((ISSUES + 1))
[ "\$PTR" != "\$HOSTNAME" ] && ISSUES=\$((ISSUES + 1))

if [ \$ISSUES -eq 0 ]; then
    echo -e "\${GREEN}✓ All DNS records configured correctly!\${NC}"
else
    echo -e "\${YELLOW}⚠ \$ISSUES DNS issues found\${NC}"
    echo "Fix the issues above for optimal email delivery"
fi

echo ""
echo "Test email authentication:"
echo "  test-email check-auth@verifier.port25.com"
EOF

chmod +x /usr/local/bin/check-dns
print_message "✓ check-dns command created"

# ===================================================================
# 4. MAIL STATUS CHECKER
# ===================================================================

echo "Creating mail-status command..."

cat > /usr/local/bin/mail-status << EOF
#!/bin/bash

# Mail Server Status Checker
# Version: 17.0.0

GREEN='\033[38;5;208m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[1;33m'
NC='\033[0m'

echo -e "\${BLUE}Mail Server Status\${NC}"
echo "=================="
echo ""

# Check services
echo "Service Status:"
for service in postfix dovecot opendkim mysql nginx; do
    printf "  %-10s: " "\$service"
    if systemctl is-active --quiet \$service; then
        echo -e "\${GREEN}✓ Running\${NC}"
    else
        echo -e "\${RED}✗ Not running\${NC}"
    fi
done

echo ""
echo "Port Status:"
for port in 25:SMTP 587:Submission 465:SMTPS 143:IMAP 993:IMAPS 110:POP3 995:POP3S 80:HTTP 443:HTTPS 8891:OpenDKIM; do
    PORT_NUM="\${port%%:*}"
    PORT_NAME="\${port##*:}"
    printf "  %-15s (%-4s): " "\$PORT_NAME" "\$PORT_NUM"
    if netstat -tuln 2>/dev/null | grep -q ":\$PORT_NUM "; then
        echo -e "\${GREEN}✓ Listening\${NC}"
    else
        echo -e "\${YELLOW}✗ Not listening\${NC}"
    fi
done

echo ""
echo "Mail Queue:"
QUEUE_COUNT=\$(mailq | grep -c "^[A-Z0-9]" 2>/dev/null || echo "0")
if [ "\$QUEUE_COUNT" -eq 0 ]; then
    echo -e "  \${GREEN}✓ Queue is empty\${NC}"
else
    echo -e "  \${YELLOW}⚠ \$QUEUE_COUNT messages in queue\${NC}"
    echo "  Run 'mail-queue show' for details"
fi

echo ""
echo "DKIM Status:"
if [ -f "/etc/opendkim/keys/$DOMAIN_NAME/mail.txt" ]; then
    echo -e "  Key File: \${GREEN}✓ Present\${NC}"
else
    echo -e "  Key File: \${RED}✗ Missing\${NC}"
fi

if systemctl is-active --quiet opendkim; then
    echo -e "  Service:  \${GREEN}✓ Running\${NC}"
    if netstat -lnp 2>/dev/null | grep -q ":8891"; then
        echo -e "  Socket:   \${GREEN}✓ Listening on port 8891\${NC}"
    else
        echo -e "  Socket:   \${RED}✗ Not listening\${NC}"
    fi
else
    echo -e "  Service:  \${RED}✗ Not running\${NC}"
fi

# Check for IP rotation
NUM_IPS=\$(grep -c "smtp-ip" /etc/postfix/master.cf 2>/dev/null || echo "0")
if [ "\$NUM_IPS" -gt 0 ]; then
    echo ""
    echo "IP Rotation:"
    echo -e "  Status: \${GREEN}✓ Configured\${NC}"
    echo "  Transports: \$NUM_IPS"
    echo "  Check usage: ip-rotation-status"
fi

echo ""
echo "Disk Usage:"
df -h /var/vmail 2>/dev/null | tail -1 | awk '{printf "  Mail storage: %s used of %s (%s)\\n", \$3, \$2, \$5}'
df -h /var/log 2>/dev/null | tail -1 | awk '{printf "  Logs: %s used of %s (%s)\\n", \$3, \$2, \$5}'

echo ""
echo "Recent Activity:"
echo -n "  Emails sent (last hour): "
grep -c "status=sent" /var/log/mail.log 2>/dev/null | tail -1 || echo "0"
echo -n "  Authentication failures (last hour): "
grep -c "authentication failed" /var/log/mail.log 2>/dev/null | tail -1 || echo "0"

echo ""
echo "Quick Commands:"
echo "  View logs:        mail-log follow"
echo "  Check DNS:        check-dns"
echo "  Send test:        test-email"
echo "  Manage accounts:  mail-account list"
EOF

chmod +x /usr/local/bin/mail-status
print_message "✓ mail-status command created"

# ===================================================================
# 5. MAIL QUEUE MANAGER
# ===================================================================

echo "Creating mail-queue command..."

cat > /usr/local/bin/mail-queue << 'EOF'
#!/bin/bash

# Mail Queue Manager
# Version: 17.0.0

case "$1" in
    show)
        mailq
        ;;
    flush)
        echo "Flushing mail queue..."
        postqueue -f
        echo "✓ Queue flush initiated"
        ;;
    delete)
        if [ -z "$2" ]; then
            echo "Usage: mail-queue delete <queue-id>"
            echo "       mail-queue delete ALL"
            exit 1
        fi
        if [ "$2" == "ALL" ]; then
            echo "Deleting all queued messages..."
            postsuper -d ALL
        else
            echo "Deleting message $2..."
            postsuper -d "$2"
        fi
        ;;
    hold)
        echo "Putting all messages on hold..."
        postsuper -h ALL
        ;;
    release)
        echo "Releasing all held messages..."
        postsuper -H ALL
        ;;
    *)
        echo "Mail Queue Manager"
        echo "Usage: mail-queue {show|flush|delete|hold|release} [options]"
        echo ""
        echo "Commands:"
        echo "  show              - Display mail queue"
        echo "  flush             - Attempt to deliver all queued mail"
        echo "  delete <id>       - Delete specific message"
        echo "  delete ALL        - Delete all queued messages"
        echo "  hold              - Put all messages on hold"
        echo "  release           - Release all held messages"
        ;;
esac
EOF

chmod +x /usr/local/bin/mail-queue
print_message "✓ mail-queue command created"

# ===================================================================
# 6. MAIL LOG VIEWER
# ===================================================================

echo "Creating mail-log command..."

cat > /usr/local/bin/mail-log << 'EOF'
#!/bin/bash

# Mail Log Viewer
# Version: 17.0.0

case "$1" in
    follow)
        tail -f /var/log/mail.log
        ;;
    today)
        grep "$(date +'%b %e')" /var/log/mail.log
        ;;
    errors)
        grep -i "error\|failed\|rejected\|warning" /var/log/mail.log | tail -50
        ;;
    sent)
        grep "status=sent" /var/log/mail.log | tail -50
        ;;
    auth)
        grep -i "auth\|sasl\|login" /var/log/mail.log | tail -50
        ;;
    dkim)
        grep -i "dkim\|opendkim" /var/log/mail.log | tail -50
        ;;
    ip-rotation)
        echo "IP Rotation Activity:"
        for i in $(seq 1 10); do
            count=$(grep "postfix-ip$i" /var/log/mail.log 2>/dev/null | wc -l)
            if [ $count -gt 0 ]; then
                echo "  Transport smtp-ip$i: $count entries"
            fi
        done
        ;;
    search)
        if [ -z "$2" ]; then
            echo "Usage: mail-log search <pattern>"
            exit 1
        fi
        grep -i "$2" /var/log/mail.log | tail -50
        ;;
    *)
        echo "Mail Log Viewer"
        echo "Usage: mail-log {follow|today|errors|sent|auth|dkim|ip-rotation|search} [pattern]"
        echo ""
        echo "Commands:"
        echo "  follow         - Follow log in real-time"
        echo "  today          - Show today's logs"
        echo "  errors         - Show recent errors"
        echo "  sent           - Show recently sent emails"
        echo "  auth           - Show authentication logs"
        echo "  dkim           - Show DKIM-related logs"
        echo "  ip-rotation    - Show IP rotation activity"
        echo "  search <text>  - Search for specific text"
        ;;
esac
EOF

chmod +x /usr/local/bin/mail-log
print_message "✓ mail-log command created"

# ===================================================================
# 7. MAILWIZZ INFO
# ===================================================================

echo "Creating mailwizz-info command..."

cat > /usr/local/bin/mailwizz-info << EOF
#!/bin/bash

# Mailwizz Configuration Info
# Version: 17.0.0

GREEN='\033[38;5;208m'
BLUE='\033[1;33m'
NC='\033[0m'

echo -e "\${BLUE}Mailwizz Configuration Information\${NC}"
echo "===================================="
echo ""
echo -e "\${GREEN}SMTP Settings for Mailwizz:\${NC}"
echo "  Hostname: $HOSTNAME"
echo "  Port: 587 (STARTTLS) or 465 (SSL/TLS)"
echo "  Encryption: TLS (port 587) or SSL (port 465)"
echo "  Username: Your email address (e.g., ${FIRST_EMAIL:-user@$DOMAIN_NAME})"
echo "  Password: The password for that email account"
echo ""
echo -e "\${GREEN}Delivery Server Configuration:\${NC}"
echo "  Type: SMTP"
echo "  From Name: Your Company Name"
echo "  From Email: ${FIRST_EMAIL:-noreply@$DOMAIN_NAME}"
echo "  Reply-To: ${FIRST_EMAIL:-support@$DOMAIN_NAME}"
echo "  Bounce Email: bounce@$DOMAIN_NAME"
echo ""
echo -e "\${GREEN}Important Settings:\${NC}"
echo "  • Use authentication: YES"
echo "  • Signing enabled: YES (Mailwizz will add headers)"
echo "  • Force FROM: NO (allow different from addresses)"
echo "  • Max connection messages: 100"
echo "  • Max connections: 10"
echo ""

# Check if IP rotation is configured
NUM_IPS=\$(grep -c "smtp-ip" /etc/postfix/master.cf 2>/dev/null || echo "0")
if [ "\$NUM_IPS" -gt 0 ]; then
    echo -e "\${GREEN}IP Rotation Configuration:\${NC}"
    echo "  • Multiple IPs configured: \$NUM_IPS"
    echo "  • Rotation type: Sticky sessions (sender-based)"
    echo "  • Monitor command: ip-rotation-status"
    echo ""
fi

echo -e "\${GREEN}Required Headers (Mailwizz should add):\${NC}"
echo "  • List-Unsubscribe"
echo "  • List-Unsubscribe-Post"
echo "  • Precedence: bulk"
echo ""
echo -e "\${GREEN}Website Integration:\${NC}"
echo "  Update unsubscribe URL in: /etc/nginx/sites-available/$DOMAIN_NAME"
echo "  Change: return 302 https://your-mailwizz-domain.com/lists/unsubscribe;"
echo "  To your actual Mailwizz URL"
echo "  Then run: systemctl reload nginx"
echo ""
echo -e "\${GREEN}Compliance Checklist:\${NC}"
echo "  ✓ DKIM signing enabled (automatic)"
echo "  ✓ SPF record configured"
echo "  ✓ Privacy policy at: http://$DOMAIN_NAME/privacy.html"
echo "  ✓ Physical address: Update in /var/www/$DOMAIN_NAME/contact.html"
echo "  ✓ Unsubscribe mechanism: Configure in Mailwizz"
echo ""
echo -e "\${GREEN}Testing:\${NC}"
echo "  1. Send test from Mailwizz to: check-auth@verifier.port25.com"
echo "  2. Check authentication passes (SPF, DKIM, DMARC)"
echo "  3. Monitor delivery with: mail-log follow"
echo ""
echo -e "\${GREEN}Warm-up Recommendation:\${NC}"
echo "  Start with 50-100 emails/day, increase by 50% weekly"
echo "  Monitor reputation at: https://www.senderscore.org"
EOF

chmod +x /usr/local/bin/mailwizz-info
print_message "✓ mailwizz-info command created"

# ===================================================================
# 8. COMPREHENSIVE TEST COMMAND
# ===================================================================

echo "Creating mail-test command..."

cat > /usr/local/bin/mail-test << 'EOF'
#!/bin/bash

# Comprehensive Mail Server Test
# Version: 17.0.0

GREEN='\033[38;5;208m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}Comprehensive Mail Server Test${NC}"
echo "=============================="
echo ""

TESTS_PASSED=0
TESTS_FAILED=0

# Test function
run_test() {
    local test_name="$1"
    local test_cmd="$2"
    
    echo -n "Testing $test_name... "
    if eval "$test_cmd" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ PASS${NC}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        echo -e "${RED}✗ FAIL${NC}"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

# Service tests
echo "Service Tests:"
run_test "Postfix service" "systemctl is-active --quiet postfix"
run_test "Dovecot service" "systemctl is-active --quiet dovecot"
run_test "OpenDKIM service" "systemctl is-active --quiet opendkim"
run_test "MySQL/MariaDB service" "systemctl is-active --quiet mysql || systemctl is-active --quiet mariadb"
run_test "Nginx service" "systemctl is-active --quiet nginx"

echo ""
echo "Port Tests:"
run_test "SMTP (25)" "netstat -tuln 2>/dev/null | grep -q ':25 '"
run_test "Submission (587)" "netstat -tuln 2>/dev/null | grep -q ':587 '"
run_test "IMAPS (993)" "netstat -tuln 2>/dev/null | grep -q ':993 '"
run_test "OpenDKIM (8891)" "netstat -tuln 2>/dev/null | grep -q ':8891 '"
run_test "HTTP (80)" "netstat -tuln 2>/dev/null | grep -q ':80 '"

echo ""
echo "Configuration Tests:"
run_test "Postfix config" "postfix check"
run_test "DKIM key exists" "[ -f /etc/opendkim/keys/$(hostname -d)/mail.txt ]"
run_test "Database connection" "[ -f /root/.mail_db_password ] && mysql -u mailuser -p\$(cat /root/.mail_db_password) -h localhost mailserver -e 'SELECT 1' 2>/dev/null"
run_test "Website exists" "[ -f /var/www/$(hostname -d)/index.html ]"

# Check IP rotation
echo ""
echo "IP Rotation Test:"
NUM_IPS=$(grep -c "smtp-ip" /etc/postfix/master.cf 2>/dev/null || echo "0")
if [ "$NUM_IPS" -gt 0 ]; then
    echo -e "  ${GREEN}✓ IP rotation configured with $NUM_IPS transports${NC}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "  ${YELLOW}○ Single IP configuration (no rotation)${NC}"
fi

echo ""
echo "DNS Tests:"
DOMAIN=$(hostname -d)
run_test "A record for mail.$DOMAIN" "dig +short A mail.$DOMAIN @8.8.8.8 | grep -q ."
run_test "MX record" "dig +short MX $DOMAIN @8.8.8.8 | grep -q ."
run_test "SPF record" "dig +short TXT $DOMAIN @8.8.8.8 | grep -q 'v=spf1'"
run_test "DKIM record" "dig +short TXT mail._domainkey.$DOMAIN @8.8.8.8 | grep -q 'v=DKIM1'"

echo ""
echo "=============================="
echo "Results:"
echo -e "  Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "  Failed: ${RED}$TESTS_FAILED${NC}"

if [ $TESTS_FAILED -eq 0 ]; then
    echo ""
    echo -e "${GREEN}✓ All tests passed! Your mail server is ready.${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Send test email: test-email check-auth@verifier.port25.com"
    echo "  2. Check mail score: https://www.mail-tester.com"
    echo "  3. Configure Mailwizz: mailwizz-info"
else
    echo ""
    echo -e "${YELLOW}⚠ Some tests failed. Review the issues above.${NC}"
    echo ""
    echo "Troubleshooting:"
    echo "  • Check service status: mail-status"
    echo "  • View logs: mail-log errors"
    echo "  • Check DNS: check-dns"
fi
EOF

chmod +x /usr/local/bin/mail-test
print_message "✓ mail-test command created"

# ===================================================================
# 9. BACKUP UTILITY
# ===================================================================

echo "Creating mail-backup command..."

cat > /usr/local/bin/mail-backup << 'EOF'
#!/bin/bash

# Mail Server Backup Utility
# Version: 17.0.0

BACKUP_DIR="/root/mail-backups"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_FILE="$BACKUP_DIR/mailserver-backup-$TIMESTAMP.tar.gz"

echo "Mail Server Backup"
echo "=================="
echo ""

# Create backup directory
mkdir -p "$BACKUP_DIR"

echo "Creating backup..."

# Load DB password
if [ -f /root/.mail_db_password ]; then
    DB_PASS=$(cat /root/.mail_db_password)
else
    echo "Error: Database password not found"
    exit 1
fi

# Create temporary directory
TMP_DIR="/tmp/mailbackup-$TIMESTAMP"
mkdir -p "$TMP_DIR"

# Backup database
echo "  • Backing up database..."
mysqldump -u mailuser -p"$DB_PASS" -h localhost mailserver > "$TMP_DIR/mailserver.sql" 2>/dev/null || \
mysqldump -u mailuser -p"$DB_PASS" -h 127.0.0.1 mailserver > "$TMP_DIR/mailserver.sql" 2>/dev/null

# Backup configurations
echo "  • Backing up configurations..."
cp -r /etc/postfix "$TMP_DIR/" 2>/dev/null
cp -r /etc/dovecot "$TMP_DIR/" 2>/dev/null
cp -r /etc/opendkim "$TMP_DIR/" 2>/dev/null
cp -r /etc/nginx/sites-available "$TMP_DIR/nginx-sites" 2>/dev/null

# Backup credentials and configs
echo "  • Backing up credentials..."
cp /root/.mail_db_password "$TMP_DIR/" 2>/dev/null
cp /root/mail-server-config.txt "$TMP_DIR/" 2>/dev/null || true
cp /root/mail-installer/install.conf "$TMP_DIR/" 2>/dev/null || true

# Create archive
echo "  • Creating archive..."
tar -czf "$BACKUP_FILE" -C /tmp "mailbackup-$TIMESTAMP" 2>/dev/null

# Cleanup
rm -rf "$TMP_DIR"

# Report
SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
echo ""
echo "✓ Backup completed!"
echo "  File: $BACKUP_FILE"
echo "  Size: $SIZE"
echo ""
echo "To restore, extract the archive and:"
echo "  1. Restore database: mysql mailserver < mailserver.sql"
echo "  2. Copy config files back to /etc/"
echo "  3. Restart services"
EOF

chmod +x /usr/local/bin/mail-backup
print_message "✓ mail-backup command created"

# ===================================================================
# 10. IP ROTATION STATUS (if multiple IPs configured)
# ===================================================================

if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
    echo "Creating ip-rotation-status command..."
    
    cat > /usr/local/bin/ip-rotation-status << 'EOF'
#!/bin/bash

# IP Rotation Status Monitor
# Version: 17.0.0

GREEN='\033[38;5;208m'
YELLOW='\033[1;33m'
BLUE='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}IP Rotation Status Monitor${NC}"
echo "=========================="
echo ""

# Load database password
if [ -f /root/.mail_db_password ]; then
    DB_PASS=$(cat /root/.mail_db_password)
    HAS_DB=true
else
    HAS_DB=false
fi

# Check configuration
NUM_IPS=$(grep -c "smtp-ip" /etc/postfix/master.cf 2>/dev/null || echo "0")
echo "Configured IP Transports: $NUM_IPS"
echo ""

if [ "$HAS_DB" = true ]; then
    # Try to get stats from database
    echo "Database Statistics:"
    mysql -u mailuser -p"$DB_PASS" -h localhost mailserver -e "
        SELECT 
            transport_id as 'Transport',
            assigned_ip as 'IP Address',
            COUNT(*) as 'Active Senders',
            SUM(message_count) as 'Total Messages',
            MAX(last_used) as 'Last Activity'
        FROM ip_rotation_log
        GROUP BY transport_id, assigned_ip
        ORDER BY transport_id
    " 2>/dev/null || echo "  No rotation data in database yet"
    echo ""
fi

echo "Log File Statistics (last 24 hours):"
for i in $(seq 1 $NUM_IPS); do
    sent_count=$(grep "postfix-ip$i" /var/log/mail.log 2>/dev/null | grep -c "status=sent" || echo "0")
    deferred_count=$(grep "postfix-ip$i" /var/log/mail.log 2>/dev/null | grep -c "status=deferred" || echo "0")
    bounced_count=$(grep "postfix-ip$i" /var/log/mail.log 2>/dev/null | grep -c "status=bounced" || echo "0")
    
    echo -e "Transport smtp-ip$i:"
    echo "  Sent: $sent_count | Deferred: $deferred_count | Bounced: $bounced_count"
done

echo ""
echo "Current Mail Queue:"
QUEUE_COUNT=$(mailq | grep -c "^[A-Z0-9]" 2>/dev/null || echo "0")
if [ "$QUEUE_COUNT" -eq 0 ]; then
    echo -e "  ${GREEN}✓ Queue is empty${NC}"
else
    echo -e "  ${YELLOW}⚠ $QUEUE_COUNT messages in queue${NC}"
fi

echo ""
echo "Recent IP Usage (last 10 sent emails):"
grep "status=sent" /var/log/mail.log 2>/dev/null | tail -10 | while read line; do
    if echo "$line" | grep -q "postfix-ip"; then
        transport=$(echo "$line" | grep -oP 'postfix-ip\d+' | head -1)
        recipient=$(echo "$line" | grep -oP 'to=<[^>]+>' | sed 's/to=<//;s/>//')
        echo "  $transport -> $recipient"
    fi
done

echo ""
echo "Commands:"
echo "  mail-log ip-rotation  - View all IP rotation logs"
echo "  maildb ip-stats       - Database IP statistics"
echo "  mail-queue show       - View mail queue"
EOF
    
    chmod +x /usr/local/bin/ip-rotation-status
    print_message "✓ ip-rotation-status command created"
fi

# ===================================================================
# COMPLETION
# ===================================================================

print_header "Utility Creation Complete!"

echo ""
echo "Created management commands:"
echo ""
echo "Account Management:"
echo "  mail-account    - Manage email accounts"
echo ""
echo "Testing & Monitoring:"
echo "  test-email      - Send test emails with DKIM"
echo "  check-dns       - Verify DNS records"
echo "  mail-status     - Check server status"
echo "  mail-test       - Run comprehensive tests"
echo ""
echo "Operations:"
echo "  mail-queue      - Manage mail queue"
echo "  mail-log        - View mail logs"
echo "  mail-backup     - Backup server configuration"
echo ""
echo "Integration:"
echo "  mailwizz-info   - Mailwizz configuration guide"

if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
    echo ""
    echo "IP Rotation:"
    echo "  ip-rotation-status - Monitor IP rotation"
fi

echo ""

# Create quick reference
cat > /root/mail-commands.txt << EOF
MAIL SERVER COMMAND REFERENCE
==============================

Account Management:
  mail-account add user@domain.com password
  mail-account list
  mail-account delete user@domain.com
  mail-account disable user@domain.com
  mail-account enable user@domain.com
  mail-account password user@domain.com newpass

Testing:
  test-email                                    # Send to Port25
  test-email user@example.com                  # Send to address
  check-dns                                     # Check all DNS
  mail-test                                     # Full system test

Monitoring:
  mail-status                                   # Server status
  mail-log follow                               # Live log view
  mail-log errors                               # Recent errors
  mail-log dkim                                 # DKIM logs
  mail-log ip-rotation                          # IP rotation logs
  mail-queue show                               # View queue

Operations:
  mail-queue flush                              # Send queued mail
  mail-queue delete ALL                         # Clear queue
  mail-backup                                   # Backup config
  get-ssl-cert                                  # Get SSL certificates

Integration:
  mailwizz-info                                 # Setup guide

$(if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
echo "IP Rotation:
  ip-rotation-status                            # Monitor IP usage
  maildb ip-stats                               # Database IP stats"
fi)

Server Details:
  Domain: $DOMAIN_NAME
  Hostname: $HOSTNAME
  Primary IP: $PRIMARY_IP
$(if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
echo "  Total IPs: ${#IP_ADDRESSES[@]}"
fi)

Logs:
  /var/log/mail.log                             # Main mail log
  /var/log/nginx/${DOMAIN_NAME}_access.log      # Website access
  /var/log/nginx/${DOMAIN_NAME}_error.log       # Website errors

Configuration Files:
  /etc/postfix/main.cf                          # Postfix config
  /etc/dovecot/dovecot.conf                     # Dovecot config
  /etc/opendkim.conf                            # OpenDKIM config
  /etc/nginx/sites-available/$DOMAIN_NAME       # Website config
  /root/mail-server-config.txt                  # Server summary

EOF

print_message "✓ All utilities created successfully!"
echo ""
echo "Quick reference saved to: /root/mail-commands.txt"
echo ""
echo "Test your server now:"
echo "  mail-test                    # Run all tests"
echo "  test-email                   # Send test email"
if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
    echo "  ip-rotation-status           # Check IP rotation"
fi
echo ""
print_message "✓ Utility creation completed!"
