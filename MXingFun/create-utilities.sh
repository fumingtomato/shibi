#!/bin/bash

# =================================================================
# MAIL SERVER UTILITY SCRIPTS CREATOR
# Version: 16.1.0
# Creates helpful management scripts for the mail server
# Updated for Mailwizz integration and website support
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

print_header() {
    echo -e "${BLUE}==================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}==================================================${NC}"
}

print_header "Creating Mail Server Utilities"

# Create directory for utilities
mkdir -p /usr/local/bin

# Load configuration if available
if [ -f "$(pwd)/install.conf" ]; then
    source "$(pwd)/install.conf"
elif [ -f "/root/mail-installer/install.conf" ]; then
    source "/root/mail-installer/install.conf"
fi

# ===================================================================
# 1. EMAIL ACCOUNT MANAGER
# ===================================================================

print_message "Creating email account manager..."

cat > /usr/local/bin/mail-account << 'EOF'
#!/bin/bash

# Email Account Manager for Mailwizz Integration
DOMAIN="${2##*@}"
EMAIL="$2"
PASSWORD="$3"

# Database credentials
if [ -f /root/.mail_db_password ]; then
    DB_PASS=$(cat /root/.mail_db_password)
else
    echo "Error: Database password file not found"
    exit 1
fi

case "$1" in
    add)
        if [ -z "$EMAIL" ] || [ -z "$PASSWORD" ]; then
            echo "Usage: mail-account add email@domain.com password"
            exit 1
        fi
        
        # Hash password
        HASH=$(doveadm pw -s SHA512-CRYPT -p "$PASSWORD" 2>/dev/null || echo "{PLAIN}$PASSWORD")
        
        # Add to database
        mysql -u mailuser -p"$DB_PASS" mailserver <<SQL 2>/dev/null
INSERT INTO virtual_domains (name) VALUES ('$DOMAIN') 
ON DUPLICATE KEY UPDATE name=name;

INSERT INTO virtual_users (domain_id, email, password) 
SELECT id, '$EMAIL', '$HASH' FROM virtual_domains WHERE name='$DOMAIN'
ON DUPLICATE KEY UPDATE password='$HASH';
SQL
        
        if [ $? -eq 0 ]; then
            # Create mail directory
            MAIL_USER="${EMAIL%@*}"
            MAIL_DOMAIN="${EMAIL#*@}"
            MAIL_DIR="/var/vmail/$MAIL_DOMAIN/$MAIL_USER"
            mkdir -p "$MAIL_DIR"
            chown -R vmail:vmail /var/vmail/
            
            echo "✓ Account created: $EMAIL"
            echo "  Mail directory: $MAIL_DIR"
            echo ""
            echo "Use in Mailwizz:"
            echo "  SMTP Username: $EMAIL"
            echo "  SMTP Password: [the password you set]"
        else
            echo "✗ Failed to create account"
        fi
        ;;
        
    delete)
        if [ -z "$EMAIL" ]; then
            echo "Usage: mail-account delete email@domain.com"
            exit 1
        fi
        
        mysql -u mailuser -p"$DB_PASS" mailserver <<SQL 2>/dev/null
DELETE FROM virtual_users WHERE email='$EMAIL';
SQL
        
        if [ $? -eq 0 ]; then
            echo "✓ Account deleted: $EMAIL"
        else
            echo "✗ Failed to delete account"
        fi
        ;;
        
    list)
        echo "Email accounts:"
        mysql -u mailuser -p"$DB_PASS" mailserver -e "SELECT email, active, created_at FROM virtual_users ORDER BY email;" 2>/dev/null
        ;;
        
    *)
        echo "Mail Account Manager"
        echo "Usage: mail-account {add|delete|list} [email] [password]"
        echo ""
        echo "Commands:"
        echo "  add email@domain.com password  - Add new account"
        echo "  delete email@domain.com        - Delete account"
        echo "  list                           - List all accounts"
        echo ""
        echo "Examples:"
        echo "  mail-account add sender@example.com MyPassword123"
        echo "  mail-account delete sender@example.com"
        echo "  mail-account list"
        echo ""
        echo "Note: Accounts created here can be used in Mailwizz as SMTP credentials"
        ;;
esac
EOF

chmod +x /usr/local/bin/mail-account

# ===================================================================
# 2. MAIL QUEUE MANAGER
# ===================================================================

print_message "Creating mail queue manager..."

cat > /usr/local/bin/mail-queue << 'EOF'
#!/bin/bash

# Mail Queue Manager

case "$1" in
    show)
        mailq
        ;;
        
    count)
        echo -n "Messages in queue: "
        mailq | grep -c "^[A-F0-9]" || echo "0"
        ;;
        
    flush)
        postqueue -f
        echo "✓ Queue flush initiated"
        ;;
        
    clear)
        read -p "This will delete ALL queued mail. Are you sure? (yes/no): " confirm
        if [ "$confirm" = "yes" ]; then
            postsuper -d ALL
            echo "✓ Queue cleared"
        else
            echo "Cancelled"
        fi
        ;;
        
    hold)
        postsuper -h ALL
        echo "✓ All messages put on hold"
        ;;
        
    release)
        postsuper -H ALL
        echo "✓ All messages released from hold"
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
        echo "  hold    - Put all mail on hold"
        echo "  release - Release held mail"
        ;;
esac
EOF

chmod +x /usr/local/bin/mail-queue

# ===================================================================
# 3. TEST EMAIL SENDER - MAILWIZZ AWARE
# ===================================================================

print_message "Creating test email sender..."

cat > /usr/local/bin/test-email << 'EOF'
#!/bin/bash

# Test Email Sender - Compatible with Mailwizz testing

# Get default domain from postfix
DEFAULT_DOMAIN=$(postconf -h mydomain 2>/dev/null || hostname -d)

# Check for parameters
TO="${1}"
FROM="${2}"

# If no recipient provided, show usage
if [ -z "$TO" ]; then
    echo "TEST EMAIL SENDER"
    echo "================="
    echo ""
    echo "Usage: test-email <recipient> [from-address]"
    echo ""
    echo "Examples:"
    echo "  test-email admin@example.com"
    echo "  test-email check-auth@verifier.port25.com newsletter@yourdomain.com"
    echo "  test-email test@mail-tester.com user@yourdomain.com"
    echo ""
    echo "Popular test services:"
    echo "  • check-auth@verifier.port25.com - Tests SPF, DKIM, DMARC"
    echo "  • https://www.mail-tester.com - Get a test address from website"
    echo "  • https://www.gmass.co/smtp-test - SMTP connection test"
    echo ""
    echo "Your configured email accounts:"
    if [ -f /root/.mail_db_password ]; then
        DB_PASS=$(cat /root/.mail_db_password)
        mysql -u mailuser -p"$DB_PASS" mailserver -e "SELECT email FROM virtual_users WHERE active=1;" 2>/dev/null | tail -n +2
    fi
    echo ""
    echo "Note: These same accounts can be used in Mailwizz as SMTP users"
    exit 1
fi

# If no FROM address, try to find one
if [ -z "$FROM" ]; then
    if [ -f /root/.mail_db_password ]; then
        DB_PASS=$(cat /root/.mail_db_password)
        FIRST_ACCOUNT=$(mysql -u mailuser -p"$DB_PASS" mailserver -e "SELECT email FROM virtual_users WHERE active=1 LIMIT 1;" 2>/dev/null | tail -1)
        if [ ! -z "$FIRST_ACCOUNT" ] && [ "$FIRST_ACCOUNT" != "email" ]; then
            FROM="$FIRST_ACCOUNT"
            echo "Using sender: $FROM"
        else
            FROM="test@$DEFAULT_DOMAIN"
            echo "No email accounts found. Using: $FROM"
            echo "Create an account first with: mail-account add user@$DEFAULT_DOMAIN password"
        fi
    else
        FROM="test@$DEFAULT_DOMAIN"
    fi
fi

SUBJECT="Test Email from $FROM - $(date)"
TRACKING_ID=$(openssl rand -hex 16)

# Create test email with headers that Mailwizz would use
cat <<MESSAGE | sendmail -f "$FROM" "$TO"
From: $FROM
To: $TO
Subject: $SUBJECT
Date: $(date -R)
Message-ID: <$(date +%s).$(openssl rand -hex 8)@$(hostname -f)>
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
List-Unsubscribe: <http://$DEFAULT_DOMAIN/unsubscribe>
X-Mailer: Mail Server Test

This is a test email from your mail server.

========================================
SERVER INFORMATION
========================================
Timestamp: $(date)
Hostname: $(hostname -f)
Domain: $DEFAULT_DOMAIN
Server IP: $(hostname -I | awk '{print $1}')
From Address: $FROM
To Address: $TO

========================================
AUTHENTICATION TEST
========================================
This email tests:
✓ SMTP delivery
✓ SPF authentication (IP authorized)
✓ DKIM signature (if configured)
✓ DMARC policy compliance

========================================
MAILWIZZ INTEGRATION
========================================
This server is configured for Mailwizz:
- SMTP Host: $(hostname -f)
- Port: 587 (TLS) or 465 (SSL)
- Username: $FROM
- Website: http://$DEFAULT_DOMAIN

========================================

This email was generated by the mail server testing utility.
If you received this, your mail server is working correctly!

For authentication results:
• check-auth@verifier.port25.com
• https://www.mail-tester.com

Unsubscribe: This is a test email. For production emails,
Mailwizz will handle all unsubscribe links automatically.

MESSAGE

if [ $? -eq 0 ]; then
    echo "✓ Test email sent successfully!"
    echo ""
    echo "Details:"
    echo "  From: $FROM"
    echo "  To: $TO"
    echo "  Subject: $SUBJECT"
    echo ""
    echo "Check delivery status:"
    echo "  mail-log sent | grep '$TO'"
    echo ""
    if [[ "$TO" == *"verifier.port25.com"* ]]; then
        echo "Port25 will reply with authentication results to: $FROM"
    fi
    if [[ "$TO" == *"mail-tester.com"* ]]; then
        echo "Check your score at: https://www.mail-tester.com"
    fi
else
    echo "✗ Failed to send test email"
    echo ""
    echo "Troubleshooting:"
    echo "1. Check services: mail-status"
    echo "2. Check logs: mail-log errors"
    echo "3. Verify account: mail-account list"
    echo "4. Check DNS: check-dns"
fi
EOF

chmod +x /usr/local/bin/test-email

# ===================================================================
# 4. MAIL SERVER STATUS - WEBSITE AWARE
# ===================================================================

print_message "Creating mail server status checker..."

cat > /usr/local/bin/mail-status << 'EOF'
#!/bin/bash

# Mail Server Status Checker with Website Status

echo "MAIL SERVER STATUS"
echo "=================="
echo ""

# Get configuration
DOMAIN=$(postconf -h mydomain 2>/dev/null || hostname -d)
HOSTNAME=$(postconf -h myhostname 2>/dev/null || hostname -f)

# Services
echo "Services:"
for service in postfix dovecot opendkim mysql nginx; do
    printf "  %-10s: " "$service"
    if systemctl is-active --quiet $service; then
        echo "✓ Running"
    else
        echo "✗ Stopped"
    fi
done

echo ""

# Website Status
echo "Website:"
if [ -d "/var/www/$DOMAIN" ]; then
    echo "  URL: http://$DOMAIN"
    if [ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
        echo "  SSL: https://$DOMAIN (✓ Certificate installed)"
    else
        echo "  SSL: Not configured"
    fi
    echo "  Root: /var/www/$DOMAIN"
else
    echo "  Not configured"
fi

echo ""

# Email accounts
if [ -f /root/.mail_db_password ]; then
    DB_PASS=$(cat /root/.mail_db_password)
    ACCOUNT_COUNT=$(mysql -u mailuser -p"$DB_PASS" mailserver -e "SELECT COUNT(*) FROM virtual_users WHERE active=1;" 2>/dev/null | tail -1)
    DOMAIN_COUNT=$(mysql -u mailuser -p"$DB_PASS" mailserver -e "SELECT COUNT(*) FROM virtual_domains;" 2>/dev/null | tail -1)
    echo "Email Configuration:"
    echo "  Domains: $DOMAIN_COUNT"
    echo "  Accounts: $ACCOUNT_COUNT"
    echo ""
fi

# Ports
echo "Listening Ports:"
netstat -tlnp 2>/dev/null | grep -E ":(25|110|143|465|587|993|995|80|443|8891)\s" | while read line; do
    port=$(echo $line | grep -oE ":[0-9]+" | tr -d ':')
    service=$(echo $line | awk '{print $NF}' | cut -d'/' -f2)
    case $port in
        25) desc="SMTP" ;;
        587) desc="Submission" ;;
        465) desc="SMTPS" ;;
        143) desc="IMAP" ;;
        993) desc="IMAPS" ;;
        110) desc="POP3" ;;
        995) desc="POP3S" ;;
        80) desc="HTTP" ;;
        443) desc="HTTPS" ;;
        8891) desc="OpenDKIM" ;;
        *) desc="" ;;
    esac
    printf "  Port %-5s: %-12s (%s)\n" "$port" "$desc" "$service"
done

echo ""

# Queue
echo "Mail Queue:"
count=$(mailq | grep -c "^[A-F0-9]" 2>/dev/null || echo 0)
echo "  Messages: $count"

echo ""

# Disk usage
echo "Disk Usage:"
df -h /var/vmail 2>/dev/null | tail -1 | awk '{printf "  Mail storage: %s used of %s (%s)\n", $3, $2, $5}'
if [ -d "/var/www/$DOMAIN" ]; then
    du -sh "/var/www/$DOMAIN" 2>/dev/null | awk '{printf "  Website: %s\n", $1}'
fi

echo ""

# Mailwizz Configuration
echo "Mailwizz Configuration:"
echo "  SMTP Host: $HOSTNAME"
echo "  SMTP Port: 587 (TLS) or 465 (SSL)"
echo "  Website: http://$DOMAIN"
echo "  Config file: /var/www/$DOMAIN/mailwizz-config.txt"

echo ""

# Recent logs
echo "Recent Activity (last 5 entries):"
tail -5 /var/log/mail.log 2>/dev/null | sed 's/^/  /'
EOF

chmod +x /usr/local/bin/mail-status

# ===================================================================
# 5. DNS RECORD CHECKER
# ===================================================================

print_message "Creating DNS record checker..."

cat > /usr/local/bin/check-dns << 'EOF'
#!/bin/bash

# DNS Record Checker

DOMAIN="${1:-$(hostname -d)}"
HOSTNAME="mail.$DOMAIN"

echo "DNS RECORD CHECK FOR: $DOMAIN"
echo "============================"
echo ""

# A Records
echo "A Records:"
echo -n "  $DOMAIN: "
A_RECORD=$(dig +short A $DOMAIN @8.8.8.8)
if [ ! -z "$A_RECORD" ]; then
    echo "✓ $A_RECORD"
else
    echo "✗ NOT FOUND (needed for website)"
fi

echo -n "  mail.$DOMAIN: "
A_RECORD=$(dig +short A mail.$DOMAIN @8.8.8.8)
if [ ! -z "$A_RECORD" ]; then
    echo "✓ $A_RECORD"
else
    echo "✗ NOT FOUND"
fi

echo ""

# MX Record
echo -n "MX record: "
MX_RECORD=$(dig +short MX $DOMAIN @8.8.8.8)
if [ ! -z "$MX_RECORD" ]; then
    echo "✓ $MX_RECORD"
else
    echo "✗ NOT FOUND"
fi

# SPF Record
echo -n "SPF record: "
SPF_RECORD=$(dig +short TXT $DOMAIN @8.8.8.8 | grep "v=spf1")
if [ ! -z "$SPF_RECORD" ]; then
    echo "✓ Found"
    echo "  $SPF_RECORD"
else
    echo "✗ NOT FOUND"
fi

# DKIM Record
echo -n "DKIM record: "
DKIM_RECORD=$(dig +short TXT mail._domainkey.$DOMAIN @8.8.8.8 | head -1)
if [ ! -z "$DKIM_RECORD" ]; then
    echo "✓ Found (key present)"
else
    echo "✗ NOT FOUND"
fi

# DMARC Record
echo -n "DMARC record: "
DMARC_RECORD=$(dig +short TXT _dmarc.$DOMAIN @8.8.8.8)
if [ ! -z "$DMARC_RECORD" ]; then
    echo "✓ $DMARC_RECORD"
else
    echo "✗ NOT FOUND"
fi

# PTR Record
IP=$(dig +short A mail.$DOMAIN @8.8.8.8 | head -1)
if [ ! -z "$IP" ]; then
    echo -n "PTR record ($IP): "
    PTR=$(dig +short -x $IP @8.8.8.8)
    if [ ! -z "$PTR" ]; then
        echo "✓ $PTR"
    else
        echo "✗ NOT SET (contact hosting provider)"
    fi
fi

echo ""
echo "Test your configuration:"
echo "  • Send test: test-email check-auth@verifier.port25.com"
echo "  • Check score: https://www.mail-tester.com"
echo "  • MX Toolbox: https://mxtoolbox.com/SuperTool.aspx?action=mx:$DOMAIN"
echo "  • Website: http://$DOMAIN"
echo ""
echo "Note: DNS propagation can take up to 48 hours"
EOF

chmod +x /usr/local/bin/check-dns

# ===================================================================
# 6. BACKUP SCRIPT - INCLUDES WEBSITE
# ===================================================================

print_message "Creating backup script..."

cat > /usr/local/bin/mail-backup << 'EOF'
#!/bin/bash

# Mail Server Backup including Website

BACKUP_DIR="/backup/mailserver"
DATE=$(date +%Y%m%d-%H%M%S)
BACKUP_FILE="$BACKUP_DIR/mailserver-$DATE.tar.gz"
DOMAIN=$(postconf -h mydomain 2>/dev/null || hostname -d)

# Create backup directory
mkdir -p "$BACKUP_DIR"

echo "Starting backup..."

# Create backup including website
tar czf "$BACKUP_FILE" \
    /etc/postfix \
    /etc/dovecot \
    /etc/opendkim \
    /etc/nginx/sites-available \
    /var/vmail \
    /var/www/$DOMAIN \
    /root/.mail_db_password \
    /root/dns-records-*.txt \
    /root/cloudflare-dns-config.txt \
    /root/mail-server-config.txt \
    2>/dev/null

if [ $? -eq 0 ]; then
    echo "✓ Backup completed: $BACKUP_FILE"
    echo "  Size: $(du -h $BACKUP_FILE | cut -f1)"
    
    # Keep only last 7 backups
    ls -t $BACKUP_DIR/mailserver-*.tar.gz | tail -n +8 | xargs -r rm
    
    # Show backup contents
    echo ""
    echo "Backup includes:"
    echo "  • Postfix configuration"
    echo "  • Dovecot configuration"
    echo "  • OpenDKIM keys and config"
    echo "  • Nginx website configuration"
    echo "  • All mailboxes (/var/vmail)"
    echo "  • Website files (/var/www/$DOMAIN)"
    echo "  • Database password"
    echo "  • DNS configuration"
else
    echo "✗ Backup failed"
fi
EOF

chmod +x /usr/local/bin/mail-backup

# ===================================================================
# 7. MAIL LOG VIEWER
# ===================================================================

print_message "Creating mail log viewer..."

cat > /usr/local/bin/mail-log << 'EOF'
#!/bin/bash

# Mail Log Viewer

case "$1" in
    follow)
        tail -f /var/log/mail.log
        ;;
        
    errors)
        echo "Recent errors and warnings:"
        grep -i "error\|warning\|fatal\|panic" /var/log/mail.log | tail -20
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
        echo "DKIM signing activity:"
        grep -i "dkim" /var/log/mail.log | tail -20
        ;;
        
    today)
        echo "Today's activity:"
        grep "$(date +'%b %e')" /var/log/mail.log | tail -50
        ;;
        
    search)
        if [ -z "$2" ]; then
            echo "Usage: mail-log search <pattern>"
            exit 1
        fi
        echo "Searching for: $2"
        grep -i "$2" /var/log/mail.log | tail -20
        ;;
        
    *)
        echo "Mail Log Viewer"
        echo "Usage: mail-log {follow|errors|sent|bounced|dkim|today|search <pattern>}"
        echo ""
        echo "Commands:"
        echo "  follow         - Follow log in real-time"
        echo "  errors         - Show recent errors"
        echo "  sent           - Show recently sent mail"
        echo "  bounced        - Show recently bounced mail"
        echo "  dkim           - Show DKIM signing activity"
        echo "  today          - Show today's activity"
        echo "  search <text>  - Search for pattern"
        echo ""
        echo "Examples:"
        echo "  mail-log follow"
        echo "  mail-log sent"
        echo "  mail-log dkim"
        echo "  mail-log search gmail.com"
        ;;
esac
EOF

chmod +x /usr/local/bin/mail-log

# ===================================================================
# 8. QUICK MAIL TEST
# ===================================================================

print_message "Creating quick mail test utility..."

cat > /usr/local/bin/mail-test << 'EOF'
#!/bin/bash

echo "QUICK MAIL SERVER TEST"
echo "======================"
echo ""

# Get domain info
DOMAIN=$(postconf -h mydomain 2>/dev/null || hostname -d)
HOSTNAME=$(postconf -h myhostname 2>/dev/null || hostname -f)

# 1. Service check
echo "1. Service Status:"
SERVICES_OK=0
for service in postfix dovecot opendkim nginx; do
    printf "   %-10s: " "$service"
    if systemctl is-active --quiet $service; then
        echo "✓ Running"
        SERVICES_OK=$((SERVICES_OK + 1))
    else
        echo "✗ Not running"
        echo "     Fix with: systemctl start $service"
    fi
done
echo ""

# 2. Port check
echo "2. Port Status:"
PORTS_OK=0
for port in 25 587 993 80; do
    printf "   Port %-5s: " "$port"
    if netstat -tln 2>/dev/null | grep -q ":$port "; then
        echo "✓ Open"
        PORTS_OK=$((PORTS_OK + 1))
    else
        echo "✗ Closed"
    fi
done
echo ""

# 3. Website check
echo "3. Website Status:"
if curl -s -o /dev/null -w "%{http_code}" "http://$DOMAIN" | grep -q "200\|301\|302"; then
    echo "   ✓ Website is accessible"
else
    echo "   ✗ Website not responding"
fi
echo ""

# 4. Email accounts
echo "4. Email Accounts:"
if [ -f /root/.mail_db_password ]; then
    DB_PASS=$(cat /root/.mail_db_password)
    ACCOUNTS=$(mysql -u mailuser -p"$DB_PASS" mailserver -e "SELECT email FROM virtual_users WHERE active=1;" 2>/dev/null | tail -n +2)
    if [ ! -z "$ACCOUNTS" ]; then
        echo "$ACCOUNTS" | while read account; do
            echo "   • $account"
        done
    else
        echo "   ✗ No email accounts found"
        echo "   Create one with: mail-account add user@$DOMAIN password"
    fi
else
    echo "   ✗ Database not configured"
fi
echo ""

# 5. DNS check
echo "5. DNS Quick Check:"
printf "   MX Record : "
if dig +short MX $DOMAIN @8.8.8.8 | grep -q mail.$DOMAIN; then
    echo "✓ Configured"
else
    echo "✗ Not found or incorrect"
fi
printf "   A Record  : "
if [ ! -z "$(dig +short A mail.$DOMAIN @8.8.8.8)" ]; then
    echo "✓ Configured"
else
    echo "✗ Not found"
fi
printf "   Website   : "
if [ ! -z "$(dig +short A $DOMAIN @8.8.8.8)" ]; then
    echo "✓ Configured"
else
    echo "✗ Not found"
fi
echo ""

# 6. SSL Certificate
echo "6. SSL Certificates:"
if [ -f "/etc/letsencrypt/live/mail.$DOMAIN/fullchain.pem" ]; then
    echo "   Mail: ✓ Let's Encrypt certificate installed"
else
    echo "   Mail: ✗ No certificate"
fi
if [ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
    echo "   Website: ✓ Let's Encrypt certificate installed"
else
    echo "   Website: ✗ No certificate"
fi
echo ""

# 7. OpenDKIM check
echo "7. DKIM Status:"
if netstat -lnp 2>/dev/null | grep -q ":8891"; then
    echo "   ✓ OpenDKIM is listening on port 8891"
else
    echo "   ✗ OpenDKIM not listening"
fi
if [ -f "/etc/opendkim/keys/$DOMAIN/mail.txt" ]; then
    echo "   ✓ DKIM key generated"
else
    echo "   ✗ DKIM key missing"
fi
echo ""

# Summary
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if [ $SERVICES_OK -eq 4 ] && [ $PORTS_OK -eq 4 ]; then
    echo "✓ Server appears to be working!"
    echo ""
    echo "Next steps:"
    echo "1. Send test email: test-email check-auth@verifier.port25.com"
    echo "2. Check score: https://www.mail-tester.com"
    echo "3. Configure Mailwizz with: $HOSTNAME:587"
    echo "4. Update unsubscribe URL in: /etc/nginx/sites-available/$DOMAIN"
else
    echo "⚠ Some issues detected. Please fix them before sending emails."
    echo ""
    echo "For detailed diagnosis run: troubleshoot"
fi
EOF

chmod +x /usr/local/bin/mail-test

# ===================================================================
# 9. MAILWIZZ HELPER
# ===================================================================

print_message "Creating Mailwizz helper..."

cat > /usr/local/bin/mailwizz-info << 'EOF'
#!/bin/bash

# Mailwizz Configuration Helper

DOMAIN=$(postconf -h mydomain 2>/dev/null || hostname -d)
HOSTNAME=$(postconf -h myhostname 2>/dev/null || hostname -f)

echo "MAILWIZZ CONFIGURATION INFORMATION"
echo "==================================="
echo ""
echo "Add this server to Mailwizz as a Delivery Server:"
echo ""
echo "Server Type: SMTP"
echo "─────────────────"
echo "Hostname: $HOSTNAME"
echo "Port: 587 (recommended) or 465"
echo "Protocol: TLS (for port 587) or SSL (for port 465)"
echo "Timeout: 30"
echo ""
echo "Authentication:"
echo "─────────────"
if [ -f /root/.mail_db_password ]; then
    DB_PASS=$(cat /root/.mail_db_password)
    ACCOUNTS=$(mysql -u mailuser -p"$DB_PASS" mailserver -e "SELECT email FROM virtual_users WHERE active=1 LIMIT 5;" 2>/dev/null | tail -n +2)
    if [ ! -z "$ACCOUNTS" ]; then
        echo "Available SMTP users:"
        echo "$ACCOUNTS" | while read account; do
            echo "  • Username: $account"
        done
        echo "  • Password: [use the password you set]"
    else
        echo "No SMTP users configured yet."
        echo "Create one with: mail-account add sender@$DOMAIN password"
    fi
fi
echo ""
echo "Sending Settings:"
echo "───────────────"
echo "From Email: Use any configured account above"
echo "From Name: Your choice"
echo "Reply-To: Your choice"
echo "Return-Path: Same as From Email"
echo ""
echo "Signing:"
echo "────────"
echo "Force Signing: Yes"
echo "Signing Enabled: Yes"
echo "DKIM Signing: Handled by this server automatically"
echo ""
echo "Website Configuration:"
echo "────────────────────"
echo "Domain URL: http://$DOMAIN"
if [ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
    echo "SSL URL: https://$DOMAIN"
fi
echo ""
echo "IMPORTANT: Update unsubscribe redirect"
echo "Edit: /etc/nginx/sites-available/$DOMAIN"
echo "Change the placeholder URL to your Mailwizz unsubscribe URL"
echo "Then run: systemctl reload nginx"
echo ""
echo "Testing:"
echo "────────"
echo "1. Test SMTP connection from Mailwizz using 'Validate Server'"
echo "2. Send test campaign to: check-auth@verifier.port25.com"
echo "3. Check authentication at: https://www.mail-tester.com"
echo ""
echo "For more details see: /var/www/$DOMAIN/mailwizz-config.txt"
EOF

chmod +x /usr/local/bin/mailwizz-info

# ===================================================================
# COMPLETION
# ===================================================================

print_header "Utilities Created Successfully!"
echo ""
echo "Available commands:"
echo ""
echo "ESSENTIAL COMMANDS:"
echo "  test-email     - Send test email with auth checking"
echo "  mail-account   - Manage email accounts (SMTP users)"
echo "  mail-status    - Check server and website status"
echo "  check-dns      - Verify all DNS records"
echo "  mailwizz-info  - Show Mailwizz configuration"
echo ""
echo "MANAGEMENT COMMANDS:"
echo "  mail-queue     - Manage mail queue"
echo "  mail-backup    - Backup mail server and website"
echo "  mail-log       - View mail logs with DKIM info"
echo "  mail-test      - Quick server test"
echo "  maildb         - Database management"
echo ""
echo "QUICK EXAMPLES:"

# Show domain-specific examples if available
if [ ! -z "$DOMAIN_NAME" ]; then
    if [ ! -z "$FIRST_EMAIL" ]; then
        echo "  test-email recipient@example.com $FIRST_EMAIL"
        echo "  mailwizz-info    # Shows config for Mailwizz"
    else
        echo "  mail-account add user@$DOMAIN_NAME password123"
        echo "  test-email recipient@example.com user@$DOMAIN_NAME"
    fi
    echo "  check-dns $DOMAIN_NAME"
else
    echo "  mail-account add user@yourdomain.com password123"
    echo "  test-email check-auth@verifier.port25.com"
    echo "  mailwizz-info"
fi

echo "  mail-status"
echo "  mail-log follow"
echo ""
echo "✓ All utilities have been created in /usr/local/bin/"
echo ""
echo "Note: These utilities are optimized for use with Mailwizz"
