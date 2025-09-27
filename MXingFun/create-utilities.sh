#!/bin/bash

# =================================================================
# MAIL SERVER UTILITY SCRIPTS CREATOR
# Version: 16.0.2
# Creates helpful management scripts for the mail server
# =================================================================

# This script creates various utility commands for managing the mail server
# It should be run after the main installation is complete

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

# ===================================================================
# 1. EMAIL ACCOUNT MANAGER
# ===================================================================

print_message "Creating email account manager..."

cat > /usr/local/bin/mail-account << 'EOF'
#!/bin/bash

# Email Account Manager
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
            echo "✓ Account created: $EMAIL"
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
        mysql -u mailuser -p"$DB_PASS" mailserver -e "SELECT email FROM virtual_users;" 2>/dev/null | tail -n +2
        ;;
        
    *)
        echo "Mail Account Manager"
        echo "Usage: mail-account {add|delete|list} [email] [password]"
        echo ""
        echo "Commands:"
        echo "  add email@domain.com password  - Add new account"
        echo "  delete email@domain.com        - Delete account"
        echo "  list                           - List all accounts"
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
# 3. TEST EMAIL SENDER
# ===================================================================

print_message "Creating test email sender..."

cat > /usr/local/bin/test-email << 'EOF'
#!/bin/bash

# Test Email Sender

TO="${1:-check-auth@verifier.port25.com}"
FROM="${2:-test@$(hostname -d)}"
SUBJECT="Test Email - $(date)"

# Create test email
cat <<MESSAGE | sendmail -f "$FROM" "$TO"
From: $FROM
To: $TO
Subject: $SUBJECT
Date: $(date -R)

This is a test email from your mail server.

Server: $(hostname -f)
IP: $(hostname -I | awk '{print $1}')
Time: $(date)

This email was sent to verify that your mail server is working correctly.
MESSAGE

if [ $? -eq 0 ]; then
    echo "✓ Test email sent"
    echo "  From: $FROM"
    echo "  To: $TO"
    echo ""
    echo "Check the mail log for delivery status:"
    echo "  tail -f /var/log/mail.log"
else
    echo "✗ Failed to send test email"
fi
EOF

chmod +x /usr/local/bin/test-email

# ===================================================================
# 4. MAIL SERVER STATUS
# ===================================================================

print_message "Creating mail server status checker..."

cat > /usr/local/bin/mail-status << 'EOF'
#!/bin/bash

# Mail Server Status Checker

echo "MAIL SERVER STATUS"
echo "=================="
echo ""

# Services
echo "Services:"
for service in postfix dovecot opendkim mysql; do
    printf "  %-10s: " "$service"
    if systemctl is-active --quiet $service; then
        echo "✓ Running"
    else
        echo "✗ Stopped"
    fi
done

echo ""

# Ports
echo "Listening Ports:"
netstat -tlnp 2>/dev/null | grep -E ":(25|110|143|465|587|993|995)\s" | while read line; do
    port=$(echo $line | grep -oE ":[0-9]+" | tr -d ':')
    service=$(echo $line | awk '{print $NF}' | cut -d'/' -f2)
    printf "  Port %-5s: %s\n" "$port" "$service"
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

# A Record
echo -n "A record (mail.$DOMAIN): "
dig +short A mail.$DOMAIN @8.8.8.8 || echo "NOT FOUND"

# MX Record
echo -n "MX record ($DOMAIN): "
dig +short MX $DOMAIN @8.8.8.8 || echo "NOT FOUND"

# SPF Record
echo -n "SPF record ($DOMAIN): "
dig +short TXT $DOMAIN @8.8.8.8 | grep "v=spf1" || echo "NOT FOUND"

# DKIM Record
echo -n "DKIM record (mail._domainkey.$DOMAIN): "
dig +short TXT mail._domainkey.$DOMAIN @8.8.8.8 | head -1 || echo "NOT FOUND"

# DMARC Record
echo -n "DMARC record (_dmarc.$DOMAIN): "
dig +short TXT _dmarc.$DOMAIN @8.8.8.8 || echo "NOT FOUND"

# PTR Record
IP=$(dig +short A mail.$DOMAIN @8.8.8.8 | head -1)
if [ ! -z "$IP" ]; then
    echo -n "PTR record ($IP): "
    dig +short -x $IP @8.8.8.8 || echo "NOT FOUND"
fi

echo ""
echo "Note: DNS propagation can take up to 48 hours"
EOF

chmod +x /usr/local/bin/check-dns

# ===================================================================
# 6. SIMPLE BACKUP SCRIPT
# ===================================================================

print_message "Creating backup script..."

cat > /usr/local/bin/mail-backup << 'EOF'
#!/bin/bash

# Simple Mail Server Backup

BACKUP_DIR="/backup/mailserver"
DATE=$(date +%Y%m%d-%H%M%S)
BACKUP_FILE="$BACKUP_DIR/mailserver-$DATE.tar.gz"

# Create backup directory
mkdir -p "$BACKUP_DIR"

echo "Starting backup..."

# Create backup
tar czf "$BACKUP_FILE" \
    /etc/postfix \
    /etc/dovecot \
    /etc/opendkim \
    /var/vmail \
    /root/.mail_db_password \
    /root/dns-records-*.txt \
    2>/dev/null

if [ $? -eq 0 ]; then
    echo "✓ Backup completed: $BACKUP_FILE"
    echo "  Size: $(du -h $BACKUP_FILE | cut -f1)"
    
    # Keep only last 7 backups
    ls -t $BACKUP_DIR/mailserver-*.tar.gz | tail -n +8 | xargs -r rm
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
        grep -i "error\|warning\|fatal\|panic" /var/log/mail.log | tail -20
        ;;
        
    sent)
        grep "status=sent" /var/log/mail.log | tail -20
        ;;
        
    bounced)
        grep "status=bounced" /var/log/mail.log | tail -20
        ;;
        
    search)
        if [ -z "$2" ]; then
            echo "Usage: mail-log search <pattern>"
            exit 1
        fi
        grep -i "$2" /var/log/mail.log | tail -20
        ;;
        
    *)
        echo "Mail Log Viewer"
        echo "Usage: mail-log {follow|errors|sent|bounced|search <pattern>}"
        echo ""
        echo "Commands:"
        echo "  follow         - Follow log in real-time"
        echo "  errors         - Show recent errors"
        echo "  sent           - Show recently sent mail"
        echo "  bounced        - Show recently bounced mail"
        echo "  search <text>  - Search for pattern"
        ;;
esac
EOF

chmod +x /usr/local/bin/mail-log

# ===================================================================
# COMPLETION
# ===================================================================

print_header "Utilities Created Successfully!"
echo ""
echo "Available commands:"
echo ""
echo "  mail-account  - Manage email accounts"
echo "  mail-queue    - Manage mail queue"
echo "  mail-status   - Check server status"
echo "  mail-backup   - Backup mail server"
echo "  mail-log      - View mail logs"
echo "  test-email    - Send test email"
echo "  check-dns     - Check DNS records"
echo ""
echo "Examples:"
echo "  mail-account add user@domain.com password123"
echo "  mail-queue show"
echo "  test-email recipient@example.com"
echo "  check-dns yourdomain.com"
echo ""
echo "✓ All utilities have been created in /usr/local/bin/"
