#!/bin/bash

# =================================================================
# MAIL SERVER TROUBLESHOOTING SCRIPT
# Version: 16.1.0
# Diagnoses and fixes common mail server issues including DKIM
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

print_header "Mail Server Troubleshooting"
echo ""

# Load configuration
if [ -f "$(pwd)/install.conf" ]; then
    source "$(pwd)/install.conf"
elif [ -f "/root/mail-installer/install.conf" ]; then
    source "/root/mail-installer/install.conf"
fi

# Get domain info
if [ -z "$DOMAIN_NAME" ]; then
    DOMAIN_NAME=$(hostname -d)
    HOSTNAME=$(hostname -f)
else
    HOSTNAME=${HOSTNAME:-"mail.$DOMAIN_NAME"}
fi

PRIMARY_IP=$(curl -s https://ipinfo.io/ip 2>/dev/null || hostname -I | awk '{print $1}')

echo "Domain: $DOMAIN_NAME"
echo "Hostname: $HOSTNAME"
echo "Server IP: $PRIMARY_IP"
echo ""

# ===================================================================
# 1. SERVICE CHECKS
# ===================================================================

print_header "Checking Services"

ISSUES_FOUND=0

check_service() {
    local service=$1
    echo -n "  $service: "
    if systemctl is-active --quiet $service; then
        print_message "✓ Running"
    else
        print_error "✗ Not running"
        ISSUES_FOUND=$((ISSUES_FOUND + 1))
        echo -n "    Attempting to start... "
        systemctl start $service 2>/dev/null
        sleep 2
        if systemctl is-active --quiet $service; then
            print_message "✓ Started"
        else
            print_error "✗ Failed"
            echo "    Error: $(systemctl status $service 2>&1 | grep -m1 "Active:" )"
        fi
    fi
}

check_service "postfix"
check_service "dovecot"
check_service "opendkim"
check_service "mysql" || check_service "mariadb"
check_service "nginx"

# ===================================================================
# 2. DKIM TROUBLESHOOTING
# ===================================================================

print_header "DKIM Configuration Check"

DKIM_ISSUES=0

# Check DKIM key exists
echo -n "DKIM key file: "
if [ -f "/etc/opendkim/keys/$DOMAIN_NAME/mail.private" ]; then
    print_message "✓ Exists"
else
    print_error "✗ Missing"
    DKIM_ISSUES=$((DKIM_ISSUES + 1))
    echo -n "  Generating DKIM keys... "
    mkdir -p /etc/opendkim/keys/$DOMAIN_NAME
    cd /etc/opendkim/keys/$DOMAIN_NAME
    opendkim-genkey -s mail -d $DOMAIN_NAME -b 2048 2>/dev/null
    chown -R opendkim:opendkim /etc/opendkim
    chmod 600 mail.private
    chmod 644 mail.txt
    cd - > /dev/null
    if [ -f "/etc/opendkim/keys/$DOMAIN_NAME/mail.private" ]; then
        print_message "✓ Generated"
    else
        print_error "✗ Generation failed"
    fi
fi

# Check OpenDKIM configuration
echo -n "OpenDKIM config: "
if [ -f "/etc/opendkim.conf" ]; then
    if grep -q "Socket.*inet:8891@localhost" /etc/opendkim.conf; then
        print_message "✓ Configured"
    else
        print_warning "⚠ Incorrect socket configuration"
        echo "  Fixing configuration..."
        sed -i 's/^Socket.*/Socket inet:8891@localhost/' /etc/opendkim.conf
        systemctl restart opendkim
    fi
else
    print_error "✗ Missing"
    DKIM_ISSUES=$((DKIM_ISSUES + 1))
fi

# Check if OpenDKIM is listening
echo -n "OpenDKIM port 8891: "
if netstat -lnp 2>/dev/null | grep -q ":8891"; then
    print_message "✓ Listening"
else
    print_error "✗ Not listening"
    DKIM_ISSUES=$((DKIM_ISSUES + 1))
    echo "  Restarting OpenDKIM..."
    systemctl restart opendkim
    sleep 2
    if netstat -lnp 2>/dev/null | grep -q ":8891"; then
        print_message "  ✓ Now listening"
    else
        print_error "  ✗ Still not listening"
    fi
fi

# Check Postfix milter configuration
echo -n "Postfix DKIM integration: "
MILTER=$(postconf smtpd_milters 2>/dev/null)
if [[ "$MILTER" == *"localhost:8891"* ]]; then
    print_message "✓ Configured"
else
    print_error "✗ Not configured"
    DKIM_ISSUES=$((DKIM_ISSUES + 1))
    echo "  Configuring Postfix to use OpenDKIM..."
    postconf -e "milter_protocol = 6"
    postconf -e "milter_default_action = accept"
    postconf -e "smtpd_milters = inet:localhost:8891"
    postconf -e "non_smtpd_milters = inet:localhost:8891"
    systemctl reload postfix
    print_message "  ✓ Configured"
fi

# Check DKIM in DNS
echo -n "DKIM DNS record: "
DKIM_DNS=$(dig +short TXT mail._domainkey.$DOMAIN_NAME @8.8.8.8 2>/dev/null | grep "v=DKIM1")
if [ ! -z "$DKIM_DNS" ]; then
    print_message "✓ Found in DNS"
else
    print_warning "⚠ Not found in DNS"
    if [ -f "/etc/opendkim/keys/$DOMAIN_NAME/mail.txt" ]; then
        echo "  Add this TXT record to DNS:"
        echo "  Name: mail._domainkey.$DOMAIN_NAME"
        echo "  Value: $(cat /etc/opendkim/keys/$DOMAIN_NAME/mail.txt | grep -v '(' | grep -v ')' | tr -d '\n\t" ')"
    fi
fi

# ===================================================================
# 3. PORT CHECKS
# ===================================================================

print_header "Port Availability Check"

check_port() {
    local port=$1
    local service=$2
    echo -n "  Port $port ($service): "
    if netstat -tuln 2>/dev/null | grep -q ":$port "; then
        print_message "✓ Open"
    else
        print_warning "⚠ Not listening"
        ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
}

check_port 25 "SMTP"
check_port 587 "Submission"
check_port 465 "SMTPS"
check_port 143 "IMAP"
check_port 993 "IMAPS"
check_port 110 "POP3"
check_port 995 "POP3S"
check_port 80 "HTTP"
check_port 443 "HTTPS"
check_port 8891 "OpenDKIM"

# ===================================================================
# 4. DNS CHECKS
# ===================================================================

print_header "DNS Configuration Check"

DNS_ISSUES=0

# A record for mail subdomain
echo -n "A record for $HOSTNAME: "
A_RECORD=$(dig +short A $HOSTNAME @8.8.8.8 2>/dev/null | head -1)
if [ "$A_RECORD" == "$PRIMARY_IP" ]; then
    print_message "✓ Correct ($A_RECORD)"
else
    if [ -z "$A_RECORD" ]; then
        print_error "✗ Not found"
    else
        print_warning "⚠ Incorrect ($A_RECORD, expected $PRIMARY_IP)"
    fi
    DNS_ISSUES=$((DNS_ISSUES + 1))
fi

# MX record
echo -n "MX record: "
MX_RECORD=$(dig +short MX $DOMAIN_NAME @8.8.8.8 2>/dev/null | awk '{print $2}' | sed 's/\.$//' | head -1)
if [ "$MX_RECORD" == "$HOSTNAME" ]; then
    print_message "✓ Correct ($MX_RECORD)"
else
    if [ -z "$MX_RECORD" ]; then
        print_error "✗ Not found"
    else
        print_warning "⚠ Incorrect ($MX_RECORD, expected $HOSTNAME)"
    fi
    DNS_ISSUES=$((DNS_ISSUES + 1))
fi

# SPF record
echo -n "SPF record: "
SPF=$(dig +short TXT $DOMAIN_NAME @8.8.8.8 2>/dev/null | grep "v=spf1")
if [ ! -z "$SPF" ]; then
    print_message "✓ Found"
else
    print_error "✗ Not found"
    DNS_ISSUES=$((DNS_ISSUES + 1))
    echo "  Add TXT record: v=spf1 mx a ip4:$PRIMARY_IP ~all"
fi

# PTR record
echo -n "PTR record: "
PTR=$(dig +short -x $PRIMARY_IP @8.8.8.8 2>/dev/null | sed 's/\.$//')
if [ "$PTR" == "$HOSTNAME" ]; then
    print_message "✓ Correct ($PTR)"
else
    if [ -z "$PTR" ]; then
        print_warning "⚠ Not configured"
    else
        print_warning "⚠ Incorrect ($PTR, expected $HOSTNAME)"
    fi
    echo "  Contact your hosting provider to set PTR record"
fi

# ===================================================================
# 5. PERMISSION CHECKS
# ===================================================================

print_header "Permission Checks"

# Check mail directory permissions
echo -n "Mail directory (/var/vmail): "
if [ -d "/var/vmail" ]; then
    OWNER=$(stat -c "%U:%G" /var/vmail)
    if [ "$OWNER" == "vmail:vmail" ]; then
        print_message "✓ Correct ownership"
    else
        print_warning "⚠ Incorrect ownership ($OWNER)"
        chown -R vmail:vmail /var/vmail
        print_message "  ✓ Fixed"
    fi
else
    print_warning "⚠ Directory doesn't exist"
    mkdir -p /var/vmail
    chown -R vmail:vmail /var/vmail
    print_message "  ✓ Created"
fi

# Check DKIM key permissions
echo -n "DKIM key permissions: "
if [ -f "/etc/opendkim/keys/$DOMAIN_NAME/mail.private" ]; then
    PERMS=$(stat -c "%a" /etc/opendkim/keys/$DOMAIN_NAME/mail.private)
    if [ "$PERMS" == "600" ]; then
        print_message "✓ Correct (600)"
    else
        print_warning "⚠ Incorrect ($PERMS)"
        chmod 600 /etc/opendkim/keys/$DOMAIN_NAME/mail.private
        print_message "  ✓ Fixed"
    fi
else
    print_warning "⚠ Key doesn't exist"
fi

# ===================================================================
# 6. MAIL QUEUE CHECK
# ===================================================================

print_header "Mail Queue Status"

QUEUE_COUNT=$(mailq | grep -c "^[A-Z0-9]" 2>/dev/null || echo "0")
echo -n "Messages in queue: "
if [ "$QUEUE_COUNT" -eq 0 ]; then
    print_message "✓ Empty"
else
    print_warning "$QUEUE_COUNT messages"
    echo "  Run 'mail-queue show' to view"
    echo "  Run 'mail-queue flush' to attempt delivery"
fi

# ===================================================================
# 7. DATABASE CHECK
# ===================================================================

print_header "Database Connectivity"

echo -n "Database connection: "
if [ -f /root/.mail_db_password ]; then
    DB_PASS=$(cat /root/.mail_db_password)
    if mysql -u mailuser -p"$DB_PASS" mailserver -e "SELECT 1" > /dev/null 2>&1; then
        print_message "✓ Working"
        
        # Count users
        USER_COUNT=$(mysql -u mailuser -p"$DB_PASS" mailserver -e "SELECT COUNT(*) FROM virtual_users;" 2>/dev/null | tail -1)
        echo "  Email accounts: $USER_COUNT"
    else
        print_error "✗ Connection failed"
        ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
else
    print_error "✗ Password file missing"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
fi

# ===================================================================
# 8. LOG CHECK
# ===================================================================

print_header "Recent Log Errors"

echo "Last 5 mail errors:"
grep -i "error\|failed\|rejected" /var/log/mail.log 2>/dev/null | tail -5 | while read line; do
    echo "  • $(echo "$line" | cut -d' ' -f6-)"
done

if [ ! -s /var/log/mail.log ]; then
    print_warning "  Mail log is empty or doesn't exist"
fi

# ===================================================================
# 9. COMMON FIXES
# ===================================================================

if [ $ISSUES_FOUND -gt 0 ] || [ $DNS_ISSUES -gt 0 ] || [ $DKIM_ISSUES -gt 0 ]; then
    print_header "Applying Common Fixes"
    
    echo "Restarting services..."
    systemctl restart postfix dovecot opendkim nginx 2>/dev/null
    
    echo "Flushing mail queue..."
    postqueue -f 2>/dev/null
    
    echo "Setting correct permissions..."
    chown -R vmail:vmail /var/vmail 2>/dev/null
    chown -R opendkim:opendkim /etc/opendkim 2>/dev/null
    
    print_message "✓ Common fixes applied"
fi

# ===================================================================
# SUMMARY
# ===================================================================

print_header "Troubleshooting Summary"

TOTAL_ISSUES=$((ISSUES_FOUND + DNS_ISSUES + DKIM_ISSUES))

if [ $TOTAL_ISSUES -eq 0 ]; then
    print_message "✓ No issues found! Your mail server appears healthy."
    echo ""
    echo "Test your server:"
    echo "  1. Send test: test-email check-auth@verifier.port25.com"
    echo "  2. Check score: https://www.mail-tester.com"
else
    print_warning "⚠ Found $TOTAL_ISSUES issue(s)"
    echo ""
    
    if [ $ISSUES_FOUND -gt 0 ]; then
        echo "• $ISSUES_FOUND service/configuration issues"
    fi
    
    if [ $DNS_ISSUES -gt 0 ]; then
        echo "• $DNS_ISSUES DNS configuration issues"
        echo "  Update your DNS records at your provider"
    fi
    
    if [ $DKIM_ISSUES -gt 0 ]; then
        echo "• $DKIM_ISSUES DKIM configuration issues"
        echo "  Check DKIM setup and DNS record"
    fi
    
    echo ""
    echo "After fixing issues:"
    echo "  1. Run this script again to verify"
    echo "  2. Test with: test-email check-auth@verifier.port25.com"
    echo "  3. Monitor logs: mail-log follow"
fi

echo ""
echo "For detailed status: mail-status"
echo "For comprehensive test: mail-test"
