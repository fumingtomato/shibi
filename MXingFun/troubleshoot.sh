#!/bin/bash

# =================================================================
# MAIL SERVER TROUBLESHOOTING AND DIAGNOSTIC TOOL
# Version: 16.0.2
# Identifies and fixes common mail server issues
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

clear
print_header "Mail Server Troubleshooting Tool"
echo ""

# Initialize counters
ISSUES_FOUND=0
ISSUES_FIXED=0

# Get system info
HOSTNAME=$(hostname -f)
DOMAIN=$(hostname -d)
PRIMARY_IP=$(curl -s --max-time 5 https://ipinfo.io/ip 2>/dev/null || hostname -I | awk '{print $1}')

echo "Server Information:"
echo "  Hostname: $HOSTNAME"
echo "  Domain: $DOMAIN"
echo "  Primary IP: $PRIMARY_IP"
echo ""

# ===================================================================
# 1. SERVICE CHECKS
# ===================================================================

print_header "Checking Services"

check_service() {
    local service=$1
    local description=$2
    
    echo -n "Checking $description... "
    
    if systemctl is-active --quiet $service; then
        print_message "✓ Running"
        return 0
    else
        print_error "✗ Not running"
        ISSUES_FOUND=$((ISSUES_FOUND + 1))
        
        # Try to fix
        echo -n "  Attempting to start $service... "
        if systemctl start $service 2>/dev/null; then
            print_message "✓ Started"
            ISSUES_FIXED=$((ISSUES_FIXED + 1))
            return 0
        else
            print_error "✗ Failed"
            echo "  Error details:"
            systemctl status $service --no-pager 2>&1 | head -10 | sed 's/^/    /'
            return 1
        fi
    fi
}

check_service "postfix" "Postfix (SMTP)"
check_service "dovecot" "Dovecot (IMAP/POP3)"
check_service "opendkim" "OpenDKIM"
check_service "mysql" "MySQL" || check_service "mariadb" "MariaDB"

echo ""

# ===================================================================
# 2. PORT CHECKS
# ===================================================================

print_header "Checking Network Ports"

check_port() {
    local port=$1
    local service=$2
    
    echo -n "Port $port ($service)... "
    
    if netstat -tlnp 2>/dev/null | grep -q ":$port "; then
        print_message "✓ Open"
        return 0
    else
        print_warning "✗ Not listening"
        ISSUES_FOUND=$((ISSUES_FOUND + 1))
        
        # Check if blocked by firewall
        if command -v ufw &>/dev/null; then
            if ! ufw status | grep -q "$port"; then
                echo "  Port might be blocked by firewall"
                echo -n "  Adding firewall rule... "
                ufw allow $port/tcp comment "$service" 2>/dev/null
                print_message "✓ Added"
                ISSUES_FIXED=$((ISSUES_FIXED + 1))
            fi
        fi
        return 1
    fi
}

check_port 25 "SMTP"
check_port 587 "Submission"
check_port 143 "IMAP"
check_port 993 "IMAPS"
check_port 3306 "MySQL"

echo ""

# ===================================================================
# 3. DNS CHECKS
# ===================================================================

print_header "Checking DNS Records"

check_dns() {
    local record_type=$1
    local record_name=$2
    local description=$3
    
    echo -n "$description... "
    
    local result=$(dig +short $record_type $record_name @8.8.8.8 2>/dev/null)
    
    if [ ! -z "$result" ]; then
        print_message "✓ Found"
        echo "  Value: $result" | head -1
        return 0
    else
        print_warning "✗ Not found"
        ISSUES_FOUND=$((ISSUES_FOUND + 1))
        echo "  Add this record to your DNS:"
        
        case $record_type in
            A)
                echo "    Type: A, Name: $record_name, Value: $PRIMARY_IP"
                ;;
            MX)
                echo "    Type: MX, Name: $DOMAIN, Value: $HOSTNAME, Priority: 10"
                ;;
            TXT)
                if [[ $record_name == *"_domainkey"* ]]; then
                    echo "    Type: TXT, Name: $record_name"
                    echo "    Value: Check /etc/opendkim/keys/$DOMAIN/mail.txt"
                elif [[ $record_name == "_dmarc"* ]]; then
                    echo "    Type: TXT, Name: $record_name"
                    echo "    Value: v=DMARC1; p=none; rua=mailto:admin@$DOMAIN"
                else
                    echo "    Type: TXT, Name: $record_name"
                    echo "    Value: v=spf1 mx a ip4:$PRIMARY_IP ~all"
                fi
                ;;
        esac
        return 1
    fi
}

check_dns "A" "$HOSTNAME" "A record for $HOSTNAME"
check_dns "MX" "$DOMAIN" "MX record for $DOMAIN"
check_dns "TXT" "$DOMAIN" "SPF record"
check_dns "TXT" "mail._domainkey.$DOMAIN" "DKIM record"
check_dns "TXT" "_dmarc.$DOMAIN" "DMARC record"

# Check reverse DNS
echo -n "Reverse DNS (PTR)... "
PTR=$(dig +short -x $PRIMARY_IP @8.8.8.8 2>/dev/null)
if [ ! -z "$PTR" ]; then
    if [[ "$PTR" == *"$HOSTNAME"* ]]; then
        print_message "✓ Correct"
        echo "  $PRIMARY_IP -> $PTR"
    else
        print_warning "⚠ Incorrect"
        echo "  Current: $PRIMARY_IP -> $PTR"
        echo "  Should be: $PRIMARY_IP -> $HOSTNAME"
        ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
else
    print_warning "✗ Not set"
    echo "  Contact your hosting provider to set PTR record"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
fi

echo ""

# ===================================================================
# 4. CONFIGURATION CHECKS
# ===================================================================

print_header "Checking Configuration Files"

# Check Postfix configuration
echo -n "Postfix configuration... "
if postfix check 2>/dev/null; then
    print_message "✓ Valid"
else
    print_error "✗ Invalid"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
    echo "  Running postconf to show issues:"
    postconf -n 2>&1 | grep -i error | head -5 | sed 's/^/    /'
fi

# Check Dovecot configuration
echo -n "Dovecot configuration... "
if doveconf -n >/dev/null 2>&1; then
    print_message "✓ Valid"
else
    print_error "✗ Invalid"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
    echo "  Check: doveconf -n"
fi

# Check database connection
echo -n "Database connection... "
if [ -f /root/.mail_db_password ]; then
    DB_PASS=$(cat /root/.mail_db_password)
    if mysql -u mailuser -p"$DB_PASS" -e "SELECT 1;" mailserver &>/dev/null; then
        print_message "✓ Working"
    else
        print_error "✗ Failed"
        ISSUES_FOUND=$((ISSUES_FOUND + 1))
        
        # Try to fix
        echo "  Attempting to reset database password..."
        NEW_PASS=$(openssl rand -base64 25)
        mysql -e "ALTER USER 'mailuser'@'localhost' IDENTIFIED BY '$NEW_PASS';" 2>/dev/null
        if [ $? -eq 0 ]; then
            echo "$NEW_PASS" > /root/.mail_db_password
            print_message "  ✓ Password reset"
            ISSUES_FIXED=$((ISSUES_FIXED + 1))
        fi
    fi
else
    print_error "✗ Password file missing"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
fi

echo ""

# ===================================================================
# 5. PERMISSION CHECKS
# ===================================================================

print_header "Checking File Permissions"

check_permission() {
    local file=$1
    local expected_owner=$2
    local expected_perms=$3
    local description=$4
    
    echo -n "$description... "
    
    if [ ! -e "$file" ]; then
        print_warning "✗ File missing"
        ISSUES_FOUND=$((ISSUES_FOUND + 1))
        return 1
    fi
    
    local current_owner=$(stat -c %U:%G "$file")
    local current_perms=$(stat -c %a "$file")
    
    local needs_fix=0
    
    if [ "$current_owner" != "$expected_owner" ]; then
        needs_fix=1
    fi
    
    if [ "$current_perms" != "$expected_perms" ]; then
        needs_fix=1
    fi
    
    if [ $needs_fix -eq 0 ]; then
        print_message "✓ Correct"
        return 0
    else
        print_warning "✗ Incorrect"
        ISSUES_FOUND=$((ISSUES_FOUND + 1))
        
        echo -n "  Fixing permissions... "
        chown $expected_owner "$file" 2>/dev/null
        chmod $expected_perms "$file" 2>/dev/null
        print_message "✓ Fixed"
        ISSUES_FIXED=$((ISSUES_FIXED + 1))
        return 0
    fi
}

check_permission "/var/vmail" "vmail:vmail" "770" "Mail storage directory"
check_permission "/etc/opendkim/keys" "opendkim:opendkim" "750" "DKIM keys directory"
check_permission "/root/.mail_db_password" "root:root" "600" "Database password file"

echo ""

# ===================================================================
# 6. MAIL DELIVERY TEST
# ===================================================================

print_header "Testing Mail Delivery"

echo "Checking mail queue..."
QUEUE_COUNT=$(mailq | grep -c "^[A-F0-9]" 2>/dev/null || echo 0)
echo "Messages in queue: $QUEUE_COUNT"

if [ $QUEUE_COUNT -gt 100 ]; then
    print_warning "⚠ Large mail queue detected"
    echo ""
    echo "Recent queue samples:"
    mailq | head -20
    echo ""
    
    read -p "Flush mail queue? (y/n): " FLUSH_QUEUE
    if [[ "${FLUSH_QUEUE,,}" == "y" ]]; then
        postqueue -f
        print_message "Queue flush initiated"
    fi
elif [ $QUEUE_COUNT -gt 0 ]; then
    echo "Queue appears normal"
fi

echo ""

# Check for recent delivery errors
echo "Recent delivery errors:"
grep -i "status=bounced\|status=deferred" /var/log/mail.log 2>/dev/null | tail -5 | sed 's/^/  /'
if [ ${PIPESTATUS[0]} -ne 0 ]; then
    echo "  No recent errors found"
fi

echo ""

# ===================================================================
# 7. SECURITY CHECKS
# ===================================================================

print_header "Security Checks"

# Check if firewall is enabled
echo -n "Firewall status... "
if command -v ufw &>/dev/null; then
    if ufw status | grep -q "Status: active"; then
        print_message "✓ Active"
    else
        print_warning "✗ Inactive"
        ISSUES_FOUND=$((ISSUES_FOUND + 1))
        echo -n "  Enabling firewall... "
        ufw --force enable &>/dev/null
        print_message "✓ Enabled"
        ISSUES_FIXED=$((ISSUES_FIXED + 1))
    fi
else
    print_warning "⚠ UFW not installed"
fi

# Check fail2ban
echo -n "Fail2ban status... "
if systemctl is-active --quiet fail2ban; then
    print_message "✓ Active"
    # Show banned IPs
    BANNED=$(fail2ban-client status postfix 2>/dev/null | grep "Banned IP" | wc -l)
    if [ $BANNED -gt 0 ]; then
        echo "  Currently banned IPs: $BANNED"
    fi
else
    print_warning "✗ Not running"
    ISSUES_FOUND=$((ISSUES_FOUND + 1))
    systemctl start fail2ban 2>/dev/null && ISSUES_FIXED=$((ISSUES_FIXED + 1))
fi

echo ""

# ===================================================================
# 8. QUICK FIXES
# ===================================================================

if [ $ISSUES_FOUND -gt 0 ]; then
    print_header "Applying Quick Fixes"
    
    echo "Found $ISSUES_FOUND issues, attempting automatic fixes..."
    echo ""
    
    # Restart services that were fixed
    echo "Restarting services..."
    for service in postfix dovecot opendkim; do
        systemctl restart $service 2>/dev/null
    done
    
    # Reload Postfix
    postfix reload 2>/dev/null
    
    echo ""
fi

# ===================================================================
# SUMMARY
# ===================================================================

print_header "Diagnostic Summary"

echo "Issues found: $ISSUES_FOUND"
echo "Issues fixed: $ISSUES_FIXED"
echo "Issues remaining: $((ISSUES_FOUND - ISSUES_FIXED))"
echo ""

if [ $ISSUES_FOUND -eq 0 ]; then
    print_message "✓ No issues detected! Your mail server appears healthy."
elif [ $((ISSUES_FOUND - ISSUES_FIXED)) -eq 0 ]; then
    print_message "✓ All detected issues have been fixed!"
    echo ""
    echo "Please run 'systemctl restart postfix dovecot' to ensure changes take effect."
else
    print_warning "⚠ Some issues require manual intervention:"
    echo ""
    echo "1. Check DNS records at your domain registrar"
    echo "2. Configure PTR record with your hosting provider"
    echo "3. Review log files: /var/log/mail.log"
    echo "4. Run: mail-test for additional checks"
fi

echo ""
echo "For detailed logs, check:"
echo "  /var/log/mail.log      - Mail delivery logs"
echo "  /var/log/syslog        - System logs"
echo "  journalctl -xe         - Service logs"
echo ""

print_message "Diagnostic complete!"
