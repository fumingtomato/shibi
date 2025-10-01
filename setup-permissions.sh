#!/bin/bash

# =================================================================
# SETUP PERMISSIONS FOR MAIL SERVER COMMANDS
# Version: 17.1.0 - Enable non-root user access to mail commands
# Allows all users to run mail management commands
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

print_header "Setting Up Universal User Access"

# ===================================================================
# CREATE MAIL CONFIG DIRECTORY
# ===================================================================

print_message "Creating shared configuration directory..."

# Create directory for shared configs
mkdir -p /etc/mail-config
chmod 755 /etc/mail-config

# Copy database password to shared location
if [ -f /root/.mail_db_password ]; then
    cp /root/.mail_db_password /etc/mail-config/db_password
    chmod 644 /etc/mail-config/db_password
    print_message "✓ Database password copied to shared location"
fi

# Copy installation config
if [ -f /root/mail-installer/install.conf ]; then
    cp /root/mail-installer/install.conf /etc/mail-config/install.conf
    chmod 644 /etc/mail-config/install.conf
    print_message "✓ Installation config copied to shared location"
fi

# ===================================================================
# CREATE MAIL MANAGEMENT GROUP
# ===================================================================

print_message "Creating mail management group..."

# Create group for mail management
groupadd -f mailadmin
print_message "✓ Created mailadmin group"

# ===================================================================
# SETUP SUDO PERMISSIONS
# ===================================================================

print_message "Configuring sudo permissions..."

# Create sudoers file for mail commands
cat > /etc/sudoers.d/mail-commands <<'EOF'
# Mail Server Management Commands
# Allows mailadmin group to run specific commands without password

# Service management
%mailadmin ALL=(root) NOPASSWD: /bin/systemctl status postfix
%mailadmin ALL=(root) NOPASSWD: /bin/systemctl status dovecot
%mailadmin ALL=(root) NOPASSWD: /bin/systemctl status opendkim
%mailadmin ALL=(root) NOPASSWD: /bin/systemctl status nginx
%mailadmin ALL=(root) NOPASSWD: /bin/systemctl status mysql
%mailadmin ALL=(root) NOPASSWD: /bin/systemctl status mariadb
%mailadmin ALL=(root) NOPASSWD: /bin/systemctl restart postfix
%mailadmin ALL=(root) NOPASSWD: /bin/systemctl restart dovecot
%mailadmin ALL=(root) NOPASSWD: /bin/systemctl restart opendkim
%mailadmin ALL=(root) NOPASSWD: /bin/systemctl reload postfix
%mailadmin ALL=(root) NOPASSWD: /bin/systemctl reload nginx

# Mail queue management
%mailadmin ALL=(root) NOPASSWD: /usr/sbin/postqueue
%mailadmin ALL=(root) NOPASSWD: /usr/sbin/postsuper
%mailadmin ALL=(root) NOPASSWD: /usr/bin/mailq

# Database access (read-only)
%mailadmin ALL=(root) NOPASSWD: /usr/bin/mysql -u mailuser *

# Postfix commands
%mailadmin ALL=(root) NOPASSWD: /usr/sbin/postmap
%mailadmin ALL=(root) NOPASSWD: /usr/sbin/postconf

# Network commands for diagnostics
%mailadmin ALL=(root) NOPASSWD: /bin/netstat
%mailadmin ALL=(root) NOPASSWD: /usr/bin/ss

# Allow all users to run mail management commands
ALL ALL=(root) NOPASSWD: /usr/local/bin/mail-status
ALL ALL=(root) NOPASSWD: /usr/local/bin/mail-account list
ALL ALL=(root) NOPASSWD: /usr/local/bin/check-dns
ALL ALL=(root) NOPASSWD: /usr/local/bin/test-email
ALL ALL=(root) NOPASSWD: /usr/local/bin/bulk-ip-manage list
ALL ALL=(root) NOPASSWD: /usr/local/bin/bulk-ip-manage stats
ALL ALL=(root) NOPASSWD: /usr/local/bin/ip-rotation-status
ALL ALL=(root) NOPASSWD: /usr/local/bin/mailwizz-info
EOF

chmod 440 /etc/sudoers.d/mail-commands
print_message "✓ Sudo permissions configured"

# ===================================================================
# CREATE WRAPPER SCRIPTS
# ===================================================================

print_message "Creating wrapper scripts for non-root access..."

# Create wrapper for mail-status
cat > /usr/local/bin/mail-status-wrapper <<'EOF'
#!/bin/bash
# Wrapper script to allow non-root users to check mail status

if [ $EUID -eq 0 ]; then
    /usr/local/bin/mail-status "$@"
else
    sudo /usr/local/bin/mail-status "$@"
fi
EOF
chmod 755 /usr/local/bin/mail-status-wrapper

# Create wrapper for mail-account (read operations only for non-root)
cat > /usr/local/bin/mail-account-wrapper <<'EOF'
#!/bin/bash
# Wrapper script for mail account management

if [ $EUID -eq 0 ]; then
    /usr/local/bin/mail-account "$@"
else
    case "$1" in
        list|"")
            sudo /usr/local/bin/mail-account "$@"
            ;;
        *)
            echo "Permission denied. Only 'list' command available for non-root users."
            echo "Contact system administrator for account changes."
            exit 1
            ;;
    esac
fi
EOF
chmod 755 /usr/local/bin/mail-account-wrapper

# Create wrapper for bulk-ip-manage
cat > /usr/local/bin/bulk-ip-manage-wrapper <<'EOF'
#!/bin/bash
# Wrapper script for IP management

if [ $EUID -eq 0 ]; then
    /usr/local/bin/bulk-ip-manage "$@"
else
    case "$1" in
        list|stats|report|"")
            sudo /usr/local/bin/bulk-ip-manage "$@"
            ;;
        *)
            echo "Permission denied. Read-only commands available for non-root users."
            echo "Available: list, stats, report"
            exit 1
            ;;
    esac
fi
EOF
chmod 755 /usr/local/bin/bulk-ip-manage-wrapper

# ===================================================================
# CREATE MAIL HELP COMMAND
# ===================================================================

cat > /usr/local/bin/mail-help <<'EOF'
#!/bin/bash

GREEN='\033[38;5;208m'
YELLOW='\033[1;33m'
BLUE='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}==================================================${NC}"
echo -e "${BLUE}Mail Server Management Commands${NC}"
echo -e "${BLUE}==================================================${NC}"
echo ""

echo -e "${GREEN}Status & Monitoring:${NC}"
echo "  mail-status          - Check server status"
echo "  ip-rotation-status   - View IP rotation status"
echo "  check-dns            - Verify DNS records"
echo "  mailwizz-info        - MailWizz configuration info"
echo ""

echo -e "${GREEN}Account Management:${NC}"
if [ $EUID -eq 0 ]; then
    echo "  mail-account add     - Create new email account"
    echo "  mail-account delete  - Remove email account"
    echo "  mail-account list    - List all accounts"
    echo "  mail-account password - Change account password"
else
    echo "  mail-account list    - List all accounts"
    echo "  (Other operations require root access)"
fi
echo ""

echo -e "${GREEN}IP Rotation Management:${NC}"
if [ $EUID -eq 0 ]; then
    echo "  bulk-ip-manage assign    - Assign IP to sender"
    echo "  bulk-ip-manage list      - List IP assignments"
    echo "  bulk-ip-manage stats     - Show IP statistics"
    echo "  bulk-ip-manage reset     - Reset assignments"
    echo "  bulk-ip-manage report    - Generate usage report"
else
    echo "  bulk-ip-manage list      - List IP assignments"
    echo "  bulk-ip-manage stats     - Show IP statistics"
    echo "  bulk-ip-manage report    - Generate usage report"
    echo "  (Modifications require root access)"
fi
echo ""

echo -e "${GREEN}Testing:${NC}"
echo "  test-email <recipient>   - Send test email"
echo ""

echo -e "${GREEN}Logs & Troubleshooting:${NC}"
echo "  mail-log live        - Watch live mail log"
echo "  mail-log errors      - Show recent errors"
echo "  mail-log sent        - Show sent emails"
echo "  mail-queue show      - Show mail queue"
echo ""

if [ $EUID -ne 0 ]; then
    echo -e "${YELLOW}Note: You're running as a regular user.${NC}"
    echo -e "${YELLOW}Some commands have limited functionality.${NC}"
    echo -e "${YELLOW}For full access, use: sudo <command>${NC}"
fi
EOF

chmod 755 /usr/local/bin/mail-help

# ===================================================================
# UPDATE COMMAND SCRIPTS FOR NON-ROOT ACCESS
# ===================================================================

print_message "Updating command scripts for universal access..."

# Update scripts to check for both password locations
for script in /usr/local/bin/mail-account /usr/local/bin/bulk-ip-manage /usr/local/bin/ip-rotation-status /usr/local/bin/maildb; do
    if [ -f "$script" ]; then
        # Update password loading logic
        sed -i 's|if \[ -f /root/.mail_db_password \]; then|if [ -f /root/.mail_db_password ]; then\n    DB_PASS=$(cat /root/.mail_db_password)\nelif [ -f /etc/mail-config/db_password ]; then\n    DB_PASS=$(cat /etc/mail-config/db_password)|' "$script" 2>/dev/null || true
    fi
done

# ===================================================================
# CREATE SYMBOLIC LINKS
# ===================================================================

print_message "Creating command aliases..."

# Create symbolic links for easier access
ln -sf /usr/local/bin/mail-status-wrapper /usr/bin/mail-status 2>/dev/null || true
ln -sf /usr/local/bin/mail-account-wrapper /usr/bin/mail-account 2>/dev/null || true
ln -sf /usr/local/bin/bulk-ip-manage-wrapper /usr/bin/bulk-ip-manage 2>/dev/null || true
ln -sf /usr/local/bin/mail-help /usr/bin/mail-help 2>/dev/null || true
ln -sf /usr/local/bin/test-email /usr/bin/test-email 2>/dev/null || true
ln -sf /usr/local/bin/check-dns /usr/bin/check-dns 2>/dev/null || true
ln -sf /usr/local/bin/ip-rotation-status /usr/bin/ip-rotation-status 2>/dev/null || true
ln -sf /usr/local/bin/mailwizz-info /usr/bin/mailwizz-info 2>/dev/null || true

print_message "✓ Command aliases created"

# ===================================================================
# TEST COMMAND ACCESS
# ===================================================================

print_header "Testing Command Access"

test_command() {
    local cmd=$1
    local user=${2:-nobody}
    
    echo -n "Testing $cmd as $user: "
    if su - $user -s /bin/bash -c "command -v $cmd" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Available${NC}"
        return 0
    else
        echo -e "${RED}✗ Not found${NC}"
        return 1
    fi
}

# Test as nobody user
echo "Testing commands for regular users..."
test_command "mail-help" "nobody"
test_command "mail-status" "nobody"
test_command "check-dns" "nobody"

# ===================================================================
# ADD CURRENT USER TO MAILADMIN GROUP (IF NOT ROOT)
# ===================================================================

CURRENT_USER="${SUDO_USER:-$USER}"
if [ ! -z "$CURRENT_USER" ] && [ "$CURRENT_USER" != "root" ]; then
    print_message "Adding $CURRENT_USER to mailadmin group..."
    usermod -a -G mailadmin "$CURRENT_USER" 2>/dev/null && \
        print_message "✓ User $CURRENT_USER added to mailadmin group" || \
        print_warning "⚠ Could not add $CURRENT_USER to mailadmin group"
    echo "Note: $CURRENT_USER may need to log out and back in for group changes to take effect"
fi

# ===================================================================
# COMPLETION
# ===================================================================

echo ""
print_header "Universal Access Setup Complete!"

echo ""
echo "✓ Shared configuration directory created: /etc/mail-config"
echo "✓ Mail management group created: mailadmin"
echo "✓ Sudo permissions configured"
echo "✓ Wrapper scripts created for non-root access"
echo "✓ Command aliases installed"
echo ""
echo "Available commands for ALL users:"
echo "  • mail-help     - Show all available commands"
echo "  • mail-status   - Check server status"
echo "  • check-dns     - Verify DNS records"
echo "  • test-email    - Send test emails"
echo ""
echo "Read-only commands for regular users:"
echo "  • mail-account list      - View email accounts"
echo "  • bulk-ip-manage list    - View IP assignments"
echo "  • bulk-ip-manage stats   - View IP statistics"
echo "  • ip-rotation-status     - Monitor IP rotation"
echo ""
echo "To grant full access to a user:"
echo "  usermod -a -G mailadmin username"
echo ""
print_message "✓ All users can now use mail management commands!"
print_message "✓ Type 'mail-help' from any user account to see available commands"
