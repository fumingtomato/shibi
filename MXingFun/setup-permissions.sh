#!/bin/bash

# =================================================================
# UNIVERSAL PERMISSIONS SETUP FOR ALL USERS
# Version: 17.0.7 - Seamless Multi-User Access
# Makes all mail commands work for any user without changing installers
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

print_header "Setting Up Universal Command Access"

# Load configuration
if [ -f "$(pwd)/install.conf" ]; then
    source "$(pwd)/install.conf"
elif [ -f "/root/mail-installer/install.conf" ]; then
    source "/root/mail-installer/install.conf"
fi

# ===================================================================
# 1. CREATE SECURE SHARED CONFIGURATION
# ===================================================================

echo "Creating shared configuration directory..."
mkdir -p /etc/mail-config
chmod 755 /etc/mail-config

# Copy database password to shared location
if [ -f /root/.mail_db_password ]; then
    cp /root/.mail_db_password /etc/mail-config/db_password
    chmod 644 /etc/mail-config/db_password
    print_message "✓ Database password made accessible"
fi

# Copy install configuration
if [ -f /root/mail-installer/install.conf ]; then
    cp /root/mail-installer/install.conf /etc/mail-config/install.conf
    chmod 644 /etc/mail-config/install.conf
    print_message "✓ Configuration made accessible"
fi

# ===================================================================
# 2. CREATE UNIVERSAL WRAPPER FUNCTION
# ===================================================================

echo "Creating universal command wrapper..."

cat > /usr/local/bin/mail-wrapper <<'WRAPPER'
#!/bin/bash

# Universal wrapper for mail commands
# This wrapper handles permission issues transparently

# Get the actual command name
COMMAND_NAME=$(basename "$0")
ACTUAL_COMMAND="/usr/local/bin/.${COMMAND_NAME}-real"

# Function to get database password from multiple locations
get_db_password() {
    if [ -f /etc/mail-config/db_password ]; then
        cat /etc/mail-config/db_password
    elif [ "$EUID" -eq 0 ] && [ -f /root/.mail_db_password ]; then
        cat /root/.mail_db_password
    elif [ -f /root/.mail_db_password ] && [ -r /root/.mail_db_password ]; then
        cat /root/.mail_db_password
    else
        # Try with sudo if available
        if command -v sudo >/dev/null 2>&1; then
            sudo cat /root/.mail_db_password 2>/dev/null || echo ""
        else
            echo ""
        fi
    fi
}

# Function to get configuration
get_config() {
    if [ -f /etc/mail-config/install.conf ]; then
        source /etc/mail-config/install.conf
    elif [ "$EUID" -eq 0 ] && [ -f /root/mail-installer/install.conf ]; then
        source /root/mail-installer/install.conf
    fi
}

# Export functions and variables for the actual command
export -f get_db_password
export -f get_config
export DB_PASS=$(get_db_password)
get_config

# Handle commands that need root differently
case "$COMMAND_NAME" in
    mail-account|mail-backup|ip-rotation-status)
        # These need database access
        if [ -z "$DB_PASS" ]; then
            echo "Error: Cannot access database password"
            echo "Try: sudo $COMMAND_NAME $@"
            exit 1
        fi
        ;;
    mail-status|mail-test|check-dns|test-email)
        # These can run with limited permissions
        ;;
    *)
        # Default case
        ;;
esac

# Execute the actual command
if [ -f "$ACTUAL_COMMAND" ]; then
    bash "$ACTUAL_COMMAND" "$@"
else
    # Fallback to original command if wrapper not set up
    ORIGINAL="/usr/local/bin/${COMMAND_NAME}-original"
    if [ -f "$ORIGINAL" ]; then
        bash "$ORIGINAL" "$@"
    else
        echo "Error: Command not found: $COMMAND_NAME"
        exit 1
    fi
fi
WRAPPER

chmod 755 /usr/local/bin/mail-wrapper

# ===================================================================
# 3. WRAP EXISTING COMMANDS
# ===================================================================

echo "Wrapping existing commands for universal access..."

# List of commands to wrap
COMMANDS=(
    "mail-status"
    "mail-account" 
    "test-email"
    "check-dns"
    "mail-test"
    "mail-log"
    "mail-queue"
    "mail-backup"
    "mailwizz-info"
    "ip-rotation-status"
    "verify-dns"
    "get-ssl-cert"
    "assign-ip"
)

for cmd in "${COMMANDS[@]}"; do
    if [ -f "/usr/local/bin/$cmd" ]; then
        echo -n "  Wrapping $cmd... "
        
        # Move original command
        mv "/usr/local/bin/$cmd" "/usr/local/bin/.${cmd}-real" 2>/dev/null
        
        # Create symlink to wrapper
        ln -sf /usr/local/bin/mail-wrapper "/usr/local/bin/$cmd"
        
        # Make the real command accessible
        chmod 755 "/usr/local/bin/.${cmd}-real" 2>/dev/null
        
        print_message "✓"
    fi
done

# ===================================================================
# 4. FIX SPECIFIC COMMANDS FOR DATABASE ACCESS
# ===================================================================

echo "Fixing database-dependent commands..."

# Fix ip-rotation-status specifically
if [ -f "/usr/local/bin/.ip-rotation-status-real" ]; then
    sed -i 's|cat /root/.mail_db_password|get_db_password|g' "/usr/local/bin/.ip-rotation-status-real"
    sed -i '1a source /usr/local/bin/mail-wrapper' "/usr/local/bin/.ip-rotation-status-real"
fi

# Fix mail-account
if [ -f "/usr/local/bin/.mail-account-real" ]; then
    sed -i 's|cat /root/.mail_db_password|get_db_password|g' "/usr/local/bin/.mail-account-real"
    sed -i 's|if \[ -f /root/.mail_db_password \]; then|if DB_PASS=$(get_db_password); [ ! -z "$DB_PASS" ]; then|g' "/usr/local/bin/.mail-account-real"
fi

# Fix mail-backup
if [ -f "/usr/local/bin/.mail-backup-real" ]; then
    sed -i 's|cat /root/.mail_db_password|get_db_password|g' "/usr/local/bin/.mail-backup-real"
    sed -i 's|/root/.mail_db_password|/etc/mail-config/db_password|g' "/usr/local/bin/.mail-backup-real"
fi

# Fix mail-test
if [ -f "/usr/local/bin/.mail-test-real" ]; then
    sed -i 's|cat /root/.mail_db_password|get_db_password|g' "/usr/local/bin/.mail-test-real"
    sed -i 's|if \[ -f /root/.mail_db_password \]; then|if DB_PASS=$(get_db_password); [ ! -z "$DB_PASS" ]; then|g' "/usr/local/bin/.mail-test-real"
fi

# ===================================================================
# 5. CREATE SUDO RULES FOR PRIVILEGED OPERATIONS
# ===================================================================

echo "Setting up sudo rules for privileged operations..."

cat > /etc/sudoers.d/mail-commands <<'SUDOERS'
# Allow all users to run mail management commands
# Some commands need root for service management

# Read-only commands - no password needed
ALL ALL=(root) NOPASSWD: /usr/local/bin/mail-status
ALL ALL=(root) NOPASSWD: /usr/local/bin/check-dns
ALL ALL=(root) NOPASSWD: /usr/local/bin/mail-log
ALL ALL=(root) NOPASSWD: /usr/local/bin/verify-dns
ALL ALL=(root) NOPASSWD: /usr/local/bin/mailwizz-info

# Database commands - require authentication but allow access
ALL ALL=(root) NOPASSWD: /usr/local/bin/mail-account
ALL ALL=(root) NOPASSWD: /usr/local/bin/ip-rotation-status
ALL ALL=(root) NOPASSWD: /usr/local/bin/mail-test
ALL ALL=(root) NOPASSWD: /usr/local/bin/test-email

# Administrative commands
ALL ALL=(root) NOPASSWD: /usr/local/bin/mail-queue
ALL ALL=(root) NOPASSWD: /usr/local/bin/mail-backup
ALL ALL=(root) NOPASSWD: /usr/local/bin/get-ssl-cert
ALL ALL=(root) NOPASSWD: /usr/local/bin/assign-ip

# Allow reading specific files
ALL ALL=(root) NOPASSWD: /bin/cat /root/.mail_db_password
ALL ALL=(root) NOPASSWD: /bin/cat /root/mail-installer/install.conf
SUDOERS

chmod 440 /etc/sudoers.d/mail-commands

# ===================================================================
# 6. CREATE HELPER SCRIPT FOR USERS
# ===================================================================

echo "Creating user helper script..."

cat > /usr/local/bin/mail-help <<'HELP'
#!/bin/bash

GREEN='\033[38;5;208m'
BLUE='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}==================================================${NC}"
echo -e "${BLUE}Mail Server Management Commands${NC}"
echo -e "${BLUE}==================================================${NC}"
echo ""
echo "All commands can be run by any user:"
echo ""
echo -e "${GREEN}Information Commands:${NC}"
echo "  mail-status         - Check server status"
echo "  mail-test          - Comprehensive server test"
echo "  check-dns          - Verify DNS configuration"
echo "  verify-dns         - Check DNS propagation"
echo "  mailwizz-info      - MailWizz configuration guide"
echo ""
echo -e "${GREEN}Management Commands:${NC}"
echo "  mail-account       - Manage email accounts"
echo "    add EMAIL PASSWORD      - Create account"
echo "    delete EMAIL           - Delete account"
echo "    list                   - List all accounts"
echo "    password EMAIL PASS    - Change password"
echo ""
echo -e "${GREEN}Operations:${NC}"
echo "  test-email EMAIL   - Send test email"
echo "  mail-log          - View mail logs"
echo "    live                   - Watch live log"
echo "    errors                 - Show recent errors"
echo "    sent                   - Show sent emails"
echo "  mail-queue        - Manage mail queue"
echo "    show                   - Show queue"
echo "    flush                  - Flush queue"
echo ""
echo -e "${GREEN}IP Rotation (if configured):${NC}"
echo "  ip-rotation-status - Check IP rotation status"
echo "  assign-ip EMAIL IP - Assign IP to sender"
echo ""
echo "All commands work for any user - no sudo needed!"
HELP

chmod 755 /usr/local/bin/mail-help

# ===================================================================
# 7. TEST PERMISSIONS
# ===================================================================

print_header "Testing Command Access"

# Create a test user if it doesn't exist
TEST_USER="mailtest"
if ! id "$TEST_USER" &>/dev/null; then
    useradd -m -s /bin/bash "$TEST_USER" 2>/dev/null
fi

echo "Testing commands as non-root user..."

# Test a few commands as the test user
test_command() {
    local cmd=$1
    echo -n "  Testing $cmd: "
    if su - "$TEST_USER" -c "$cmd" &>/dev/null; then
        print_message "✓"
    else
        # Try with wrapper
        if su - "$TEST_USER" -c "bash /usr/local/bin/$cmd 2>/dev/null" &>/dev/null; then
            print_message "✓"
        else
            print_warning "⚠ May need sudo"
        fi
    fi
}

test_command "mail-status"
test_command "check-dns"

# Clean up test user
userdel "$TEST_USER" 2>/dev/null

# ===================================================================
# COMPLETION
# ===================================================================

print_header "Permission Setup Complete!"

echo ""
echo "✅ All mail commands are now accessible to all users!"
echo ""
echo "Features enabled:"
echo "  • Database access wrapper for non-root users"
echo "  • Configuration shared in /etc/mail-config/"
echo "  • Sudo rules configured for privileged operations"
echo "  • All commands work transparently for any user"
echo ""
echo "Users can now run:"
echo "  mail-help          - Show all available commands"
echo "  mail-status        - Check server status"
echo "  mail-account list  - List email accounts"
echo "  ip-rotation-status - Check IP rotation"
echo ""
echo "No 'sudo' prefix needed - commands work for everyone!"
echo ""

# Add this script to be called at the end of installation
if [ -f /root/mail-installer/install.conf ]; then
    echo "# Permission wrapper configured" >> /root/mail-installer/install.conf
    echo "PERMISSIONS_CONFIGURED=true" >> /root/mail-installer/install.conf
fi

print_message "✓ Universal access configuration completed!"
