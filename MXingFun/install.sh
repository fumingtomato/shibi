#!/bin/bash

# =================================================================
# MULTI-IP BULK MAIL SERVER INSTALLER - SIMPLIFIED VERSION
# Version: 16.0.2
# Author: fumingtomato
# Repository: https://github.com/fumingtomato/shibi
# =================================================================
# Single-option installer - Express installation only
# =================================================================

set -e
set -o pipefail

# Configuration
REPO_OWNER="fumingtomato"
REPO_NAME="shibi"
BRANCH="main"
BASE_URL="https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/${BRANCH}/MultiIPMail"

# Colors
GREEN='\033[38;5;208m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[1;33m'
NC='\033[0m'

# Logging
LOG_FILE="/var/log/mail-installer-$(date +%Y%m%d-%H%M%S).log"
touch "$LOG_FILE"
chmod 640 "$LOG_FILE"

# Functions for output
print_message() {
    echo -e "${GREEN}$1${NC}"
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] [INFO] $1" >> "$LOG_FILE"
}

print_error() {
    echo -e "${RED}$1${NC}" >&2
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] [ERROR] $1" >> "$LOG_FILE"
}

print_warning() {
    echo -e "${YELLOW}$1${NC}"
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] [WARNING] $1" >> "$LOG_FILE"
}

print_header() {
    echo -e "${BLUE}==================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}==================================================${NC}"
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] [HEADER] $1" >> "$LOG_FILE"
}

# Clear screen and show header
clear
cat << "EOF"
╔══════════════════════════════════════════════════════════════╗
║     MULTI-IP BULK MAIL SERVER INSTALLER v16.0.2             ║
║                                                              ║
║     Professional Mail Server with Multi-IP Support          ║
║     Repository: https://github.com/fumingtomato/shibi       ║
╚══════════════════════════════════════════════════════════════╝

EOF

echo "Installation started at: $(date)"
echo "Log file: $LOG_FILE"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    print_error "This script must be run as root or with sudo privileges"
    echo "Please run: sudo $0"
    exit 1
fi

# Check for required commands
for cmd in wget curl apt-get; do
    if ! command -v $cmd &> /dev/null; then
        print_error "Required command '$cmd' not found. Please install it first."
        exit 1
    fi
done

# Create working directory
INSTALLER_DIR="$(pwd)/mail-installer"
MODULES_DIR="${INSTALLER_DIR}/modules"

print_header "Setting up installation environment"
print_message "Creating directory structure..."

# Clean up any previous installation attempts
if [ -d "$INSTALLER_DIR" ]; then
    print_warning "Removing existing installer directory..."
    rm -rf "$INSTALLER_DIR"
fi

# Create fresh directories
mkdir -p "$MODULES_DIR"
cd "$INSTALLER_DIR"

# List of all modules to download
declare -a MODULES=(
    "core-functions.sh"
    "packages-system.sh"
    "mysql-dovecot.sh"
    "multiip-config.sh"
    "postfix-setup.sh"
    "dkim-spf.sh"
    "dns-ssl.sh"
    "sticky-ip.sh"
    "monitoring-scripts.sh"
    "security-hardening.sh"
    "utility-scripts.sh"
    "mailwizz-integration.sh"
    "main-installer-part2.sh"
)

print_header "Downloading installation modules"
echo "Downloading from: ${BASE_URL}/modules/"
echo ""

DOWNLOAD_FAILED=0

# Download each module
for i in "${!MODULES[@]}"; do
    module="${MODULES[$i]}"
    module_url="${BASE_URL}/modules/${module}"
    module_file="${MODULES_DIR}/${module}"
    
    echo -n "[$((i+1))/${#MODULES[@]}] Downloading ${module}... "
    
    if wget -q -O "$module_file" "$module_url" 2>/dev/null || \
       curl -sfL -o "$module_file" "$module_url" 2>/dev/null; then
        
        if [ -s "$module_file" ]; then
            echo "✓"
            chmod +x "$module_file"
        else
            echo "✗ (empty file)"
            rm -f "$module_file"
            DOWNLOAD_FAILED=$((DOWNLOAD_FAILED + 1))
        fi
    else
        echo "✗ (download failed)"
        DOWNLOAD_FAILED=$((DOWNLOAD_FAILED + 1))
    fi
done

echo ""

if [ $DOWNLOAD_FAILED -gt 0 ]; then
    print_error "$DOWNLOAD_FAILED modules failed to download"
    exit 1
fi

print_message "✓ All modules downloaded successfully"
echo ""

# Now create the main execution script
print_header "Creating main installer"

cat > "${INSTALLER_DIR}/run-installer.sh" << 'INSTALLER_SCRIPT'
#!/bin/bash

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULES_DIR="${SCRIPT_DIR}/modules"

# Redirect output to log
LOG_FILE="/var/log/mail-installer-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$LOG_FILE")
exec 2>&1

print_header "Starting Mail Server Installation"
echo ""

# Load all modules
echo "Loading installer modules..."

# Core modules that must be loaded first
CORE_MODULES=(
    "core-functions.sh"
    "packages-system.sh"
)

# Feature modules
FEATURE_MODULES=(
    "mysql-dovecot.sh"
    "multiip-config.sh"
    "postfix-setup.sh"
    "dkim-spf.sh"
    "dns-ssl.sh"
    "sticky-ip.sh"
    "monitoring-scripts.sh"
    "security-hardening.sh"
    "utility-scripts.sh"
    "mailwizz-integration.sh"
    "main-installer-part2.sh"
)

LOADED_MODULES=0
FAILED_MODULES=0

# Load core modules first
for module in "${CORE_MODULES[@]}"; do
    module_file="${MODULES_DIR}/${module}"
    if [ -f "$module_file" ]; then
        echo "  ✓ Loading: $module"
        source "$module_file"
        LOADED_MODULES=$((LOADED_MODULES + 1))
    else
        echo "  ✗ Required module not found: $module"
        FAILED_MODULES=$((FAILED_MODULES + 1))
    fi
done

if [ $FAILED_MODULES -gt 0 ]; then
    echo ""
    echo "ERROR: Core modules are missing. Cannot continue."
    exit 1
fi

# Load feature modules
for module in "${FEATURE_MODULES[@]}"; do
    module_file="${MODULES_DIR}/${module}"
    if [ -f "$module_file" ]; then
        echo "  ✓ Loading: $module"
        source "$module_file"
        LOADED_MODULES=$((LOADED_MODULES + 1))
    else
        echo "  ⚠ Optional module not found: $module"
    fi
done

echo ""
echo "✓ Loaded $LOADED_MODULES modules successfully"
echo ""

# ===================================================================
# MAIN INSTALLATION - NO MENUS, JUST INSTALL
# ===================================================================

# Warning
echo "⚠ WARNING: This will modify system configuration files."
echo "It is recommended to run this on a fresh server installation."
echo ""
read -p "Continue with installation? (y/n): " CONTINUE

if [[ "${CONTINUE,,}" != "y" ]]; then
    echo "Installation cancelled."
    exit 0
fi

# Gather configuration
print_header "Configuration"

# Get domain name
read -p "Enter your domain name (e.g., example.com): " DOMAIN_NAME
while [[ ! "$DOMAIN_NAME" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; do
    echo "Invalid domain format. Please use format: example.com"
    read -p "Enter your domain name: " DOMAIN_NAME
done
export DOMAIN_NAME

# Set hostname
HOSTNAME="mail.$DOMAIN_NAME"
echo "Mail server hostname will be: $HOSTNAME"
export HOSTNAME

# Get admin email
read -p "Enter admin email address: " ADMIN_EMAIL
while [[ ! "$ADMIN_EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; do
    echo "Invalid email format."
    read -p "Enter admin email address: " ADMIN_EMAIL
done
export ADMIN_EMAIL

# Get public IP
echo ""
echo "Detecting server IP address..."
PRIMARY_IP=$(curl -s https://ipinfo.io/ip 2>/dev/null || curl -s https://api.ipify.org 2>/dev/null || echo "")
if [ -z "$PRIMARY_IP" ]; then
    read -p "Could not detect IP. Please enter server IP address: " PRIMARY_IP
else
    echo "Detected IP: $PRIMARY_IP"
    read -p "Is this correct? (y/n): " CONFIRM_IP
    if [[ "${CONFIRM_IP,,}" != "y" ]]; then
        read -p "Enter correct IP address: " PRIMARY_IP
    fi
fi
export PRIMARY_IP
export IP_ADDRESSES=("$PRIMARY_IP")

# Multi-IP option (optional)
echo ""
read -p "Do you want to configure additional IP addresses? (y/n) [n]: " MULTI_IP
if [[ "${MULTI_IP,,}" == "y" ]]; then
    echo "Enter additional IP addresses (one per line, empty to finish):"
    while true; do
        read -p "IP: " ip
        [ -z "$ip" ] && break
        if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            IP_ADDRESSES+=("$ip")
            echo "Added: $ip"
        else
            echo "Invalid IP format, skipping"
        fi
    done
fi
export IP_ADDRESSES

# Summary
echo ""
print_header "Installation Summary"
echo "Domain: $DOMAIN_NAME"
echo "Hostname: $HOSTNAME"
echo "Admin Email: $ADMIN_EMAIL"
echo "Primary IP: $PRIMARY_IP"
if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
    echo "Additional IPs: ${IP_ADDRESSES[@]:1}"
fi
echo ""
read -p "Proceed with installation? (y/n): " FINAL_CONFIRM
if [[ "${FINAL_CONFIRM,,}" != "y" ]]; then
    echo "Installation cancelled."
    exit 0
fi

# ===================================================================
# PERFORM INSTALLATION
# ===================================================================

print_header "Installing Mail Server"

# Step 1: Update system
echo "Step 1: Updating system packages..."
if declare -f update_system_packages > /dev/null; then
    update_system_packages
else
    apt-get update -y
    apt-get upgrade -y
fi

# Step 2: Install packages
echo ""
echo "Step 2: Installing required packages..."
if declare -f install_all_packages > /dev/null; then
    install_all_packages
else
    # Basic package installation
    apt-get install -y \
        postfix postfix-mysql postfix-pcre \
        dovecot-core dovecot-imapd dovecot-pop3d dovecot-lmtpd dovecot-mysql \
        mysql-server mysql-client \
        opendkim opendkim-tools \
        spamassassin spamc \
        clamav clamav-daemon \
        certbot \
        ufw fail2ban
fi

# Step 3: Setup MySQL
echo ""
echo "Step 3: Setting up database..."
if declare -f setup_mysql > /dev/null; then
    setup_mysql
else
    echo "MySQL setup skipped - function not available"
fi

# Step 4: Setup Postfix
echo ""
echo "Step 4: Setting up Postfix..."
if declare -f setup_postfix_multi_ip > /dev/null; then
    setup_postfix_multi_ip "$DOMAIN_NAME" "$HOSTNAME"
else
    echo "Postfix setup skipped - function not available"
fi

# Step 5: Setup Dovecot
echo ""
echo "Step 5: Setting up Dovecot..."
if declare -f setup_dovecot > /dev/null; then
    setup_dovecot "$DOMAIN_NAME" "$HOSTNAME"
else
    echo "Dovecot setup skipped - function not available"
fi

# Step 6: Setup DKIM
echo ""
echo "Step 6: Setting up DKIM..."
if declare -f setup_opendkim > /dev/null; then
    setup_opendkim "$DOMAIN_NAME"
else
    echo "DKIM setup skipped - function not available"
fi

# Step 7: Create utilities
echo ""
echo "Step 7: Creating utility scripts..."
if declare -f create_all_utilities > /dev/null; then
    create_all_utilities
else
    echo "Utility creation skipped - function not available"
fi

# ===================================================================
# COMPLETION
# ===================================================================

print_header "Installation Complete!"
echo ""
echo "Mail server has been installed with the following configuration:"
echo ""
echo "  Domain: $DOMAIN_NAME"
echo "  Hostname: $HOSTNAME"
echo "  Admin Email: $ADMIN_EMAIL"
echo "  Primary IP: $PRIMARY_IP"
echo ""
echo "IMPORTANT NEXT STEPS:"
echo "====================="
echo ""
echo "1. Configure DNS records:"
echo "   - A record: mail.$DOMAIN_NAME -> $PRIMARY_IP"
echo "   - MX record: $DOMAIN_NAME -> mail.$DOMAIN_NAME (priority 10)"
echo "   - PTR record: $PRIMARY_IP -> mail.$DOMAIN_NAME (contact your provider)"
echo ""
echo "2. Check configuration files:"
echo "   - /root/dns-records.txt (if created)"
echo "   - /root/dkim-record-*.txt (if created)"
echo ""
echo "3. Set up SSL certificate:"
echo "   certbot certonly --standalone -d $HOSTNAME"
echo ""
echo "4. Test your installation:"
echo "   - Send a test email"
echo "   - Check logs: tail -f /var/log/mail.log"
echo ""
echo "Installation log: $LOG_FILE"
echo ""
echo "Thank you for using the Multi-IP Mail Server Installer!"
INSTALLER_SCRIPT

chmod +x "${INSTALLER_DIR}/run-installer.sh"

# Execute the installer
print_header "Starting Mail Server Installation"
echo ""

cd "$INSTALLER_DIR"
exec bash ./run-installer.sh
