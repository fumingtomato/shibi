#!/bin/bash

# =================================================================
# MULTI-IP BULK MAIL SERVER INSTALLER - SINGLE FILE INSTALLER
# Version: 16.0.1
# Author: fumingtomato
# Repository: https://github.com/fumingtomato/shibi
# =================================================================
# This is THE ONLY file you need to download and run
# It will fetch all modules from GitHub and run the installation
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
║     MULTI-IP BULK MAIL SERVER INSTALLER v16.0.1             ║
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
for cmd in wget curl; do
    if ! command -v $cmd &> /dev/null; then
        print_message "Installing $cmd..."
        apt-get update && apt-get install -y $cmd
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
# DEFINE MISSING FUNCTIONS HERE
# ===================================================================

# Custom installation function
custom_installation() {
    print_header "Custom Installation"
    print_warning "Starting custom installation mode..."
    
    # For now, just run express installation
    # You can customize this later
    gather_basic_info
    perform_express_installation
}

# Repair installation function
repair_installation() {
    print_header "Repair Installation"
    print_warning "Starting repair mode..."
    
    # Basic repair actions
    print_message "Checking system status..."
    
    # Fix MySQL if needed
    if command -v mysql &>/dev/null; then
        print_message "Checking MySQL..."
        systemctl status mysql --no-pager || systemctl start mysql
    fi
    
    # Fix Postfix if needed
    if command -v postfix &>/dev/null; then
        print_message "Checking Postfix..."
        postfix check || postfix reload
    fi
    
    # For now, offer to reinstall
    read -p "Run full reinstallation? (y/n): " REINSTALL
    if [[ "${REINSTALL,,}" == "y" ]]; then
        gather_basic_info
        perform_express_installation
    fi
}

# Gather basic configuration
gather_basic_info() {
    print_header "Basic Configuration"
    
    # Get domain name
    read -p "Enter your domain name (e.g., example.com): " DOMAIN_NAME
    # Basic domain validation
    if [[ ! "$DOMAIN_NAME" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        print_error "Invalid domain format"
        gather_basic_info
        return
    fi
    export DOMAIN_NAME
    
    # Get hostname
    default_hostname="mail.$DOMAIN_NAME"
    read -p "Enter mail server hostname [$default_hostname]: " HOSTNAME
    HOSTNAME=${HOSTNAME:-$default_hostname}
    export HOSTNAME
    
    # Get admin email
    read -p "Enter admin email address: " ADMIN_EMAIL
    # Basic email validation
    if [[ ! "$ADMIN_EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        print_error "Invalid email format"
        gather_basic_info
        return
    fi
    export ADMIN_EMAIL
    
    # Multi-IP configuration
    echo ""
    read -p "Configure multiple IP addresses? (y/n) [n]: " MULTI_IP
    
    if [[ "${MULTI_IP,,}" == "y" ]]; then
        configure_multiple_ips
    else
        # Get public IP
        PRIMARY_IP=$(curl -s https://ipinfo.io/ip || curl -s https://api.ipify.org || echo "127.0.0.1")
        export PRIMARY_IP
        export IP_ADDRESSES=("$PRIMARY_IP")
        print_message "Using single IP: $PRIMARY_IP"
    fi
}

# Configure multiple IPs
configure_multiple_ips() {
    IP_ADDRESSES=()
    echo "Enter IP addresses (one per line, empty to finish):"
    while true; do
        read -p "IP: " ip
        [ -z "$ip" ] && break
        # Basic IP validation
        if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            IP_ADDRESSES+=("$ip")
        else
            echo "Invalid IP format"
        fi
    done
    export IP_ADDRESSES
    export PRIMARY_IP="${IP_ADDRESSES[0]}"
}

# Perform express installation
perform_express_installation() {
    print_header "Starting Installation"
    
    # Check if functions exist before calling them
    print_message "Installing system packages..."
    if declare -f update_system_packages > /dev/null; then
        update_system_packages
    else
        apt-get update && apt-get upgrade -y
    fi
    
    if declare -f install_all_packages > /dev/null; then
        install_all_packages
    else
        print_message "Installing mail server packages..."
        apt-get install -y postfix dovecot-core dovecot-imapd mysql-server opendkim
    fi
    
    print_message "Basic installation complete!"
    print_message ""
    print_message "Server configured with:"
    print_message "  Domain: $DOMAIN_NAME"
    print_message "  Hostname: $HOSTNAME"
    print_message "  Admin: $ADMIN_EMAIL"
    print_message "  Primary IP: $PRIMARY_IP"
    print_message ""
    print_message "Next steps:"
    print_message "1. Configure DNS records"
    print_message "2. Set up SSL certificates"
    print_message "3. Test email delivery"
}

# Main installation menu
select_installation_mode() {
    echo "SELECT INSTALLATION MODE"
    echo "========================"
    echo ""
    echo "1. Express Installation (Recommended)"
    echo "   - Automatic configuration"
    echo "   - Single or multi-IP support"
    echo ""
    echo "2. Custom Installation (Advanced)"
    echo "   - Component selection"
    echo "   - Manual configuration"
    echo ""
    echo "3. Repair/Update Installation"
    echo "   - Fix issues"
    echo "   - Reconfigure services"
    echo ""
    
    read -p "Select mode (1-3): " INSTALL_MODE
    
    case $INSTALL_MODE in
        1) 
            gather_basic_info
            perform_express_installation
            ;;
        2) 
            custom_installation
            ;;
        3) 
            repair_installation
            ;;
        *) 
            echo "Invalid selection. Starting express installation..."
            gather_basic_info
            perform_express_installation
            ;;
    esac
}

# Warning and start
echo "⚠ WARNING: This will modify system configuration files."
echo "Recommended for fresh server installations only."
echo ""
read -p "Continue? (y/n): " CONTINUE

if [[ "${CONTINUE,,}" != "y" ]]; then
    echo "Installation cancelled."
    exit 0
fi

# Start installation
select_installation_mode
INSTALLER_SCRIPT

chmod +x "${INSTALLER_DIR}/run-installer.sh"

# Execute the installer
print_header "Starting Mail Server Installation"
echo ""

cd "$INSTALLER_DIR"
exec bash ./run-installer.sh
