#!/bin/bash

# =================================================================
# MULTI-IP BULK MAIL SERVER INSTALLER - SIMPLIFIED VERSION
# Version: 16.0.3
# Author: fumingtomato
# Repository: https://github.com/fumingtomato/shibi
# =================================================================
# Single-option installer with automatic Cloudflare DNS setup
# Now with IP range and CIDR notation support!
# =================================================================

set -e
set -o pipefail

# Configuration
REPO_OWNER="fumingtomato"
REPO_NAME="shibi"
BRANCH="main"
BASE_URL="https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/${BRANCH}/MXingFun"

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
║     MULTI-IP BULK MAIL SERVER INSTALLER v16.0.3             ║
║                                                              ║
║     Professional Mail Server with Multi-IP Support          ║
║     • Automatic Cloudflare DNS Setup                        ║
║     • IP Range and CIDR Support                            ║
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

# List of all modules to download - INCLUDING CLOUDFLARE SETUP
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

# Also download standalone scripts
declare -a STANDALONE_SCRIPTS=(
    "create-utilities.sh"
    "setup-database.sh"
    "post-install-config.sh"
    "troubleshoot.sh"
    "cloudflare-dns-setup.sh"
)

print_header "Downloading installation files"
echo "Downloading from: ${BASE_URL}/"
echo ""

DOWNLOAD_FAILED=0

# Download modules (these might not exist, that's OK)
echo "Downloading modules (optional)..."
for module in "${MODULES[@]}"; do
    module_url="${BASE_URL}/modules/${module}"
    module_file="${MODULES_DIR}/${module}"
    
    if wget -q -O "$module_file" "$module_url" 2>/dev/null || \
       curl -sfL -o "$module_file" "$module_url" 2>/dev/null; then
        if [ -s "$module_file" ]; then
            chmod +x "$module_file"
        else
            rm -f "$module_file"
        fi
    fi
done

# Download standalone scripts (these should exist)
echo "Downloading core scripts..."
for script in "${STANDALONE_SCRIPTS[@]}"; do
    script_url="${BASE_URL}/${script}"
    script_file="${INSTALLER_DIR}/${script}"
    
    echo -n "  Downloading ${script}... "
    
    if wget -q -O "$script_file" "$script_url" 2>/dev/null || \
       curl -sfL -o "$script_file" "$script_url" 2>/dev/null; then
        
        if [ -s "$script_file" ]; then
            echo "✓"
            chmod +x "$script_file"
        else
            echo "✗ (empty file)"
            rm -f "$script_file"
            if [[ "$script" == "cloudflare-dns-setup.sh" ]]; then
                echo "    (Cloudflare DNS automation will not be available)"
            else
                DOWNLOAD_FAILED=$((DOWNLOAD_FAILED + 1))
            fi
        fi
    else
        echo "✗ (download failed)"
        if [[ "$script" != "cloudflare-dns-setup.sh" ]]; then
            DOWNLOAD_FAILED=$((DOWNLOAD_FAILED + 1))
        fi
    fi
done

echo ""

if [ $DOWNLOAD_FAILED -gt 0 ]; then
    print_warning "Some optional scripts failed to download, but installation can continue"
fi

print_message "✓ Core files downloaded successfully"
echo ""

# Now create the main execution script with Cloudflare integration
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

# IP validation and expansion functions
validate_ip() {
    local ip=$1
    local valid=1
    
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        OIFS=$IFS
        IFS='.'
        ip=($ip)
        IFS=$OIFS
        [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
        valid=$?
    else
        valid=1
    fi
    
    return $valid
}

ip_to_decimal() {
    local ip=$1
    local a b c d
    IFS='.' read -r a b c d <<< "$ip"
    echo "$((a * 256**3 + b * 256**2 + c * 256 + d))"
}

decimal_to_ip() {
    local dec=$1
    echo "$((dec >> 24 & 255)).$((dec >> 16 & 255)).$((dec >> 8 & 255)).$((dec & 255))"
}

expand_ip_range() {
    local start_ip=$1
    local end_ip=$2
    local max_ips=100  # Safety limit
    
    if ! validate_ip "$start_ip" || ! validate_ip "$end_ip"; then
        echo "  Invalid IP addresses in range"
        return 1
    fi
    
    local start_dec=$(ip_to_decimal "$start_ip")
    local end_dec=$(ip_to_decimal "$end_ip")
    
    if [ $start_dec -gt $end_dec ]; then
        echo "  Start IP must be less than end IP"
        return 1
    fi
    
    local range_size=$((end_dec - start_dec + 1))
    if [ $range_size -gt $max_ips ]; then
        echo "  Range too large (${range_size} IPs). Maximum is ${max_ips}."
        read -p "  Add first ${max_ips} IPs only? (y/n): " confirm
        if [[ "${confirm,,}" != "y" ]]; then
            return 1
        fi
        end_dec=$((start_dec + max_ips - 1))
    fi
    
    local count=0
    for ((dec=start_dec; dec<=end_dec; dec++)); do
        local ip=$(decimal_to_ip $dec)
        if [[ "$ip" != "$PRIMARY_IP" ]] && validate_ip "$ip"; then
            IP_ADDRESSES+=("$ip")
            count=$((count + 1))
            [ $count -le 10 ] && echo "  Added: $ip"
        fi
    done
    [ $count -gt 10 ] && echo "  ... and $((count - 10)) more IPs"
    echo "  Total added from range: $count IPs"
}

expand_cidr() {
    local cidr=$1
    local ip_part=${cidr%/*}
    local mask=${cidr#*/}
    
    if ! validate_ip "$ip_part"; then
        echo "  Invalid IP in CIDR notation"
        return 1
    fi
    
    if ! [[ "$mask" =~ ^[0-9]+$ ]] || [ "$mask" -lt 8 ] || [ "$mask" -gt 32 ]; then
        echo "  Invalid CIDR mask (must be 8-32)"
        return 1
    fi
    
    # Calculate network range
    local ip_dec=$(ip_to_decimal "$ip_part")
    local mask_bits=$((32 - mask))
    local net_size=$((2 ** mask_bits))
    local net_mask=$(((0xFFFFFFFF << mask_bits) & 0xFFFFFFFF))
    local network=$((ip_dec & net_mask))
    local broadcast=$((network | ~net_mask & 0xFFFFFFFF))
    
    # Skip network and broadcast addresses
    local first_host=$((network + 1))
    local last_host=$((broadcast - 1))
    
    # Safety check for large networks
    local host_count=$((last_host - first_host + 1))
    if [ $host_count -gt 100 ]; then
        echo "  CIDR $cidr contains $host_count hosts."
        read -p "  Add first 100 IPs only? (y/n): " confirm
        if [[ "${confirm,,}" != "y" ]]; then
            return 1
        fi
        last_host=$((first_host + 99))
    fi
    
    echo "  Expanding CIDR $cidr..."
    local count=0
    for ((dec=first_host; dec<=last_host; dec++)); do
        local ip=$(decimal_to_ip $dec)
        if [[ "$ip" != "$PRIMARY_IP" ]] && validate_ip "$ip"; then
            IP_ADDRESSES+=("$ip")
            count=$((count + 1))
            [ $count -le 5 ] && echo "  Added: $ip"
        fi
    done
    [ $count -gt 5 ] && echo "  ... and $((count - 5)) more IPs"
    echo "  Total added from CIDR: $count IPs"
}

print_header "Starting Mail Server Installation"
echo ""

# Load any available modules
echo "Loading installer modules..."
for module_file in "$MODULES_DIR"/*.sh; do
    if [ -f "$module_file" ]; then
        source "$module_file" 2>/dev/null || true
    fi
done
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

# Ask about Cloudflare DNS automation
echo ""
print_header "DNS Configuration"
echo "Do you want to automatically configure DNS records in Cloudflare?"
echo "(You'll need your Cloudflare API credentials)"
echo ""
read -p "Use Cloudflare automatic DNS setup? (y/n) [n]: " USE_CLOUDFLARE
export USE_CLOUDFLARE

if [[ "${USE_CLOUDFLARE,,}" == "y" ]]; then
    echo ""
    echo "Great! We'll set up Cloudflare DNS after the mail server installation."
    echo "You'll need:"
    echo "  1. Your Cloudflare account email"
    echo "  2. Your Global API Key from: https://dash.cloudflare.com/profile/api-tokens"
    echo ""
    read -p "Press Enter to continue..."
fi

# Multi-IP configuration with range and CIDR support
echo ""
read -p "Do you want to configure additional IP addresses? (y/n) [n]: " MULTI_IP
if [[ "${MULTI_IP,,}" == "y" ]]; then
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    IP ADDRESS INPUT                          ║"
    echo "╠══════════════════════════════════════════════════════════════╣"
    echo "║ Supported formats:                                           ║"
    echo "║   • Single IP:     192.168.1.100                            ║"
    echo "║   • Range:         192.168.1.100-192.168.1.110              ║"
    echo "║   • Short range:   192.168.1.100-110                        ║"
    echo "║   • CIDR:          192.168.1.0/24                           ║"
    echo "║   • Multiple:      192.168.1.100,192.168.1.101              ║"
    echo "║                                                              ║"
    echo "║ Enter empty line to finish                                  ║"
    echo "║ Maximum 100 IPs per entry for safety                        ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    
    while true; do
        read -p "IP/Range/CIDR: " ip_input
        [ -z "$ip_input" ] && break
        
        # Remove spaces
        ip_input=$(echo "$ip_input" | tr -d ' ')
        
        # Check for comma-separated IPs
        if [[ "$ip_input" == *","* ]]; then
            IFS=',' read -ra ADDR_ARRAY <<< "$ip_input"
            local count=0
            for addr in "${ADDR_ARRAY[@]}"; do
                if validate_ip "$addr"; then
                    if [[ "$addr" != "$PRIMARY_IP" ]]; then
                        IP_ADDRESSES+=("$addr")
                        count=$((count + 1))
                        echo "  Added: $addr"
                    fi
                else
                    echo "  Invalid IP: $addr"
                fi
            done
            echo "  Total added: $count IPs"
        
        # Check for IP range
        elif [[ "$ip_input" == *"-"* ]]; then
            local start_ip=${ip_input%-*}
            local end_ip=${ip_input#*-}
            
            # Handle short notation (192.168.1.100-110)
            if [[ ! "$end_ip" == *.*.*.* ]]; then
                local base_ip=${start_ip%.*}
                end_ip="$base_ip.$end_ip"
            fi
            
            expand_ip_range "$start_ip" "$end_ip"
        
        # Check for CIDR notation
        elif [[ "$ip_input" == *"/"* ]]; then
            expand_cidr "$ip_input"
        
        # Single IP address
        elif validate_ip "$ip_input"; then
            if [[ "$ip_input" != "$PRIMARY_IP" ]]; then
                IP_ADDRESSES+=("$ip_input")
                echo "  Added: $ip_input"
            else
                echo "  Skipping primary IP"
            fi
        
        else
            echo "  Invalid format. Please see examples above."
        fi
        
        # Show current count
        local unique_ips=($(echo "${IP_ADDRESSES[@]}" | tr ' ' '\n' | sort -u))
        echo "  Current total: ${#unique_ips[@]} unique IPs"
        
        # Safety limit
        if [ ${#unique_ips[@]} -gt 500 ]; then
            echo ""
            print_warning "Warning: You have configured ${#unique_ips[@]} IPs."
            echo "Large numbers of IPs may impact performance."
            read -p "Continue adding more IPs? (y/n): " cont
            if [[ "${cont,,}" != "y" ]]; then
                break
            fi
        fi
    done
    
    # Remove duplicates and sort
    IFS=" " read -ra IP_ADDRESSES <<< "$(echo "${IP_ADDRESSES[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' ')"
    
    echo ""
    echo "═══════════════════════════════════════════════════════"
    echo "Total IP addresses configured: ${#IP_ADDRESSES[@]}"
    if [ ${#IP_ADDRESSES[@]} -le 10 ]; then
        echo "IPs: ${IP_ADDRESSES[@]}"
    else
        echo "First 5 IPs: ${IP_ADDRESSES[@]:0:5}"
        echo "Last 5 IPs: ${IP_ADDRESSES[@]: -5}"
    fi
    echo "═══════════════════════════════════════════════════════"
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
    echo "Additional IPs: $((${#IP_ADDRESSES[@]} - 1)) configured"
fi
if [[ "${USE_CLOUDFLARE,,}" == "y" ]]; then
    echo "Cloudflare DNS: Yes (automatic setup)"
else
    echo "Cloudflare DNS: No (manual setup required)"
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
apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y

# Step 2: Install packages
echo ""
echo "Step 2: Installing required packages..."
# Install jq for Cloudflare API if using Cloudflare
if [[ "${USE_CLOUDFLARE,,}" == "y" ]]; then
    apt-get install -y jq
fi

# Pre-configure Postfix
debconf-set-selections <<< "postfix postfix/mailname string $HOSTNAME"
debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Internet Site'"

DEBIAN_FRONTEND=noninteractive apt-get install -y \
    postfix postfix-mysql postfix-pcre \
    dovecot-core dovecot-imapd dovecot-pop3d dovecot-lmtpd dovecot-mysql \
    mysql-server mysql-client \
    opendkim opendkim-tools \
    spamassassin spamc \
    certbot \
    ufw fail2ban

# Step 3: Run additional setup scripts if available
echo ""
echo "Step 3: Running configuration scripts..."

# Run database setup
if [ -f "$SCRIPT_DIR/setup-database.sh" ]; then
    echo "Setting up database..."
    bash "$SCRIPT_DIR/setup-database.sh"
fi

# Run utilities creation
if [ -f "$SCRIPT_DIR/create-utilities.sh" ]; then
    echo "Creating utility scripts..."
    bash "$SCRIPT_DIR/create-utilities.sh"
fi

# Run post-install configuration
if [ -f "$SCRIPT_DIR/post-install-config.sh" ]; then
    echo "Running post-installation configuration..."
    bash "$SCRIPT_DIR/post-install-config.sh"
fi

# ===================================================================
# CLOUDFLARE DNS SETUP (if requested)
# ===================================================================

if [[ "${USE_CLOUDFLARE,,}" == "y" ]]; then
    print_header "Cloudflare DNS Setup"
    
    if [ -f "$SCRIPT_DIR/cloudflare-dns-setup.sh" ]; then
        echo "Running Cloudflare DNS automatic configuration..."
        echo ""
        bash "$SCRIPT_DIR/cloudflare-dns-setup.sh"
    else
        print_warning "Cloudflare setup script not found."
        echo "You can manually download and run it later:"
        echo "  wget https://raw.githubusercontent.com/fumingtomato/shibi/main/MXingFun/cloudflare-dns-setup.sh"
        echo "  sudo bash cloudflare-dns-setup.sh"
    fi
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
if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
    echo "  Additional IPs: $((${#IP_ADDRESSES[@]} - 1))"
fi
echo ""

if [[ "${USE_CLOUDFLARE,,}" == "y" ]]; then
    echo "✓ Cloudflare DNS records have been configured automatically!"
    echo ""
    echo "DNS records should be active within 5-30 minutes."
else
    echo "IMPORTANT NEXT STEPS:"
    echo "====================="
    echo ""
    echo "1. Configure DNS records:"
    echo "   - A record: mail.$DOMAIN_NAME -> $PRIMARY_IP"
    echo "   - MX record: $DOMAIN_NAME -> mail.$DOMAIN_NAME (priority 10)"
    echo "   - PTR record: $PRIMARY_IP -> mail.$DOMAIN_NAME (contact your provider)"
    echo ""
    echo "2. Check configuration files:"
    echo "   - /root/dns-records-*.txt (for complete DNS records)"
    echo ""
fi

echo "3. Test your installation:"
echo "   - Send a test email: test-email check-auth@verifier.port25.com"
echo "   - Check DNS: check-dns $DOMAIN_NAME"
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
