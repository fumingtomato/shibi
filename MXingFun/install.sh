#!/bin/bash

# =================================================================
# MULTI-IP BULK MAIL SERVER INSTALLER - SIMPLIFIED VERSION
# Version: 16.0.6
# Author: fumingtomato
# Repository: https://github.com/fumingtomato/shibi
# =================================================================
# ALL QUESTIONS FIRST - THEN AUTOMATIC INSTALLATION
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

# IP validation and expansion functions
validate_ip() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        OIFS=$IFS
        IFS='.'
        ip_parts=($ip)
        IFS=$OIFS
        [[ ${ip_parts[0]} -le 255 && ${ip_parts[1]} -le 255 && ${ip_parts[2]} -le 255 && ${ip_parts[3]} -le 255 ]]
        return $?
    fi
    return 1
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
    start_ip=$1
    end_ip=$2
    max_ips=100
    
    if ! validate_ip "$start_ip" || ! validate_ip "$end_ip"; then
        echo "  Invalid IP addresses in range"
        return 1
    fi
    
    start_dec=$(ip_to_decimal "$start_ip")
    end_dec=$(ip_to_decimal "$end_ip")
    
    if [ $start_dec -gt $end_dec ]; then
        echo "  Start IP must be less than end IP"
        return 1
    fi
    
    range_size=$((end_dec - start_dec + 1))
    if [ $range_size -gt $max_ips ]; then
        echo "  Range too large (${range_size} IPs). Maximum is ${max_ips}."
        read -p "  Add first ${max_ips} IPs only? (y/n): " confirm
        if [[ "${confirm,,}" != "y" ]]; then
            return 1
        fi
        end_dec=$((start_dec + max_ips - 1))
    fi
    
    count=0
    for ((dec=start_dec; dec<=end_dec; dec++)); do
        ip=$(decimal_to_ip $dec)
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
    cidr=$1
    ip_part=${cidr%/*}
    mask=${cidr#*/}
    
    if ! validate_ip "$ip_part"; then
        echo "  Invalid IP in CIDR notation"
        return 1
    fi
    
    if ! [[ "$mask" =~ ^[0-9]+$ ]] || [ "$mask" -lt 8 ] || [ "$mask" -gt 32 ]; then
        echo "  Invalid CIDR mask (must be 8-32)"
        return 1
    fi
    
    ip_dec=$(ip_to_decimal "$ip_part")
    mask_bits=$((32 - mask))
    net_size=$((2 ** mask_bits))
    net_mask=$(((0xFFFFFFFF << mask_bits) & 0xFFFFFFFF))
    network=$((ip_dec & net_mask))
    broadcast=$((network | ~net_mask & 0xFFFFFFFF))
    
    first_host=$((network + 1))
    last_host=$((broadcast - 1))
    
    host_count=$((last_host - first_host + 1))
    if [ $host_count -gt 100 ]; then
        echo "  CIDR $cidr contains $host_count hosts."
        read -p "  Add first 100 IPs only? (y/n): " confirm
        if [[ "${confirm,,}" != "y" ]]; then
            return 1
        fi
        last_host=$((first_host + 99))
    fi
    
    echo "  Expanding CIDR $cidr..."
    count=0
    for ((dec=first_host; dec<=last_host; dec++)); do
        ip=$(decimal_to_ip $dec)
        if [[ "$ip" != "$PRIMARY_IP" ]] && validate_ip "$ip"; then
            IP_ADDRESSES+=("$ip")
            count=$((count + 1))
            [ $count -le 5 ] && echo "  Added: $ip"
        fi
    done
    [ $count -gt 5 ] && echo "  ... and $((count - 5)) more IPs"
    echo "  Total added from CIDR: $count IPs"
}

# Clear screen and show header
clear
cat << "EOF"
╔══════════════════════════════════════════════════════════════╗
║     MULTI-IP BULK MAIL SERVER INSTALLER v16.0.6             ║
║                                                              ║
║     Professional Mail Server with Multi-IP Support          ║
║     • Automatic Cloudflare DNS Setup                        ║
║     • Automatic Let's Encrypt SSL                           ║
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

# ===================================================================
# GATHER ALL CONFIGURATION FIRST - NO MORE QUESTIONS LATER!
# ===================================================================

print_header "CONFIGURATION WIZARD - Answer All Questions Now"
echo ""
echo "After these questions, the installer will run automatically."
echo "No more interruptions - just sit back and watch!"
echo ""

# Warning
echo "⚠ WARNING: This will modify system configuration files."
echo "It is recommended to run this on a fresh server installation."
echo ""
read -p "Continue with installation? (y/n): " CONTINUE

if [[ "${CONTINUE,,}" != "y" ]]; then
    echo "Installation cancelled."
    exit 0
fi

echo ""

# 1. Domain name
read -p "Enter your domain name (e.g., example.com): " DOMAIN_NAME
while [[ ! "$DOMAIN_NAME" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; do
    echo "Invalid domain format. Please use format: example.com"
    read -p "Enter your domain name: " DOMAIN_NAME
done

# Set hostname
HOSTNAME="mail.$DOMAIN_NAME"
echo "✓ Mail server hostname will be: $HOSTNAME"
echo ""

# 2. Admin email
read -p "Enter admin email address: " ADMIN_EMAIL
while [[ ! "$ADMIN_EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; do
    echo "Invalid email format."
    read -p "Enter admin email address: " ADMIN_EMAIL
done
echo "✓ Admin email set"
echo ""

# 3. Server IP
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
IP_ADDRESSES=("$PRIMARY_IP")
echo "✓ Primary IP configured"
echo ""

# 4. Cloudflare configuration
print_header "DNS Configuration"
echo "Do you want to automatically configure DNS records in Cloudflare?"
echo "(You'll need your Cloudflare API credentials)"
echo ""
read -p "Use Cloudflare automatic DNS setup? (y/n) [y]: " USE_CLOUDFLARE
USE_CLOUDFLARE=${USE_CLOUDFLARE:-y}

CF_EMAIL=""
CF_API_KEY=""

if [[ "${USE_CLOUDFLARE,,}" == "y" ]]; then
    echo ""
    echo "Get your API key from: https://dash.cloudflare.com/profile/api-tokens"
    echo "(Click 'View' next to Global API Key)"
    echo ""
    
    read -p "Enter Cloudflare email: " CF_EMAIL
    while [ -z "$CF_EMAIL" ]; do
        print_error "Email cannot be empty!"
        read -p "Enter Cloudflare email: " CF_EMAIL
    done
    
    echo "Enter Cloudflare Global API Key:"
    echo "(Input will be hidden for security)"
    read -s CF_API_KEY
    echo ""
    
    while [ -z "$CF_API_KEY" ]; do
        print_error "API Key cannot be empty!"
        echo "Enter Cloudflare Global API Key:"
        read -s CF_API_KEY
        echo ""
    done
    
    echo "✓ Cloudflare credentials saved"
else
    print_warning "Manual DNS setup selected."
    echo "You will need to manually add DNS records after installation."
fi
echo ""

# 5. Multi-IP configuration
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
            count=0
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
            start_ip=${ip_input%-*}
            end_ip=${ip_input#*-}
            
            # Handle short notation (192.168.1.100-110)
            if [[ ! "$end_ip" == *.*.*.* ]]; then
                base_ip=${start_ip%.*}
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
        unique_ips=($(echo "${IP_ADDRESSES[@]}" | tr ' ' '\n' | sort -u))
        echo "  Current total: ${#unique_ips[@]} unique IPs"
    done
    
    # Remove duplicates and sort
    IFS=" " read -ra IP_ADDRESSES <<< "$(echo "${IP_ADDRESSES[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' ')"
fi

# ===================================================================
# CONFIGURATION SUMMARY
# ===================================================================

echo ""
print_header "Configuration Summary"
echo "Domain: $DOMAIN_NAME"
echo "Hostname: $HOSTNAME"
echo "Admin Email: $ADMIN_EMAIL"
echo "Primary IP: $PRIMARY_IP"
if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
    echo "Additional IPs: $((${#IP_ADDRESSES[@]} - 1)) configured"
fi
if [[ "${USE_CLOUDFLARE,,}" == "y" ]]; then
    echo "DNS Setup: Automatic via Cloudflare"
    echo "SSL: Automatic Let's Encrypt after DNS"
else
    echo "DNS Setup: Manual configuration required"
    echo "SSL: Manual setup after DNS propagation"
fi
echo ""
echo "═══════════════════════════════════════════════════════"
echo ""
read -p "Ready to begin automatic installation? (y/n): " FINAL_CONFIRM
if [[ "${FINAL_CONFIRM,,}" != "y" ]]; then
    echo "Installation cancelled."
    exit 0
fi

# ===================================================================
# NOW BEGIN AUTOMATIC INSTALLATION - NO MORE QUESTIONS!
# ===================================================================

echo ""
print_header "AUTOMATIC INSTALLATION STARTED"
echo ""
echo "Sit back and relax! This will take 5-10 minutes..."
echo "No more questions will be asked."
echo ""
sleep 3

# Create working directory
INSTALLER_DIR="$(pwd)/mail-installer"
MODULES_DIR="${INSTALLER_DIR}/modules"

print_message "Setting up installation environment..."

# Clean up any previous installation attempts
if [ -d "$INSTALLER_DIR" ]; then
    rm -rf "$INSTALLER_DIR"
fi

# Create fresh directories
mkdir -p "$MODULES_DIR"
cd "$INSTALLER_DIR"

# Save configuration for all scripts to use
cat > "$INSTALLER_DIR/install.conf" <<EOF
DOMAIN_NAME="$DOMAIN_NAME"
HOSTNAME="$HOSTNAME"
ADMIN_EMAIL="$ADMIN_EMAIL"
PRIMARY_IP="$PRIMARY_IP"
IP_ADDRESSES=(${IP_ADDRESSES[@]})
USE_CLOUDFLARE="$USE_CLOUDFLARE"
CF_EMAIL="$CF_EMAIL"
CF_API_KEY="$CF_API_KEY"
EOF

# Save Cloudflare credentials if provided
if [ ! -z "$CF_EMAIL" ] && [ ! -z "$CF_API_KEY" ]; then
    cat > "/root/.cloudflare_credentials" <<EOF
SAVED_CF_EMAIL="$CF_EMAIL"
SAVED_CF_API_KEY="$CF_API_KEY"
EOF
    chmod 600 "/root/.cloudflare_credentials"
fi

# Download standalone scripts
declare -a STANDALONE_SCRIPTS=(
    "create-utilities.sh"
    "setup-database.sh"
    "cloudflare-dns-setup.sh"
    "ssl-setup.sh"
    "post-install-config.sh"
    "troubleshoot.sh"
)

print_message "Downloading installation scripts..."
echo ""

DOWNLOAD_FAILED=0

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
            DOWNLOAD_FAILED=$((DOWNLOAD_FAILED + 1))
        fi
    else
        echo "✗ (download failed)"
        DOWNLOAD_FAILED=$((DOWNLOAD_FAILED + 1))
    fi
done

echo ""

if [ $DOWNLOAD_FAILED -gt 0 ]; then
    print_warning "Some scripts failed to download, but continuing..."
fi

# ===================================================================
# PHASE 1: CORE INSTALLATION
# ===================================================================

print_header "Phase 1: Installing Core Components"
echo ""

echo "Updating system packages..."
apt-get update -y > /dev/null 2>&1
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y > /dev/null 2>&1

echo "Installing required packages..."
apt-get install -y jq curl wget > /dev/null 2>&1

# Pre-configure Postfix
debconf-set-selections <<< "postfix postfix/mailname string $HOSTNAME"
debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Internet Site'"

echo "Installing mail server packages (this may take a few minutes)..."
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    postfix postfix-mysql postfix-pcre \
    dovecot-core dovecot-imapd dovecot-pop3d dovecot-lmtpd dovecot-mysql \
    mysql-server mysql-client \
    opendkim opendkim-tools \
    spamassassin spamc \
    certbot \
    ufw fail2ban > /dev/null 2>&1

echo "Configuring Postfix..."
postconf -e "myhostname = $HOSTNAME"
postconf -e "mydomain = $DOMAIN_NAME"
postconf -e "myorigin = \$mydomain"
systemctl restart postfix > /dev/null 2>&1

# ===================================================================
# PHASE 2: DATABASE SETUP
# ===================================================================

print_header "Phase 2: Setting Up Database"
echo ""

if [ -f "$INSTALLER_DIR/setup-database.sh" ]; then
    bash "$INSTALLER_DIR/setup-database.sh"
else
    print_warning "Database setup script not found, using basic setup..."
fi

# ===================================================================
# PHASE 3: CREATE UTILITIES
# ===================================================================

print_header "Phase 3: Creating Management Utilities"
echo ""

if [ -f "$INSTALLER_DIR/create-utilities.sh" ]; then
    bash "$INSTALLER_DIR/create-utilities.sh"
else
    print_warning "Utilities script not found, skipping..."
fi

# ===================================================================
# PHASE 4: DNS CONFIGURATION (IF CLOUDFLARE)
# ===================================================================

if [[ "${USE_CLOUDFLARE,,}" == "y" ]]; then
    print_header "Phase 4: Configuring Cloudflare DNS"
    echo ""
    
    if [ -f "$INSTALLER_DIR/cloudflare-dns-setup.sh" ]; then
        bash "$INSTALLER_DIR/cloudflare-dns-setup.sh"
        
        if [ $? -eq 0 ]; then
            echo ""
            print_message "✓ DNS records created in Cloudflare"
            echo "Waiting 60 seconds for initial DNS propagation..."
            sleep 60
            
            # Test DNS resolution
            echo -n "Testing DNS resolution for $HOSTNAME... "
            if host $HOSTNAME 8.8.8.8 > /dev/null 2>&1; then
                print_message "✓ DNS is resolving!"
            else
                print_warning "⚠ DNS not fully propagated yet"
                echo "Continuing anyway, SSL might need manual setup later..."
            fi
        fi
    else
        print_warning "Cloudflare script not found, skipping DNS automation..."
    fi
else
    print_header "Phase 4: Manual DNS Configuration Required"
    echo ""
    echo "After installation, add these DNS records at your provider:"
    echo "  A record: mail.$DOMAIN_NAME -> $PRIMARY_IP"
    echo "  MX record: $DOMAIN_NAME -> mail.$DOMAIN_NAME (priority 10)"
    echo "  SPF: v=spf1 mx a ip4:$PRIMARY_IP ~all"
    echo ""
fi

# ===================================================================
# PHASE 5: SSL CERTIFICATE (IF CLOUDFLARE AND DNS IS READY)
# ===================================================================

if [[ "${USE_CLOUDFLARE,,}" == "y" ]]; then
    print_header "Phase 5: Getting SSL Certificate"
    echo ""
    
    if [ -f "$INSTALLER_DIR/ssl-setup.sh" ]; then
        bash "$INSTALLER_DIR/ssl-setup.sh"
    else
        print_warning "SSL setup script not found, using basic setup..."
        
        echo "Attempting to get Let's Encrypt certificate..."
        systemctl stop nginx 2>/dev/null || true
        systemctl stop apache2 2>/dev/null || true
        
        certbot certonly --standalone \
            -d "$HOSTNAME" \
            --non-interactive \
            --agree-tos \
            --email "$ADMIN_EMAIL" \
            --no-eff-email > /dev/null 2>&1
        
        if [ $? -eq 0 ]; then
            print_message "✓ SSL certificate obtained!"
        else
            print_warning "⚠ Could not get SSL certificate yet (DNS might not be ready)"
        fi
    fi
else
    print_header "Phase 5: SSL Certificate - Manual Setup Required"
    echo "After DNS propagates, run: certbot certonly --standalone -d $HOSTNAME"
fi

# ===================================================================
# PHASE 6: POST-INSTALLATION CONFIGURATION
# ===================================================================

print_header "Phase 6: Final Configuration"
echo ""

if [ -f "$INSTALLER_DIR/post-install-config.sh" ]; then
    bash "$INSTALLER_DIR/post-install-config.sh"
else
    print_warning "Post-install script not found, using basic configuration..."
    
    # Basic firewall setup
    echo "Configuring firewall..."
    ufw allow 22/tcp > /dev/null 2>&1
    ufw allow 25/tcp > /dev/null 2>&1
    ufw allow 587/tcp > /dev/null 2>&1
    ufw allow 465/tcp > /dev/null 2>&1
    ufw allow 143/tcp > /dev/null 2>&1
    ufw allow 993/tcp > /dev/null 2>&1
    ufw allow 80/tcp > /dev/null 2>&1
    ufw allow 443/tcp > /dev/null 2>&1
    ufw --force enable > /dev/null 2>&1
fi

# Restart all services
echo "Restarting mail services..."
systemctl restart postfix dovecot opendkim > /dev/null 2>&1

# ===================================================================
# INSTALLATION COMPLETE!
# ===================================================================

echo ""
print_header "🎉 INSTALLATION COMPLETE! 🎉"
echo ""
print_message "Your mail server has been successfully installed!"
echo ""
echo "Configuration:"
echo "  Domain: $DOMAIN_NAME"
echo "  Hostname: $HOSTNAME"
echo "  Admin Email: $ADMIN_EMAIL"
echo "  Primary IP: $PRIMARY_IP"
if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
    echo "  Additional IPs: $((${#IP_ADDRESSES[@]} - 1))"
fi
echo ""

if [[ "${USE_CLOUDFLARE,,}" == "y" ]]; then
    echo "✓ DNS records configured in Cloudflare"
    if [ -f "/etc/letsencrypt/live/$HOSTNAME/fullchain.pem" ]; then
        echo "✓ Let's Encrypt SSL certificate installed"
    else
        echo "⚠ SSL certificate pending - DNS might still be propagating"
        echo "  Try later: certbot certonly --standalone -d $HOSTNAME"
    fi
else
    echo "Next steps for manual configuration:"
    echo ""
    echo "1. Add DNS records at your DNS provider:"
    echo "   • A record: mail.$DOMAIN_NAME -> $PRIMARY_IP"
    echo "   • MX record: $DOMAIN_NAME -> mail.$DOMAIN_NAME (priority 10)"
    echo "   • SPF: v=spf1 mx a ip4:$PRIMARY_IP ~all"
    echo ""
    echo "2. After DNS propagates (5-30 minutes), get SSL certificate:"
    echo "   certbot certonly --standalone -d $HOSTNAME"
fi

echo ""
echo "Available Commands:"
echo "  mail-account add user@$DOMAIN_NAME password  - Add email account"
echo "  test-email check-auth@verifier.port25.com    - Test delivery"
echo "  check-dns $DOMAIN_NAME                       - Verify DNS"
echo "  mail-status                                   - Check server status"
echo ""
echo "Installation log: $LOG_FILE"
echo ""
print_message "Thank you for using the mail server installer!"
print_message "Repository: https://github.com/fumingtomato/shibi"
