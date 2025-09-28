#!/bin/bash

# =================================================================
# MULTI-IP BULK MAIL SERVER INSTALLER - SIMPLIFIED VERSION
# Version: 16.0.5
# Author: fumingtomato
# Repository: https://github.com/fumingtomato/shibi
# =================================================================
# Single-option installer with Cloudflare DNS THEN Let's Encrypt SSL
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
║     MULTI-IP BULK MAIL SERVER INSTALLER v16.0.5             ║
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

# Download standalone scripts - REMOVED final-config.sh
declare -a STANDALONE_SCRIPTS=(
    "create-utilities.sh"
    "setup-database.sh"
    "cloudflare-dns-setup.sh"
    "ssl-setup.sh"
    "post-install-config.sh"
    "troubleshoot.sh"
)

print_header "Downloading installation files"
echo "Downloading from: ${BASE_URL}/"
echo ""

DOWNLOAD_FAILED=0
CRITICAL_MISSING=0

# Download standalone scripts
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
            if [[ "$script" == "cloudflare-dns-setup.sh" ]] || [[ "$script" == "ssl-setup.sh" ]]; then
                echo "    (Optional - manual configuration will be needed)"
            else
                CRITICAL_MISSING=$((CRITICAL_MISSING + 1))
            fi
            DOWNLOAD_FAILED=$((DOWNLOAD_FAILED + 1))
        fi
    else
        echo "✗ (download failed)"
        if [[ "$script" == "cloudflare-dns-setup.sh" ]] || [[ "$script" == "ssl-setup.sh" ]]; then
            echo "    (Optional - manual configuration will be needed)"
        else
            CRITICAL_MISSING=$((CRITICAL_MISSING + 1))
        fi
        DOWNLOAD_FAILED=$((DOWNLOAD_FAILED + 1))
    fi
done

echo ""

if [ $CRITICAL_MISSING -gt 0 ]; then
    print_error "Critical scripts are missing. Installation cannot continue."
    exit 1
fi

if [ $DOWNLOAD_FAILED -gt 0 ]; then
    print_warning "Some optional scripts failed to download"
fi

print_message "✓ Core files ready"
echo ""

# Now create the main execution script
print_header "Creating main installer"

cat > "${INSTALLER_DIR}/run-installer.sh" << 'INSTALLER_SCRIPT'
#!/bin/bash

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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

print_header "Starting Mail Server Installation"
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
print_header "DNS Configuration Method"
echo "Do you want to automatically configure DNS records in Cloudflare?"
echo "(You'll need your Cloudflare API credentials)"
echo ""
read -p "Use Cloudflare automatic DNS setup? (y/n) [y]: " USE_CLOUDFLARE
USE_CLOUDFLARE=${USE_CLOUDFLARE:-y}
export USE_CLOUDFLARE

if [[ "${USE_CLOUDFLARE,,}" != "y" ]]; then
    print_warning "Manual DNS setup selected."
    echo "You will need to manually add DNS records after installation."
    echo "SSL certificates will need to be obtained manually after DNS propagates."
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

# Save configuration to file
cat > "$SCRIPT_DIR/install.conf" <<EOF
DOMAIN_NAME="$DOMAIN_NAME"
HOSTNAME="$HOSTNAME"
ADMIN_EMAIL="$ADMIN_EMAIL"
PRIMARY_IP="$PRIMARY_IP"
IP_ADDRESSES=(${IP_ADDRESSES[@]})
USE_CLOUDFLARE="$USE_CLOUDFLARE"
EOF

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
    echo "DNS & SSL: Automatic via Cloudflare + Let's Encrypt"
else
    echo "DNS & SSL: Manual configuration required"
fi
echo ""
read -p "Proceed with installation? (y/n): " FINAL_CONFIRM
if [[ "${FINAL_CONFIRM,,}" != "y" ]]; then
    echo "Installation cancelled."
    exit 0
fi

# ===================================================================
# INSTALLATION SEQUENCE - PROPER ORDER
# ===================================================================

print_header "Installing Mail Server - Phase 1: Core Components"

# Step 1: Update system
echo ""
echo "Step 1: Updating system packages..."
apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y

# Step 2: Install packages
echo ""
echo "Step 2: Installing required packages..."
apt-get install -y jq curl wget

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

# Step 3: Basic Postfix configuration
echo ""
echo "Step 3: Configuring Postfix with correct domain..."
postconf -e "myhostname = $HOSTNAME"
postconf -e "mydomain = $DOMAIN_NAME"
postconf -e "myorigin = \$mydomain"
systemctl restart postfix

# Step 4: Database setup
echo ""
echo "Step 4: Setting up database..."
if [ -f "$SCRIPT_DIR/setup-database.sh" ]; then
    export DOMAIN_NAME HOSTNAME ADMIN_EMAIL PRIMARY_IP
    bash "$SCRIPT_DIR/setup-database.sh"
fi

# Step 5: Create utilities
echo ""
echo "Step 5: Creating utility scripts..."
if [ -f "$SCRIPT_DIR/create-utilities.sh" ]; then
    export DOMAIN_NAME HOSTNAME ADMIN_EMAIL PRIMARY_IP
    bash "$SCRIPT_DIR/create-utilities.sh"
fi

# ===================================================================
# Phase 2: DNS CONFIGURATION (MUST BE BEFORE SSL!)
# ===================================================================

if [[ "${USE_CLOUDFLARE,,}" == "y" ]]; then
    print_header "Installing Mail Server - Phase 2: Cloudflare DNS"
    
    if [ -f "$SCRIPT_DIR/cloudflare-dns-setup.sh" ]; then
        echo "Setting up DNS records in Cloudflare..."
        export DOMAIN_NAME HOSTNAME ADMIN_EMAIL PRIMARY_IP
        bash "$SCRIPT_DIR/cloudflare-dns-setup.sh"
        
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
                echo "Waiting additional 60 seconds..."
                sleep 60
            fi
        fi
    fi
fi

# ===================================================================
# Phase 3: SSL CERTIFICATE (AFTER DNS IS SET!)
# ===================================================================

if [[ "${USE_CLOUDFLARE,,}" == "y" ]]; then
    print_header "Installing Mail Server - Phase 3: Let's Encrypt SSL"
    
    if [ -f "$SCRIPT_DIR/ssl-setup.sh" ]; then
        echo "Getting Let's Encrypt SSL certificate..."
        export DOMAIN_NAME HOSTNAME ADMIN_EMAIL PRIMARY_IP
        bash "$SCRIPT_DIR/ssl-setup.sh"
    else
        # Inline SSL setup if separate file doesn't exist
        echo "Setting up Let's Encrypt SSL certificate for $HOSTNAME..."
        
        # Stop services using port 80
        systemctl stop nginx 2>/dev/null || true
        systemctl stop apache2 2>/dev/null || true
        
        # Get certificate
        certbot certonly --standalone \
            -d "$HOSTNAME" \
            --non-interactive \
            --agree-tos \
            --email "$ADMIN_EMAIL" \
            --no-eff-email
        
        if [ $? -eq 0 ]; then
            print_message "✓ SSL certificate obtained!"
            
            # Configure Postfix
            postconf -e "smtpd_tls_cert_file = /etc/letsencrypt/live/$HOSTNAME/fullchain.pem"
            postconf -e "smtpd_tls_key_file = /etc/letsencrypt/live/$HOSTNAME/privkey.pem"
            postconf -e "smtpd_use_tls = yes"
            postconf -e "smtpd_tls_auth_only = yes"
            
            # Configure Dovecot
            cat > /etc/dovecot/conf.d/10-ssl.conf <<SSLEOF
ssl = required
ssl_cert = </etc/letsencrypt/live/$HOSTNAME/fullchain.pem
ssl_key = </etc/letsencrypt/live/$HOSTNAME/privkey.pem
ssl_min_protocol = TLSv1.2
ssl_cipher_list = ECDHE+AESGCM:ECDHE+RSA+AESGCM:DHE+RSA+AESGCM
ssl_prefer_server_ciphers = yes
SSLEOF
            
            # Setup auto-renewal
            cat > /etc/cron.d/certbot-renewal <<CRONEOF
0 2 * * * root certbot renew --quiet --post-hook "systemctl reload postfix dovecot"
CRONEOF
            
            systemctl restart postfix dovecot
        else
            print_error "Failed to obtain SSL certificate"
        fi
    fi
fi

# ===================================================================
# Phase 4: POST-INSTALLATION CONFIGURATION
# ===================================================================

print_header "Installing Mail Server - Phase 4: Final Configuration"

if [ -f "$SCRIPT_DIR/post-install-config.sh" ]; then
    echo "Running post-installation configuration..."
    export DOMAIN_NAME HOSTNAME ADMIN_EMAIL PRIMARY_IP USE_CLOUDFLARE
    bash "$SCRIPT_DIR/post-install-config.sh"
else
    # Basic final steps
    echo "Configuring firewall..."
    ufw allow 22/tcp
    ufw allow 25/tcp
    ufw allow 587/tcp
    ufw allow 465/tcp
    ufw allow 143/tcp
    ufw allow 993/tcp
    ufw allow 80/tcp
    ufw allow 443/tcp
    ufw --force enable
    
    echo "Restarting all services..."
    systemctl restart postfix dovecot opendkim
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
    echo "✓ DNS records configured in Cloudflare"
    if [ -f "/etc/letsencrypt/live/$HOSTNAME/fullchain.pem" ]; then
        echo "✓ Let's Encrypt SSL certificate installed"
    else
        echo "⚠ SSL certificate pending - run: certbot certonly --standalone -d $HOSTNAME"
    fi
else
    echo "Next steps for manual configuration:"
    echo "1. Add DNS records at your DNS provider:"
    echo "   - A record: mail.$DOMAIN_NAME -> $PRIMARY_IP"
    echo "   - MX record: $DOMAIN_NAME -> mail.$DOMAIN_NAME (priority 10)"
    echo "   - SPF: v=spf1 mx a ip4:$PRIMARY_IP ~all"
    echo ""
    echo "2. After DNS propagates, get SSL certificate:"
    echo "   certbot certonly --standalone -d $HOSTNAME"
fi

echo ""
echo "Test your installation:"
echo "  test-email check-auth@verifier.port25.com"
echo "  check-dns $DOMAIN_NAME"
echo "  mail-status"
echo ""
echo "Installation log: $LOG_FILE"
INSTALLER_SCRIPT

chmod +x "${INSTALLER_DIR}/run-installer.sh"

# Execute the installer
print_header "Starting Mail Server Installation"
echo ""

cd "$INSTALLER_DIR"
exec bash ./run-installer.sh
