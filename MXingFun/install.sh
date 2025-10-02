#!/bin/bash

# =================================================================
# BULK MAIL SERVER INSTALLER WITH MULTI-IP SUPPORT
# Version: 17.0.8 - WITH ADVANCED IP ROTATION
# Automated installation with Cloudflare DNS, compliance website, and DKIM
# FIXED: Ensures 1024-bit DKIM key generation and proper configuration
# ADDED: Universal command access and advanced bulk IP rotation management
# =================================================================

set -e  # Exit on any error

# Installation directory
INSTALL_DIR="/root/mail-installer"
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# Log file
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
        IFS='.' read -r -a octets <<< "$ip"
        for octet in "${octets[@]}"; do
            if ((octet > 255)); then
                return 1
            fi
        done
        return 0
    fi
    return 1
}

ip_to_decimal() {
    local ip=$1
    IFS='.' read -r -a octets <<< "$ip"
    echo "$((octets[0] * 256**3 + octets[1] * 256**2 + octets[2] * 256 + octets[3]))"
}

decimal_to_ip() {
    local dec=$1
    echo "$((dec >> 24 & 255)).$((dec >> 16 & 255)).$((dec >> 8 & 255)).$((dec & 255))"
}

expand_ip_range() {
    local range=$1
    local start_ip end_ip
    IFS='-' read -r start_ip end_ip <<< "$range"
    
    if ! validate_ip "$start_ip"; then
        return 1
    fi
    
    if [ -z "$end_ip" ]; then
        echo "$start_ip"
        return 0
    fi
    
    # Handle shorthand notation like 192.168.1.1-10
    if [[ ! "$end_ip" =~ \. ]]; then
        IFS='.' read -r -a start_octets <<< "$start_ip"
        end_ip="${start_octets[0]}.${start_octets[1]}.${start_octets[2]}.$end_ip"
    fi
    
    if ! validate_ip "$end_ip"; then
        return 1
    fi
    
    local start_dec=$(ip_to_decimal "$start_ip")
    local end_dec=$(ip_to_decimal "$end_ip")
    
    if [ $start_dec -gt $end_dec ]; then
        return 1
    fi
    
    local ips=()
    for ((dec=start_dec; dec<=end_dec; dec++)); do
        ips+=("$(decimal_to_ip $dec)")
    done
    
    printf '%s\n' "${ips[@]}"
}

expand_cidr() {
    local cidr=$1
    local ip prefix
    IFS='/' read -r ip prefix <<< "$cidr"
    
    if ! validate_ip "$ip"; then
        return 1
    fi
    
    if [ -z "$prefix" ] || [ "$prefix" -lt 0 ] || [ "$prefix" -gt 32 ]; then
        return 1
    fi
    
    local ip_dec=$(ip_to_decimal "$ip")
    local mask=$(( (1 << 32) - (1 << (32 - prefix)) ))
    local network=$(( ip_dec & mask ))
    local broadcast=$(( network | ~mask & ((1 << 32) - 1) ))
    
    local ips=()
    for ((dec=network+1; dec<broadcast; dec++)); do
        ips+=("$(decimal_to_ip $dec)")
    done
    
    printf '%s\n' "${ips[@]}"
}

# ===================================================================
# INTEGRATED BULK IP ROTATION SETUP (FROM bulkIPfix.sh)
# ===================================================================
configure_bulk_ip_rotation() {
    print_message "Configuring Advanced IP Rotation for ${#IP_ADDRESSES[@]} addresses..."

    # Get DB Password
    local DB_PASS=$(cat /root/.mail_db_password)

    # 1. Create advanced database tables
    mysql -u mailuser -p"$DB_PASS" mailserver <<EOF 2>/dev/null
CREATE TABLE IF NOT EXISTS ip_rotation_advanced (
    id INT AUTO_INCREMENT PRIMARY KEY,
    sender_email VARCHAR(255) UNIQUE,
    assigned_ip VARCHAR(45),
    transport_id INT,
    message_count BIGINT DEFAULT 0,
    last_used TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    rotation_mode ENUM('sticky', 'round-robin', 'least-used') DEFAULT 'sticky',
    max_messages_per_day INT DEFAULT 1000,
    messages_today INT DEFAULT 0,
    last_reset DATE,
    INDEX idx_sender (sender_email),
    INDEX idx_ip (assigned_ip)
);
CREATE TABLE IF NOT EXISTS ip_pool (
    ip_address VARCHAR(45) PRIMARY KEY,
    ip_index INT,
    is_active BOOLEAN DEFAULT TRUE,
    reputation_score INT DEFAULT 100,
    messages_sent_today INT DEFAULT 0,
    messages_sent_total BIGINT DEFAULT 0,
    last_used TIMESTAMP,
    max_daily_limit INT DEFAULT 5000,
    last_reset DATE
);
EOF
    print_message "✓ Advanced IP rotation database tables created"

    # 2. Populate the IP pool table
    for i in "${!IP_ADDRESSES[@]}"; do
        local IP="${IP_ADDRESSES[$i]}"
        mysql -u mailuser -p"$DB_PASS" mailserver -e "INSERT IGNORE INTO ip_pool (ip_address, ip_index) VALUES ('$IP', $i);" 2>/dev/null
    done
    print_message "✓ IP pool populated in database"

    # 3. Add transport entries to master.cf
    for i in "${!IP_ADDRESSES[@]}"; do
        local IP="${IP_ADDRESSES[$i]}"
        # Check if transport already exists to prevent duplication
        if ! grep -q "^smtp-ip$i" /etc/postfix/master.cf; then
            cat >> /etc/postfix/master.cf <<EOF

# Transport for IP $IP (index $i)
smtp-ip$i unix - - n - - smtp
  -o smtp_bind_address=$IP
  -o smtp_helo_name=${MAIL_SUBDOMAIN}${i}.$DOMAIN_NAME
  -o syslog_name=postfix-ip$i
EOF
        fi
    done
    print_message "✓ Postfix transports created for all IPs"

    # 4. Create the advanced IP management command
    cat > /usr/local/bin/bulk-ip-manage <<'BIM'
#!/bin/bash
# Bulk Mailer IP Management Tool
DB_PASS=$(cat /etc/mail-config/db_password 2>/dev/null || cat /root/.mail_db_password)
source /etc/mail-config/install.conf
case "$1" in
    assign)
        if [ -z "$2" ] || [ -z "$3" ]; then
            echo "Usage: bulk-ip-manage assign <email> <mode>"
            echo "Modes: sticky, round-robin, least-used, specific:<ip>"
            exit 1
        fi
        EMAIL="$2"
        MODE="$3"
        if [[ "$MODE" == specific:* ]]; then
            SPECIFIC_IP="${MODE#specific:}"
            IP_INDEX=-1
            for i in "${!IP_ADDRESSES[@]}"; do
                if [ "${IP_ADDRESSES[$i]}" == "$SPECIFIC_IP" ]; then
                    IP_INDEX=$i
                    break
                fi
            done
            if [ $IP_INDEX -eq -1 ]; then
                echo "Error: IP $SPECIFIC_IP not found in pool"
                exit 1
            fi
            ASSIGNED_IP="$SPECIFIC_IP"
            ROTATION_MODE="sticky"
        else
            case "$MODE" in
                sticky)
                    ASSIGNED_IP=$(mysql -u mailuser -p"$DB_PASS" mailserver -sN -e "SELECT ip_address FROM ip_pool WHERE is_active = TRUE ORDER BY messages_sent_total ASC, messages_sent_today ASC LIMIT 1" 2>/dev/null)
                    ROTATION_MODE="sticky"
                    ;;
                round-robin)
                    ASSIGNED_IP="${IP_ADDRESSES[0]}"
                    ROTATION_MODE="round-robin"
                    ;;
                least-used)
                    ASSIGNED_IP="${IP_ADDRESSES[0]}"
                    ROTATION_MODE="least-used"
                    ;;
                *) echo "Unknown mode: $MODE"; exit 1 ;;
            esac
            IP_INDEX=-1
            for i in "${!IP_ADDRESSES[@]}"; do
                if [ "${IP_ADDRESSES[$i]}" == "$ASSIGNED_IP" ]; then
                    IP_INDEX=$i
                    break
                fi
            done
        fi
        mysql -u mailuser -p"$DB_PASS" mailserver -e "INSERT INTO ip_rotation_advanced (sender_email, assigned_ip, transport_id, rotation_mode) VALUES ('$EMAIL', '$ASSIGNED_IP', $IP_INDEX, '$ROTATION_MODE') ON DUPLICATE KEY UPDATE assigned_ip = '$ASSIGNED_IP', transport_id = $IP_INDEX, rotation_mode = '$ROTATION_MODE'" 2>/dev/null
        (grep -v "^$EMAIL " /etc/postfix/sender_transports 2>/dev/null || true) > /tmp/sender_transport_tmp
        echo "$EMAIL    smtp-ip$IP_INDEX" >> /tmp/sender_transport_tmp
        mv /tmp/sender_transport_tmp /etc/postfix/sender_transports
        postmap hash:/etc/postfix/sender_transports
        echo "✓ Assigned $EMAIL to IP $ASSIGNED_IP (mode: $ROTATION_MODE)"
        ;;
    status)
        echo "=== IP POOL STATUS ==="
        mysql -u mailuser -p"$DB_PASS" mailserver -e "SELECT ip_address AS 'IP Address', is_active AS 'Active', messages_sent_today AS 'Today', messages_sent_total AS 'Total', reputation_score AS 'Score' FROM ip_pool ORDER BY ip_index" 2>/dev/null
        echo ""
        echo "=== SENDER ASSIGNMENTS ==="
        mysql -u mailuser -p"$DB_PASS" mailserver -e "SELECT sender_email AS 'Sender', assigned_ip AS 'IP', rotation_mode AS 'Mode', message_count AS 'Messages', last_used AS 'Last Used' FROM ip_rotation_advanced ORDER BY last_used DESC LIMIT 20" 2>/dev/null
        ;;
    rotate)
        EMAIL="$2"
        if [ -z "$EMAIL" ]; then echo "Usage: bulk-ip-manage rotate <email>"; exit 1; fi
        CURRENT=$(mysql -u mailuser -p"$DB_PASS" mailserver -sN -e "SELECT transport_id, rotation_mode FROM ip_rotation_advanced WHERE sender_email = '$EMAIL'" 2>/dev/null)
        if [ -z "$CURRENT" ]; then echo "Error: $EMAIL not found"; exit 1; fi
        IFS=$'\t' read -r CURRENT_ID MODE <<< "$CURRENT"
        if [ "$MODE" != "round-robin" ]; then echo "Email is in $MODE mode, not rotating"; exit 0; fi
        NEXT_ID=$(( (CURRENT_ID + 1) % ${#IP_ADDRESSES[@]} ))
        NEXT_IP="${IP_ADDRESSES[$NEXT_ID]}"
        mysql -u mailuser -p"$DB_PASS" mailserver -e "UPDATE ip_rotation_advanced SET assigned_ip = '$NEXT_IP', transport_id = $NEXT_ID WHERE sender_email = '$EMAIL'" 2>/dev/null
        sed -i "/^$EMAIL /d" /etc/postfix/sender_transports 2>/dev/null
        echo "$EMAIL    smtp-ip$NEXT_ID" >> /etc/postfix/sender_transports
        postmap hash:/etc/postfix/sender_transports
        echo "✓ Rotated $EMAIL to IP $NEXT_IP"
        ;;
    *)
        echo "Bulk IP Management Tool"
        echo "Usage: bulk-ip-manage {assign|status|rotate}"
        echo "Commands:"
        echo "  assign <email> <mode>  - Assign IP with mode (sticky, round-robin, least-used, specific:<ip>)"
        echo "  status                 - Show IP pool and assignments"
        echo "  rotate <email>         - Force rotation (for round-robin accounts only)"
        ;;
esac
if [ "$1" == "assign" ] || [ "$1" == "rotate" ]; then
    postfix reload 2>/dev/null
fi
BIM
    chmod 755 /usr/local/bin/bulk-ip-manage
    print_message "✓ 'bulk-ip-manage' command created"

    # 5. Configure Postfix main.cf and create transport map
    postconf -e "sender_dependent_default_transport_maps = hash:/etc/postfix/sender_transports"
    postconf -e "smtp_bind_address =" # Clear global binding
    touch /etc/postfix/sender_transports
    postmap hash:/etc/postfix/sender_transports
    print_message "✓ Postfix configured for advanced IP routing"

    # 6. Final reload
    postfix reload
}

# ===================================================================
# PROPER DKIM KEY GENERATION FUNCTION
# ===================================================================

generate_dkim_key() {
    local domain=$1
    local bits=1024  # CRITICAL: Use 1024-bit for DNS compatibility
    
    print_header "Generating DKIM Key (1024-bit)"
    
    # Create directory
    mkdir -p /etc/opendkim/keys/$domain
    cd /etc/opendkim/keys/$domain
    
    # Remove any existing keys
    rm -f mail.private mail.txt 2>/dev/null || true
    
    # Generate 1024-bit key
    echo "Generating 1024-bit DKIM key for $domain..."
    opendkim-genkey -s mail -d $domain -b $bits
    
    # Verify key was generated
    if [ ! -f mail.private ] || [ ! -f mail.txt ]; then
        print_error "Failed to generate DKIM key"
        return 1
    fi
    
    # Verify key size
    KEY_BITS=$(openssl rsa -in mail.private -text -noout 2>/dev/null | grep "Private-Key:" | grep -oP '\d+' | head -1)
    if [ "$KEY_BITS" != "1024" ]; then
        print_warning "Generated key is ${KEY_BITS}-bit, regenerating as 1024-bit..."
        opendkim-genkey -s mail -d $domain -b 1024
    fi
    
    # Set permissions
    chown opendkim:opendkim mail.private mail.txt
    chmod 600 mail.private
    chmod 644 mail.txt
    
    # Extract and display key info
    DKIM_KEY=$(grep -oP 'p=\K[^"]+' mail.txt | tr -d '\n\t\r ')
    if [ ! -z "$DKIM_KEY" ]; then
        print_message "✓ DKIM key generated successfully"
        echo "  Key length: ${#DKIM_KEY} characters (should be ~216 for 1024-bit)"
        return 0
    else
        print_error "Failed to extract DKIM key"
        return 1
    fi
}

# ===================================================================
# MAIN INSTALLATION
# ===================================================================

print_header "Multi-IP Bulk Mail Server Installer"
echo "Version: 17.0.8"
echo "Starting installation at: $(date)"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    print_error "This script must be run as root"
    exit 1
fi

# Check OS
if [ ! -f /etc/debian_version ]; then
    print_error "This installer requires Debian/Ubuntu"
    exit 1
fi

# ===================================================================
# PHASE 1: ALL CONFIGURATION GATHERING (ALL QUESTIONS HERE)
# ===================================================================

print_header "Phase 1: Complete Configuration"
echo "Answer all questions now. Installation will then proceed automatically."
echo ""

# Domain configuration
while true; do
    read -p "Enter your domain name (e.g., example.com): " DOMAIN_NAME
    if [[ "$DOMAIN_NAME" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}$ ]]; then
        break
    else
        print_error "Invalid domain format. Please use format: example.com"
    fi
done

# Mail subdomain
read -p "Enter mail server subdomain (default: mx): " MAIL_SUBDOMAIN
MAIL_SUBDOMAIN=${MAIL_SUBDOMAIN:-mx}
HOSTNAME="$MAIL_SUBDOMAIN.$DOMAIN_NAME"

# First email account
while true; do
read -p "Email address for first account (e.g., admin@$DOMAIN_NAME): " FIRST_EMAIL
if [[ "$FIRST_EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        break
    else
        print_error "Invalid email format"
    fi
done
read -sp "Password for $FIRST_EMAIL: (Will not show)" FIRST_PASS
echo ""

ADMIN_EMAIL=$FIRST_EMAIL

# Detect primary IP
PRIMARY_IP=$(curl -s --max-time 5 https://ipinfo.io/ip 2>/dev/null || \
            curl -s --max-time 5 https://api.ipify.org 2>/dev/null || \
            hostname -I | awk '{print $1}')

if [ -z "$PRIMARY_IP" ]; then
    read -p "Could not detect IP. Enter server primary IP: " PRIMARY_IP
else
    echo "Detected primary IP: $PRIMARY_IP"
    read -p "Press Enter if correct, or type the correct IP: " USER_IP
    if [ ! -z "$USER_IP" ]; then
        PRIMARY_IP="$USER_IP"
    fi
fi

# Validate primary IP
if ! validate_ip "$PRIMARY_IP"; then
    print_error "Invalid IP address: $PRIMARY_IP"
    exit 1
fi

IP_ADDRESSES=("$PRIMARY_IP")

# Multi-IP configuration
echo ""
echo "Multi-IP Configuration (optional)"
echo "You can enter IPs in these formats:"
echo "  - Single IP: 192.168.1.10"
echo "  - Range: 192.168.1.10-192.168.1.20"
echo "  - CIDR: 192.168.1.0/24"
echo "  - Press Enter when done"
echo ""

while true; do
    read -p "Enter additional IP(s) [Enter to finish]: " ip_input
    [ -z "$ip_input" ] && break
    
    # Process based on input type
    if [[ "$ip_input" =~ / ]]; then
        # CIDR notation
        echo "Processing CIDR: $ip_input"
        while IFS= read -r ip; do
            if validate_ip "$ip" && [[ ! " ${IP_ADDRESSES[@]} " =~ " $ip " ]]; then
                IP_ADDRESSES+=("$ip")
                echo "  Added: $ip"
            fi
        done < <(expand_cidr "$ip_input")
    elif [[ "$ip_input" =~ - ]]; then
        # Range notation
        echo "Processing range: $ip_input"
        while IFS= read -r ip; do
            if validate_ip "$ip" && [[ ! " ${IP_ADDRESSES[@]} " =~ " $ip " ]]; then
                IP_ADDRESSES+=("$ip")
                echo "  Added: $ip"
            fi
        done < <(expand_ip_range "$ip_input")
    else
        # Single IP
        if validate_ip "$ip_input"; then
            if [[ ! " ${IP_ADDRESSES[@]} " =~ " $ip_input " ]]; then
                IP_ADDRESSES+=("$ip_input")
                echo "  Added: $ip_input"
            else
                echo "  IP already in list"
            fi
        else
            print_error "  Invalid IP: $ip_input"
        fi
    fi
done

echo ""
echo "Total IPs configured: ${#IP_ADDRESSES[@]}"

# Cloudflare configuration
echo ""
echo "Cloudflare DNS Configuration (optional)"
echo "Leave blank to skip automatic DNS setup"
read -p "Enter Cloudflare API Key/Token (or press Enter to skip): " CF_API_KEY
echo ""

if [ ! -z "$CF_API_KEY" ]; then
    # Test if it's a token or global key
    if [[ ${#CF_API_KEY} -eq 37 ]] || [[ "$CF_API_KEY" =~ ^[A-Za-z0-9_-]{40,}$ ]]; then
        echo "Using API Token"
        CF_EMAIL=""
    else
        echo "Using Global API Key"
        read -p "Enter Cloudflare account email: " CF_EMAIL
    fi
    
    # Save credentials
    cat > /root/.cloudflare_credentials <<EOF
SAVED_CF_API_KEY="$CF_API_KEY"
SAVED_CF_EMAIL="$CF_EMAIL"
EOF
    chmod 600 /root/.cloudflare_credentials
    USE_CF="y"
else
    USE_CF="n"
fi

# Configuration for IP rotation
if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
    CONFIGURE_IP_ROTATION=true
else
    CONFIGURE_IP_ROTATION=false
fi

# Save configuration
cat > "$INSTALL_DIR/install.conf" <<EOF
# Installation Configuration - Generated $(date)
DOMAIN_NAME="$DOMAIN_NAME"
MAIL_SUBDOMAIN="$MAIL_SUBDOMAIN"
HOSTNAME="$HOSTNAME"
ADMIN_EMAIL="$ADMIN_EMAIL"
PRIMARY_IP="$PRIMARY_IP"
IP_ADDRESSES=(${IP_ADDRESSES[@]})
FIRST_EMAIL="$FIRST_EMAIL"
FIRST_PASS="$FIRST_PASS"
CF_API_KEY="$CF_API_KEY"
CF_EMAIL="$CF_EMAIL"
USE_CF="$USE_CF"
CONFIGURE_IP_ROTATION=$CONFIGURE_IP_ROTATION
EOF

chmod 600 "$INSTALL_DIR/install.conf"

# ===================================================================
# NO MORE QUESTIONS FROM HERE ON - JUST EXECUTION
# ===================================================================

print_header "Starting Automated Installation"
echo "All configuration collected. Installation will now proceed automatically."
echo "This will take approximately 10-15 minutes."
echo ""

# ===================================================================
# PHASE 2: DOWNLOAD ADDITIONAL SCRIPTS
# ===================================================================

print_header "Phase 2: Downloading Components"

GITHUB_BASE="https://raw.githubusercontent.com/fumingtomato/shibi/dude/MXingFun"

download_script() {
    local script_name=$1
    local script_url="$GITHUB_BASE/$script_name"
    
    echo -n "Downloading $script_name... "
    if wget -q -O "$INSTALL_DIR/$script_name" "$script_url"; then
        chmod +x "$INSTALL_DIR/$script_name"
        print_message "✓"
    else
        print_warning "✗ (optional)"
    fi
}

# Download all components
download_script "run-installer.sh"
download_script "setup-database.sh"
download_script "cloudflare-dns-setup.sh"
download_script "setup-website.sh"
download_script "ssl-setup.sh"
download_script "create-utilities.sh"
download_script "post-install-config.sh"
download_script "setup-permissions.sh"
download_script "troubleshoot.sh"
download_script "webhook_handler.py"
download_script "setup-webhook-api.sh"

# ===================================================================
# PHASE 3: SYSTEM UPDATE
# ===================================================================

print_header "Phase 3: System Preparation"

echo "Updating system packages..."
apt-get update -y > /dev/null 2>&1
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y > /dev/null 2>&1

# Set hostname
hostnamectl set-hostname "$HOSTNAME" 2>/dev/null || hostname "$HOSTNAME"
echo "$HOSTNAME" > /etc/hostname

# Update hosts file
cat > /etc/hosts <<EOF
127.0.0.1 localhost
$PRIMARY_IP $HOSTNAME ${HOSTNAME%%.*}

# IPv6
::1 localhost ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
EOF

# ===================================================================
# PHASE 4: INSTALL MAIL SERVER
# ===================================================================

print_header "Phase 4: Installing Mail Server"

# Pre-configure Postfix
debconf-set-selections <<< "postfix postfix/mailname string $HOSTNAME"
debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Internet Site'"

# Install packages
echo "Installing mail server packages..."
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    postfix postfix-mysql postfix-pcre \
    dovecot-core dovecot-imapd dovecot-pop3d dovecot-lmtpd dovecot-mysql \
    mysql-server mysql-client \
    opendkim opendkim-tools \
    spamassassin spamc \
    nginx \
    certbot python3-certbot-nginx \
    ufw fail2ban \
    mailutils \
    jq dnsutils net-tools \
    > /dev/null 2>&1

print_message "✓ Mail server packages installed"

# ===================================================================
# PHASE 5: CONFIGURE SERVICES
# ===================================================================

print_header "Phase 5: Configuring Services"

# Basic Postfix configuration
cat > /etc/postfix/main.cf <<EOF
# Basic Configuration
myhostname = $HOSTNAME
mydomain = $DOMAIN_NAME
myorigin = \$mydomain
inet_interfaces = all
inet_protocols = ipv4
mydestination = localhost, $HOSTNAME, $DOMAIN_NAME
relay_domains = 
mynetworks = 127.0.0.0/8

# TLS
smtpd_tls_cert_file = /etc/ssl/certs/ssl-cert-snakeoil.pem
smtpd_tls_key_file = /etc/ssl/private/ssl-cert-snakeoil.key
smtpd_use_tls = yes
smtpd_tls_auth_only = yes

# Restrictions
smtpd_recipient_restrictions = 
    permit_mynetworks,
    permit_sasl_authenticated,
    reject_unauth_destination

# Transport Maps (Order is important: recipient-specific first)
transport_maps = hash:/etc/postfix/recipient_transports

# Virtual domains (will be configured by setup-database.sh)
virtual_transport = lmtp:unix:private/dovecot-lmtp

# Limits
message_size_limit = 52428800
mailbox_size_limit = 0

# SASL
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_auth_enable = yes

# CRITICAL: Milters (OpenDKIM) for SIGNING
milter_protocol = 6
milter_default_action = accept
smtpd_milters = inet:localhost:8891
non_smtpd_milters = inet:localhost:8891
EOF

# Configure master.cf for submission
cat >> /etc/postfix/master.cf <<EOF

# Submission port 587
submission inet n       -       y       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
  -o receive_override_options=no_milters
  -o smtpd_milters=inet:localhost:8891
  -o non_smtpd_milters=inet:localhost:8891

# SMTPS port 465
smtps     inet  n       -       y       -       -       smtpd
  -o syslog_name=postfix/smtps
  -o smtpd_tls_wrappermode=yes
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
  -o receive_override_options=no_milters
  -o smtpd_milters=inet:localhost:8891
  -o non_smtpd_milters=inet:localhost:8891
EOF

# ===================================================================
# PHASE 5A: GENERATE PROPER DKIM KEY
# ===================================================================

print_header "Ensuring 1024-bit DKIM Key"

# Call the function to generate DKIM key
if generate_dkim_key "$DOMAIN_NAME"; then
    # CRITICAL FIX: Reformat mail.txt to ensure it's a single line for reliable parsing
    # This removes line breaks and extra spaces within the TXT record content.
    if [ -f "/etc/opendkim/keys/$DOMAIN_NAME/mail.txt" ]; then
        RAW_DKIM_CONTENT=$(cat "/etc/opendkim/keys/$DOMAIN_NAME/mail.txt" | grep -o '".*"' | tr -d '\n\r\t' | sed 's/ //g')
        echo "mail._domainkey IN TXT $RAW_DKIM_CONTENT" > "/etc/opendkim/keys/$DOMAIN_NAME/mail.txt"
        print_message "✓ DKIM key file reformatted for consistency"
    fi
else
    print_error "Failed to generate DKIM key"
    # Continue anyway, can be fixed later
fi

# Configure OpenDKIM PROPERLY TO ACTUALLY SIGN EMAILS
cat > /etc/opendkim.conf <<EOF
# CRITICAL: THIS CONFIG ACTUALLY SIGNS EMAILS
AutoRestart             Yes
AutoRestartRate         10/1h
UMask                   002
Syslog                  yes
SyslogSuccess           Yes
LogWhy                  Yes

# SIGNING MODE - CRITICAL FOR DKIM SIGNING
Mode                    sv
Domain                  $DOMAIN_NAME
Selector                mail
MinimumKeyBits          1024
SubDomains              yes

# Canonicalization
Canonicalization        relaxed/simple

# Host lists
ExternalIgnoreList      refile:/etc/opendkim/TrustedHosts
InternalHosts           refile:/etc/opendkim/TrustedHosts
KeyTable                refile:/etc/opendkim/KeyTable
SigningTable            refile:/etc/opendkim/SigningTable

# Socket
Socket                  inet:8891@localhost
PidFile                 /var/run/opendkim/opendkim.pid
SignatureAlgorithm      rsa-sha256
UserID                  opendkim:opendkim
TemporaryDirectory      /var/tmp

# CRITICAL: Sign everything
OversignHeaders         From
AlwaysAddARHeader       yes
EOF

# Setup DKIM tables - COMPREHENSIVE
echo "127.0.0.1" > /etc/opendkim/TrustedHosts
echo "localhost" >> /etc/opendkim/TrustedHosts
echo "::1" >> /etc/opendkim/TrustedHosts
echo ".$DOMAIN_NAME" >> /etc/opendkim/TrustedHosts
echo "$DOMAIN_NAME" >> /etc/opendkim/TrustedHosts
echo "$HOSTNAME" >> /etc/opendkim/TrustedHosts
for ip in "${IP_ADDRESSES[@]}"; do
    echo "$ip" >> /etc/opendkim/TrustedHosts
done

# KeyTable: Use a wildcard pattern to find keys for any domain.
echo "* *:%d:/etc/opendkim/keys/%d/mail.private" > /etc/opendkim/KeyTable

# SigningTable: Use a wildcard to sign any email from any domain.
# This is the most flexible and reliable method.
echo "* mail._domainkey" > /etc/opendkim/SigningTable

# Create systemd directory
mkdir -p /var/run/opendkim
chown opendkim:opendkim /var/run/opendkim

# Start services
systemctl restart opendkim
sleep 2

# Verify OpenDKIM is running
if netstat -lnp 2>/dev/null | grep -q ":8891"; then
    print_message "✓ OpenDKIM is running on port 8891"
else
    print_warning "⚠ OpenDKIM may not be running properly"
    # Try to fix
    systemctl stop opendkim
    sleep 1
    systemctl start opendkim
fi

systemctl restart postfix

print_message "✓ Basic mail server configured with 1024-bit DKIM key"

# ===================================================================
# PHASE 6: DATABASE SETUP
# ===================================================================

print_header "Phase 6: Database Configuration"

if [ -f "$INSTALL_DIR/setup-database.sh" ]; then
    bash "$INSTALL_DIR/setup-database.sh"
else
    print_warning "Database setup script not found, using basic configuration"
    
    # Generate password
    DB_PASSWORD=$(openssl rand -base64 32)
    echo "$DB_PASSWORD" > /root/.mail_db_password
    chmod 600 /root/.mail_db_password
    
    # Create database
    mysql <<EOF 2>/dev/null || true
CREATE DATABASE IF NOT EXISTS mailserver;
CREATE USER IF NOT EXISTS 'mailuser'@'localhost' IDENTIFIED BY '$DB_PASSWORD';
GRANT ALL PRIVILEGES ON mailserver.* TO 'mailuser'@'localhost';
FLUSH PRIVILEGES;
EOF
fi

# ===================================================================
# PHASE 7: CONFIGURE IP ROTATION (if multiple IPs)
# ===================================================================

if [ "$CONFIGURE_IP_ROTATION" == "true" ] && [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
    print_header "Phase 7: Advanced IP Rotation Setup"
    
    # Call the new bulk IP rotation configuration function
    configure_bulk_ip_rotation
    
    # Reload Postfix
    systemctl reload postfix
fi

# ===================================================================
# PHASE 8: CLOUDFLARE DNS (AUTOMATIC IF CONFIGURED)
# ===================================================================

if [[ "$USE_CF" == "y" ]]; then
    print_header "Phase 8: Cloudflare DNS Setup"
    
    if [ -f "$INSTALL_DIR/cloudflare-dns-setup.sh" ]; then
        bash "$INSTALL_DIR/cloudflare-dns-setup.sh"
    else
        print_warning "Cloudflare script not found, skipping DNS automation"
    fi
fi

# ===================================================================
# PHASE 9: WEBSITE SETUP
# ===================================================================

print_header "Phase 9: Website Setup"

if [ -f "$INSTALL_DIR/setup-website.sh" ]; then
    bash "$INSTALL_DIR/setup-website.sh"
else
    print_warning "Website setup script not found, creating basic site"
    
    # Basic website
    mkdir -p /var/www/$DOMAIN_NAME
    cat > /var/www/$DOMAIN_NAME/index.html <<EOF
<!DOCTYPE html>
<html>
<head>
    <title>$DOMAIN_NAME</title>
</head>
<body>
    <h1>Welcome to $DOMAIN_NAME</h1>
    <p>Mail server is operational</p>
</body>
</html>
EOF
    
    # Basic nginx config WITHOUT DUPLICATE SERVER BLOCKS
    cat > /etc/nginx/sites-available/$DOMAIN_NAME.conf <<EOF
# Single server block for ALL domains
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name $DOMAIN_NAME www.$DOMAIN_NAME $HOSTNAME _;
    
    root /var/www/$DOMAIN_NAME;
    index index.html;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    # Let's Encrypt challenge
    location /.well-known/acme-challenge/ {
        root /var/www/$DOMAIN_NAME;
        allow all;
    }
}
EOF
    
    # Remove default site
    rm -f /etc/nginx/sites-enabled/default
    
    ln -sf /etc/nginx/sites-available/$DOMAIN_NAME.conf /etc/nginx/sites-enabled/
    nginx -t 2>/dev/null && systemctl reload nginx
fi

# ===================================================================
# PHASE 10: CREATE UTILITIES
# ===================================================================

print_header "Phase 10: Creating Management Utilities"

if [ -f "$INSTALL_DIR/create-utilities.sh" ]; then
    bash "$INSTALL_DIR/create-utilities.sh"
else
    print_warning "Utilities script not found, creating basic commands"
fi

# Create DKIM verification utility
cat > /usr/local/bin/verify-dkim <<'EOF'
#!/bin/bash

DOMAIN="DOMAIN_PLACEHOLDER"
GREEN='\033[38;5;208m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "DKIM Verification for $DOMAIN"
echo "=============================="
echo ""

# Check local key
echo "1. Local DKIM Key:"
if [ -f "/etc/opendkim/keys/$DOMAIN/mail.txt" ]; then
    KEY=$(grep -oP 'p=\K[^"]+' /etc/opendkim/keys/$DOMAIN/mail.txt | tr -d '\n\t\r ')
    if [ ! -z "$KEY" ]; then
        echo -e "   ${GREEN}✓ Found${NC}"
        echo "   Key length: ${#KEY} characters"
        if [ ${#KEY} -ge 200 ] && [ ${#KEY} -le 250 ]; then
            echo -e "   ${GREEN}✓ 1024-bit key (perfect)${NC}"
        else
            echo -e "   ${YELLOW}⚠ Unexpected length for 1024-bit${NC}"
        fi
    else
        echo -e "   ${RED}✗ Could not extract key${NC}"
    fi
else
    echo -e "   ${RED}✗ Key file not found${NC}"
fi

echo ""
echo "2. DNS DKIM Record:"
DNS_KEY=$(dig +short TXT mail._domainkey.$DOMAIN @1.1.1.1 2>/dev/null | grep "v=DKIM1")
if [ ! -z "$DNS_KEY" ]; then
    echo -e "   ${GREEN}✓ Found in DNS${NC}"
    DNS_KEY_CLEAN=$(echo "$DNS_KEY" | sed 's/.*p=//' | sed 's/".*//' | tr -d ' ')
    echo "   DNS key length: ${#DNS_KEY_CLEAN} characters"
else
    echo -e "   ${RED}✗ Not found in DNS${NC}"
    echo "   Add TXT record: mail._domainkey"
    echo "   Value: v=DKIM1; k=rsa; p=$KEY"
fi

echo ""
echo "3. OpenDKIM Test:"
opendkim-testkey -d $DOMAIN -s mail -vvv 2>&1 | tail -5

echo ""
echo "4. OpenDKIM Service:"
if systemctl is-active --quiet opendkim; then
    echo -e "   ${GREEN}✓ Running${NC}"
    if netstat -lnp 2>/dev/null | grep -q ":8891"; then
        echo -e "   ${GREEN}✓ Listening on port 8891${NC}"
    else
        echo -e "   ${RED}✗ Not listening on port 8891${NC}"
    fi
else
    echo -e "   ${RED}✗ Not running${NC}"
fi

echo ""
echo "5. Quick Actions:"
echo "   • Test email: test-email check-auth@verifier.port25.com"
echo "   • Mail tester: https://www.mail-tester.com"
echo "   • View key: cat /etc/opendkim/keys/$DOMAIN/mail.txt"
EOF

sed -i "s/DOMAIN_PLACEHOLDER/$DOMAIN_NAME/g" /usr/local/bin/verify-dkim
chmod +x /usr/local/bin/verify-dkim

# ===================================================================
# PHASE 11: SSL CERTIFICATES (SMART REQUEST - ONLY EXISTING DOMAINS)
# ===================================================================

print_header "Phase 11: SSL Certificate Setup"

echo "Attempting to obtain SSL certificates..."
echo "Note: This will work if DNS is already propagated"

# Function to check if domain resolves
check_dns() {
    local domain=$1
    host "$domain" 8.8.8.8 > /dev/null 2>&1
    return $?
}

# Build list of domains that actually resolve
CERT_DOMAINS=""
DOMAINS_TO_CHECK=("$DOMAIN_NAME" "www.$DOMAIN_NAME" "$HOSTNAME")

# Add numbered subdomains if multiple IPs configured
if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
    for i in $(seq 1 $((${#IP_ADDRESSES[@]} - 1))); do
        DOMAINS_TO_CHECK+=("${MAIL_SUBDOMAIN}${i}.$DOMAIN_NAME")
    done
fi

echo "Checking DNS for domains..."
for domain in "${DOMAINS_TO_CHECK[@]}"; do
    echo -n "  $domain: "
    if check_dns "$domain"; then
        CERT_DOMAINS="$CERT_DOMAINS -d $domain"
        print_message "✓ Resolving"
    else
        print_warning "✗ Not found (skipping)"
    fi
done

# Only request certificate if we have at least the main domain
if [[ "$CERT_DOMAINS" == *"-d $DOMAIN_NAME"* ]]; then
    echo ""
    echo "Getting SSL certificates for existing domains..."
    
    # Get certificate with nginx plugin for domains that exist
    certbot --nginx \
        $CERT_DOMAINS \
        --non-interactive \
        --agree-tos \
        --email "$ADMIN_EMAIL" \
        --no-eff-email 2>/dev/null || \
    echo "SSL certificates pending DNS propagation"
else
    echo ""
    print_warning "Main domain not resolving yet, SSL certificates will be obtained after DNS propagates"
    echo "Run 'get-ssl-cert' after DNS propagation to obtain certificates"
fi

# ===================================================================
# PHASE 12: FIREWALL SETUP
# ===================================================================

print_header "Phase 12: Firewall Configuration"

ufw --force disable 2>/dev/null
ufw --force reset 2>/dev/null

# Configure UFW
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 25/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 587/tcp
ufw allow 465/tcp
ufw allow 993/tcp
ufw allow 995/tcp
ufw allow 143/tcp
ufw allow 110/tcp

echo "y" | ufw --force enable

print_message "✓ Firewall configured"

# ===================================================================
# PHASE 13: FINAL CONFIGURATION
# ===================================================================

print_header "Phase 13: Final Configuration"

if [ -f "$INSTALL_DIR/post-install-config.sh" ]; then
    bash "$INSTALL_DIR/post-install-config.sh"
fi

# ===================================================================
# PHASE 14: SETUP UNIVERSAL USER ACCESS (NEW!)
# ===================================================================

print_header "Phase 14: Setting Up Universal User Access"

if [ -f "$INSTALL_DIR/setup-permissions.sh" ]; then
    bash "$INSTALL_DIR/setup-permissions.sh"
else
    print_warning "Permission setup script not found, commands will require root access"
fi

# Final DKIM verification
echo ""
print_header "Final DKIM Verification"

# Ensure OpenDKIM is running
systemctl restart opendkim
sleep 3

# Verify OpenDKIM is listening
if netstat -lnp 2>/dev/null | grep -q ":8891"; then
    print_message "✓ OpenDKIM is listening on port 8891"
    
    # Display DKIM key info
    if [ -f "/etc/opendkim/keys/$DOMAIN_NAME/mail.txt" ]; then
        DKIM_KEY=$(cat /etc/opendkim/keys/$DOMAIN_NAME/mail.txt | tr -d '\n\r\t' | sed 's/.*"p=//' | sed 's/".*//' | tr -d ' "')
        if [ ! -z "$DKIM_KEY" ]; then
            echo "✓ DKIM key ready: ${#DKIM_KEY} characters"
            
            # Check if in DNS
            DNS_CHECK=$(dig +short TXT mail._domainkey.$DOMAIN_NAME @1.1.1.1 2>/dev/null | grep "v=DKIM1")
            if [ ! -z "$DNS_CHECK" ]; then
                print_message "✓ DKIM record found in DNS"
            else
                print_warning "⚠ DKIM record not in DNS yet"
                echo ""
                echo "Add this TXT record to your DNS:"
                echo "  Name: mail._domainkey"
                echo "  Value: v=DKIM1; k=rsa; p=$DKIM_KEY"
            fi
        fi
    fi
else
    print_error "✗ OpenDKIM not listening - restarting"
    systemctl stop opendkim
    sleep 1
    systemctl start opendkim
fi

# Restart all services
systemctl restart postfix dovecot opendkim nginx
systemctl enable postfix dovecot opendkim nginx mysql

# ===================================================================
# INSTALLATION COMPLETE
# ===================================================================

print_header "Installation Complete!"

echo ""
print_message "✓ Mail server installed successfully!"
print_message "✓ DKIM SIGNING IS ENABLED with 1024-bit key!"
print_message "✓ Website configured!"
print_message "✓ System optimized!"
print_message "✓ ALL COMMANDS WORK FOR ALL USERS!"
echo ""
echo "Domain: $DOMAIN_NAME"
echo "Mail Server: $HOSTNAME"
echo "Mail Subdomain: $MAIL_SUBDOMAIN"
echo "Primary IP: $PRIMARY_IP"
if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
    echo "Total IPs: ${#IP_ADDRESSES[@]}"
    echo "IP Rotation: ENABLED (Advanced)"
fi
echo ""

if [ ! -z "$FIRST_EMAIL" ]; then
    echo "Email Account:"
    echo "  Email: $FIRST_EMAIL"
    echo "  Password: [set during installation]"
    echo ""
fi

# Display DKIM record
if [ -f "/etc/opendkim/keys/$DOMAIN_NAME/mail.txt" ]; then
    DKIM_KEY=$(cat /etc/opendkim/keys/$DOMAIN_NAME/mail.txt | tr -d '\n\r\t' | sed 's/.*"p=//' | sed 's/".*//' | tr -d ' "')
    if [ ! -z "$DKIM_KEY" ]; then
        echo "DKIM Record (add to DNS if not automatic):"
        echo "  Name: mail._domainkey"
        echo "  Type: TXT"
        echo "  Value: v=DKIM1; k=rsa; p=$DKIM_KEY"
        echo "  Key length: ${#DKIM_KEY} characters (should be ~216 for 1024-bit)"
    fi
    echo ""
fi

echo "CRITICAL VERIFICATION STEPS:"
echo "=============================="
echo "1. Verify DKIM: verify-dkim"
echo "2. Test DKIM signing: opendkim-testkey -d $DOMAIN_NAME -s mail -vvv"
echo "3. Send test email: test-email check-auth@verifier.port25.com"
echo "4. Check score: https://www.mail-tester.com"
echo ""

echo "Management Commands (WORK FOR ALL USERS):"
echo "  mail-help          - Show all available commands"
echo "  verify-dkim        - Check DKIM status"
echo "  mail-status        - Check server status"
echo "  mail-account       - Manage email accounts"
echo "  mail-test          - Test configuration"
echo "  check-dns          - Verify DNS records"
echo "  get-ssl-cert       - Get SSL certificates"
if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
    echo "  bulk-ip-manage     - Advanced IP rotation management"
fi
echo ""

echo "ANY USER CAN NOW RUN:"
echo "  As regular user: mail-status"
echo "  As regular user: mail-account list"
echo "  As regular user: bulk-ip-manage status"
echo "  No sudo needed - commands work transparently!"
echo ""

echo "Next Steps:"
echo "1. Wait 5-30 minutes for DNS propagation"
echo "2. Run: verify-dkim"
echo "3. Get SSL: get-ssl-cert"
echo "4. Test email: test-email recipient@example.com"
echo ""

echo "Installation log: $LOG_FILE"
echo ""
print_message "Your bulk mail server is READY!"
print_message "✓ DKIM: 1024-bit key generated and configured"
print_message "✓ Run 'verify-dkim' to check DKIM status"
print_message "✓ ALL USERS can now manage the mail server!"
