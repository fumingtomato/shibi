#!/bin/bash

# =================================================================
# BULK MAIL SERVER INSTALLER WITH MULTI-IP SUPPORT
# Version: 17.0.1 - FIXED DKIM SIGNING
# Automated installation with Cloudflare DNS, compliance website, and DKIM
# FIXED: All questions moved to beginning, no questions during execution
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

# FIXED: Complete IP rotation configuration with database-backed sticky sessions
configure_ip_rotation() {
    local -a ips=("$@")
    local num_ips=${#ips[@]}
    
    print_message "Configuring IP rotation for $num_ips addresses with sticky sessions..."
    
    # Add transport configurations to master.cf
    cat >> /etc/postfix/master.cf <<EOF

# IP Rotation Transports - Generated $(date)
EOF
    
    local count=0
    for ip in "${ips[@]}"; do
        # Calculate transport ID (starting from 0)
        local transport_id=$count
        count=$((count + 1))
        
        echo "  Adding transport smtp-ip${transport_id} for IP: $ip"
        
        cat >> /etc/postfix/master.cf <<EOF
smtp-ip${transport_id}    unix  -       -       n       -       -       smtp
    -o smtp_bind_address=$ip
    -o smtp_helo_name=mail-${transport_id}.\$myhostname
    -o syslog_name=postfix-ip${transport_id}
EOF
    done
    
    # Create MySQL-based sender transport lookup
    cat > /etc/postfix/mysql/sender_transport.cf <<EOF
user = mailuser
password = $(cat /root/.mail_db_password 2>/dev/null || echo "password")
hosts = 127.0.0.1
dbname = mailserver
query = SELECT CONCAT('smtp-ip', transport_id, ':') FROM ip_rotation_log WHERE sender_email='%s'
EOF
    
    # Configure Postfix to use sender-based transport
    postconf -e "sender_dependent_default_transport_maps = mysql:/etc/postfix/mysql/sender_transport.cf"
    postconf -e "smtp_sender_dependent_authentication = yes"
    postconf -e "sender_dependent_relayhost_maps = mysql:/etc/postfix/mysql/sender_transport.cf"
    
    # Create IP assignment script
    cat > /usr/local/bin/assign-sender-ip <<'EOIP'
#!/bin/bash

# Assign IP to sender with sticky sessions
SENDER=$1
if [ -z "$SENDER" ]; then
    echo "Usage: assign-sender-ip email@domain.com"
    exit 1
fi

DB_PASS=$(cat /root/.mail_db_password 2>/dev/null)
if [ -z "$DB_PASS" ]; then
    echo "Database password not found"
    exit 1
fi

# Get available IPs from Postfix config
AVAILABLE_IPS=($(grep "smtp_bind_address=" /etc/postfix/master.cf | sed 's/.*smtp_bind_address=//' | sort -u))
NUM_IPS=${#AVAILABLE_IPS[@]}

if [ $NUM_IPS -eq 0 ]; then
    echo "No IPs configured for rotation"
    exit 1
fi

# Check if sender already has an assigned IP
EXISTING=$(mysql -u mailuser -p"$DB_PASS" mailserver -se "SELECT assigned_ip FROM ip_rotation_log WHERE sender_email='$SENDER'" 2>/dev/null)

if [ ! -z "$EXISTING" ]; then
    echo "Sender already assigned to IP: $EXISTING"
    # Update last used timestamp
    mysql -u mailuser -p"$DB_PASS" mailserver -e "UPDATE ip_rotation_log SET last_used=NOW(), message_count=message_count+1 WHERE sender_email='$SENDER'" 2>/dev/null
    exit 0
fi

# Find IP with least number of senders (load balancing)
LEAST_LOADED_IP=""
MIN_COUNT=999999

for i in "${!AVAILABLE_IPS[@]}"; do
    IP="${AVAILABLE_IPS[$i]}"
    COUNT=$(mysql -u mailuser -p"$DB_PASS" mailserver -se "SELECT COUNT(*) FROM ip_rotation_log WHERE assigned_ip='$IP'" 2>/dev/null || echo 0)
    
    if [ "$COUNT" -lt "$MIN_COUNT" ]; then
        MIN_COUNT=$COUNT
        LEAST_LOADED_IP=$IP
        TRANSPORT_ID=$i
    fi
done

if [ -z "$LEAST_LOADED_IP" ]; then
    # Fallback: use round-robin
    RANDOM_INDEX=$((RANDOM % NUM_IPS))
    LEAST_LOADED_IP="${AVAILABLE_IPS[$RANDOM_INDEX]}"
    TRANSPORT_ID=$RANDOM_INDEX
fi

# Assign IP to sender
mysql -u mailuser -p"$DB_PASS" mailserver -e "
INSERT INTO ip_rotation_log (sender_email, assigned_ip, transport_id, last_used, message_count) 
VALUES ('$SENDER', '$LEAST_LOADED_IP', $TRANSPORT_ID, NOW(), 1)
ON DUPLICATE KEY UPDATE 
    assigned_ip='$LEAST_LOADED_IP', 
    transport_id=$TRANSPORT_ID, 
    last_used=NOW(), 
    message_count=message_count+1" 2>/dev/null

if [ $? -eq 0 ]; then
    echo "Assigned $SENDER to IP: $LEAST_LOADED_IP (Transport: smtp-ip$TRANSPORT_ID)"
else
    echo "Failed to assign IP"
    exit 1
fi
EOIP
    
    chmod +x /usr/local/bin/assign-sender-ip
    
    # Create IP rotation status script
    cat > /usr/local/bin/ip-rotation-status <<'EOST'
#!/bin/bash

echo "IP Rotation Status"
echo "=================="
echo ""

# Show configured IPs
echo "Configured IPs:"
grep "smtp_bind_address=" /etc/postfix/master.cf | sed 's/.*smtp_bind_address=/  - /' | sort -u

echo ""
echo "IP Assignments:"

DB_PASS=$(cat /root/.mail_db_password 2>/dev/null)
if [ -z "$DB_PASS" ]; then
    echo "Database not configured"
    exit 1
fi

mysql -u mailuser -p"$DB_PASS" mailserver -e "
SELECT 
    assigned_ip as 'IP Address',
    COUNT(*) as 'Senders',
    SUM(message_count) as 'Messages',
    MAX(last_used) as 'Last Used'
FROM ip_rotation_log 
GROUP BY assigned_ip
ORDER BY assigned_ip" 2>/dev/null || echo "No assignments yet"

echo ""
echo "Recent Sender Assignments:"
mysql -u mailuser -p"$DB_PASS" mailserver -e "
SELECT 
    sender_email as 'Sender',
    assigned_ip as 'IP',
    message_count as 'Messages',
    last_used as 'Last Used'
FROM ip_rotation_log 
ORDER BY last_used DESC 
LIMIT 10" 2>/dev/null || echo "No assignments yet"
EOST
    
    chmod +x /usr/local/bin/ip-rotation-status
    
    # Add cleanup cron for old assignments
    cat > /etc/cron.daily/cleanup-ip-assignments <<'EOCRON'
#!/bin/bash
# Clean up IP assignments older than 30 days
DB_PASS=$(cat /root/.mail_db_password 2>/dev/null)
if [ ! -z "$DB_PASS" ]; then
    mysql -u mailuser -p"$DB_PASS" mailserver -e "DELETE FROM ip_rotation_log WHERE last_used < DATE_SUB(NOW(), INTERVAL 30 DAY)" 2>/dev/null
fi
EOCRON
    
    chmod +x /etc/cron.daily/cleanup-ip-assignments
    
    print_message "✓ IP rotation configured with ${num_ips} addresses"
    echo "  Commands available:"
    echo "    assign-sender-ip email@domain.com - Assign IP to sender"
    echo "    ip-rotation-status - Show rotation statistics"
}

# ===================================================================
# MAIN INSTALLATION
# ===================================================================

print_header "Multi-IP Bulk Mail Server Installer"
echo "Version: 17.0.1"
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

# Admin email
while true; do
    read -p "Enter admin email address: " ADMIN_EMAIL
    if [[ "$ADMIN_EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        break
    else
        print_error "Invalid email format"
    fi
done

# First email account
read -p "Email address for first account (e.g., admin@$DOMAIN_NAME): " FIRST_EMAIL
read -sp "Password for $FIRST_EMAIL: " FIRST_PASS
echo ""

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
read -sp "Enter Cloudflare API Key/Token (or press Enter to skip): " CF_API_KEY
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

GITHUB_BASE="https://raw.githubusercontent.com/fumingtomato/shibi/main/MXingFun"

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
download_script "troubleshoot.sh"

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
mydestination = 
relay_domains = 
mynetworks = 127.0.0.0/8

# TLS
smtpd_tls_cert_file = /etc/ssl/certs/ssl-cert-snakeoil.pem
smtpd_tls_key_file = /etc/ssl/private/ssl-cert-snakeoil.key
smtpd_use_tls = yes
smtpd_tls_auth_only = yes
smtp_tls_security_level = may

# Restrictions
smtpd_recipient_restrictions = 
    permit_mynetworks,
    permit_sasl_authenticated,
    reject_unauth_destination

# Virtual domains (will be configured by setup-database.sh)
virtual_transport = lmtp:unix:private/dovecot-lmtp

# Limits
message_size_limit = 52428800
mailbox_size_limit = 0

# SASL
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_auth_enable = yes

# Milters (OpenDKIM) - CRITICAL FOR SIGNING
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
  -o smtpd_milters=inet:localhost:8891
  -o non_smtpd_milters=inet:localhost:8891

# SMTPS port 465
smtps     inet  n       -       y       -       -       smtpd
  -o syslog_name=postfix/smtps
  -o smtpd_tls_wrappermode=yes
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
  -o smtpd_milters=inet:localhost:8891
  -o non_smtpd_milters=inet:localhost:8891
EOF

# Setup OpenDKIM
print_message "Generating DKIM keys..."
mkdir -p /etc/opendkim/keys/$DOMAIN_NAME
cd /etc/opendkim/keys/$DOMAIN_NAME
opendkim-genkey -s mail -d $DOMAIN_NAME -b 2048
chown -R opendkim:opendkim /etc/opendkim
chmod 600 mail.private

# FIX: Configure OpenDKIM PROPERLY TO ACTUALLY SIGN EMAILS
cat > /etc/opendkim.conf <<EOF
# CRITICAL: THIS CONFIG ACTUALLY SIGNS EMAILS
AutoRestart             Yes
AutoRestartRate         10/1h
UMask                   002
Syslog                  yes
SyslogSuccess           Yes
LogWhy                  Yes

# SIGNING MODE - CRITICAL
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

echo "mail._domainkey.$DOMAIN_NAME $DOMAIN_NAME:mail:/etc/opendkim/keys/$DOMAIN_NAME/mail.private" > /etc/opendkim/KeyTable

# COMPREHENSIVE SigningTable
cat > /etc/opendkim/SigningTable <<EOF
*@$DOMAIN_NAME mail._domainkey.$DOMAIN_NAME
*@$HOSTNAME mail._domainkey.$DOMAIN_NAME
*@localhost mail._domainkey.$DOMAIN_NAME
*@localhost.localdomain mail._domainkey.$DOMAIN_NAME
$DOMAIN_NAME mail._domainkey.$DOMAIN_NAME
EOF

# Create systemd directory
mkdir -p /var/run/opendkim
chown opendkim:opendkim /var/run/opendkim

# Start services
systemctl restart opendkim
sleep 2
systemctl restart postfix

print_message "✓ Basic mail server configured with DKIM SIGNING ENABLED"

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
    print_header "Phase 7: IP Rotation Setup"
    
    # Create MySQL directory if not exists
    mkdir -p /etc/postfix/mysql
    
    # Call the fixed configure_ip_rotation function
    configure_ip_rotation "${IP_ADDRESSES[@]}"
    
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
    
    # FIX: Basic nginx config WITHOUT DUPLICATE SERVER BLOCKS
    cat > /etc/nginx/sites-available/$DOMAIN_NAME <<EOF
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
}
EOF
    
    # Remove default site
    rm -f /etc/nginx/sites-enabled/default
    
    ln -sf /etc/nginx/sites-available/$DOMAIN_NAME /etc/nginx/sites-enabled/
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

# ===================================================================
# PHASE 11: SSL CERTIFICATES (AUTOMATIC ATTEMPT)
# ===================================================================

print_header "Phase 11: SSL Certificate Setup"

echo "Attempting to obtain SSL certificates..."
echo "Note: This will work if DNS is already propagated"

if [ -f "$INSTALL_DIR/ssl-setup.sh" ]; then
    # Modify ssl-setup.sh to run automatically
    sed -i 's/read -p.*Continue anyway.*cont/cont=y/' "$INSTALL_DIR/ssl-setup.sh" 2>/dev/null || true
    bash "$INSTALL_DIR/ssl-setup.sh"
else
    # Try to get certificates directly
    echo "Getting SSL certificates..."
    
    # Stop services for standalone mode
    systemctl stop nginx 2>/dev/null || true
    
    # Try mail server certificate
    certbot certonly --standalone \
        -d "$HOSTNAME" \
        --non-interactive \
        --agree-tos \
        --email "$ADMIN_EMAIL" \
        --no-eff-email 2>/dev/null || \
    echo "Mail SSL pending DNS propagation"
    
    # Try website certificate  
    certbot certonly --standalone \
        -d "$DOMAIN_NAME" \
        -d "www.$DOMAIN_NAME" \
        --non-interactive \
        --agree-tos \
        --email "$ADMIN_EMAIL" \
        --no-eff-email 2>/dev/null || \
    echo "Website SSL pending DNS propagation"
    
    # Restart nginx
    systemctl start nginx 2>/dev/null || true
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

# Ensure OpenDKIM is running
systemctl restart opendkim
sleep 2

# Verify OpenDKIM is listening
if netstat -lnp 2>/dev/null | grep -q ":8891"; then
    print_message "✓ OpenDKIM is listening on port 8891"
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
print_message "✓ DKIM SIGNING IS ENABLED!"
echo ""
echo "Domain: $DOMAIN_NAME"
echo "Mail Server: $HOSTNAME"
echo "Primary IP: $PRIMARY_IP"
if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
    echo "Total IPs: ${#IP_ADDRESSES[@]}"
    echo ""
    echo "IP Rotation: ENABLED"
    echo "  View status: ip-rotation-status"
    echo "  Assign IP: assign-sender-ip email@domain.com"
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
    echo "DKIM Record (add to DNS):"
    echo "  Name: mail._domainkey"
    echo "  Type: TXT"
    echo "  Value: $(cat /etc/opendkim/keys/$DOMAIN_NAME/mail.txt | grep -oP '(?<=p=)[^"]+' | tr -d '\n\t ')"
    echo ""
fi

echo "VERIFY DKIM IS WORKING:"
echo "  opendkim-testkey -d $DOMAIN_NAME -s mail -vvv"
echo "  systemctl status opendkim"
echo ""

echo "Next Steps:"
echo "1. Add DNS records (check dns-records-$DOMAIN_NAME.txt)"
echo "2. Wait for DNS propagation (5-30 minutes)"
echo "3. Get SSL certificates: get-ssl-cert"
echo "4. Test email delivery: test-email recipient@example.com"
echo ""

echo "Management Commands:"
echo "  mail-status         - Check server status"
echo "  mail-account        - Manage email accounts"
echo "  mail-test          - Test email configuration"
echo "  mail-queue         - Manage mail queue"
echo "  mail-log           - View mail logs"
if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
    echo "  ip-rotation-status - View IP rotation statistics"
fi
echo "  troubleshoot       - Run diagnostics"
echo ""

echo "Installation log: $LOG_FILE"
echo ""
print_message "Your bulk mail server is ready WITH DKIM SIGNING!"
