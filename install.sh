#!/bin/bash

# =================================================================
# MULTI-IP BULK MAIL SERVER INSTALLER WITH DKIM AUTHENTICATION
# Version: 17.1.0 - Fixed hostname generation and IP rotation
# =================================================================

set -e  # Exit on error
set -o pipefail  # Exit on pipe failure

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

# Prevent running on unsupported OS
if ! grep -qE "debian|ubuntu" /etc/os-release 2>/dev/null; then
    echo "This installer only supports Debian/Ubuntu systems"
    exit 1
fi

# Colors for output
GREEN='\033[38;5;208m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[1;33m'
NC='\033[0m'

# Logging
LOG_FILE="/var/log/mail-installer-$(date +%Y%m%d-%H%M%S).log"
exec 2> >(tee -a "$LOG_FILE" >&2)

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
    echo ""
    echo -e "${BLUE}==================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}==================================================${NC}"
    echo ""
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
    echo $((octets[0] * 256**3 + octets[1] * 256**2 + octets[2] * 256 + octets[3]))
}

decimal_to_ip() {
    local dec=$1
    echo "$((dec >> 24 & 255)).$((dec >> 16 & 255)).$((dec >> 8 & 255)).$((dec & 255))"
}

expand_ip_range() {
    local range=$1
    local start_ip end_ip
    
    if [[ $range =~ ^([0-9.]+)-([0-9.]+)$ ]]; then
        start_ip="${BASH_REMATCH[1]}"
        end_ip="${BASH_REMATCH[2]}"
        
        if validate_ip "$start_ip" && validate_ip "$end_ip"; then
            local start_dec=$(ip_to_decimal "$start_ip")
            local end_dec=$(ip_to_decimal "$end_ip")
            
            if ((start_dec <= end_dec)); then
                for ((i=start_dec; i<=end_dec; i++)); do
                    decimal_to_ip $i
                done
                return 0
            fi
        fi
    fi
    return 1
}

expand_cidr() {
    local cidr=$1
    
    if [[ $cidr =~ ^([0-9.]+)/([0-9]+)$ ]]; then
        local base_ip="${BASH_REMATCH[1]}"
        local mask="${BASH_REMATCH[2]}"
        
        if validate_ip "$base_ip" && ((mask >= 24 && mask <= 32)); then
            local base_dec=$(ip_to_decimal "$base_ip")
            local num_hosts=$((2 ** (32 - mask)))
            
            # Align to network boundary
            local network=$((base_dec & (0xFFFFFFFF << (32 - mask))))
            
            for ((i=0; i<num_hosts; i++)); do
                decimal_to_ip $((network + i))
            done
            return 0
        fi
    fi
    return 1
}

# IP rotation configuration with database-backed sticky sessions
configure_ip_rotation() {
    print_header "Configuring IP Rotation"
    
    # Create transport entries in master.cf for each IP
    for i in "${!IP_ADDRESSES[@]}"; do
        IP="${IP_ADDRESSES[$i]}"
        
        # FIX 2: Properly set up smtp-ipN transports with correct format
        cat >> /etc/postfix/master.cf <<EOF

# Transport for IP $IP (index $i)
smtp-ip$i unix - - n - - smtp
  -o smtp_bind_address=$IP
  -o smtp_helo_name=${MAIL_SUBDOMAIN}$i.$DOMAIN_NAME
  -o syslog_name=postfix-ip$i
EOF
        
        echo "  Created transport smtp-ip$i for IP $IP"
    done
    
    # FIX 5: Create advanced database tables for IP rotation
    mysql -u mailuser -p"$DB_ROOT_PASSWORD" mailserver <<EOF 2>/dev/null || true
-- Enhanced IP rotation table for bulk mailing
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

-- IP pool management
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

-- Legacy table for compatibility
CREATE TABLE IF NOT EXISTS ip_rotation_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    sender_email VARCHAR(255) UNIQUE,
    assigned_ip VARCHAR(45),
    transport_id INT,
    message_count INT DEFAULT 0,
    last_used TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_sender (sender_email)
);
EOF

    # Populate IP pool
    for i in "${!IP_ADDRESSES[@]}"; do
        IP="${IP_ADDRESSES[$i]}"
        mysql -u mailuser -p"$DB_ROOT_PASSWORD" mailserver -e "
            INSERT IGNORE INTO ip_pool (ip_address, ip_index) VALUES ('$IP', $i)
        " 2>/dev/null || true
    done
    
    print_message "✓ IP rotation configured with ${#IP_ADDRESSES[@]} IP addresses"
}

# Generate DKIM key function
generate_dkim_key() {
    local domain=$1
    local selector=${2:-mail}
    local key_size=${3:-1024}
    
    print_message "Generating DKIM key for $domain..."
    
    mkdir -p /etc/opendkim/keys/$domain
    cd /etc/opendkim/keys/$domain
    
    # Generate key with specified size (1024 for compatibility, 2048 for security)
    opendkim-genkey -b $key_size -s $selector -d $domain
    
    chown -R opendkim:opendkim /etc/opendkim/keys/$domain
    chmod 600 $selector.private
    chmod 644 $selector.txt
    
    cd - > /dev/null
    
    # Update KeyTable and SigningTable
    echo "${selector}._domainkey.$domain $domain:$selector:/etc/opendkim/keys/$domain/$selector.private" >> /etc/opendkim/KeyTable
    echo "*@$domain ${selector}._domainkey.$domain" >> /etc/opendkim/SigningTable
    
    print_message "✓ DKIM key generated for $domain"
}

# Script download function
download_script() {
    local script_name=$1
    local dest_path=$2
    
    if [ -f "modules/$script_name" ]; then
        cp "modules/$script_name" "$dest_path"
    else
        local url="https://raw.githubusercontent.com/fumingtomato/shibi/main/MXingFun/$script_name"
        curl -sL "$url" -o "$dest_path" 2>/dev/null || \
        wget -q "$url" -O "$dest_path" 2>/dev/null || \
        return 1
    fi
    
    chmod +x "$dest_path" 2>/dev/null || true
    return 0
}

# DNS check function
check_dns() {
    local record_type=$1
    local domain=$2
    local expected=$3
    
    local result=$(dig +short $record_type $domain @8.8.8.8 2>/dev/null | head -1)
    
    if [ "$record_type" == "MX" ]; then
        result=$(echo "$result" | awk '{print $2}' | sed 's/\.$//')
    elif [ "$record_type" == "TXT" ]; then
        result=$(echo "$result" | tr -d '"')
    fi
    
    if [ "$result" == "$expected" ]; then
        return 0
    else
        return 1
    fi
}

# ===================================================================
# MAIN INSTALLATION
# ===================================================================

print_header "Multi-IP Mail Server Installer v17.1.0"

echo "This installer will set up a complete mail server with:"
echo "  • Postfix + Dovecot + OpenDKIM"
echo "  • MySQL/MariaDB backend"
echo "  • Multi-IP support with rotation"
echo "  • DKIM authentication"
echo "  • Compliance website"
echo "  • SSL certificates"
echo "  • Management tools"
echo ""

# Get installation directory
INSTALL_DIR="$(pwd)"
MODULES_DIR="$INSTALL_DIR/modules"

# Configuration file
CONFIG_FILE="$INSTALL_DIR/install.conf"

# ===================================================================
# CONFIGURATION COLLECTION
# ===================================================================

# Check if config exists
if [ -f "$CONFIG_FILE" ]; then
    read -p "Found existing configuration. Use it? (y/n): " USE_CONFIG
    if [[ "${USE_CONFIG,,}" == "y" ]]; then
        source "$CONFIG_FILE"
        CONFIG_LOADED=true
    else
        CONFIG_LOADED=false
    fi
else
    CONFIG_LOADED=false
fi

if [ "$CONFIG_LOADED" = false ]; then
    print_header "Configuration Setup"
    
    # Domain name
    while true; do
        read -p "Enter your domain name (e.g., example.com): " DOMAIN_NAME
        DOMAIN_NAME=$(echo "$DOMAIN_NAME" | tr '[:upper:]' '[:lower:]' | sed 's/^www\.//')
        
        if [[ "$DOMAIN_NAME" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$ ]]; then
            break
        else
            print_error "Invalid domain format. Please use format: example.com"
        fi
    done
    
    # FIX 1: Mail subdomain configuration (use custom subdomain instead of mail)
    read -p "Enter mail subdomain (e.g., 'mail' for mail.example.com, 'souper' for souper.example.com) [mail]: " MAIL_SUBDOMAIN
    MAIL_SUBDOMAIN=${MAIL_SUBDOMAIN:-mail}
    MAIL_SUBDOMAIN=$(echo "$MAIL_SUBDOMAIN" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]//g')
    
    # Set hostname using the custom subdomain
    HOSTNAME="$MAIL_SUBDOMAIN.$DOMAIN_NAME"
    
    echo "Mail server hostname will be: $HOSTNAME"
    
    # Admin email
    while true; do
        read -p "Enter admin email address: " ADMIN_EMAIL
        if [[ "$ADMIN_EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
            break
        else
            print_error "Invalid email format"
        fi
    done
    
    # Admin password
    while true; do
        read -s -p "Enter admin password (min 8 characters): " ADMIN_PASSWORD
        echo
        if [ ${#ADMIN_PASSWORD} -ge 8 ]; then
            read -s -p "Confirm password: " CONFIRM_PASSWORD
            echo
            if [ "$ADMIN_PASSWORD" == "$CONFIRM_PASSWORD" ]; then
                break
            else
                print_error "Passwords don't match"
            fi
        else
            print_error "Password must be at least 8 characters"
        fi
    done

        
    # Server IP detection
    print_message "Detecting server IP address..."
    PRIMARY_IP=$(curl -s --connect-timeout 5 https://ipinfo.io/ip 2>/dev/null || \
                curl -s --connect-timeout 5 https://api.ipify.org 2>/dev/null || \
                curl -s --connect-timeout 5 https://ifconfig.me 2>/dev/null || \
                hostname -I | awk '{print $1}')
    
    if [ -z "$PRIMARY_IP" ] || ! validate_ip "$PRIMARY_IP"; then
        read -p "Could not detect IP. Enter server primary IP: " PRIMARY_IP
        while ! validate_ip "$PRIMARY_IP"; do
            print_error "Invalid IP format"
            read -p "Enter valid IP address: " PRIMARY_IP
        done
    else
        echo "Detected primary IP: $PRIMARY_IP"
        read -p "Is this correct? (y/n) [y]: " CONFIRM
        if [[ "${CONFIRM,,}" == "n" ]]; then
            read -p "Enter correct IP address: " PRIMARY_IP
            while ! validate_ip "$PRIMARY_IP"; do
                print_error "Invalid IP format"
                read -p "Enter valid IP address: " PRIMARY_IP
            done
        fi
    fi
    
    # Initialize IP array
    IP_ADDRESSES=("$PRIMARY_IP")
    
    # Multi-IP configuration
    echo ""
    read -p "Do you want to configure additional IPs? (y/n) [n]: " MULTI_IP
    
    if [[ "${MULTI_IP,,}" == "y" ]]; then
        echo ""
        echo "Enter additional IPs (one per line, empty line to finish)"
        echo "Formats supported: single IP, range (1.2.3.4-1.2.3.10), CIDR (1.2.3.0/24)"
        
        while true; do
            read -p "IP/Range/CIDR: " ip_input
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
    fi
    
    # Cloudflare configuration (optional)
    echo ""
    read -p "Do you want to configure Cloudflare DNS automatically? (y/n) [n]: " USE_CF
    
    if [[ "${USE_CF,,}" == "y" ]]; then
        read -p "Enter Cloudflare API Token or Global API Key: " CF_API_KEY
        
        if [ ${#CF_API_KEY} -eq 37 ] || [[ "$CF_API_KEY" =~ ^[A-Za-z0-9_-]{40,}$ ]]; then
            echo "Detected API Token format"
            CF_EMAIL=""
        else
            echo "Detected Global API Key format"
            read -p "Enter Cloudflare account email: " CF_EMAIL
        fi
    else
        CF_API_KEY=""
        CF_EMAIL=""
    fi
    
    # Save configuration
    cat > "$CONFIG_FILE" <<EOF
# Mail Server Installation Configuration
# Generated: $(date)

DOMAIN_NAME="$DOMAIN_NAME"
MAIL_SUBDOMAIN="$MAIL_SUBDOMAIN"
HOSTNAME="$HOSTNAME"
ADMIN_EMAIL="$ADMIN_EMAIL"
ADMIN_PASSWORD="$ADMIN_PASSWORD"
PRIMARY_IP="$PRIMARY_IP"
IP_ADDRESSES=(${IP_ADDRESSES[@]})
CF_API_KEY="$CF_API_KEY"
CF_EMAIL="$CF_EMAIL"
USE_CF="${USE_CF,,}"
INSTALL_DIR="$INSTALL_DIR"
EOF
    
    chmod 600 "$CONFIG_FILE"
    print_message "Configuration saved to $CONFIG_FILE"
fi

# ===================================================================
# SYSTEM PREPARATION
# ===================================================================

print_header "System Preparation"

# Update system
print_message "Updating system packages..."
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq

# Set hostname
hostnamectl set-hostname "$HOSTNAME" 2>/dev/null || hostname "$HOSTNAME"
echo "$HOSTNAME" > /etc/hostname

# Update hosts file with proper subdomain
cat > /etc/hosts <<EOF
127.0.0.1   localhost
127.0.1.1   $HOSTNAME $MAIL_SUBDOMAIN

# Primary IP
$PRIMARY_IP $HOSTNAME $MAIL_SUBDOMAIN

# The following lines are desirable for IPv6 capable hosts
::1         localhost ip6-localhost ip6-loopback
ff02::1     ip6-allnodes
ff02::2     ip6-allrouters
EOF

# Add additional IPs to hosts if configured
if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
    for i in "${!IP_ADDRESSES[@]:1}"; do
        if [ $i -ne 0 ]; then
            echo "${IP_ADDRESSES[$i]} ${MAIL_SUBDOMAIN}$((i)).$DOMAIN_NAME" >> /etc/hosts
        fi
    done
fi

print_message "✓ System prepared"

# ===================================================================
# INSTALL PACKAGES
# ===================================================================

print_header "Installing Required Packages"

# Pre-configure Postfix
debconf-set-selections <<< "postfix postfix/mailname string $HOSTNAME"
debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Internet Site'"

# Install packages
PACKAGES=(
    # Mail server
    postfix postfix-mysql postfix-pcre
    dovecot-core dovecot-imapd dovecot-pop3d dovecot-lmtpd dovecot-mysql dovecot-sieve
    
    # Authentication
    opendkim opendkim-tools
    
    # Database
    mariadb-server mariadb-client
    
    # Web server and PHP
    nginx
    php-fpm php-mysql php-json php-mbstring php-xml php-curl
    
    # SSL
    certbot python3-certbot-nginx
    
    # Utilities
    mailutils dnsutils net-tools curl wget git sudo jq
    ufw fail2ban
)

print_message "Installing packages..."
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${PACKAGES[@]}"

print_message "✓ All packages installed"

# ===================================================================
# DATABASE SETUP
# ===================================================================

print_header "Database Configuration"

# Start MariaDB
systemctl start mariadb
systemctl enable mariadb

# Generate database password
DB_ROOT_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
DB_MAIL_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)

# Save database passwords
echo "$DB_ROOT_PASSWORD" > /root/.db_root_password
echo "$DB_MAIL_PASSWORD" > /root/.mail_db_password
chmod 600 /root/.db_root_password /root/.mail_db_password

# Secure MariaDB installation
mysql -e "UPDATE mysql.user SET Password=PASSWORD('$DB_ROOT_PASSWORD') WHERE User='root'"
mysql -e "DELETE FROM mysql.user WHERE User=''"
mysql -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1')"
mysql -e "DROP DATABASE IF EXISTS test"
mysql -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%'"
mysql -e "FLUSH PRIVILEGES"

# Create mail database and user
mysql -u root -p"$DB_ROOT_PASSWORD" <<EOF
CREATE DATABASE IF NOT EXISTS mailserver CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
GRANT ALL PRIVILEGES ON mailserver.* TO 'mailuser'@'localhost' IDENTIFIED BY '$DB_MAIL_PASSWORD';
GRANT ALL PRIVILEGES ON mailserver.* TO 'mailuser'@'127.0.0.1' IDENTIFIED BY '$DB_MAIL_PASSWORD';
FLUSH PRIVILEGES;
EOF

# Create database tables
mysql -u root -p"$DB_ROOT_PASSWORD" mailserver <<'EOF'
-- Domains table
CREATE TABLE IF NOT EXISTS virtual_domains (
    id INT NOT NULL AUTO_INCREMENT,
    name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY domain (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Users table
CREATE TABLE IF NOT EXISTS virtual_users (
    id INT NOT NULL AUTO_INCREMENT,
    domain_id INT NOT NULL,
    email VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    quota BIGINT DEFAULT 0,
    active TINYINT DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY email (email),
    FOREIGN KEY (domain_id) REFERENCES virtual_domains(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Aliases table
CREATE TABLE IF NOT EXISTS virtual_aliases (
    id INT NOT NULL AUTO_INCREMENT,
    domain_id INT NOT NULL,
    source VARCHAR(255) NOT NULL,
    destination VARCHAR(255) NOT NULL,
    active TINYINT DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY source (source),
    FOREIGN KEY (domain_id) REFERENCES virtual_domains(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
EOF

# Add primary domain
mysql -u root -p"$DB_ROOT_PASSWORD" mailserver -e "INSERT INTO virtual_domains (name) VALUES ('$DOMAIN_NAME')"

# Create admin account
ADMIN_HASH=$(doveadm pw -s SHA512-CRYPT -p "$ADMIN_PASSWORD")
mysql -u root -p"$DB_ROOT_PASSWORD" mailserver <<EOF
INSERT INTO virtual_users (domain_id, email, password)
SELECT id, '$ADMIN_EMAIL', '$ADMIN_HASH'
FROM virtual_domains WHERE name = '$DOMAIN_NAME';
EOF

print_message "✓ Database configured"

# ===================================================================
# POSTFIX CONFIGURATION
# ===================================================================

print_header "Configuring Postfix"

# Backup original config
cp /etc/postfix/main.cf /etc/postfix/main.cf.backup

# Main configuration
cat > /etc/postfix/main.cf <<EOF
# Basic Configuration
myhostname = $HOSTNAME
mydomain = $DOMAIN_NAME
myorigin = \$mydomain
mydestination = 
relay_domains = 
mynetworks = 127.0.0.0/8 [::1]/128
inet_interfaces = all
inet_protocols = all

# Virtual domains
virtual_transport = lmtp:unix:private/dovecot-lmtp
virtual_mailbox_domains = mysql:/etc/postfix/mysql/virtual-domains.cf
virtual_mailbox_maps = mysql:/etc/postfix/mysql/virtual-mailboxes.cf
virtual_alias_maps = mysql:/etc/postfix/mysql/virtual-aliases.cf

# TLS configuration
smtpd_tls_cert_file = /etc/ssl/certs/ssl-cert-snakeoil.pem
smtpd_tls_key_file = /etc/ssl/private/ssl-cert-snakeoil.key
smtpd_use_tls = yes
smtpd_tls_auth_only = yes
smtp_tls_security_level = may
smtpd_tls_security_level = may
smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtpd_tls_loglevel = 1

# SASL authentication
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_auth_enable = yes
smtpd_sasl_security_options = noanonymous
smtpd_sasl_local_domain = \$myhostname

# Restrictions
smtpd_helo_required = yes
smtpd_recipient_restrictions =
    permit_mynetworks,
    permit_sasl_authenticated,
    reject_unauth_destination,
    reject_invalid_hostname,
    reject_non_fqdn_hostname,
    reject_non_fqdn_sender,
    reject_non_fqdn_recipient

# Message size and mailbox limits
message_size_limit = 52428800
mailbox_size_limit = 0

# DKIM milter
milter_protocol = 6
milter_default_action = accept
smtpd_milters = inet:localhost:8891
non_smtpd_milters = inet:localhost:8891
EOF

# Add IP rotation support if multiple IPs
if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
    echo "" >> /etc/postfix/main.cf
    echo "# IP rotation" >> /etc/postfix/main.cf
    echo "sender_dependent_default_transport_maps = mysql:/etc/postfix/mysql/sender-transports.cf" >> /etc/postfix/main.cf
    echo "smtp_sender_dependent_authentication = yes" >> /etc/postfix/main.cf
fi

# Configure master.cf
cp /etc/postfix/master.cf /etc/postfix/master.cf.backup

# Add submission and smtps ports
cat >> /etc/postfix/master.cf <<'EOF'

# Submission port 587
submission inet n       -       y       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING

# SMTPS port 465
smtps     inet  n       -       y       -       -       smtpd
  -o syslog_name=postfix/smtps
  -o smtpd_tls_wrappermode=yes
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING
EOF
# Configure IP rotation if multiple IPs
if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
    configure_ip_rotation
fi

# Create MySQL configuration files
mkdir -p /etc/postfix/mysql

cat > /etc/postfix/mysql/virtual-domains.cf <<EOF
user = mailuser
password = $DB_MAIL_PASSWORD
hosts = 127.0.0.1
dbname = mailserver
query = SELECT 1 FROM virtual_domains WHERE name='%s' AND name != ''
EOF

cat > /etc/postfix/mysql/virtual-mailboxes.cf <<EOF
user = mailuser
password = $DB_MAIL_PASSWORD
hosts = 127.0.0.1
dbname = mailserver
query = SELECT CONCAT(SUBSTRING_INDEX(email,'@',-1),'/',SUBSTRING_INDEX(email,'@',1),'/') FROM virtual_users WHERE email='%s' AND active = 1
EOF

cat > /etc/postfix/mysql/virtual-aliases.cf <<EOF
user = mailuser
password = $DB_MAIL_PASSWORD
hosts = 127.0.0.1
dbname = mailserver
query = SELECT destination FROM virtual_aliases WHERE source='%s' AND active = 1
EOF

if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
    cat > /etc/postfix/mysql/sender-transports.cf <<EOF
user = mailuser
password = $DB_MAIL_PASSWORD
hosts = 127.0.0.1
dbname = mailserver
query = SELECT CONCAT('smtp-ip', transport_id, ':') FROM ip_rotation_advanced WHERE sender_email='%s'
EOF
fi

chmod 640 /etc/postfix/mysql/*.cf
chown root:postfix /etc/postfix/mysql/*.cf

print_message "✓ Postfix configured"

# ===================================================================
# DOVECOT CONFIGURATION
# ===================================================================

print_header "Configuring Dovecot"

# Create vmail user
groupadd -g 5000 vmail 2>/dev/null || true
useradd -g vmail -u 5000 vmail -d /var/vmail -m 2>/dev/null || true

# Configure Dovecot
cat > /etc/dovecot/conf.d/10-auth.conf <<'EOF'
disable_plaintext_auth = yes
auth_mechanisms = plain login

!include auth-sql.conf.ext
EOF

cat > /etc/dovecot/conf.d/auth-sql.conf.ext <<EOF
passdb {
  driver = sql
  args = /etc/dovecot/dovecot-sql.conf.ext
}

userdb {
  driver = static
  args = uid=vmail gid=vmail home=/var/vmail/%d/%n
}
EOF

cat > /etc/dovecot/dovecot-sql.conf.ext <<EOF
driver = mysql
connect = host=127.0.0.1 dbname=mailserver user=mailuser password=$DB_MAIL_PASSWORD

default_pass_scheme = SHA512-CRYPT

password_query = \\
  SELECT email as user, password \\
  FROM virtual_users \\
  WHERE email = '%u' AND active = 1

user_query = \\
  SELECT CONCAT('/var/vmail/', SUBSTRING_INDEX(email,'@',-1),'/',SUBSTRING_INDEX(email,'@',1)) as home, \\
  5000 AS uid, 5000 AS gid \\
  FROM virtual_users \\
  WHERE email = '%u' AND active = 1
EOF

cat > /etc/dovecot/conf.d/10-mail.conf <<'EOF'
mail_location = maildir:/var/vmail/%d/%n
namespace inbox {
  inbox = yes
  location = 
  mailbox Drafts {
    special_use = \Drafts
  }
  mailbox Junk {
    special_use = \Junk
  }
  mailbox Sent {
    special_use = \Sent
  }
  mailbox "Sent Messages" {
    special_use = \Sent
  }
  mailbox Trash {
    special_use = \Trash
  }
  prefix = 
}

mail_uid = vmail
mail_gid = vmail
first_valid_uid = 5000
last_valid_uid = 5000
mail_privileged_group = vmail
EOF

cat > /etc/dovecot/conf.d/10-master.conf <<'EOF'
service imap-login {
  inet_listener imap {
    port = 143
  }
  inet_listener imaps {
    port = 993
    ssl = yes
  }
}

service pop3-login {
  inet_listener pop3 {
    port = 110
  }
  inet_listener pop3s {
    port = 995
    ssl = yes
  }
}

service lmtp {
  unix_listener /var/spool/postfix/private/dovecot-lmtp {
    mode = 0600
    user = postfix
    group = postfix
  }
}

service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0666
    user = postfix
    group = postfix
  }
  
  unix_listener auth-userdb {
    mode = 0600
    user = vmail
  }
  
  user = dovecot
}

service auth-worker {
  user = vmail
}
EOF

chown -R vmail:vmail /var/vmail
chmod 600 /etc/dovecot/dovecot-sql.conf.ext

print_message "✓ Dovecot configured"

# ===================================================================
# OPENDKIM CONFIGURATION
# ===================================================================

print_header "Configuring OpenDKIM"

# Generate DKIM keys
generate_dkim_key "$DOMAIN_NAME" "mail" 1024

# Configure OpenDKIM
cat > /etc/opendkim.conf <<EOF
# OpenDKIM Configuration
AutoRestart             Yes
AutoRestartRate         10/1h
UMask                   002
Syslog                  yes
SyslogSuccess           Yes
LogWhy                  Yes

# Signing mode
Mode                    sv
Domain                  $DOMAIN_NAME
Selector                mail
MinimumKeyBits          1024
SubDomains              yes
AlwaysAddARHeader       yes

# Canonicalization
Canonicalization        relaxed/simple

# Trusted hosts
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
EOF

# Configure trusted hosts
cat > /etc/opendkim/TrustedHosts <<EOF
127.0.0.1
localhost
::1
$HOSTNAME
*.$DOMAIN_NAME
$DOMAIN_NAME
EOF

# Add all IPs to trusted hosts
for ip in "${IP_ADDRESSES[@]}"; do
    echo "$ip" >> /etc/opendkim/TrustedHosts
done

# Configure signing table
> /etc/opendkim/SigningTable
> /etc/opendkim/KeyTable

# Fix permissions
mkdir -p /var/run/opendkim
chown opendkim:opendkim /var/run/opendkim
chown -R opendkim:opendkim /etc/opendkim

print_message "✓ OpenDKIM configured"

# ===================================================================
# CREATE MANAGEMENT COMMANDS
# ===================================================================

print_header "Creating Management Commands"

# FIX 3: Create bulk IP management command
cat > /usr/local/bin/bulk-ip-manage <<'IPMANAGE'
#!/bin/bash

# Bulk IP Management Tool
DB_PASS=$(cat /root/.mail_db_password 2>/dev/null)

if [ -z "$DB_PASS" ]; then
    echo "Error: Database password not found"
    exit 1
fi

case "$1" in
    assign)
        if [ -z "$2" ] || [ -z "$3" ]; then
            echo "Usage: bulk-ip-manage assign <email> <mode>"
            echo "Modes: sticky, round-robin, least-used"
            exit 1
        fi
        
        EMAIL="$2"
        MODE="$3"
        
        mysql -u mailuser -p"$DB_PASS" mailserver <<EOF
INSERT INTO ip_rotation_advanced (sender_email, rotation_mode)
VALUES ('$EMAIL', '$MODE')
ON DUPLICATE KEY UPDATE rotation_mode = '$MODE';
EOF
        echo "Assigned $EMAIL to $MODE mode"
        ;;
        
    list)
        echo "Current IP Assignments:"
        mysql -u mailuser -p"$DB_PASS" mailserver -e "
        SELECT sender_email as 'Email', 
               assigned_ip as 'IP', 
               rotation_mode as 'Mode',
               message_count as 'Messages',
               last_used as 'Last Used'
        FROM ip_rotation_advanced
        ORDER BY last_used DESC;"
        ;;
        
    stats)
        echo "IP Pool Statistics:"
        mysql -u mailuser -p"$DB_PASS" mailserver -e "
        SELECT ip_address as 'IP Address',
               is_active as 'Active',
               reputation_score as 'Reputation',
               messages_sent_today as 'Today',
               messages_sent_total as 'Total',
               last_used as 'Last Used'
        FROM ip_pool
        ORDER BY ip_index;"
        ;;
        
    reset)
        if [ -z "$2" ]; then
            echo "Usage: bulk-ip-manage reset <email|all>"
            exit 1
        fi
        
        if [ "$2" == "all" ]; then
            mysql -u mailuser -p"$DB_PASS" mailserver -e "
            UPDATE ip_rotation_advanced SET assigned_ip = NULL, transport_id = NULL;
            UPDATE ip_pool SET messages_sent_today = 0;"
            echo "Reset all IP assignments"
        else
            mysql -u mailuser -p"$DB_PASS" mailserver -e "
            UPDATE ip_rotation_advanced 
            SET assigned_ip = NULL, transport_id = NULL 
            WHERE sender_email = '$2';"
            echo "Reset IP assignment for $2"
        fi
        ;;
        
    activate|deactivate)
        if [ -z "$2" ]; then
            echo "Usage: bulk-ip-manage $1 <ip>"
            exit 1
        fi
        
        ACTIVE=$([ "$1" == "activate" ] && echo "1" || echo "0")
        mysql -u mailuser -p"$DB_PASS" mailserver -e "
        UPDATE ip_pool SET is_active = $ACTIVE WHERE ip_address = '$2';"
        echo "IP $2 ${1}d"
        ;;
        
    *)
        echo "Bulk IP Management"
        echo "Usage: bulk-ip-manage {assign|list|stats|reset|activate|deactivate}"
        echo ""
        echo "Commands:"
        echo "  assign <email> <mode>  - Assign rotation mode (sticky/round-robin/least-used)"
        echo "  list                   - List all sender assignments"
        echo "  stats                  - Show IP pool statistics"
        echo "  reset <email|all>      - Reset IP assignments"
        echo "  activate <ip>          - Activate an IP"
        echo "  deactivate <ip>        - Deactivate an IP"
        ;;
esac
IPMANAGE

chmod +x /usr/local/bin/bulk-ip-manage

# Download and install other management scripts
download_script "create-utilities.sh" "$INSTALL_DIR/create-utilities.sh"
if [ -f "$INSTALL_DIR/create-utilities.sh" ]; then
    bash "$INSTALL_DIR/create-utilities.sh"
fi

# FIX 4: Install permissions setup script
download_script "setup-permissions.sh" "$INSTALL_DIR/setup-permissions.sh"
if [ -f "$INSTALL_DIR/setup-permissions.sh" ]; then
    bash "$INSTALL_DIR/setup-permissions.sh"
fi

print_message "✓ Management commands created"

# ===================================================================
# NGINX AND WEBSITE SETUP
# ===================================================================

print_header "Setting up Website"

download_script "setup-website.sh" "$INSTALL_DIR/setup-website.sh"
if [ -f "$INSTALL_DIR/setup-website.sh" ]; then
    bash "$INSTALL_DIR/setup-website.sh"
fi

# ===================================================================
# CLOUDFLARE DNS SETUP
# ===================================================================

if [[ "$USE_CF" == "y" ]]; then
    print_header "Configuring Cloudflare DNS"
    
    download_script "cloudflare-dns-setup.sh" "$INSTALL_DIR/cloudflare-dns-setup.sh"
    if [ -f "$INSTALL_DIR/cloudflare-dns-setup.sh" ]; then
        bash "$INSTALL_DIR/cloudflare-dns-setup.sh"
    fi
fi

# ===================================================================
# SSL CERTIFICATE
# ===================================================================

print_header "SSL Certificate Setup"

download_script "ssl-setup.sh" "$INSTALL_DIR/ssl-setup.sh"
if [ -f "$INSTALL_DIR/ssl-setup.sh" ]; then
    bash "$INSTALL_DIR/ssl-setup.sh"
fi

# ===================================================================
# POST-INSTALLATION CONFIGURATION
# ===================================================================

print_header "Final Configuration"

download_script "post-install-config.sh" "$INSTALL_DIR/post-install-config.sh"
if [ -f "$INSTALL_DIR/post-install-config.sh" ]; then
    bash "$INSTALL_DIR/post-install-config.sh"
fi

# ===================================================================
# START SERVICES
# ===================================================================

print_header "Starting Services"

systemctl restart postfix dovecot opendkim nginx
systemctl enable postfix dovecot opendkim nginx mariadb

# ===================================================================
# INSTALLATION COMPLETE
# ===================================================================

print_header "Installation Complete!"

echo "✅ Mail server installed successfully!"
echo ""
echo "Server Details:"
echo "  Domain: $DOMAIN_NAME"
echo "  Hostname: $HOSTNAME"
echo "  Mail Subdomain: $MAIL_SUBDOMAIN"
echo "  Primary IP: $PRIMARY_IP"
if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
    echo "  Total IPs: ${#IP_ADDRESSES[@]}"
fi
echo ""
echo "Admin Account:"
echo "  Email: $ADMIN_EMAIL"
echo "  Password: [set during installation]"
echo ""
echo "Management Commands:"
echo "  mail-status        - Check server status"
echo "  mail-account       - Manage email accounts"
echo "  bulk-ip-manage     - Manage IP rotation"
echo "  test-email         - Send test emails"
echo "  check-dns          - Verify DNS records"
echo ""
echo "Next Steps:"
echo "1. Add DNS records (check /root/dns-records-$DOMAIN_NAME.txt)"
echo "2. Set PTR records with your hosting provider"
echo "3. Test with: test-email check-auth@verifier.port25.com"
echo "4. Monitor: mail-status"
echo ""
echo "Website: http://$PRIMARY_IP (SSL pending DNS propagation)"
echo "Logs: $LOG_FILE"
echo ""
print_message "Installation completed successfully!"
