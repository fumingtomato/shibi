#!/bin/bash

# =================================================================
# BULK MAIL SERVER INSTALLER WITH MANAGEMENT PORTAL
# Version: 18.0.4 - FINAL INSTALLATION FLOW FIX
# Corrects the service configuration order to prevent OpenDKIM timeouts.
# =================================================================

set -e

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
            if ((octet > 255)); then return 1; fi
        done
        return 0
    fi
    return 1
}

ip_to_decimal() {
    local ip=$1; IFS='.' read -r -a octets <<< "$ip"; echo "$((octets[0] * 256**3 + octets[1] * 256**2 + octets[2] * 256 + octets[3]))"
}

decimal_to_ip() {
    local dec=$1; echo "$((dec >> 24 & 255)).$((dec >> 16 & 255)).$((dec >> 8 & 255)).$((dec & 255))"
}

expand_ip_range() {
    local range=$1; local start_ip end_ip; IFS='-' read -r start_ip end_ip <<< "$range"
    if ! validate_ip "$start_ip"; then return 1; fi
    if [ -z "$end_ip" ]; then echo "$start_ip"; return 0; fi
    if [[ ! "$end_ip" =~ \. ]]; then IFS='.' read -r -a start_octets <<< "$start_ip"; end_ip="${start_octets[0]}.${start_octets[1]}.${start_octets[2]}.$end_ip"; fi
    if ! validate_ip "$end_ip"; then return 1; fi
    local start_dec=$(ip_to_decimal "$start_ip"); local end_dec=$(ip_to_decimal "$end_ip")
    if [ $start_dec -gt $end_dec ]; then return 1; fi
    for ((dec=start_dec; dec<=end_dec; dec++)); do echo "$(decimal_to_ip $dec)"; done
}

expand_cidr() {
    local cidr=$1; local ip prefix; IFS='/' read -r ip prefix <<< "$cidr"
    if ! validate_ip "$ip" || [ -z "$prefix" ] || [ "$prefix" -lt 0 ] || [ "$prefix" -gt 32 ]; then return 1; fi
    local ip_dec=$(ip_to_decimal "$ip"); local mask=$(( (1 << 32) - (1 << (32 - prefix)) )); local network=$(( ip_dec & mask ))
    local broadcast=$(( network | ~mask & ((1 << 32) - 1) )); for ((dec=network+1; dec<broadcast; dec++)); do echo "$(decimal_to_ip $dec)"; done
}

generate_dkim_key() {
    local domain=$1; local bits=1024; print_header "Generating DKIM Key (1024-bit)"; mkdir -p /etc/opendkim/keys/$domain; cd /etc/opendkim/keys/$domain
    rm -f mail.private mail.txt 2>/dev/null || true; opendkim-genkey -s mail -d $domain -b $bits
    if [ ! -f mail.private ] || [ ! -f mail.txt ]; then print_error "Failed to generate DKIM key"; return 1; fi
    chown opendkim:opendkim mail.private mail.txt; chmod 600 mail.private; chmod 644 mail.txt
    print_message "✓ DKIM key generated successfully"
}

# ===================================================================
# MAIN INSTALLATION
# ===================================================================

print_header "Multi-IP Bulk Mail Server Installer"; echo "Version: 18.0.4"
if [[ $EUID -ne 0 ]]; then print_error "This script must be run as root"; exit 1; fi
if [ ! -f /etc/debian_version ]; then print_error "This installer requires Debian/Ubuntu"; exit 1; fi

# ===================================================================
# PHASE 1: ALL CONFIGURATION GATHERING
# ===================================================================

print_header "Phase 1: Complete Configuration"
while true; do read -p "Enter your domain name (e.g., example.com): " DOMAIN_NAME; if [[ "$DOMAIN_NAME" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}$ ]]; then break; else print_error "Invalid domain format."; fi; done
read -p "Enter mail server subdomain (default: mx): " MAIL_SUBDOMAIN; MAIL_SUBDOMAIN=${MAIL_SUBDOMAIN:-mx}; HOSTNAME="$MAIL_SUBDOMAIN.$DOMAIN_NAME"
DEFAULT_EMAIL="newsletter@$DOMAIN_NAME"; while true; do read -p "Email address for first account (default: $DEFAULT_EMAIL): " FIRST_EMAIL; FIRST_EMAIL=${FIRST_EMAIL:-$DEFAULT_EMAIL}; if [[ "$FIRST_EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then break; else print_error "Invalid email format"; fi; done
read -sp "Password for $FIRST_EMAIL: " FIRST_PASS; echo ""; ADMIN_EMAIL=$FIRST_EMAIL
PRIMARY_IP=$(curl -s --max-time 5 https://ipinfo.io/ip 2>/dev/null || hostname -I | awk '{print $1}'); if [ -z "$PRIMARY_IP" ]; then read -p "Enter server primary IP: " PRIMARY_IP; else echo "Detected primary IP: $PRIMARY_IP"; read -p "Press Enter if correct, or type new IP: " USER_IP; if [ ! -z "$USER_IP" ]; then PRIMARY_IP="$USER_IP"; fi; fi
if ! validate_ip "$PRIMARY_IP"; then print_error "Invalid IP address: $PRIMARY_IP"; exit 1; fi
IP_ADDRESSES=("$PRIMARY_IP"); echo ""; echo "Multi-IP Config: Enter IPs, ranges (1.2.3.4-10), or CIDR (1.2.3.0/24). Enter when done."; while true; do read -p "IP> " ip_input; [ -z "$ip_input" ] && break; if [[ "$ip_input" =~ / ]]; then while IFS= read -r ip; do if validate_ip "$ip" && [[ ! " ${IP_ADDRESSES[@]} " =~ " $ip " ]]; then IP_ADDRESSES+=("$ip"); fi; done < <(expand_cidr "$ip_input"); elif [[ "$ip_input" =~ - ]]; then while IFS= read -r ip; do if validate_ip "$ip" && [[ ! " ${IP_ADDRESSES[@]} " =~ " $ip " ]]; then IP_ADDRESSES+=("$ip"); fi; done < <(expand_ip_range "$ip_input"); else if validate_ip "$ip_input" && [[ ! " ${IP_ADDRESSES[@]} " =~ " $ip_input " ]]; then IP_ADDRESSES+=("$ip_input"); fi; fi; done
read -p "Enter Cloudflare API Key/Token (or press Enter to skip): " CF_API_KEY; if [ ! -z "$CF_API_KEY" ]; then if ! [[ ${#CF_API_KEY} -eq 37 ]] && ! [[ "$CF_API_KEY" =~ ^[A-Za-z0-9_-]{40,}$ ]]; then read -p "Enter Cloudflare account email: " CF_EMAIL; fi; USE_CF="y"; else USE_CF="n"; fi
if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then CONFIGURE_IP_ROTATION=true; else CONFIGURE_IP_ROTATION=false; fi
cat > "$INSTALL_DIR/install.conf" <<EOF
DOMAIN_NAME="$DOMAIN_NAME"; MAIL_SUBDOMAIN="$MAIL_SUBDOMAIN"; HOSTNAME="$HOSTNAME"; ADMIN_EMAIL="$ADMIN_EMAIL"; PRIMARY_IP="$PRIMARY_IP"; IP_ADDRESSES=(${IP_ADDRESSES[@]}); FIRST_EMAIL="$FIRST_EMAIL"; FIRST_PASS="$FIRST_PASS"; CF_API_KEY="$CF_API_KEY"; CF_EMAIL="$CF_EMAIL"; USE_CF="$USE_CF"; CONFIGURE_IP_ROTATION=$CONFIGURE_IP_ROTATION
EOF
chmod 600 "$INSTALL_DIR/install.conf"

# ===================================================================
# PHASE 2: DOWNLOAD & PREPARE
# ===================================================================

print_header "Phase 2 & 3: Downloading Components & System Prep"
GITHUB_BASE="https://raw.githubusercontent.com/fumingtomato/shibi/dude/WebSlinger"; download_script() { wget -q -O "$INSTALL_DIR/$1" "$GITHUB_BASE/$1" && chmod +x "$INSTALL_DIR/$1" || print_warning "Failed to download $1"; }; download_script "setup-database.sh"; download_script "cloudflare-dns-setup.sh"; download_script "setup-website.sh"; download_script "post-install-config.sh"; download_script "create-utilities.sh"
apt-get update -y > /dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get upgrade -y > /dev/null 2>&1
hostnamectl set-hostname "$HOSTNAME" 2>/dev/null || hostname "$HOSTNAME"; echo "$HOSTNAME" > /etc/hostname
cat > /etc/hosts <<EOF
127.0.0.1 localhost
$PRIMARY_IP $HOSTNAME ${HOSTNAME%%.*}
::1 localhost ip6-localhost ip6-loopback
EOF

# ===================================================================
# PHASE 4: INSTALL CORE PACKAGES
# ===================================================================

print_header "Phase 4: Installing Core Packages"
debconf-set-selections <<< "postfix postfix/mailname string $HOSTNAME"; debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Internet Site'"
DEBIAN_FRONTEND=noninteractive apt-get install -y postfix postfix-mysql dovecot-core dovecot-imapd dovecot-pop3d dovecot-lmtpd dovecot-mysql mysql-server opendkim opendkim-tools nginx certbot python3-certbot-nginx ufw mailutils jq dnsutils > /dev/null 2>&1
print_message "✓ Core packages installed"

# ===================================================================
# PHASE 5: CONFIGURE DATABASE (MUST HAPPEN BEFORE OTHER SERVICES)
# ===================================================================

print_header "Phase 5: Configuring Database"
if [ -f "$INSTALL_DIR/setup-database.sh" ]; then
    bash "$INSTALL_DIR/setup-database.sh"
fi

# ===================================================================
# PHASE 6: CONFIGURE POSTFIX & OPENDKIM (CORRECT ORDER)
# ===================================================================

print_header "Phase 6: Configuring Postfix & OpenDKIM"
# Postfix main.cf
cat > /etc/postfix/main.cf <<EOF
myhostname = $HOSTNAME
mydomain = $DOMAIN_NAME
myorigin = \$mydomain
inet_interfaces = all
inet_protocols = ipv4
mydestination = localhost, $HOSTNAME, $DOMAIN_NAME
virtual_transport = lmtp:unix:private/dovecot-lmtp
virtual_mailbox_domains = mysql:/etc/postfix/mysql/virtual_domains.cf
virtual_mailbox_maps = mysql:/etc/postfix/mysql/virtual_mailbox.cf
virtual_alias_maps = mysql:/etc/postfix/mysql/virtual_alias.cf
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_auth_enable = yes
milter_protocol = 6
milter_default_action = accept
smtpd_milters = inet:localhost:8891
non_smtpd_milters = inet:localhost:8891
EOF
# Postfix master.cf
cat >> /etc/postfix/master.cf <<EOF
submission inet n - y - - smtpd
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
smtps inet n - y - - smtpd
  -o smtpd_tls_wrappermode=yes
  -o smtpd_sasl_auth_enable=yes
EOF
print_message "✓ Postfix configured."

# DKIM Key Generation
generate_dkim_key "$DOMAIN_NAME"

# OpenDKIM Configuration
cat > /etc/opendkim.conf <<EOF
AutoRestart Yes
Mode sv
Domain $DOMAIN_NAME
Selector mail
MinimumKeyBits 1024
SubDomains yes
Canonicalization relaxed/simple
ExternalIgnoreList refile:/etc/opendkim/TrustedHosts
InternalHosts refile:/etc/opendkim/TrustedHosts
KeyTable refile:/etc/opendkim/KeyTable
SigningTable refile:/etc/opendkim/SigningTable
Socket inet:8891@localhost
UserID opendkim:opendkim
EOF
echo "127.0.0.1" > /etc/opendkim/TrustedHosts; echo "localhost" >> /etc/opendkim/TrustedHosts; echo ".$DOMAIN_NAME" >> /etc/opendkim/TrustedHosts
echo "mail._domainkey.$DOMAIN_NAME $DOMAIN_NAME:mail:/etc/opendkim/keys/$DOMAIN_NAME/mail.private" > /etc/opendkim/KeyTable
echo "*@$DOMAIN_NAME mail._domainkey.$DOMAIN_NAME" > /etc/opendkim/SigningTable
chown -R opendkim:opendkim /etc/opendkim; mkdir -p /var/run/opendkim && chown opendkim:opendkim /var/run/opendkim
print_message "✓ OpenDKIM configured."

# ===================================================================
# PHASE 7: START SERVICES IN CORRECT ORDER
# ===================================================================
print_header "Phase 7: Starting Core Services"
systemctl restart mysql 2>/dev/null || systemctl restart mariadb
systemctl restart dovecot
systemctl restart opendkim
systemctl restart postfix
print_message "✓ Core mail services started."

# ===================================================================
# PHASE 8: IP ROTATION, DNS, NGINX, SSL
# ===================================================================

if [ "$CONFIGURE_IP_ROTATION" == "true" ]; then
    print_header "Configuring Advanced IP Rotation"
    for i in "${!IP_ADDRESSES[@]}"; do IP="${IP_ADDRESSES[$i]}"; if ! grep -q "^smtp-ip$i" /etc/postfix/master.cf; then cat >> /etc/postfix/master.cf <<EOF
smtp-ip$i unix - - n - - smtp -o smtp_bind_address=$IP -o smtp_helo_name=${MAIL_SUBDOMAIN}${i}.$DOMAIN_NAME
EOF; fi; done
    postconf -e "sender_dependent_default_transport_maps = hash:/etc/postfix/sender_transports"; touch /etc/postfix/sender_transports; postmap hash:/etc/postfix/sender_transports
    systemctl reload postfix
fi

if [[ "$USE_CF" == "y" ]]; then print_header "Configuring Cloudflare DNS"; if [ -f "$INSTALL_DIR/cloudflare-dns-setup.sh" ]; then bash "$INSTALL_DIR/cloudflare-dns-setup.sh"; fi; fi

print_header "Configuring Management Portal & Nginx"
if [ -f "$INSTALL_DIR/setup-website.sh" ]; then bash "$INSTALL_DIR/setup-website.sh"; fi

if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
    print_message "Creating Nginx server blocks for SSL validation..."; i=0
    for ip in "${IP_ADDRESSES[@]}"; do
        if [ "$ip" == "$PRIMARY_IP" ]; then i=$((i+1)); continue; fi
        SUBDOMAIN="${MAIL_SUBDOMAIN}${i}.$DOMAIN_NAME}"; WEBROOT_DIR="/var/www/html/$SUBDOMAIN"; mkdir -p "$WEBROOT_DIR"; chown -R www-data:www-data "$WEBROOT_DIR"
        cat > "/etc/nginx/sites-available/$SUBDOMAIN.conf" <<EOF
server { listen 80; server_name $SUBDOMAIN; location /.well-known/acme-challenge/ { root $WEBROOT_DIR; } location / { return 404; } }
EOF
        ln -sf "/etc/nginx/sites-available/$SUBDOMAIN.conf" "/etc/nginx/sites-enabled/$SUBDOMAIN.conf"; i=$((i+1))
    done
    systemctl reload nginx
fi

print_header "Setting up SSL Certificates"
CERT_DOMAINS=""; DOMAINS_TO_CHECK=("$DOMAIN_NAME" "www.$DOMAIN_NAME" "$HOSTNAME")
if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then for i in $(seq 1 $((${#IP_ADDRESSES[@]} - 1))); do DOMAINS_TO_CHECK+=("${MAIL_SUBDOMAIN}${i}.$DOMAIN_NAME"); done; fi
for domain in "${DOMAINS_TO_CHECK[@]}"; do if host "$domain" 8.8.8.8 > /dev/null 2>&1; then CERT_DOMAINS="$CERT_DOMAINS -d $domain"; fi; done
if [[ "$CERT_DOMAINS" == *"-d $DOMAIN_NAME"* ]]; then certbot --nginx $CERT_DOMAINS --non-interactive --agree-tos --email "$ADMIN_EMAIL" --no-eff-email --redirect 2>/dev/null || echo "SSL generation failed for some domains."; fi

# ===================================================================
# PHASE 9: FINAL SETUP
# ===================================================================

print_header "Phase 9: Finalizing Setup"
if [ -f "$INSTALL_DIR/create-utilities.sh" ]; then bash "$INSTALL_DIR/create-utilities.sh"; fi
ufw --force disable 2>/dev/null && ufw --force reset 2>/dev/null; ufw default deny incoming; ufw default allow outgoing; ufw allow 22/tcp; ufw allow 25/tcp; ufw allow 80/tcp; ufw allow 443/tcp; ufw allow 587/tcp; ufw allow 465/tcp; ufw allow 993/tcp; ufw allow 995/tcp; echo "y" | ufw --force enable
if [ -f "$INSTALL_DIR/post-install-config.sh" ]; then bash "$INSTALL_DIR/post-install-config.sh"; fi
systemctl enable postfix dovecot opendkim nginx mysql 2>/dev/null || systemctl enable postfix dovecot opendkim nginx mariadb

# ===================================================================
# INSTALLATION COMPLETE
# ===================================================================

print_header "Installation Complete!"
echo "Domain: $DOMAIN_NAME"; echo "Mail Server: $HOSTNAME"; echo "Admin Email: $FIRST_EMAIL"
if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then echo "Total IPs: ${#IP_ADDRESSES[@]}"; fi
DKIM_KEY=$(grep -oP 'p=\K[^"]+' /etc/opendkim/keys/$DOMAIN_NAME/mail.txt | tr -d '\n\t\r '); echo "DKIM Record: Name: mail._domainkey, Type: TXT, Value: v=DKIM1; k=rsa; p=$DKIM_KEY"
echo "Run 'mail-help' for a list of management commands."
print_message "Your bulk mail server is READY!"
