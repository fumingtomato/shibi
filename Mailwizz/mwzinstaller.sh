#!/bin/bash
#
# Mailwizz Professional Installer (Direct SMTP Edition) for Ubuntu 24.04
#
# Description:
# This script provides a secure, efficient, and production-ready automated installation
# of Mailwizz on a fresh Ubuntu 24.04 server. It is specifically designed for a
# "Direct SMTP" environment where Mailwizz connects directly to external SMTP servers,
# and therefore DOES NOT install a local MTA like Postfix.
#
# --- Created by @Copilot, based on a script by fumingtomato ---
# --- Date: 2025-10-02 ---
#

set -e
set -o pipefail

# =================================================================
# SECTION 1: CORE SETUP AND UTILITIES
# =================================================================

# --- Color Codes ---
ORANGE='\033[38;5;208m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

# --- User & System Info ---
CURRENT_USER=$(logname || echo "${SUDO_USER:-${USER}}")
USER_HOME=$(eval echo ~"${CURRENT_USER}")
WEB_ROOT="/var/www/html"

# --- Helper Functions ---
print_status() { echo -e "${ORANGE}[+] $1${NC}"; }
print_warning() { echo -e "${YELLOW}[!] $1${NC}"; }
print_error() { echo -e "${RED}[-] $1${NC}"; }
print_success() { echo -e "${GREEN}[✓] $1${NC}"; }
print_header() {
    echo -e "${YELLOW}=======================================================================${NC}"
    echo -e "${ORANGE}  $1${NC}"
    echo -e "${YELLOW}=======================================================================${NC}"
}

# --- Prerequisite Checks ---
if [ "$(id -u)" -ne "0" ]; then
    print_error "This script must be run as root or with sudo privileges."
    exit 1
fi

if ! command -v curl &> /dev/null || ! command -v dig &> /dev/null; then
    print_status "Installing initial dependencies: curl and dnsutils..."
    apt-get update -y >/dev/null
    apt-get install -y curl dnsutils >/dev/null
fi

# --- Utility Functions ---
generate_password() {
    tr -dc 'A-Za-z0-9!@#$%^&*()_+' < /dev/urandom | head -c 24
}

get_public_ip() {
    local ip
    ip=$(curl -s -m 10 https://ipinfo.io/ip) || ip=$(curl -s -m 10 https://api.ipify.org)
    if [ -z "$ip" ]; then
        print_error "Could not determine the server's public IP address."
        exit 1
    fi
    echo "$ip"
}

# =================================================================
# SECTION 2: GATHER USER INPUT
# =================================================================

clear
print_header "Mailwizz Professional Installer (Direct SMTP Edition)"
echo -e "${YELLOW}Current User: ${CURRENT_USER} | Home: ${USER_HOME}${NC}"
echo

read -rp "Enter server hostname (e.g., srv1.example.com): " server_name
read -rp "Enter main domain for Mailwizz (e.g., example.com): " main_domain
read -rp "Enter email for SSL notifications: " ssl_email
read -rp "Enter CloudFlare API Token (with DNS Zone:Edit permissions): " -s cloudflare_api_token
echo
read -rp "Enter CloudFlare Zone ID for ${main_domain}: " cloudflare_zone_id

# --- Auto-generate secure credentials ---
mysql_root_password=$(generate_password)
db_password=$(generate_password)
sftp_username="mailwizz_sftp"
sftp_password=$(generate_password)
SERVER_IP=$(get_public_ip)

# =================================================================
# SECTION 3: SYSTEM & NETWORK CONFIGURATION
# =================================================================

print_header "Configuring System, Hostname, and Firewall"

# --- Set Hostname and /etc/hosts ---
print_status "Setting hostname to ${server_name}..."
hostnamectl set-hostname "$server_name"
echo "${SERVER_IP} ${server_name} ${main_domain}" >> /etc/hosts
print_success "Hostname configured."

# --- Update System ---
print_status "Updating system packages..."
apt-get update -y >/dev/null
apt-get upgrade -y >/dev/null
print_success "System updated."

# --- Configure Firewall (UFW) ---
print_status "Configuring UFW firewall..."
apt-get install -y ufw >/dev/null
ufw allow ssh >/dev/null
ufw allow http >/dev/null
ufw allow https >/dev/null
ufw --force enable >/dev/null
print_success "Firewall enabled and configured."

# =================================================================
# SECTION 4: INSTALL CORE PACKAGES (WEB, DB, PHP)
# =================================================================

print_header "Installing Core Production Environment Packages"

# --- Detect latest PHP version (8.x) ---
PHP_VERSION=$(apt-cache search php | grep -oP 'php8\.\d+' | sort -V | tail -n 1 | cut -d'-' -f1)
if [ -z "$PHP_VERSION" ]; then
    print_error "Could not detect a suitable PHP 8.x version. Exiting."
    exit 1
fi
print_status "Detected latest available PHP version: ${PHP_VERSION}"

# --- Consolidated Package Installation ---
print_status "Installing Apache, MySQL, PHP-FPM, and all extensions..."
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    apache2 mysql-server \
    "${PHP_VERSION}" "${PHP_VERSION}-fpm" "${PHP_VERSION}-mysql" "${PHP_VERSION}-curl" \
    "${PHP_VERSION}-zip" "${PHP_VERSION}-imap" "${PHP_VERSION}-mbstring" "${PHP_VERSION}-xml" \
    "${PHP_VERSION}-gd" "${PHP_VERSION}-cli" "${PHP_VERSION}-common" "${PHP_VERSION}-intl" \
    certbot python3-certbot-apache python3-certbot-dns-cloudflare \
    unzip imagemagick fail2ban libapache2-mod-security2 modsecurity-crs >/dev/null
print_success "All core packages installed successfully."

# =================================================================
# SECTION 5: CONFIGURE PRODUCTION SERVICES
# =================================================================

print_header "Configuring Services: Apache, PHP-FPM, MySQL, ModSecurity"

# --- Configure Apache with PHP-FPM ---
print_status "Configuring Apache to use PHP-FPM with mpm_event..."
a2enmod proxy_fcgi setenvif mpm_event rewrite ssl headers
a2enconf "${PHP_VERSION}-fpm"
a2dismod mpm_prefork mpm_worker php*
systemctl restart apache2
print_success "Apache configured for high performance."

# --- Secure MySQL and Create Database ---
print_status "Securing MySQL and creating Mailwizz database..."
systemctl start mysql
mysql --execute="ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '${mysql_root_password}';"
mysql -u root -p"${mysql_root_password}" --execute="DELETE FROM mysql.user WHERE User='';"
mysql -u root -p"${mysql_root_password}" --execute="DROP DATABASE IF EXISTS test;"
mysql -u root -p"${mysql_root_password}" --execute="FLUSH PRIVILEGES;"
mysql -u root -p"${mysql_root_password}" --execute="CREATE DATABASE mailwizz_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
mysql -u root -p"${mysql_root_password}" --execute="CREATE USER 'mailwizz_user'@'localhost' IDENTIFIED BY '${db_password}';"
mysql -u root -p"${mysql_root_password}" --execute="GRANT ALL PRIVILEGES ON mailwizz_db.* TO 'mailwizz_user'@'localhost';"
mysql -u root -p"${mysql_root_password}" --execute="FLUSH PRIVILEGES;"
print_success "MySQL is secured and database is ready."

# --- Optimize PHP-FPM for Mailwizz ---
print_status "Optimizing PHP-FPM configuration..."
PHP_INI_PATH="/etc/php/$(echo ${PHP_VERSION} | sed 's/php//')/fpm/php.ini"
sed -i 's/memory_limit = .*/memory_limit = 512M/' "$PHP_INI_PATH"
sed -i 's/upload_max_filesize = .*/upload_max_filesize = 100M/' "$PHP_INI_PATH"
sed -i 's/post_max_size = .*/post_max_size = 100M/' "$PHP_INI_PATH"
sed -i 's/max_execution_time = .*/max_execution_time = 300/' "$PHP_INI_PATH"
sed -i 's/expose_php = .*/expose_php = Off/' "$PHP_INI_PATH"
sed -i 's/display_errors = .*/display_errors = Off/' "$PHP_INI_PATH"
systemctl restart "${PHP_VERSION}-fpm"
print_success "PHP-FPM optimized."

# --- Configure ModSecurity (WAF) ---
print_status "Configuring ModSecurity WAF in 'DetectionOnly' mode..."
mv /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
# NOTE: Left in DetectionOnly mode to prevent breaking Mailwizz.
# Change to 'SecRuleEngine On' and add whitelists for a production WAF.
sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine DetectionOnly/' /etc/modsecurity/modsecurity.conf
systemctl restart apache2
print_success "ModSecurity is active in a non-blocking mode."

# =================================================================
# SECTION 6: DOMAIN, DNS, AND SSL CERTIFICATE
# =================================================================

print_header "Configuring DNS via CloudFlare and Generating SSL"

# --- Create CloudFlare DNS Record ---
print_status "Creating/updating DNS A record for ${main_domain} -> ${SERVER_IP}"
CLOUDFLARE_API_URL="https://api.cloudflare.com/client/v4/zones/${cloudflare_zone_id}/dns_records"
# Check for existing record
EXISTING_RECORD_ID=$(curl -s -X GET "${CLOUDFLARE_API_URL}?type=A&name=${main_domain}" \
    -H "Authorization: Bearer ${cloudflare_api_token}" -H "Content-Type: application/json" \
    | grep -o '"id":"[^"]*' | cut -d'"' -f4)

if [ -n "$EXISTING_RECORD_ID" ]; then
    # Update
    curl -s -X PUT "${CLOUDFLARE_API_URL}/${EXISTING_RECORD_ID}" \
         -H "Authorization: Bearer ${cloudflare_api_token}" -H "Content-Type: application/json" \
         --data "{\"type\":\"A\",\"name\":\"${main_domain}\",\"content\":\"${SERVER_IP}\",\"ttl\":120,\"proxied\":false}" >/dev/null
    print_status "Updated existing DNS record."
else
    # Create
    curl -s -X POST "${CLOUDFLARE_API_URL}" \
         -H "Authorization: Bearer ${cloudflare_api_token}" -H "Content-Type: application/json" \
         --data "{\"type\":\"A\",\"name\":\"${main_domain}\",\"content\":\"${SERVER_IP}\",\"ttl\":120,\"proxied\":false}" >/dev/null
    print_status "Created new DNS record."
fi
print_success "CloudFlare DNS configured."

# --- Wait for DNS Propagation ---
print_status "Waiting up to 2 minutes for DNS to propagate..."
i=0
while [ $i -lt 24 ]; do
    RESOLVED_IP=$(dig +short "$main_domain" @1.1.1.1)
    if [ "$RESOLVED_IP" == "$SERVER_IP" ]; then
        print_success "DNS has propagated successfully!"
        break
    fi
    sleep 5
    echo -n "."
    i=$((i+1))
done
echo
if [ "$RESOLVED_IP" != "$SERVER_IP" ]; then
    print_warning "DNS has not fully propagated. SSL generation might fail."
fi

# --- Configure Apache VirtualHost and Get SSL ---
print_status "Configuring Apache VirtualHost for ${main_domain}..."
cat > /etc/apache2/sites-available/mailwizz.conf <<EOF
<VirtualHost *:80>
    ServerName ${main_domain}
    Redirect permanent / https://${main_domain}/
</VirtualHost>

<VirtualHost *:443>
    ServerName ${main_domain}
    DocumentRoot ${WEB_ROOT}

    <Directory ${WEB_ROOT}>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    ErrorLog \${APACHE_LOG_DIR}/mailwizz_error.log
    CustomLog \${APACHE_LOG_DIR}/mailwizz_access.log combined

    SSLEngine on
    # Placeholder for Certbot
    SSLCertificateFile /etc/ssl/certs/ssl-cert-snakeoil.pem
    SSLCertificateKeyFile /etc/ssl/private/ssl-cert-snakeoil.key
</VirtualHost>
EOF
a2ensite mailwizz.conf >/dev/null
systemctl reload apache2

print_status "Generating SSL certificate with Certbot..."
certbot --apache -d "${main_domain}" --non-interactive --agree-tos -m "${ssl_email}"
systemctl reload apache2
print_success "SSL certificate installed and configured."

# =================================================================
# SECTION 7: MAILWIZZ INSTALLATION & PERMISSIONS
# =================================================================

print_header "Installing Mailwizz Application"

# --- Create Secure Chrooted SFTP User ---
print_status "Creating secure, chrooted SFTP user '${sftp_username}'..."
adduser --quiet --gecos "" --disabled-password "$sftp_username"
echo "$sftp_username:$sftp_password" | chpasswd
usermod -aG www-data "$sftp_username"

echo -e "\nMatch User ${sftp_username}" >> /etc/ssh/sshd_config
echo "    ForceCommand internal-sftp" >> /etc/ssh/sshd_config
echo "    ChrootDirectory ${WEB_ROOT}" >> /etc/ssh/sshd_config
echo "    PasswordAuthentication yes" >> /etc/ssh/sshd_config
systemctl restart sshd
print_success "SFTP user created and jailed to ${WEB_ROOT}."

# --- Prompt for Mailwizz ZIP ---
print_warning "Please upload the Mailwizz zip file to ${WEB_ROOT} now."
print_status "Use the SFTP credentials below:"
echo -e "  ${YELLOW}Host:${NC} ${SERVER_IP}"
echo -e "  ${YELLOW}User:${NC} ${sftp_username}"
echo -e "  ${YELLOW}Pass:${NC} ${sftp_password}"
echo -e "  ${YELLOW}Port:${NC} 22\n"

read -rp "Enter the name of the Mailwizz zip file (e.g., mailwizz.zip): " mailwizz_zip_file
MAILWIZZ_ZIP_PATH="${WEB_ROOT}/${mailwizz_zip_file}"

while [ ! -f "$MAILWIZZ_ZIP_PATH" ]; do
    print_error "File not found at ${MAILWIZZ_ZIP_PATH}. Please upload it and try again."
    read -rp "Enter the name of the Mailwizz zip file: " mailwizz_zip_file
    MAILWIZZ_ZIP_PATH="${WEB_ROOT}/${mailwizz_zip_file}"
done

# --- Extract and Set Permissions ---
print_status "Extracting Mailwizz..."
unzip -q "$MAILWIZZ_ZIP_PATH" -d "${WEB_ROOT}/temp_mw"
mv "${WEB_ROOT}/temp_mw/latest/"* "${WEB_ROOT}/" || mv "${WEB_ROOT}/temp_mw/"* "${WEB_ROOT}/"
rm -rf "${WEB_ROOT}/temp_mw" "${WEB_ROOT}/index.html" "$MAILWIZZ_ZIP_PATH"
print_success "Mailwizz extracted."

print_status "Setting secure file and directory permissions..."
chown -R www-data:www-data "${WEB_ROOT}"
find "${WEB_ROOT}" -type d -exec chmod 755 {} \;
find "${WEB_ROOT}" -type f -exec chmod 644 {} \;
# Set writable permissions for required directories
WRITABLE_DIRS=("apps/common/runtime" "apps/backend/runtime" "apps/customer/runtime" "apps/frontend/runtime" "apps/console/runtime" "backend/assets/cache" "customer/assets/cache" "frontend/assets/cache" "assets/cache" "apps/extensions" "upload")
for dir in "${WRITABLE_DIRS[@]}"; do
    mkdir -p "${WEB_ROOT}/${dir}"
    chmod -R 775 "${WEB_ROOT}/${dir}"
done
chown -R www-data:www-data "${WEB_ROOT}"
print_success "Permissions secured."

# =================================================================
# SECTION 8: AUTOMATION & FINALIZATION
# =================================================================

print_header "Finalizing Setup and Automating Cron Jobs"

# --- Install Mailwizz Cron Jobs ---
print_status "Installing Mailwizz cron jobs for www-data user..."
CRON_COMMANDS=(
    "*/2 * * * * /usr/bin/php ${WEB_ROOT}/apps/console/console.php send-campaigns"
    "*/5 * * * * /usr/bin/php ${WEB_ROOT}/apps/console/console.php bounce-handler"
    "*/10 * * * * /usr/bin/php ${WEB_ROOT}/apps/console/console.php feedback-loop-handler"
    "*/20 * * * * /usr/bin/php ${WEB_ROOT}/apps/console/console.php process-delivery-and-bounce-log"
    "* * * * * /usr/bin/php ${WEB_ROOT}/apps/console/console.php send-transactional-emails"
)
(crontab -u www-data -l 2>/dev/null; for cmd in "${CRON_COMMANDS[@]}"; do echo "$cmd"; done) | crontab -u www-data -
print_success "Mailwizz cron jobs are now automated."

# --- Final Cleanup and Security ---
print_status "Running final cleanup and security tasks..."
# This will be run after the user completes the web install
cat > /root/secure_and_finish.sh <<EOF
#!/bin/bash
echo "Securing Mailwizz post-installation..."
# Protect sensitive config files
if [ -f "${WEB_ROOT}/apps/common/config/main-custom.php" ]; then
    chmod 400 ${WEB_ROOT}/apps/common/config/main-custom.php
fi
if [ -f "${WEB_ROOT}/apps/common/config/main.php" ]; then
    chmod 400 ${WEB_ROOT}/apps/common/config/main.php
fi
# Remove install directory
if [ -d "${WEB_ROOT}/install" ]; then
    rm -rf "${WEB_ROOT}/install"
    echo "[✓] Installation directory removed."
fi
# Self-destruct
rm -- "\$0"
echo "[✓] Mailwizz is now secured."
EOF
chmod +x /root/secure_and_finish.sh

# --- Store Credentials ---
CRED_FILE="${USER_HOME}/mailwizz_credentials.txt"
cat > "$CRED_FILE" <<EOF
==================================================
 Mailwizz Server Credentials (Direct SMTP Edition)
==================================================
Date: $(date)
Server IP: ${SERVER_IP}
Mailwizz URL: https://${main_domain}/install

--- MySQL Credentials ---
Root Password: ${mysql_root_password}
DB Name: mailwizz_db
DB User: mailwizz_user
DB Pass: ${db_password}

--- SFTP Credentials ---
Host: ${SERVER_IP}
Port: 22
User: ${sftp_username}
Pass: ${sftp_password}
Jailed to: ${WEB_ROOT}
==================================================
EOF
chown "${CURRENT_USER}":"${CURRENT_USER}" "$CRED_FILE"
chmod 600 "$CRED_FILE"

# =================================================================
# SECTION 9: COMPLETION
# =================================================================

print_header "Installation Complete!"
print_success "Mailwizz has been installed and configured."
echo
print_warning "IMPORTANT: All credentials have been saved to: ${CRED_FILE}"
echo
print_status "Next Steps:"
echo "1. Go to https://${main_domain}/install to run the web installer."
echo "   - Use the database credentials from the file above."
echo "2. After the web install is complete, log in to the server and run:"
echo -e "   ${YELLOW}sudo /root/secure_and_finish.sh${NC}"
echo "   This will remove the install directory and finalize security."
echo "3. Log in to Mailwizz and configure your external SMTP servers under"
echo "   'Servers > Delivery Servers' for sending campaigns."
echo -e "4. ${YELLOW}CRITICAL:${NC} For system emails (password resets, notifications),"
echo "   you MUST configure a delivery server for transactional emails under"
echo "   'Settings > Common > Caching/Email' and select it."
echo
print_header "Thank you for using the Mailwizz Professional Installer!"
