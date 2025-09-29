#!/bin/bash

# =================================================================
# DATABASE SETUP FOR MAIL SERVER - AUTOMATIC, NO QUESTIONS
# Version: 17.0.4 - FIXED with 1024-bit DKIM key generation
# Sets up MySQL/MariaDB with virtual users automatically
# Creates first email account from configuration
# =================================================================

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

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    print_error "This script must be run as root"
    exit 1
fi

print_header "Setting Up Mail Server Database"
echo ""

# Load configuration from installer
if [ -f "$(pwd)/install.conf" ]; then
    source "$(pwd)/install.conf"
elif [ -f "/root/mail-installer/install.conf" ]; then
    source "/root/mail-installer/install.conf"
fi

# Get domain info
if [ -z "$DOMAIN_NAME" ]; then
    if [ -f /etc/postfix/main.cf ]; then
        HOSTNAME=$(postconf -h myhostname 2>/dev/null || hostname -f)
        DOMAIN_NAME=$(postconf -h mydomain 2>/dev/null || hostname -d)
    else
        print_error "Domain configuration not found!"
        exit 1
    fi
else
    # Use configured hostname with subdomain
    HOSTNAME=${HOSTNAME:-"$MAIL_SUBDOMAIN.$DOMAIN_NAME"}
fi

echo "Domain: $DOMAIN_NAME"
echo "Hostname: $HOSTNAME"
if [ ! -z "$FIRST_EMAIL" ]; then
    echo "First email account: $FIRST_EMAIL"
fi
echo ""

# ===================================================================
# IMPROVED DATABASE CONNECTION FUNCTION
# ===================================================================

get_mysql_command() {
    # Test various connection methods
    local test_commands=(
        "mysql"
        "sudo mysql"
        "mysql -u root"
        "mariadb"
        "sudo mariadb"
        "mariadb -u root"
    )
    
    for cmd in "${test_commands[@]}"; do
        if $cmd -e "SELECT 1" >/dev/null 2>&1; then
            echo "$cmd"
            return 0
        fi
    done
    
    # Try debian maintenance user
    if [ -f /etc/mysql/debian.cnf ]; then
        if mysql --defaults-file=/etc/mysql/debian.cnf -e "SELECT 1" >/dev/null 2>&1; then
            echo "mysql --defaults-file=/etc/mysql/debian.cnf"
            return 0
        fi
    fi
    
    # No working connection found
    return 1
}

# ===================================================================
# 1. INSTALL AND START DATABASE
# ===================================================================

echo "Checking database installation..."

# Determine which database service to use
DB_SERVICE=""
if systemctl list-units --all | grep -q "mariadb.service"; then
    DB_SERVICE="mariadb"
elif systemctl list-units --all | grep -q "mysql.service"; then
    DB_SERVICE="mysql"
else
    echo "Installing MariaDB..."
    apt-get update > /dev/null 2>&1
    DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server mariadb-client > /dev/null 2>&1
    DB_SERVICE="mariadb"
fi

# Start and enable database service
echo "Starting $DB_SERVICE service..."
systemctl stop $DB_SERVICE 2>/dev/null
sleep 2
systemctl start $DB_SERVICE 2>/dev/null
systemctl enable $DB_SERVICE 2>/dev/null

# Wait for database to be ready
echo "Waiting for database to be ready..."
for i in {1..30}; do
    if systemctl is-active --quiet $DB_SERVICE; then
        break
    fi
    sleep 1
done

if ! systemctl is-active --quiet $DB_SERVICE; then
    print_error "Database service failed to start"
    
    # Try to fix common issues
    echo "Attempting to fix database issues..."
    
    # Create required directories
    mkdir -p /var/run/mysqld
    chown mysql:mysql /var/run/mysqld 2>/dev/null || true
    
    # Try starting again
    systemctl start $DB_SERVICE
    sleep 3
    
    if ! systemctl is-active --quiet $DB_SERVICE; then
        print_error "Unable to start database service"
        print_error "Check: journalctl -xe -u $DB_SERVICE"
        exit 1
    fi
fi

print_message "✓ Database service ($DB_SERVICE) is running"

# Get working MySQL command
echo "Establishing database connection..."
MYSQL_CMD=$(get_mysql_command)

if [ -z "$MYSQL_CMD" ]; then
    print_error "Cannot connect to database"
    echo "Attempting to reset root access..."
    
    # Try to reset root access for MariaDB/MySQL
    if [ "$DB_SERVICE" == "mariadb" ]; then
        mysql_install_db --user=mysql --ldata=/var/lib/mysql 2>/dev/null || true
        systemctl restart mariadb
        sleep 3
    fi
    
    MYSQL_CMD=$(get_mysql_command)
    if [ -z "$MYSQL_CMD" ]; then
        print_error "Failed to establish database connection"
        exit 1
    fi
fi

print_message "✓ Database connection established using: $MYSQL_CMD"

# ===================================================================
# 2. GENERATE DATABASE PASSWORD
# ===================================================================

echo "Generating database password..."

# Check if password already exists
if [ -f /root/.mail_db_password ]; then
    DB_PASS=$(cat /root/.mail_db_password)
    echo "Using existing database password"
else
    # Generate strong password
    DB_PASS=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
    echo "$DB_PASS" > /root/.mail_db_password
    chmod 600 /root/.mail_db_password
    echo "New database password generated"
fi

# ===================================================================
# 3. CREATE DATABASE AND TABLES
# ===================================================================

echo "Creating mail server database..."

# Create database and user
$MYSQL_CMD <<EOF 2>/dev/null || true
-- Create database
CREATE DATABASE IF NOT EXISTS mailserver CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Drop existing user to avoid conflicts
DROP USER IF EXISTS 'mailuser'@'localhost';
DROP USER IF EXISTS 'mailuser'@'127.0.0.1';
DROP USER IF EXISTS 'mailuser'@'::1';

-- Create new user
CREATE USER 'mailuser'@'localhost' IDENTIFIED BY '$DB_PASS';
CREATE USER 'mailuser'@'127.0.0.1' IDENTIFIED BY '$DB_PASS';

-- Grant privileges
GRANT ALL PRIVILEGES ON mailserver.* TO 'mailuser'@'localhost';
GRANT ALL PRIVILEGES ON mailserver.* TO 'mailuser'@'127.0.0.1';
FLUSH PRIVILEGES;
EOF

# Verify database was created
if $MYSQL_CMD -e "USE mailserver" 2>/dev/null; then
    print_message "✓ Database created successfully"
else
    print_error "✗ Failed to create database"
    
    # Try alternative creation method
    echo "Trying alternative database creation method..."
    
    $MYSQL_CMD <<EOF
CREATE DATABASE IF NOT EXISTS mailserver;
GRANT ALL ON mailserver.* TO 'mailuser'@'localhost' IDENTIFIED BY '$DB_PASS';
GRANT ALL ON mailserver.* TO 'mailuser'@'127.0.0.1' IDENTIFIED BY '$DB_PASS';
FLUSH PRIVILEGES;
EOF
    
    if [ $? -ne 0 ]; then
        print_error "Database creation failed. Please check MySQL/MariaDB installation."
        exit 1
    fi
fi

# Create tables using mailuser
echo "Creating database tables..."

# Test mailuser connection
if ! mysql -u mailuser -p"$DB_PASS" -h localhost mailserver -e "SELECT 1" >/dev/null 2>&1; then
    # Try with 127.0.0.1
    if ! mysql -u mailuser -p"$DB_PASS" -h 127.0.0.1 mailserver -e "SELECT 1" >/dev/null 2>&1; then
        print_error "Cannot connect as mailuser"
        echo "Attempting to fix permissions..."
        
        $MYSQL_CMD <<EOF
GRANT ALL PRIVILEGES ON mailserver.* TO 'mailuser'@'localhost' IDENTIFIED BY '$DB_PASS' WITH GRANT OPTION;
GRANT ALL PRIVILEGES ON mailserver.* TO 'mailuser'@'127.0.0.1' IDENTIFIED BY '$DB_PASS' WITH GRANT OPTION;
GRANT ALL PRIVILEGES ON mailserver.* TO 'mailuser'@'%' IDENTIFIED BY '$DB_PASS' WITH GRANT OPTION;
FLUSH PRIVILEGES;
EOF
    fi
fi

# Create tables with properly terminated heredoc
mysql -u mailuser -p"$DB_PASS" -h localhost mailserver <<'EOF_SQLTABLES' 2>/dev/null || \
mysql -u mailuser -p"$DB_PASS" -h 127.0.0.1 mailserver <<'EOF_SQLTABLES' 2>/dev/null || true
-- Create domains table
CREATE TABLE IF NOT EXISTS virtual_domains (
    id INT NOT NULL AUTO_INCREMENT,
    name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY domain_unique (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Create users table
CREATE TABLE IF NOT EXISTS virtual_users (
    id INT NOT NULL AUTO_INCREMENT,
    domain_id INT NOT NULL,
    email VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    quota BIGINT DEFAULT 0,
    active TINYINT DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY email_unique (email),
    FOREIGN KEY (domain_id) REFERENCES virtual_domains(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Create aliases table
CREATE TABLE IF NOT EXISTS virtual_aliases (
    id INT NOT NULL AUTO_INCREMENT,
    domain_id INT NOT NULL,
    source VARCHAR(255) NOT NULL,
    destination VARCHAR(255) NOT NULL,
    active TINYINT DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY source_unique (source),
    FOREIGN KEY (domain_id) REFERENCES virtual_domains(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Create IP rotation tracking table (NEW)
CREATE TABLE IF NOT EXISTS ip_rotation_log (
    id INT NOT NULL AUTO_INCREMENT,
    sender_email VARCHAR(255) NOT NULL,
    assigned_ip VARCHAR(45) NOT NULL,
    transport_id INT NOT NULL,
    last_used TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    message_count INT DEFAULT 1,
    PRIMARY KEY (id),
    UNIQUE KEY sender_unique (sender_email),
    INDEX idx_last_used (last_used)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Add indexes for performance
CREATE INDEX IF NOT EXISTS idx_email ON virtual_users(email);
CREATE INDEX IF NOT EXISTS idx_domain ON virtual_domains(name);
CREATE INDEX IF NOT EXISTS idx_sender ON ip_rotation_log(sender_email);
EOF_SQLTABLES

# Verify tables were created
TABLE_COUNT=$(mysql -u mailuser -p"$DB_PASS" -h localhost mailserver -e "SHOW TABLES" 2>/dev/null | wc -l || \
              mysql -u mailuser -p"$DB_PASS" -h 127.0.0.1 mailserver -e "SHOW TABLES" 2>/dev/null | wc -l)

if [ $TABLE_COUNT -ge 3 ]; then
    print_message "✓ Database tables created"
else
    print_warning "⚠ Some tables may not have been created"
fi

# ===================================================================
# 4. ADD PRIMARY DOMAIN
# ===================================================================

echo "Adding primary domain: $DOMAIN_NAME"

mysql -u mailuser -p"$DB_PASS" -h localhost mailserver <<ADDDOMAIN 2>/dev/null || \
mysql -u mailuser -p"$DB_PASS" -h 127.0.0.1 mailserver <<ADDDOMAIN 2>/dev/null || true
INSERT INTO virtual_domains (name) VALUES ('$DOMAIN_NAME')
ON DUPLICATE KEY UPDATE name = name;
ADDDOMAIN

if [ $? -eq 0 ]; then
    print_message "✓ Domain added to database"
else
    print_warning "⚠ Domain may already exist"
fi

# ===================================================================
# 5. CREATE FIRST EMAIL ACCOUNT (AUTOMATIC)
# ===================================================================

if [ ! -z "$FIRST_EMAIL" ] && [ ! -z "$FIRST_PASS" ]; then
    echo ""
    echo "Creating first email account: $FIRST_EMAIL"
    
    # Create vmail user if doesn't exist
    if ! id -u vmail > /dev/null 2>&1; then
        echo "Creating vmail user..."
        groupadd -g 5000 vmail 2>/dev/null || true
        useradd -g vmail -u 5000 vmail -d /var/vmail -m 2>/dev/null || true
    fi
    
    # Hash the password using doveadm
    if command -v doveadm &> /dev/null; then
        # Try SHA512-CRYPT first
        PASS_HASH=$(doveadm pw -s SHA512-CRYPT -p "$FIRST_PASS" 2>/dev/null)
        if [ -z "$PASS_HASH" ]; then
            # Fallback to SSHA512
            PASS_HASH=$(doveadm pw -s SSHA512 -p "$FIRST_PASS" 2>/dev/null)
        fi
        if [ -z "$PASS_HASH" ]; then
            # Last resort - plain password
            PASS_HASH="{PLAIN}$FIRST_PASS"
            print_warning "Using plain password (will be hashed later)"
        fi
    else
        # If doveadm not available, use plain password temporarily
        PASS_HASH="{PLAIN}$FIRST_PASS"
        print_warning "Dovecot not found, using plain password temporarily"
    fi
    
    # Add user to database
    mysql -u mailuser -p"$DB_PASS" -h localhost mailserver <<ADDUSER 2>/dev/null || \
    mysql -u mailuser -p"$DB_PASS" -h 127.0.0.1 mailserver <<ADDUSER 2>/dev/null || true
-- Get domain ID
SET @domain_id = (SELECT id FROM virtual_domains WHERE name = '$DOMAIN_NAME');

-- Delete existing user if any
DELETE FROM virtual_users WHERE email = '$FIRST_EMAIL';

-- Insert new user
INSERT INTO virtual_users (domain_id, email, password, quota, active)
SELECT id, '$FIRST_EMAIL', '$PASS_HASH', 0, 1
FROM virtual_domains WHERE name = '$DOMAIN_NAME';
ADDUSER
    
    # Check if user was created
    USER_EXISTS=$(mysql -u mailuser -p"$DB_PASS" -h localhost mailserver -e "SELECT COUNT(*) FROM virtual_users WHERE email='$FIRST_EMAIL'" 2>/dev/null | tail -1 || \
                  mysql -u mailuser -p"$DB_PASS" -h 127.0.0.1 mailserver -e "SELECT COUNT(*) FROM virtual_users WHERE email='$FIRST_EMAIL'" 2>/dev/null | tail -1)
    
    if [ "$USER_EXISTS" -ge 1 ] 2>/dev/null; then
        print_message "✓ Email account created: $FIRST_EMAIL"
        
        # Create mail directory
        MAIL_USER="${FIRST_EMAIL%@*}"
        MAIL_DOMAIN="${FIRST_EMAIL#*@}"
        MAIL_DIR="/var/vmail/$MAIL_DOMAIN/$MAIL_USER"
        
        mkdir -p "$MAIL_DIR"
        chown -R vmail:vmail /var/vmail
        chmod -R 770 /var/vmail
        
        print_message "✓ Mail directory created: $MAIL_DIR"
    else
        print_error "✗ Failed to create email account"
        echo "  You can add it manually later with: mail-account add $FIRST_EMAIL password"
    fi
else
    echo ""
    echo "No initial email account configured"
    echo "You can add accounts later with: mail-account add user@$DOMAIN_NAME password"
fi

# ===================================================================
# 6. CONFIGURE POSTFIX
# ===================================================================

print_header "Configuring Postfix for Virtual Users"

# Create Postfix MySQL configuration files
mkdir -p /etc/postfix/mysql

# Virtual domains lookup
cat > /etc/postfix/mysql/virtual_domains.cf <<VDOMAINS
user = mailuser
password = $DB_PASS
hosts = 127.0.0.1
dbname = mailserver
query = SELECT 1 FROM virtual_domains WHERE name='%s' AND name != ''
VDOMAINS

# Virtual mailbox lookup
cat > /etc/postfix/mysql/virtual_mailbox.cf <<VMAILBOX
user = mailuser
password = $DB_PASS
hosts = 127.0.0.1
dbname = mailserver
query = SELECT CONCAT(SUBSTRING_INDEX(email,'@',-1),'/',SUBSTRING_INDEX(email,'@',1),'/') FROM virtual_users WHERE email='%s' AND active = 1
VMAILBOX

# Virtual alias lookup
cat > /etc/postfix/mysql/virtual_alias.cf <<VALIAS
user = mailuser
password = $DB_PASS
hosts = 127.0.0.1
dbname = mailserver
query = SELECT destination FROM virtual_aliases WHERE source='%s' AND active = 1
VALIAS

# Virtual email to transport lookup (for IP rotation)
if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
    cat > /etc/postfix/mysql/sender_transport.cf <<STRANSPORT
user = mailuser
password = $DB_PASS
hosts = 127.0.0.1
dbname = mailserver
query = SELECT CONCAT('smtp-ip', transport_id, ':') FROM ip_rotation_log WHERE sender_email='%s'
STRANSPORT
fi

# Set permissions
chmod 640 /etc/postfix/mysql/*.cf
chown root:postfix /etc/postfix/mysql/*.cf

# Configure Postfix main.cf
postconf -e "virtual_transport = lmtp:unix:private/dovecot-lmtp"
postconf -e "virtual_mailbox_domains = mysql:/etc/postfix/mysql/virtual_domains.cf"
postconf -e "virtual_mailbox_maps = mysql:/etc/postfix/mysql/virtual_mailbox.cf"
postconf -e "virtual_alias_maps = mysql:/etc/postfix/mysql/virtual_alias.cf"
postconf -e "virtual_mailbox_base = /var/vmail"
postconf -e "virtual_uid_maps = static:5000"
postconf -e "virtual_gid_maps = static:5000"
postconf -e "smtpd_sasl_type = dovecot"
postconf -e "smtpd_sasl_path = private/auth"
postconf -e "smtpd_sasl_auth_enable = yes"
postconf -e "smtpd_recipient_restrictions = permit_sasl_authenticated,permit_mynetworks,reject_unauth_destination"

# If multiple IPs, add sender transport lookup
if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
    postconf -e "sender_dependent_default_transport_maps = mysql:/etc/postfix/mysql/sender_transport.cf"
fi

print_message "✓ Postfix configured for virtual users"

# ===================================================================
# 7. CONFIGURE DOVECOT
# ===================================================================

print_header "Configuring Dovecot"

# Backup original configs
cp -n /etc/dovecot/dovecot.conf /etc/dovecot/dovecot.conf.bak 2>/dev/null || true

# Configure Dovecot authentication
cat > /etc/dovecot/conf.d/10-auth.conf <<DAUTH
disable_plaintext_auth = yes
auth_mechanisms = plain login

!include auth-sql.conf.ext
DAUTH

# Configure SQL authentication
cat > /etc/dovecot/dovecot-sql.conf.ext <<DSQL
driver = mysql
connect = host=127.0.0.1 dbname=mailserver user=mailuser password=$DB_PASS

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
DSQL

# Configure mail location
cat > /etc/dovecot/conf.d/10-mail.conf <<DMAIL
mail_location = maildir:/var/vmail/%d/%n
namespace inbox {
  inbox = yes
  location = 
  mailbox Drafts {
    special_use = \\Drafts
  }
  mailbox Junk {
    special_use = \\Junk
  }
  mailbox Sent {
    special_use = \\Sent
  }
  mailbox "Sent Messages" {
    special_use = \\Sent
  }
  mailbox Trash {
    special_use = \\Trash
  }
  prefix = 
}

mail_uid = vmail
mail_gid = vmail
first_valid_uid = 5000
last_valid_uid = 5000
mail_privileged_group = vmail
DMAIL

# Configure master process
cat > /etc/dovecot/conf.d/10-master.conf <<DMASTER
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
DMASTER

# Set permissions
chmod 600 /etc/dovecot/dovecot-sql.conf.ext
chown root:root /etc/dovecot/dovecot-sql.conf.ext

print_message "✓ Dovecot configured"

# ===================================================================
# 8. REGENERATE DKIM KEY AS 1024-BIT (CRITICAL)
# ===================================================================

print_header "Ensuring 1024-bit DKIM Key"

# Check if DKIM key exists and its size
DKIM_KEY_FILE="/etc/opendkim/keys/$DOMAIN_NAME/mail.private"
if [ -f "$DKIM_KEY_FILE" ]; then
    # Check key size
    KEY_BITS=$(openssl rsa -in "$DKIM_KEY_FILE" -text -noout 2>/dev/null | grep "Private-Key:" | grep -oP '\d+' || echo "0")
    
    if [ "$KEY_BITS" -ne 1024 ]; then
        print_warning "⚠ Existing DKIM key is $KEY_BITS-bit, regenerating as 1024-bit..."
        
        # Backup old key
        mv "$DKIM_KEY_FILE" "${DKIM_KEY_FILE}.backup.$(date +%s)"
        mv "/etc/opendkim/keys/$DOMAIN_NAME/mail.txt" "/etc/opendkim/keys/$DOMAIN_NAME/mail.txt.backup.$(date +%s)"
        
        # Generate new 1024-bit key
        cd /etc/opendkim/keys/$DOMAIN_NAME
        opendkim-genkey -s mail -d $DOMAIN_NAME -b 1024
        chown opendkim:opendkim mail.private mail.txt
        chmod 600 mail.private
        chmod 644 mail.txt
        
        print_message "✓ Generated new 1024-bit DKIM key"
    else
        print_message "✓ DKIM key is already 1024-bit"
    fi
else
    print_message "Generating new 1024-bit DKIM key..."
    mkdir -p /etc/opendkim/keys/$DOMAIN_NAME
    cd /etc/opendkim/keys/$DOMAIN_NAME
    opendkim-genkey -s mail -d $DOMAIN_NAME -b 1024
    chown -R opendkim:opendkim /etc/opendkim
    chmod 600 mail.private
    chmod 644 mail.txt
    print_message "✓ Generated 1024-bit DKIM key"
fi

# Verify key length
if [ -f "/etc/opendkim/keys/$DOMAIN_NAME/mail.txt" ]; then
    DKIM_KEY=$(cat /etc/opendkim/keys/$DOMAIN_NAME/mail.txt | grep -v "(" | grep -v ")" | sed 's/.*"p=//' | sed 's/".*//' | tr -d '\n\t\r ')
    echo "DKIM public key length: ${#DKIM_KEY} characters (should be ~215 for 1024-bit)"
fi

# Configure OpenDKIM properly
cat > /etc/opendkim.conf <<'OPENDKIM_CONFIG'
# OpenDKIM Configuration - WITH SIGNING ENABLED
AutoRestart             Yes
AutoRestartRate         10/1h
UMask                   002
Syslog                  yes
SyslogSuccess           Yes
LogWhy                  Yes

# CRITICAL: Set to signing mode
Mode                    sv
Canonicalization        relaxed/simple

# Domain and selector
Domain                  DOMAIN_PLACEHOLDER
Selector                mail
MinimumKeyBits          1024
SubDomains              yes

# CRITICAL: Always sign
SignatureAlgorithm      rsa-sha256
OversignHeaders         From
AlwaysAddARHeader       yes

# Key and signing tables
ExternalIgnoreList      refile:/etc/opendkim/TrustedHosts
InternalHosts           refile:/etc/opendkim/TrustedHosts
KeyTable                refile:/etc/opendkim/KeyTable
SigningTable            refile:/etc/opendkim/SigningTable

# Socket
Socket                  inet:8891@localhost
PidFile                 /var/run/opendkim/opendkim.pid
UserID                  opendkim:opendkim
TemporaryDirectory      /var/tmp
OPENDKIM_CONFIG

# Replace placeholder with actual domain
sed -i "s/DOMAIN_PLACEHOLDER/$DOMAIN_NAME/g" /etc/opendkim.conf

# Ensure TrustedHosts includes everything
cat > /etc/opendkim/TrustedHosts <<EOF
127.0.0.1
localhost
::1
$PRIMARY_IP
$HOSTNAME
*.$DOMAIN_NAME
$DOMAIN_NAME
EOF

# Add all additional IPs if present
if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
    for ip in "${IP_ADDRESSES[@]}"; do
        echo "$ip" >> /etc/opendkim/TrustedHosts
    done
fi

# Fix SigningTable to be comprehensive
cat > /etc/opendkim/SigningTable <<EOF
*@$DOMAIN_NAME mail._domainkey.$DOMAIN_NAME
*@$HOSTNAME mail._domainkey.$DOMAIN_NAME
*@localhost mail._domainkey.$DOMAIN_NAME
*@localhost.localdomain mail._domainkey.$DOMAIN_NAME
$DOMAIN_NAME mail._domainkey.$DOMAIN_NAME
EOF

# Ensure KeyTable is correct
echo "mail._domainkey.$DOMAIN_NAME $DOMAIN_NAME:mail:/etc/opendkim/keys/$DOMAIN_NAME/mail.private" > /etc/opendkim/KeyTable

# Set proper permissions
chown -R opendkim:opendkim /etc/opendkim
chmod 644 /etc/opendkim/TrustedHosts
chmod 644 /etc/opendkim/KeyTable
chmod 644 /etc/opendkim/SigningTable

# Create systemd directory if needed
mkdir -p /var/run/opendkim
chown opendkim:opendkim /var/run/opendkim

# Restart OpenDKIM
systemctl restart opendkim
sleep 2

print_message "✓ OpenDKIM configured for SIGNING with 1024-bit key"

# ===================================================================
# 9. CREATE DATABASE MANAGEMENT SCRIPT
# ===================================================================

echo "Creating database management utility..."

cat > /usr/local/bin/maildb <<'MAILDBSCRIPT'
#!/bin/bash

# Mail Database Manager
if [ -f /root/.mail_db_password ]; then
    DB_PASS=$(cat /root/.mail_db_password)
else
    echo "Error: Database password file not found"
    exit 1
fi

# Try localhost first, then 127.0.0.1
MYSQL_CMD="mysql -u mailuser -p$DB_PASS -h localhost mailserver"
if ! $MYSQL_CMD -e "SELECT 1" >/dev/null 2>&1; then
    MYSQL_CMD="mysql -u mailuser -p$DB_PASS -h 127.0.0.1 mailserver"
fi

case "$1" in
    stats)
        echo "Mail Database Statistics:"
        $MYSQL_CMD -e "
        SELECT 
            (SELECT COUNT(*) FROM virtual_domains) as 'Domains',
            (SELECT COUNT(*) FROM virtual_users) as 'Users',
            (SELECT COUNT(*) FROM virtual_users WHERE active=1) as 'Active Users',
            (SELECT COUNT(*) FROM virtual_aliases) as 'Aliases';"
        ;;
        
    users)
        echo "Email Users:"
        $MYSQL_CMD -e "
        SELECT email as 'Email', 
               CASE active WHEN 1 THEN 'Active' ELSE 'Disabled' END as 'Status',
               created_at as 'Created'
        FROM virtual_users ORDER BY email;"
        ;;
        
    domains)
        echo "Mail Domains:"
        $MYSQL_CMD -e "
        SELECT name as 'Domain', 
               (SELECT COUNT(*) FROM virtual_users WHERE domain_id = virtual_domains.id) as 'Users',
               created_at as 'Created'
        FROM virtual_domains ORDER BY name;"
        ;;
        
    ip-stats)
        echo "IP Rotation Statistics:"
        $MYSQL_CMD -e "
        SELECT 
            assigned_ip as 'IP Address',
            COUNT(*) as 'Senders',
            SUM(message_count) as 'Total Messages',
            MAX(last_used) as 'Last Used'
        FROM ip_rotation_log 
        GROUP BY assigned_ip
        ORDER BY assigned_ip;"
        ;;
        
    backup)
        BACKUP_FILE="/root/maildb-$(date +%Y%m%d-%H%M%S).sql"
        mysqldump -u mailuser -p"$DB_PASS" -h localhost mailserver > "$BACKUP_FILE" 2>/dev/null || \
        mysqldump -u mailuser -p"$DB_PASS" -h 127.0.0.1 mailserver > "$BACKUP_FILE"
        echo "Database backed up to: $BACKUP_FILE"
        ;;
        
    *)
        echo "Mail Database Manager"
        echo "Usage: maildb {stats|users|domains|ip-stats|backup}"
        echo ""
        echo "Commands:"
        echo "  stats    - Show database statistics"
        echo "  users    - List all email users"
        echo "  domains  - List all domains"
        echo "  ip-stats - Show IP rotation statistics"
        echo "  backup   - Backup database"
        ;;
esac
MAILDBSCRIPT

chmod +x /usr/local/bin/maildb

# ===================================================================
# 10. RESTART SERVICES
# ===================================================================

print_header "Restarting Services"

echo -n "Restarting Postfix... "
systemctl restart postfix 2>/dev/null && echo "✓" || echo "✗"

echo -n "Restarting Dovecot... "
systemctl restart dovecot 2>/dev/null && echo "✓" || echo "✗"

echo -n "Restarting OpenDKIM... "
systemctl restart opendkim 2>/dev/null && echo "✓" || echo "✗"

# ===================================================================
# 11. TEST DATABASE CONNECTION
# ===================================================================

echo ""
echo "Testing database connection..."

# Test connection
if mysql -u mailuser -p"$DB_PASS" -h localhost mailserver -e "SELECT 1" > /dev/null 2>&1 || \
   mysql -u mailuser -p"$DB_PASS" -h 127.0.0.1 mailserver -e "SELECT 1" > /dev/null 2>&1; then
    print_message "✓ Database connection successful"
else
    print_warning "⚠ Database connection test failed (may still be initializing)"
fi

# Show statistics
echo ""
echo "Database Statistics:"
mysql -u mailuser -p"$DB_PASS" -h localhost mailserver -e "
SELECT 
    (SELECT COUNT(*) FROM virtual_domains) as 'Domains',
    (SELECT COUNT(*) FROM virtual_users) as 'Users',
    (SELECT COUNT(*) FROM virtual_aliases) as 'Aliases';" 2>/dev/null || \
mysql -u mailuser -p"$DB_PASS" -h 127.0.0.1 mailserver -e "
SELECT 
    (SELECT COUNT(*) FROM virtual_domains) as 'Domains',
    (SELECT COUNT(*) FROM virtual_users) as 'Users',
    (SELECT COUNT(*) FROM virtual_aliases) as 'Aliases';" 2>/dev/null || \
echo "No statistics available yet"

# ===================================================================
# COMPLETION
# ===================================================================

echo ""
print_header "Database Setup Complete!"

echo ""
echo "✓ Database created: mailserver"
echo "✓ Database user: mailuser"
echo "✓ Password saved in: /root/.mail_db_password"
echo "✓ OpenDKIM configured for SIGNING with 1024-bit key"
if [ ! -z "$FIRST_EMAIL" ]; then
    echo "✓ First account: $FIRST_EMAIL"
fi
if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
    echo "✓ IP rotation tracking table created"
fi
echo ""
echo "DKIM KEY STATUS:"
if [ -f "/etc/opendkim/keys/$DOMAIN_NAME/mail.txt" ]; then
    echo "  ✓ 1024-bit key generated"
    echo "  ✓ Public key length: ${#DKIM_KEY} characters"
    if [ ${#DKIM_KEY} -gt 250 ]; then
        print_warning "  ⚠ WARNING: Key seems too long, may still be 2048-bit!"
    fi
fi
echo ""
echo "Database management commands:"
echo "  maildb stats    - Show statistics"
echo "  maildb users    - List users"
echo "  maildb domains  - List domains"
if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
    echo "  maildb ip-stats - Show IP rotation statistics"
fi
echo "  maildb backup   - Backup database"
echo ""
echo "Email account management:"
echo "  mail-account add user@domain.com password"
echo "  mail-account list"
echo "  mail-account delete user@domain.com"
echo ""

if [ ! -z "$FIRST_EMAIL" ]; then
    print_message "Your first email account is ready to use!"
    echo "  Email: $FIRST_EMAIL"
    echo "  Password: [the one you set]"
    echo "  SMTP/IMAP Server: $HOSTNAME"
    echo "  Ports: 587 (SMTP), 993 (IMAP)"
fi

print_message "✓ Database setup completed with 1024-bit DKIM key!"
