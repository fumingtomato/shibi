#!/bin/bash

# =================================================================
# DATABASE SETUP FOR MAIL SERVER
# Version: 16.1.0
# Sets up MySQL/MariaDB with virtual users for Postfix/Dovecot
# Creates first email account during installation
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
    HOSTNAME=${HOSTNAME:-"mail.$DOMAIN_NAME"}
fi

echo "Domain: $DOMAIN_NAME"
echo "Hostname: $HOSTNAME"
if [ ! -z "$FIRST_EMAIL" ]; then
    echo "First email account: $FIRST_EMAIL"
fi
echo ""

# ===================================================================
# 1. INSTALL AND START DATABASE
# ===================================================================

echo "Checking database installation..."

# Check if MySQL or MariaDB is installed
DB_SERVICE=""
if systemctl list-units --all | grep -q "mysql.service"; then
    DB_SERVICE="mysql"
elif systemctl list-units --all | grep -q "mariadb.service"; then
    DB_SERVICE="mariadb"
else
    echo "Installing MariaDB..."
    apt-get update > /dev/null 2>&1
    DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server mariadb-client > /dev/null 2>&1
    DB_SERVICE="mariadb"
fi

# Start and enable database service
systemctl start $DB_SERVICE
systemctl enable $DB_SERVICE

print_message "✓ Database service ($DB_SERVICE) is running"

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
mysql <<EOF 2>/dev/null
-- Create database
CREATE DATABASE IF NOT EXISTS mailserver;

-- Create user with proper privileges
CREATE USER IF NOT EXISTS 'mailuser'@'localhost' IDENTIFIED BY '$DB_PASS';
GRANT ALL PRIVILEGES ON mailserver.* TO 'mailuser'@'localhost';
FLUSH PRIVILEGES;

-- Use the database
USE mailserver;

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

-- Add index for performance
CREATE INDEX IF NOT EXISTS idx_email ON virtual_users(email);
CREATE INDEX IF NOT EXISTS idx_domain ON virtual_domains(name);
EOF

if [ $? -eq 0 ]; then
    print_message "✓ Database structure created"
else
    print_error "✗ Database creation failed"
    exit 1
fi

# ===================================================================
# 4. ADD PRIMARY DOMAIN
# ===================================================================

echo "Adding primary domain: $DOMAIN_NAME"

mysql -u mailuser -p"$DB_PASS" mailserver <<EOF 2>/dev/null
INSERT INTO virtual_domains (name) VALUES ('$DOMAIN_NAME')
ON DUPLICATE KEY UPDATE name = name;
EOF

print_message "✓ Domain added to database"

# ===================================================================
# 5. CREATE FIRST EMAIL ACCOUNT
# ===================================================================

if [ ! -z "$FIRST_EMAIL" ] && [ ! -z "$FIRST_PASS" ]; then
    echo ""
    echo "Creating first email account: $FIRST_EMAIL"
    
    # Hash the password using doveadm
    if command -v doveadm &> /dev/null; then
        PASS_HASH=$(doveadm pw -s SHA512-CRYPT -p "$FIRST_PASS" 2>/dev/null)
        if [ -z "$PASS_HASH" ]; then
            # Fallback to plain password if doveadm fails
            PASS_HASH="{PLAIN}$FIRST_PASS"
        fi
    else
        # If doveadm not available, use plain password temporarily
        PASS_HASH="{PLAIN}$FIRST_PASS"
    fi
    
    # Add user to database
    mysql -u mailuser -p"$DB_PASS" mailserver <<EOF 2>/dev/null
-- Get domain ID
SET @domain_id = (SELECT id FROM virtual_domains WHERE name = '$DOMAIN_NAME');

-- Insert or update user
INSERT INTO virtual_users (domain_id, email, password, quota, active)
VALUES (@domain_id, '$FIRST_EMAIL', '$PASS_HASH', 0, 1)
ON DUPLICATE KEY UPDATE password = '$PASS_HASH', active = 1;
EOF
    
    if [ $? -eq 0 ]; then
        print_message "✓ Email account created: $FIRST_EMAIL"
        
        # Create mail directory
        MAIL_USER="${FIRST_EMAIL%@*}"
        MAIL_DOMAIN="${FIRST_EMAIL#*@}"
        MAIL_DIR="/var/vmail/$MAIL_DOMAIN/$MAIL_USER"
        
        mkdir -p "$MAIL_DIR"
        
        # Create vmail user if doesn't exist
        if ! id -u vmail > /dev/null 2>&1; then
            groupadd -g 5000 vmail
            useradd -g vmail -u 5000 vmail -d /var/vmail -m
        fi
        
        chown -R vmail:vmail /var/vmail
        chmod -R 770 /var/vmail
        
        print_message "✓ Mail directory created: $MAIL_DIR"
    else
        print_error "✗ Failed to create email account"
    fi
else
    echo ""
    echo "No initial email account specified"
    echo "You can add accounts later with: mail-account add user@$DOMAIN_NAME password"
fi

# ===================================================================
# 6. CONFIGURE POSTFIX
# ===================================================================

print_header "Configuring Postfix for Virtual Users"

# Create Postfix MySQL configuration files
mkdir -p /etc/postfix/mysql

# Virtual domains lookup
cat > /etc/postfix/mysql/virtual_domains.cf <<EOF
user = mailuser
password = $DB_PASS
hosts = 127.0.0.1
dbname = mailserver
query = SELECT 1 FROM virtual_domains WHERE name='%s' AND name != ''
EOF

# Virtual mailbox lookup
cat > /etc/postfix/mysql/virtual_mailbox.cf <<EOF
user = mailuser
password = $DB_PASS
hosts = 127.0.0.1
dbname = mailserver
query = SELECT CONCAT(SUBSTRING_INDEX(email,'@',-1),'/',SUBSTRING_INDEX(email,'@',1),'/') FROM virtual_users WHERE email='%s' AND active = 1
EOF

# Virtual alias lookup
cat > /etc/postfix/mysql/virtual_alias.cf <<EOF
user = mailuser
password = $DB_PASS
hosts = 127.0.0.1
dbname = mailserver
query = SELECT destination FROM virtual_aliases WHERE source='%s' AND active = 1
EOF

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

print_message "✓ Postfix configured for virtual users"

# ===================================================================
# 7. CONFIGURE DOVECOT
# ===================================================================

print_header "Configuring Dovecot"

# Backup original configs
cp -n /etc/dovecot/dovecot.conf /etc/dovecot/dovecot.conf.bak 2>/dev/null || true

# Configure Dovecot authentication
cat > /etc/dovecot/conf.d/10-auth.conf <<EOF
disable_plaintext_auth = yes
auth_mechanisms = plain login

!include auth-sql.conf.ext
EOF

# Configure SQL authentication
cat > /etc/dovecot/dovecot-sql.conf.ext <<EOF
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
EOF

# Configure mail location
cat > /etc/dovecot/conf.d/10-mail.conf <<EOF
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
EOF

# Configure master process
cat > /etc/dovecot/conf.d/10-master.conf <<EOF
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

# Set permissions
chmod 600 /etc/dovecot/dovecot-sql.conf.ext
chown root:root /etc/dovecot/dovecot-sql.conf.ext

print_message "✓ Dovecot configured"

# ===================================================================
# 8. CREATE DATABASE MANAGEMENT SCRIPT
# ===================================================================

echo "Creating database management utility..."

cat > /usr/local/bin/maildb << 'EOF'
#!/bin/bash

# Mail Database Manager
if [ -f /root/.mail_db_password ]; then
    DB_PASS=$(cat /root/.mail_db_password)
else
    echo "Error: Database password file not found"
    exit 1
fi

case "$1" in
    stats)
        echo "Mail Database Statistics:"
        mysql -u mailuser -p"$DB_PASS" mailserver -e "
        SELECT 
            (SELECT COUNT(*) FROM virtual_domains) as 'Domains',
            (SELECT COUNT(*) FROM virtual_users) as 'Users',
            (SELECT COUNT(*) FROM virtual_users WHERE active=1) as 'Active Users',
            (SELECT COUNT(*) FROM virtual_aliases) as 'Aliases';"
        ;;
        
    users)
        echo "Email Users:"
        mysql -u mailuser -p"$DB_PASS" mailserver -e "
        SELECT email as 'Email', 
               CASE active WHEN 1 THEN 'Active' ELSE 'Disabled' END as 'Status',
               created_at as 'Created'
        FROM virtual_users ORDER BY email;"
        ;;
        
    domains)
        echo "Mail Domains:"
        mysql -u mailuser -p"$DB_PASS" mailserver -e "
        SELECT name as 'Domain', 
               (SELECT COUNT(*) FROM virtual_users WHERE domain_id = virtual_domains.id) as 'Users',
               created_at as 'Created'
        FROM virtual_domains ORDER BY name;"
        ;;
        
    backup)
        BACKUP_FILE="/root/maildb-$(date +%Y%m%d-%H%M%S).sql"
        mysqldump -u mailuser -p"$DB_PASS" mailserver > "$BACKUP_FILE"
        echo "Database backed up to: $BACKUP_FILE"
        ;;
        
    *)
        echo "Mail Database Manager"
        echo "Usage: maildb {stats|users|domains|backup}"
        echo ""
        echo "Commands:"
        echo "  stats   - Show database statistics"
        echo "  users   - List all email users"
        echo "  domains - List all domains"
        echo "  backup  - Backup database"
        ;;
esac
EOF

chmod +x /usr/local/bin/maildb

# ===================================================================
# 9. RESTART SERVICES
# ===================================================================

print_header "Restarting Services"

echo -n "Restarting Postfix... "
systemctl restart postfix && echo "✓" || echo "✗"

echo -n "Restarting Dovecot... "
systemctl restart dovecot && echo "✓" || echo "✗"

# ===================================================================
# 10. TEST DATABASE CONNECTION
# ===================================================================

echo ""
echo "Testing database connection..."

# Test connection
if mysql -u mailuser -p"$DB_PASS" mailserver -e "SELECT 1" > /dev/null 2>&1; then
    print_message "✓ Database connection successful"
else
    print_error "✗ Database connection failed"
fi

# Show statistics
echo ""
echo "Database Statistics:"
mysql -u mailuser -p"$DB_PASS" mailserver -e "
SELECT 
    (SELECT COUNT(*) FROM virtual_domains) as 'Domains',
    (SELECT COUNT(*) FROM virtual_users) as 'Users',
    (SELECT COUNT(*) FROM virtual_aliases) as 'Aliases';" 2>/dev/null

# ===================================================================
# COMPLETION
# ===================================================================

echo ""
print_header "Database Setup Complete!"

echo ""
echo "✓ Database created: mailserver"
echo "✓ Database user: mailuser"
echo "✓ Password saved in: /root/.mail_db_password"
if [ ! -z "$FIRST_EMAIL" ]; then
    echo "✓ First account created: $FIRST_EMAIL"
fi
echo ""
echo "Database management commands:"
echo "  maildb stats   - Show statistics"
echo "  maildb users   - List users"
echo "  maildb domains - List domains"
echo "  maildb backup  - Backup database"
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

print_message "✓ Database setup completed successfully!"
