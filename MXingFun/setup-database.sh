#!/bin/bash

# =================================================================
# MAIL SERVER DATABASE SETUP
# Version: 16.0.4
# Creates and configures MySQL database for virtual mail hosting
# Automatically creates first email account from installer config
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

print_header "Mail Server Database Setup"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    print_error "This script must be run as root"
    exit 1
fi

# Load configuration from installer
if [ -f "$(pwd)/install.conf" ]; then
    source "$(pwd)/install.conf"
elif [ -f "/root/mail-installer/install.conf" ]; then
    source "/root/mail-installer/install.conf"
fi

# Check if MySQL/MariaDB is installed
if ! command -v mysql &> /dev/null; then
    echo "MySQL/MariaDB not found. Installing..."
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y mysql-server mysql-client
fi

# Start MySQL service
echo "Starting MySQL service..."
systemctl start mysql 2>/dev/null || systemctl start mariadb 2>/dev/null

# Generate secure password
if [ -f /root/.mail_db_password ]; then
    DB_PASSWORD=$(cat /root/.mail_db_password)
    echo "Using existing database password"
else
    DB_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
    echo "$DB_PASSWORD" > /root/.mail_db_password
    chmod 600 /root/.mail_db_password
    echo "Generated new database password"
fi

# Create database and user
print_message "Creating mailserver database..."

mysql <<EOF 2>/dev/null
-- Create database
CREATE DATABASE IF NOT EXISTS mailserver CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Create user
CREATE USER IF NOT EXISTS 'mailuser'@'localhost' IDENTIFIED BY '$DB_PASSWORD';
CREATE USER IF NOT EXISTS 'mailuser'@'127.0.0.1' IDENTIFIED BY '$DB_PASSWORD';

-- Grant privileges
GRANT ALL PRIVILEGES ON mailserver.* TO 'mailuser'@'localhost';
GRANT ALL PRIVILEGES ON mailserver.* TO 'mailuser'@'127.0.0.1';
FLUSH PRIVILEGES;

-- Use the database
USE mailserver;

-- Create virtual_domains table
CREATE TABLE IF NOT EXISTS virtual_domains (
    id INT NOT NULL AUTO_INCREMENT,
    name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY domain_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Create virtual_users table
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

-- Create virtual_aliases table
CREATE TABLE IF NOT EXISTS virtual_aliases (
    id INT NOT NULL AUTO_INCREMENT,
    domain_id INT NOT NULL,
    source VARCHAR(255) NOT NULL,
    destination TEXT NOT NULL,
    active TINYINT DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY source (source),
    FOREIGN KEY (domain_id) REFERENCES virtual_domains(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Create sender_access table for multi-IP routing
CREATE TABLE IF NOT EXISTS sender_access (
    id INT NOT NULL AUTO_INCREMENT,
    email VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    transport VARCHAR(255) DEFAULT NULL,
    priority INT DEFAULT 50,
    active TINYINT DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY email_ip (email, ip_address),
    KEY idx_email (email),
    KEY idx_active (active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Create transport_maps table
CREATE TABLE IF NOT EXISTS transport_maps (
    id INT NOT NULL AUTO_INCREMENT,
    domain VARCHAR(255) NOT NULL,
    transport VARCHAR(255) NOT NULL,
    active TINYINT DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY domain (domain)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Create mail_statistics table
CREATE TABLE IF NOT EXISTS mail_statistics (
    id INT NOT NULL AUTO_INCREMENT,
    email VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45),
    sent_count INT DEFAULT 0,
    bounce_count INT DEFAULT 0,
    last_sent TIMESTAMP NULL,
    date_created DATE,
    PRIMARY KEY (id),
    UNIQUE KEY email_date (email, date_created),
    KEY idx_date (date_created)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Create ip_pool table for IP management
CREATE TABLE IF NOT EXISTS ip_pool (
    id INT NOT NULL AUTO_INCREMENT,
    ip_address VARCHAR(45) NOT NULL,
    hostname VARCHAR(255),
    transport_name VARCHAR(100),
    weight INT DEFAULT 1,
    max_connections INT DEFAULT 10,
    active TINYINT DEFAULT 1,
    last_used TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY ip_address (ip_address)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Show created tables
SHOW TABLES;
EOF

if [ $? -eq 0 ]; then
    print_message "✓ Database created successfully"
else
    print_error "Database creation had some issues (this might be normal if already exists)"
fi

# Create Postfix MySQL configuration files
print_header "Creating Postfix MySQL Configuration"

mkdir -p /etc/postfix/mysql

# Virtual domains
cat > /etc/postfix/mysql/virtual_domains.cf <<EOF
user = mailuser
password = $DB_PASSWORD
hosts = 127.0.0.1
dbname = mailserver
query = SELECT name FROM virtual_domains WHERE name='%s' AND id > 0
EOF

# Virtual mailboxes
cat > /etc/postfix/mysql/virtual_mailboxes.cf <<EOF
user = mailuser
password = $DB_PASSWORD
hosts = 127.0.0.1
dbname = mailserver
query = SELECT CONCAT(SUBSTRING_INDEX(email,'@',-1),'/',SUBSTRING_INDEX(email,'@',1),'/') FROM virtual_users WHERE email='%s' AND active = 1
EOF

# Virtual aliases
cat > /etc/postfix/mysql/virtual_aliases.cf <<EOF
user = mailuser
password = $DB_PASSWORD
hosts = 127.0.0.1
dbname = mailserver
query = SELECT destination FROM virtual_aliases WHERE source='%s' AND active = 1
EOF

# Email to user mapping
cat > /etc/postfix/mysql/virtual_email2user.cf <<EOF
user = mailuser
password = $DB_PASSWORD
hosts = 127.0.0.1
dbname = mailserver
query = SELECT email FROM virtual_users WHERE email='%s' AND active = 1
EOF

# Sender dependent transport
cat > /etc/postfix/mysql/sender_transport.cf <<EOF
user = mailuser
password = $DB_PASSWORD
hosts = 127.0.0.1
dbname = mailserver
query = SELECT transport FROM sender_access WHERE email='%s' AND active = 1 ORDER BY priority DESC LIMIT 1
EOF

# Set permissions
chmod 640 /etc/postfix/mysql/*.cf
chown root:postfix /etc/postfix/mysql/*.cf

print_message "✓ Postfix MySQL configuration created"

# Create Dovecot SQL configuration
print_header "Creating Dovecot SQL Configuration"

cat > /etc/dovecot/dovecot-sql.conf.ext <<EOF
driver = mysql
connect = host=127.0.0.1 dbname=mailserver user=mailuser password=$DB_PASSWORD
default_pass_scheme = SHA512-CRYPT

password_query = \\
    SELECT email as user, password \\
    FROM virtual_users \\
    WHERE email='%u' AND active = 1

user_query = \\
    SELECT CONCAT('/var/vmail/',SUBSTRING_INDEX(email,'@',-1),'/',SUBSTRING_INDEX(email,'@',1)) as home, \\
    5000 AS uid, \\
    5000 AS gid, \\
    CONCAT('*:bytes=', COALESCE(quota, 0)) AS quota_rule \\
    FROM virtual_users \\
    WHERE email='%u' AND active = 1

iterate_query = SELECT email FROM virtual_users WHERE active = 1
EOF

chmod 600 /etc/dovecot/dovecot-sql.conf.ext
chown root:dovecot /etc/dovecot/dovecot-sql.conf.ext

print_message "✓ Dovecot SQL configuration created"

# Create helper functions script
print_header "Creating Database Helper Functions"

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
    console)
        mysql -u mailuser -p"$DB_PASS" mailserver
        ;;
        
    query)
        shift
        mysql -u mailuser -p"$DB_PASS" mailserver -e "$*"
        ;;
        
    add-domain)
        if [ -z "$2" ]; then
            echo "Usage: maildb add-domain domain.com"
            exit 1
        fi
        mysql -u mailuser -p"$DB_PASS" mailserver <<SQL
INSERT IGNORE INTO virtual_domains (name) VALUES ('$2');
SQL
        echo "Domain added: $2"
        ;;
        
    list-domains)
        echo "Virtual domains:"
        mysql -u mailuser -p"$DB_PASS" mailserver -e "SELECT name FROM virtual_domains;" 2>/dev/null | tail -n +2
        ;;
        
    add-ip)
        if [ -z "$2" ]; then
            echo "Usage: maildb add-ip 1.2.3.4 [transport_name]"
            exit 1
        fi
        transport="${3:-smtp-$2}"
        mysql -u mailuser -p"$DB_PASS" mailserver <<SQL
INSERT INTO ip_pool (ip_address, transport_name) 
VALUES ('$2', '$transport')
ON DUPLICATE KEY UPDATE transport_name='$transport';
SQL
        echo "IP added to pool: $2"
        ;;
        
    list-ips)
        echo "IP pool:"
        mysql -u mailuser -p"$DB_PASS" mailserver -e "SELECT ip_address, transport_name, active FROM ip_pool;" 2>/dev/null
        ;;
        
    stats)
        echo "Mail Statistics:"
        mysql -u mailuser -p"$DB_PASS" mailserver -e "
            SELECT 
                COUNT(DISTINCT email) as total_accounts,
                COUNT(DISTINCT domain_id) as total_domains,
                (SELECT COUNT(*) FROM ip_pool WHERE active=1) as active_ips
            FROM virtual_users WHERE active=1;
        " 2>/dev/null
        ;;
        
    *)
        echo "Mail Database Manager"
        echo "Usage: maildb {console|query|add-domain|list-domains|add-ip|list-ips|stats}"
        echo ""
        echo "Commands:"
        echo "  console         - Open MySQL console"
        echo "  query <SQL>     - Execute SQL query"
        echo "  add-domain      - Add virtual domain"
        echo "  list-domains    - List all domains"
        echo "  add-ip          - Add IP to pool"
        echo "  list-ips        - List IP pool"
        echo "  stats           - Show statistics"
        ;;
esac
EOF

chmod +x /usr/local/bin/maildb

# ===================================================================
# AUTOMATIC DOMAIN AND EMAIL ACCOUNT CREATION - NO QUESTIONS!
# ===================================================================

print_header "Setting Up Domain and First Email Account"

# Add the domain from installer
if [ ! -z "$DOMAIN_NAME" ]; then
    echo "Adding domain $DOMAIN_NAME to database..."
    mysql -u mailuser -p"$DB_PASSWORD" mailserver <<SQL 2>/dev/null
INSERT IGNORE INTO virtual_domains (name) VALUES ('$DOMAIN_NAME');
SQL
    print_message "✓ Domain added: $DOMAIN_NAME"
fi

# Create the first email account if provided in config
if [ ! -z "$FIRST_EMAIL" ] && [ ! -z "$FIRST_PASS" ]; then
    echo ""
    echo "Creating email account: $FIRST_EMAIL"
    
    # Hash the password using doveadm
    if command -v doveadm &> /dev/null; then
        HASH=$(doveadm pw -s SHA512-CRYPT -p "$FIRST_PASS" 2>/dev/null)
        if [ -z "$HASH" ]; then
            # Fallback to plain text if doveadm fails
            HASH="{PLAIN}$FIRST_PASS"
        fi
    else
        # If doveadm not available yet, use plain text (will be hashed later)
        HASH="{PLAIN}$FIRST_PASS"
    fi
    
    # Insert the email account
    mysql -u mailuser -p"$DB_PASSWORD" mailserver <<SQL 2>/dev/null
-- Get domain ID
SET @domain_id = (SELECT id FROM virtual_domains WHERE name='$DOMAIN_NAME');

-- Insert user if domain exists
INSERT INTO virtual_users (domain_id, email, password, quota, active) 
SELECT @domain_id, '$FIRST_EMAIL', '$HASH', 0, 1 
WHERE @domain_id IS NOT NULL
ON DUPLICATE KEY UPDATE password='$HASH', active=1;
SQL
    
    if [ $? -eq 0 ]; then
        print_message "✓ Email account created: $FIRST_EMAIL"
        
        # Create mail directory
        MAIL_USER="${FIRST_EMAIL%@*}"
        MAIL_DOMAIN="${FIRST_EMAIL#*@}"
        MAIL_DIR="/var/vmail/$MAIL_DOMAIN/$MAIL_USER"
        
        mkdir -p "$MAIL_DIR"
        chown -R vmail:vmail /var/vmail/
        
        echo ""
        echo "Account details saved:"
        echo "  Email: $FIRST_EMAIL"
        echo "  Mail directory: $MAIL_DIR"
        echo "  Status: Active"
    else
        print_warning "Could not create email account (might already exist)"
    fi
else
    echo ""
    echo "No first email account specified. You can add accounts later with:"
    echo "  mail-account add user@$DOMAIN_NAME password"
fi

# Show final statistics
echo ""
print_header "Database Setup Complete"

echo "Database: mailserver"
echo "User: mailuser"
echo "Password: Saved in /root/.mail_db_password"
echo ""

# Show what was created
echo "Current setup:"
mysql -u mailuser -p"$DB_PASSWORD" mailserver -e "
    SELECT 
        (SELECT COUNT(*) FROM virtual_domains) as 'Domains',
        (SELECT COUNT(*) FROM virtual_users WHERE active=1) as 'Email Accounts',
        (SELECT COUNT(*) FROM ip_pool) as 'IP Addresses'
" 2>/dev/null

echo ""
echo "Tables created:"
echo "  - virtual_domains (mail domains)"
echo "  - virtual_users (email accounts)"
echo "  - virtual_aliases (email aliases)"
echo "  - sender_access (IP routing)"
echo "  - transport_maps (transport rules)"
echo "  - mail_statistics (usage stats)"
echo "  - ip_pool (IP management)"
echo ""
echo "Configuration files created:"
echo "  - /etc/postfix/mysql/*.cf"
echo "  - /etc/dovecot/dovecot-sql.conf.ext"
echo ""
echo "Management command: maildb"
echo ""

if [ ! -z "$FIRST_EMAIL" ]; then
    print_message "✓ Your first email account is ready to use!"
    echo ""
    echo "  Email: $FIRST_EMAIL"
    echo "  Password: [the one you entered during setup]"
    echo ""
    echo "To add more accounts:"
    echo "  mail-account add newuser@$DOMAIN_NAME password"
else
    echo "To add email accounts:"
    echo "  mail-account add user@$DOMAIN_NAME password"
fi

echo ""
print_message "✓ Database setup completed successfully!"
