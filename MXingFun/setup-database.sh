#!/bin/bash

# =================================================================
# MAIL SERVER DATABASE SETUP
# Version: 16.0.3
# Creates and configures MySQL database for virtual mail hosting
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

# Add sample data if requested
print_header "Database Setup Complete"
echo ""
echo "Database: mailserver"
echo "User: mailuser"
echo "Password: Saved in /root/.mail_db_password"
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

# AUTOMATICALLY ADD THE DOMAIN FROM INSTALLER - NO QUESTIONS!
if [ ! -z "$DOMAIN_NAME" ]; then
    echo "Adding domain $DOMAIN_NAME to database..."
    mysql -u mailuser -p"$DB_PASSWORD" mailserver <<SQL 2>/dev/null
INSERT IGNORE INTO virtual_domains (name) VALUES ('$DOMAIN_NAME');
SQL
    echo "✓ Domain added: $DOMAIN_NAME"
    echo ""
    echo "You can now add email accounts with:"
    echo "  mail-account add user@$DOMAIN_NAME password"
else
    echo "Note: No domain configured yet. Add domains with:"
    echo "  maildb add-domain yourdomain.com"
fi

echo ""
print_message "✓ Database setup completed successfully!"
