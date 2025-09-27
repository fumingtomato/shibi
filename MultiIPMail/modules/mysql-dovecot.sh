#!/bin/bash

# =================================================================
# MYSQL AND DOVECOT CONFIGURATION MODULE - FIXED VERSION
# Database setup, user authentication, and mail storage
# Fixed: SQL injection prevention, proper error handling, service dependencies
# =================================================================

# Global variables for database configuration
export DB_NAME="mailserver"
export DB_USER="mailuser"
export DB_PASSWORD=""
export DB_HOST="127.0.0.1"
export DB_PORT="3306"

# Check if MySQL/MariaDB is installed and running
check_mysql_service() {
    local service_name=""
    
    # Check for MySQL or MariaDB
    if systemctl list-units --full -all | grep -q "mysql.service"; then
        service_name="mysql"
    elif systemctl list-units --full -all | grep -q "mariadb.service"; then
        service_name="mariadb"
    else
        print_error "Neither MySQL nor MariaDB service found"
        return 1
    fi
    
    # Start the service if not running
    if ! systemctl is-active --quiet "$service_name"; then
        print_message "Starting $service_name service..."
        systemctl start "$service_name" || return 1
        sleep 2
    fi
    
    # Enable the service
    systemctl enable "$service_name" 2>/dev/null || true
    
    return 0
}

# Wait for MySQL to be ready with timeout
wait_for_mysql() {
    local max_wait=${1:-30}
    local waited=0
    
    print_message "Waiting for MySQL/MariaDB to be ready..."
    
    while [ $waited -lt $max_wait ]; do
        if mysqladmin ping --silent 2>/dev/null; then
            print_message "✓ Database server is ready"
            return 0
        fi
        
        sleep 1
        waited=$((waited + 1))
        echo -n "."
    done
    
    echo ""
    print_error "Database server failed to start within ${max_wait} seconds"
    return 1
}

# Generate secure password
generate_secure_password() {
    local length=${1:-32}
    openssl rand -base64 "$length" | tr -d "=+/" | cut -c1-"$length"
}

# Execute SQL with error handling
execute_sql() {
    local sql="$1"
    local database="${2:-}"
    
    local mysql_cmd="mysql"
    
    # Add database if specified
    if [ ! -z "$database" ]; then
        mysql_cmd="$mysql_cmd -D $database"
    fi
    
    # Execute SQL
    if echo "$sql" | $mysql_cmd 2>&1 | tee -a "$log_file"; then
        return 0
    else
        print_error "SQL execution failed"
        return 1
    fi
}

# Setup MySQL server for mail storage
setup_mysql() {
    print_header "Setting up MySQL/MariaDB Database Server"
    
    # Check and start MySQL service
    if ! check_mysql_service; then
        print_message "Installing MySQL server..."
        apt-get update
        apt-get install -y mysql-server mysql-client || apt-get install -y mariadb-server mariadb-client
        check_mysql_service || return 1
    fi
    
    # Wait for MySQL to be ready
    wait_for_mysql || return 1
    
    # Generate secure password for mail user
    DB_PASSWORD=$(generate_secure_password)
    
    # Save password securely
    echo "$DB_PASSWORD" > /root/.mail_db_password
    chmod 600 /root/.mail_db_password
    chown root:root /root/.mail_db_password
    
    print_message "Creating mail server database and tables..."
    
    # Create database and user with proper escaping
    local sql_script=$(cat <<EOF
-- Drop database if exists for clean install
DROP DATABASE IF EXISTS ${DB_NAME};

-- Create database with UTF8MB4 support
CREATE DATABASE ${DB_NAME} 
    CHARACTER SET utf8mb4 
    COLLATE utf8mb4_unicode_ci;

-- Use the database
USE ${DB_NAME};

-- Create virtual domains table
CREATE TABLE IF NOT EXISTS virtual_domains (
    id INT NOT NULL AUTO_INCREMENT,
    name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY name (name),
    KEY idx_domain_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Create virtual users table with enhanced fields
CREATE TABLE IF NOT EXISTS virtual_users (
    id INT NOT NULL AUTO_INCREMENT,
    domain_id INT NOT NULL,
    email VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    quota BIGINT DEFAULT 1073741824,
    enabled TINYINT(1) DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    PRIMARY KEY (id),
    UNIQUE KEY email (email),
    KEY idx_email (email),
    KEY idx_domain_id (domain_id),
    CONSTRAINT fk_users_domain 
        FOREIGN KEY (domain_id) REFERENCES virtual_domains(id) 
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Create virtual aliases table
CREATE TABLE IF NOT EXISTS virtual_aliases (
    id INT NOT NULL AUTO_INCREMENT,
    domain_id INT NOT NULL,
    source VARCHAR(255) NOT NULL,
    destination TEXT NOT NULL,
    enabled TINYINT(1) DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY source (source),
    KEY idx_source (source),
    KEY idx_destination (destination(100)),
    KEY idx_domain_id (domain_id),
    CONSTRAINT fk_aliases_domain 
        FOREIGN KEY (domain_id) REFERENCES virtual_domains(id) 
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Create recipient BCC table for compliance
CREATE TABLE IF NOT EXISTS recipient_bcc (
    id INT NOT NULL AUTO_INCREMENT,
    email VARCHAR(255) NOT NULL,
    bcc_email VARCHAR(255) NOT NULL,
    enabled TINYINT(1) DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY email (email),
    KEY idx_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Create sender BCC table for compliance
CREATE TABLE IF NOT EXISTS sender_bcc (
    id INT NOT NULL AUTO_INCREMENT,
    email VARCHAR(255) NOT NULL,
    bcc_email VARCHAR(255) NOT NULL,
    enabled TINYINT(1) DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY email (email),
    KEY idx_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Create mail log table for tracking
CREATE TABLE IF NOT EXISTS mail_log (
    id BIGINT NOT NULL AUTO_INCREMENT,
    message_id VARCHAR(255),
    sender VARCHAR(255),
    recipient VARCHAR(255),
    subject TEXT,
    status VARCHAR(50),
    relay_ip VARCHAR(45),
    size INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_created (created_at),
    KEY idx_sender (sender),
    KEY idx_recipient (recipient),
    KEY idx_status (status),
    KEY idx_message_id (message_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Create stored procedures for common operations
DELIMITER $$

-- Procedure to add a domain
CREATE PROCEDURE add_domain(IN domain_name VARCHAR(255))
BEGIN
    INSERT IGNORE INTO virtual_domains (name) VALUES (domain_name);
END$$

-- Procedure to add a user with secure password
CREATE PROCEDURE add_user(
    IN user_email VARCHAR(255),
    IN user_password VARCHAR(255),
    IN user_quota BIGINT
)
BEGIN
    DECLARE domain_name VARCHAR(255);
    DECLARE domain_id_val INT;
    
    -- Extract domain from email
    SET domain_name = SUBSTRING_INDEX(user_email, '@', -1);
    
    -- Ensure domain exists
    CALL add_domain(domain_name);
    
    -- Get domain ID
    SELECT id INTO domain_id_val FROM virtual_domains WHERE name = domain_name;
    
    -- Insert or update user
    INSERT INTO virtual_users (domain_id, email, password, quota)
    VALUES (domain_id_val, user_email, user_password, user_quota)
    ON DUPLICATE KEY UPDATE 
        password = VALUES(password),
        quota = VALUES(quota),
        updated_at = CURRENT_TIMESTAMP;
END$$

-- Procedure to add an alias
CREATE PROCEDURE add_alias(
    IN alias_source VARCHAR(255),
    IN alias_destination TEXT
)
BEGIN
    DECLARE domain_name VARCHAR(255);
    DECLARE domain_id_val INT;
    
    -- Extract domain from source
    SET domain_name = SUBSTRING_INDEX(alias_source, '@', -1);
    
    -- Ensure domain exists
    CALL add_domain(domain_name);
    
    -- Get domain ID
    SELECT id INTO domain_id_val FROM virtual_domains WHERE name = domain_name;
    
    -- Insert or update alias
    INSERT INTO virtual_aliases (domain_id, source, destination)
    VALUES (domain_id_val, alias_source, alias_destination)
    ON DUPLICATE KEY UPDATE 
        destination = VALUES(destination),
        updated_at = CURRENT_TIMESTAMP;
END$$

DELIMITER ;

-- Create indexes for performance
CREATE INDEX idx_users_enabled ON virtual_users(enabled);
CREATE INDEX idx_aliases_enabled ON virtual_aliases(enabled);
CREATE INDEX idx_log_date_sender ON mail_log(created_at, sender);
CREATE INDEX idx_log_date_recipient ON mail_log(created_at, recipient);

-- Drop user if exists and recreate
DROP USER IF EXISTS '${DB_USER}'@'localhost';
DROP USER IF EXISTS '${DB_USER}'@'127.0.0.1';
DROP USER IF EXISTS '${DB_USER}'@'%';

-- Create mail user with specific privileges
CREATE USER '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASSWORD}';
CREATE USER '${DB_USER}'@'127.0.0.1' IDENTIFIED BY '${DB_PASSWORD}';

-- Grant privileges
GRANT SELECT, INSERT, UPDATE, DELETE ON ${DB_NAME}.* TO '${DB_USER}'@'localhost';
GRANT SELECT, INSERT, UPDATE, DELETE ON ${DB_NAME}.* TO '${DB_USER}'@'127.0.0.1';
GRANT EXECUTE ON ${DB_NAME}.* TO '${DB_USER}'@'localhost';
GRANT EXECUTE ON ${DB_NAME}.* TO '${DB_USER}'@'127.0.0.1';

-- Flush privileges
FLUSH PRIVILEGES;
EOF
)
    
    # Execute the SQL script
    if execute_sql "$sql_script"; then
        print_message "✓ Database created successfully"
    else
        print_error "Failed to create database"
        return 1
    fi
    
    # Create MySQL configuration files for Postfix
    create_postfix_mysql_configs
    
    # Create MySQL configuration files for Dovecot
    create_dovecot_mysql_configs
    
    print_message "✓ MySQL setup completed"
    return 0
}

# Create Postfix MySQL configuration files
create_postfix_mysql_configs() {
    print_message "Creating Postfix MySQL configuration files..."
    
    # Virtual domains configuration
    cat > /etc/postfix/mysql-virtual-mailbox-domains.cf <<EOF
# Postfix MySQL configuration for virtual domains
user = ${DB_USER}
password = ${DB_PASSWORD}
hosts = ${DB_HOST}
port = ${DB_PORT}
dbname = ${DB_NAME}
query = SELECT 1 FROM virtual_domains WHERE name='%s' AND id > 0
EOF
    
    # Virtual mailboxes configuration
    cat > /etc/postfix/mysql-virtual-mailbox-maps.cf <<EOF
# Postfix MySQL configuration for virtual mailboxes
user = ${DB_USER}
password = ${DB_PASSWORD}
hosts = ${DB_HOST}
port = ${DB_PORT}
dbname = ${DB_NAME}
query = SELECT 1 FROM virtual_users WHERE email='%s' AND enabled = 1
EOF
    
    # Virtual aliases configuration
    cat > /etc/postfix/mysql-virtual-alias-maps.cf <<EOF
# Postfix MySQL configuration for virtual aliases
user = ${DB_USER}
password = ${DB_PASSWORD}
hosts = ${DB_HOST}
port = ${DB_PORT}
dbname = ${DB_NAME}
query = SELECT destination FROM virtual_aliases WHERE source='%s' AND enabled = 1
EOF
    
    # Email to email mapping (for catchall support)
    cat > /etc/postfix/mysql-email2email.cf <<EOF
# Postfix MySQL configuration for email to email mapping
user = ${DB_USER}
password = ${DB_PASSWORD}
hosts = ${DB_HOST}
port = ${DB_PORT}
dbname = ${DB_NAME}
query = SELECT email FROM virtual_users WHERE email='%s' AND enabled = 1
EOF
    
    # Recipient BCC configuration
    cat > /etc/postfix/mysql-recipient-bcc.cf <<EOF
# Postfix MySQL configuration for recipient BCC
user = ${DB_USER}
password = ${DB_PASSWORD}
hosts = ${DB_HOST}
port = ${DB_PORT}
dbname = ${DB_NAME}
query = SELECT bcc_email FROM recipient_bcc WHERE email='%s' AND enabled = 1
EOF
    
    # Sender BCC configuration
    cat > /etc/postfix/mysql-sender-bcc.cf <<EOF
# Postfix MySQL configuration for sender BCC
user = ${DB_USER}
password = ${DB_PASSWORD}
hosts = ${DB_HOST}
port = ${DB_PORT}
dbname = ${DB_NAME}
query = SELECT bcc_email FROM sender_bcc WHERE email='%s' AND enabled = 1
EOF
    
    # Set proper permissions
    chmod 640 /etc/postfix/mysql-*.cf
    chown root:postfix /etc/postfix/mysql-*.cf
    
    print_message "✓ Postfix MySQL configuration files created"
}

# Create Dovecot MySQL configuration files
create_dovecot_mysql_configs() {
    print_message "Creating Dovecot MySQL configuration files..."
    
    # Main Dovecot SQL configuration
    cat > /etc/dovecot/dovecot-sql.conf.ext <<EOF
# Dovecot SQL configuration
# Generated by Mail Server Installer

driver = mysql
connect = host=${DB_HOST} port=${DB_PORT} dbname=${DB_NAME} user=${DB_USER} password=${DB_PASSWORD}

# Password query
password_query = \\
    SELECT email as user, password, \\
    CONCAT('/var/vmail/', SUBSTRING_INDEX(email, '@', -1), '/', SUBSTRING_INDEX(email, '@', 1)) as userdb_home, \\
    5000 as userdb_uid, \\
    5000 as userdb_gid, \\
    CONCAT('*:bytes=', quota) as userdb_quota_rule \\
    FROM virtual_users \\
    WHERE email = '%u' AND enabled = 1

# User query
user_query = \\
    SELECT CONCAT('/var/vmail/', SUBSTRING_INDEX(email, '@', -1), '/', SUBSTRING_INDEX(email, '@', 1)) as home, \\
    5000 as uid, \\
    5000 as gid, \\
    CONCAT('*:bytes=', quota) as quota_rule \\
    FROM virtual_users \\
    WHERE email = '%u' AND enabled = 1

# Iterate query (for doveadm)
iterate_query = SELECT email as user FROM virtual_users WHERE enabled = 1

# Update last login time
# This requires Dovecot's last_login plugin
# post_login_query = UPDATE virtual_users SET last_login = NOW() WHERE email = '%u'
EOF
    
    # Set proper permissions
    chmod 600 /etc/dovecot/dovecot-sql.conf.ext
    chown root:dovecot /etc/dovecot/dovecot-sql.conf.ext
    
    print_message "✓ Dovecot MySQL configuration files created"
}

# Add a domain to the database using stored procedure
add_domain_to_mysql() {
    local domain=$1
    
    if [ -z "$domain" ]; then
        print_error "Domain not provided"
        return 1
    fi
    
    # Validate domain
    if ! validate_domain "$domain"; then
        return 1
    fi
    
    print_message "Adding domain $domain to database..."
    
    # Use stored procedure to add domain
    local sql="CALL add_domain('$domain');"
    
    if execute_sql "$sql" "$DB_NAME"; then
        print_message "✓ Domain $domain added successfully"
        
        # Add standard aliases for the domain
        add_standard_aliases "$domain"
        
        return 0
    else
        print_error "Failed to add domain $domain"
        return 1
    fi
}

# Add standard email aliases for a domain
add_standard_aliases() {
    local domain=$1
    local admin_email="${ADMIN_EMAIL:-root@localhost}"
    
    print_message "Adding standard aliases for $domain..."
    
    local aliases=(
        "postmaster@$domain:$admin_email"
        "abuse@$domain:$admin_email"
        "webmaster@$domain:$admin_email"
        "hostmaster@$domain:$admin_email"
        "admin@$domain:$admin_email"
        "noreply@$domain:$admin_email"
    )
    
    for alias_pair in "${aliases[@]}"; do
        local source="${alias_pair%:*}"
        local destination="${alias_pair#*:}"
        
        local sql="CALL add_alias('$source', '$destination');"
        execute_sql "$sql" "$DB_NAME" 2>/dev/null || true
    done
    
    print_message "✓ Standard aliases added"
}

# Add an email user to the database
add_email_user() {
    local email=$1
    local password=$2
    local quota=${3:-1073741824}  # Default 1GB quota
    
    if [ -z "$email" ] || [ -z "$password" ]; then
        print_error "Email or password not provided"
        return 1
    fi
    
    # Validate email
    if ! validate_email "$email"; then
        return 1
    fi
    
    print_message "Adding email user $email..."
    
    # Hash password using doveadm or fallback method
    local hashed_password=""
    
    if command -v doveadm &>/dev/null; then
        # Use doveadm for secure password hashing
        hashed_password=$(doveadm pw -s SHA512-CRYPT -p "$password" 2>/dev/null)
    elif command -v python3 &>/dev/null; then
        # Fallback to Python
        hashed_password=$(python3 -c "
import crypt
import random
import string
salt = '\$6\$' + ''.join(random.choices(string.ascii_letters + string.digits, k=16)) + '\$'
print(crypt.crypt('$password', salt))
" 2>/dev/null)
    else
        # Last resort: use SHA256 (less secure)
        hashed_password="{SHA256}$(echo -n "$password" | sha256sum | awk '{print $1}')"
        print_warning "Using basic SHA256 hashing (less secure). Install doveadm for better security."
    fi
    
    if [ -z "$hashed_password" ]; then
        print_error "Failed to hash password"
        return 1
    fi
    
    # Escape password for SQL
    hashed_password=$(echo "$hashed_password" | sed "s/'/\\\\'/g")
    
    # Use stored procedure to add user
    local sql="CALL add_user('$email', '$hashed_password', $quota);"
    
    if execute_sql "$sql" "$DB_NAME"; then
        print_message "✓ Email user $email added successfully"
        
        # Extract domain and ensure it exists
        local domain="${email#*@}"
        add_domain_to_mysql "$domain" 2>/dev/null || true
        
        return 0
    else
        print_error "Failed to add email user $email"
        return 1
    fi
}

# Setup Dovecot IMAP/POP3 server
setup_dovecot() {
    local domain=$1
    local hostname=$2
    
    print_header "Setting up Dovecot IMAP/POP3 Server"
    
    # Ensure Dovecot is installed
    if ! command -v dovecot &>/dev/null; then
        print_message "Installing Dovecot packages..."
        apt-get update
        apt-get install -y dovecot-core dovecot-imapd dovecot-pop3d dovecot-lmtpd \
                          dovecot-mysql dovecot-sieve dovecot-managesieved
    fi
    
    # Stop Dovecot during configuration
    systemctl stop dovecot 2>/dev/null || true
    
    # Create mail user and directories
    print_message "Creating mail user and directories..."
    
    # Create vmail user and group
    if ! id -u vmail &>/dev/null; then
        groupadd -g 5000 vmail
        useradd -u 5000 -g vmail -s /usr/sbin/nologin -d /var/vmail -m vmail
    fi
    
    # Create mail storage directory
    mkdir -p /var/vmail
    chown -R vmail:vmail /var/vmail
    chmod 770 /var/vmail
    
    # Configure Dovecot
    configure_dovecot_main "$domain" "$hostname"
    configure_dovecot_auth
    configure_dovecot_mail
    configure_dovecot_ssl "$hostname"
    configure_dovecot_master
    
    # Start and enable Dovecot
    systemctl start dovecot
    systemctl enable dovecot
    
    print_message "✓ Dovecot setup completed"
}

# Configure Dovecot main settings
configure_dovecot_main() {
    local domain=$1
    local hostname=$2
    
    cat > /etc/dovecot/dovecot.conf <<EOF
# Dovecot configuration
# Generated by Mail Server Installer

# Protocols
protocols = imap pop3 lmtp sieve

# Listen addresses
listen = *, ::

# Base directory
base_dir = /var/run/dovecot/

# Greeting
login_greeting = Mail Server Ready

# Shutdown clients
shutdown_clients = yes

# Enable auth debugging (disable in production)
auth_debug = no
auth_debug_passwords = no
mail_debug = no
verbose_ssl = no

# Include configuration files
!include conf.d/*.conf
!include_try local.conf
EOF
    
    print_message "✓ Dovecot main configuration created"
}

# Configure Dovecot authentication
configure_dovecot_auth() {
    cat > /etc/dovecot/conf.d/10-auth.conf <<EOF
# Authentication configuration

disable_plaintext_auth = yes
auth_mechanisms = plain login

# Use SQL for user database and passwords
!include auth-sql.conf.ext

# Authentication cache
auth_cache_size = 10M
auth_cache_ttl = 1 hour
auth_cache_negative_ttl = 1 hour
EOF
    
    cat > /etc/dovecot/conf.d/auth-sql.conf.ext <<EOF
# SQL authentication configuration

passdb {
  driver = sql
  args = /etc/dovecot/dovecot-sql.conf.ext
}

userdb {
  driver = sql
  args = /etc/dovecot/dovecot-sql.conf.ext
}
EOF
    
    print_message "✓ Dovecot authentication configured"
}

# Configure Dovecot mail settings
configure_dovecot_mail() {
    cat > /etc/dovecot/conf.d/10-mail.conf <<EOF
# Mail location and settings

mail_location = maildir:/var/vmail/%d/%n/Maildir
mail_uid = 5000
mail_gid = 5000
first_valid_uid = 5000
first_valid_gid = 5000
mail_privileged_group = vmail

# Mailbox configuration
namespace inbox {
  inbox = yes
  
  mailbox Drafts {
    special_use = \\Drafts
    auto = subscribe
  }
  mailbox Junk {
    special_use = \\Junk
    auto = subscribe
  }
  mailbox Sent {
    special_use = \\Sent
    auto = subscribe
  }
  mailbox Trash {
    special_use = \\Trash
    auto = subscribe
  }
  mailbox Archive {
    special_use = \\Archive
    auto = subscribe
  }
}

# Mail plugins
mail_plugins = \$mail_plugins quota
EOF
    
    print_message "✓ Dovecot mail settings configured"
}

# Configure Dovecot SSL
configure_dovecot_ssl() {
    local hostname=$1
    
    cat > /etc/dovecot/conf.d/10-ssl.conf <<EOF
# SSL configuration

ssl = required
ssl_cert = </etc/ssl/certs/ssl-cert-snakeoil.pem
ssl_key = </etc/ssl/private/ssl-cert-snakeoil.key

# SSL protocols and ciphers
ssl_min_protocol = TLSv1.2
ssl_cipher_list = ECDHE+AESGCM:ECDHE+RSA+AESGCM:ECDHE+RSA+SHA256:ECDHE+RSA+SHA384
ssl_prefer_server_ciphers = yes

# DH parameters
ssl_dh = </etc/dovecot/dh.pem
EOF
    
    # Generate DH parameters if not exists
    if [ ! -f /etc/dovecot/dh.pem ]; then
        print_message "Generating DH parameters (this may take a while)..."
        openssl dhparam -out /etc/dovecot/dh.pem 2048
    fi
    
    print_message "✓ Dovecot SSL configured"
}

# Configure Dovecot master process
configure_dovecot_master() {
    cat > /etc/dovecot/conf.d/10-master.conf <<EOF
# Master process configuration

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
    mode = 0660
    user = postfix
    group = postfix
  }
}

service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
  
  unix_listener auth-userdb {
    mode = 0660
    user = vmail
    group = vmail
  }
}

service auth-worker {
  user = vmail
}
EOF
    
    print_message "✓ Dovecot master process configured"
}

# Test database connection
test_database_connection() {
    print_message "Testing database connection..."
    
    if [ -f /root/.mail_db_password ]; then
        DB_PASSWORD=$(cat /root/.mail_db_password)
    fi
    
    if mysql -u "$DB_USER" -p"$DB_PASSWORD" -h "$DB_HOST" -P "$DB_PORT" \
           -e "SELECT 1;" "$DB_NAME" &>/dev/null; then
        print_message "✓ Database connection successful"
        return 0
    else
        print_error "Database connection failed"
        return 1
    fi
}

# Export functions
export -f check_mysql_service wait_for_mysql generate_secure_password
export -f execute_sql setup_mysql create_postfix_mysql_configs
export -f create_dovecot_mysql_configs add_domain_to_mysql
export -f add_standard_aliases add_email_user setup_dovecot
export -f configure_dovecot_main configure_dovecot_auth
export -f configure_dovecot_mail configure_dovecot_ssl
export -f configure_dovecot_master test_database_connection

# Export database variables
export DB_NAME DB_USER DB_PASSWORD DB_HOST DB_PORT
