#!/bin/bash

# =================================================================
# MYSQL AND DOVECOT CONFIGURATION MODULE - COMPLETE FIXED VERSION
# Database setup, user authentication, and mail storage
# Fixed: Complete implementations, proper MySQL handling, no duplicate warnings
# =================================================================

# Setup MySQL server for mail storage with proper duplicate handling
setup_mysql() {
    print_header "Setting up MySQL Database Server"
    
    # Install MySQL server and client packages first
    print_message "Installing MySQL server and client packages..."
    apt-get update
    apt-get install -y mysql-server mysql-client
    
    # Now install postfix-mysql
    print_message "Installing postfix-mysql package..."
    apt-get install -y postfix-mysql
    
    # Clean up any existing MySQL dynamic maps to prevent duplicates
    print_message "Cleaning up MySQL dynamic maps configuration..."
    
    # Remove all existing mysql dynamicmaps files
    rm -f /etc/postfix/dynamicmaps.cf.d/mysql* 2>/dev/null
    rm -f /etc/postfix/dynamicmaps.cf.d/*mysql* 2>/dev/null
    
    # Clean the main dynamicmaps file
    if [ -f /etc/postfix/dynamicmaps.cf ]; then
        grep -v "mysql" /etc/postfix/dynamicmaps.cf > /tmp/dynamicmaps.cf.clean 2>/dev/null || true
        if [ -s /tmp/dynamicmaps.cf.clean ]; then
            mv /tmp/dynamicmaps.cf.clean /etc/postfix/dynamicmaps.cf
        fi
    fi
    
    # Clear all cache databases
    rm -f /var/lib/postfix/dynamicmaps.cf.db 2>/dev/null
    rm -f /var/spool/postfix/etc/dynamicmaps.cf.db 2>/dev/null
    rm -f /etc/postfix/dynamicmaps.cf.db 2>/dev/null
    
    # Create the directory if it doesn't exist
    mkdir -p /etc/postfix/dynamicmaps.cf.d
    
    # Find the correct MySQL library path
    local mysql_lib=""
    local possible_paths=(
        "/usr/lib/postfix/postfix-mysql.so"
        "/usr/lib/postfix/dict_mysql.so"
        "/usr/lib/x86_64-linux-gnu/postfix/dict_mysql.so"
        "/usr/lib/postfix/postfix-mysql.so.1.0.1"
    )
    
    for path in "${possible_paths[@]}"; do
        if [ -f "$path" ]; then
            mysql_lib="$path"
            print_message "Found MySQL library at: $mysql_lib"
            break
        fi
    done
    
    if [ -z "$mysql_lib" ]; then
        print_warning "Could not find MySQL library, using default path"
        mysql_lib="postfix-mysql.so.1.0.1"
    fi
    
    # Create a single MySQL dynamic maps configuration file
    cat > /etc/postfix/dynamicmaps.cf.d/50-mysql.cf <<EOF
# MySQL support for Postfix
mysql	${mysql_lib}	dict_mysql_open
EOF
    
    # Ensure proper ownership and permissions
    chown root:root /etc/postfix/dynamicmaps.cf.d/50-mysql.cf
    chmod 644 /etc/postfix/dynamicmaps.cf.d/50-mysql.cf
    
    # Also fix main dynamicmaps.cf file permissions
    if [ -f /etc/postfix/dynamicmaps.cf ]; then
        chown root:root /etc/postfix/dynamicmaps.cf
        chmod 644 /etc/postfix/dynamicmaps.cf
    fi
    
    # Create a secure random password for the mail user
    DB_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
    
    print_message "Setting up MySQL database for mail server..."
    
    # Check if MySQL service is running
    if ! systemctl is-active --quiet mysql; then
        print_message "Starting MySQL service..."
        systemctl start mysql
        systemctl enable mysql
        sleep 2
    fi
    
    # Wait for MySQL to be ready
    print_message "Waiting for MySQL to be ready..."
    for i in {1..30}; do
        if mysqladmin ping &>/dev/null; then
            print_message "MySQL is ready"
            break
        fi
        if [ $i -eq 30 ]; then
            print_error "MySQL failed to start within 30 seconds"
            return 1
        fi
        sleep 1
    done
    
    # Create a secure temporary SQL file
    SQL_TMPFILE=$(mktemp)
    chmod 600 "$SQL_TMPFILE"
    
    # Prepare SQL commands to setup the database and permissions
    cat > "$SQL_TMPFILE" <<EOF
-- Create database if it doesn't exist
CREATE DATABASE IF NOT EXISTS mailserver CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Create tables if they don't exist
USE mailserver;

CREATE TABLE IF NOT EXISTS virtual_domains (
  id int NOT NULL auto_increment,
  name varchar(50) NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY name (name),
  KEY idx_domain_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS virtual_users (
  id int NOT NULL auto_increment,
  domain_id int NOT NULL,
  password varchar(255) NOT NULL,
  email varchar(100) NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY email (email),
  KEY idx_email (email),
  KEY idx_domain_id (domain_id),
  FOREIGN KEY (domain_id) REFERENCES virtual_domains(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS virtual_aliases (
  id int NOT NULL auto_increment,
  domain_id int NOT NULL,
  source varchar(100) NOT NULL,
  destination varchar(100) NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY source (source),
  KEY idx_source (source),
  KEY idx_destination (destination),
  KEY idx_domain_id (domain_id),
  FOREIGN KEY (domain_id) REFERENCES virtual_domains(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Drop user if exists to avoid errors
DROP USER IF EXISTS 'mailuser'@'localhost';

-- Create mail user with restricted permissions
CREATE USER 'mailuser'@'localhost' IDENTIFIED BY '$DB_PASSWORD';
GRANT SELECT ON mailserver.* TO 'mailuser'@'localhost';
GRANT SELECT, INSERT, UPDATE, DELETE ON mailserver.virtual_domains TO 'mailuser'@'localhost';
GRANT SELECT, INSERT, UPDATE, DELETE ON mailserver.virtual_users TO 'mailuser'@'localhost';
GRANT SELECT, INSERT, UPDATE, DELETE ON mailserver.virtual_aliases TO 'mailuser'@'localhost';

FLUSH PRIVILEGES;
EOF
    
    # Execute the SQL commands
    if mysql -u root < "$SQL_TMPFILE"; then
        print_message "MySQL database 'mailserver' created successfully"
    else
        print_error "Failed to create MySQL database"
        cat "$SQL_TMPFILE" # Show SQL for debugging
        rm -f "$SQL_TMPFILE"
        return 1
    fi
    
    # Remove temporary SQL file
    rm -f "$SQL_TMPFILE"
    
    # Create MySQL configuration files for Postfix
    print_message "Creating MySQL configuration files for Postfix..."
    
    # Virtual domains configuration
    cat > /etc/postfix/mysql-virtual-mailbox-domains.cf <<EOF
user = mailuser
password = $DB_PASSWORD
hosts = 127.0.0.1
dbname = mailserver
query = SELECT 1 FROM virtual_domains WHERE name='%s'
EOF
    
    # Virtual mailboxes configuration
    cat > /etc/postfix/mysql-virtual-mailbox-maps.cf <<EOF
user = mailuser
password = $DB_PASSWORD
hosts = 127.0.0.1
dbname = mailserver
query = SELECT 1 FROM virtual_users WHERE email='%s'
EOF
    
    # Virtual aliases configuration
    cat > /etc/postfix/mysql-virtual-alias-maps.cf <<EOF
user = mailuser
password = $DB_PASSWORD
hosts = 127.0.0.1
dbname = mailserver
query = SELECT destination FROM virtual_aliases WHERE source='%s'
EOF
    
    # Set proper permissions for security
    chmod 640 /etc/postfix/mysql-virtual-*.cf
    chown root:postfix /etc/postfix/mysql-virtual-*.cf
    
    # Save the database password securely
    echo "$DB_PASSWORD" > /root/.mail_db_password
    chmod 600 /root/.mail_db_password
    chown root:root /root/.mail_db_password
    
    print_message "MySQL setup for mail server completed"
    
    # Store DB variables for other functions
    export DB_PASSWORD
    
    # Fix root alias in /etc/aliases if needed
    if ! grep -q "^root:" /etc/aliases 2>/dev/null; then
        if [ ! -z "$ADMIN_EMAIL" ]; then
            echo "root: $ADMIN_EMAIL" >> /etc/aliases
            newaliases 2>/dev/null || true
        fi
    fi
    
    # Verify mysql module is loaded
    if ! postconf -m 2>/dev/null | grep -q mysql; then
        print_warning "MySQL module not detected in Postfix, attempting to reload..."
        postfix reload 2>/dev/null || true
    fi
    
    print_message "MySQL configuration completed successfully"
    return 0
}

# Add a domain to the MySQL database with proper error handling
add_domain_to_mysql() {
    local domain=$1
    
    if [ -z "$domain" ]; then
        print_error "Domain not provided to add_domain_to_mysql"
        return 1
    fi
    
    # Ensure DB_PASSWORD is available
    if [ -z "$DB_PASSWORD" ] && [ -f /root/.mail_db_password ]; then
        DB_PASSWORD=$(cat /root/.mail_db_password)
    fi
    
    if [ -z "$DB_PASSWORD" ]; then
        print_error "Database password not found"
        return 1
    fi
    
    local SQL_TMPFILE=$(mktemp)
    chmod 600 "$SQL_TMPFILE"
    
    print_message "Adding domain $domain to MySQL database..."
    
    # Escape domain for SQL
    domain_escaped=$(echo "$domain" | sed "s/'/\\\\'/g")
    
    cat > "$SQL_TMPFILE" <<EOF
USE mailserver;

-- Insert domain, ignore if already exists
INSERT INTO virtual_domains (name) VALUES ('$domain_escaped') 
ON DUPLICATE KEY UPDATE name=name;

-- Get the domain ID for the added domain
SET @domain_id = (SELECT id FROM virtual_domains WHERE name='$domain_escaped');

-- Ensure the postmaster alias exists for this domain
INSERT INTO virtual_aliases (domain_id, source, destination) 
VALUES (@domain_id, 'postmaster@$domain_escaped', 'root@localhost')
ON DUPLICATE KEY UPDATE destination='root@localhost';

-- Add abuse and webmaster aliases
INSERT INTO virtual_aliases (domain_id, source, destination) 
VALUES (@domain_id, 'abuse@$domain_escaped', 'root@localhost')
ON DUPLICATE KEY UPDATE destination='root@localhost';

INSERT INTO virtual_aliases (domain_id, source, destination) 
VALUES (@domain_id, 'webmaster@$domain_escaped', 'root@localhost')
ON DUPLICATE KEY UPDATE destination='root@localhost';
EOF
    
    if mysql -u root < "$SQL_TMPFILE" 2>/dev/null; then
        print_message "Domain $domain added successfully to MySQL database"
    else
        print_error "Failed to add domain $domain to MySQL database"
        cat "$SQL_TMPFILE" # Show SQL for debugging
        rm -f "$SQL_TMPFILE"
        return 1
    fi
    
    rm -f "$SQL_TMPFILE"
    return 0
}

# Add an email user to the MySQL database with validation
add_email_user() {
    local email=$1
    local password=$2
    
    if [ -z "$email" ] || [ -z "$password" ]; then
        print_error "Email or password not provided to add_email_user"
        return 1
    fi
    
    local domain=$(echo "$email" | cut -d '@' -f 2)
    local username=$(echo "$email" | cut -d '@' -f 1)
    
    # Validate email format
    if [[ ! "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        print_error "Invalid email format: $email"
        return 1
    fi
    
    # Ensure DB_PASSWORD is available
    if [ -z "$DB_PASSWORD" ] && [ -f /root/.mail_db_password ]; then
        DB_PASSWORD=$(cat /root/.mail_db_password)
    fi
    
    if [ -z "$DB_PASSWORD" ]; then
        print_error "Database password not found"
        return 1
    fi
    
    local SQL_TMPFILE=$(mktemp)
    chmod 600 "$SQL_TMPFILE"
    
    # Generate salted SHA512 password hash
    local hashed_password=""
    if command -v doveadm &> /dev/null; then
        hashed_password=$(doveadm pw -s SHA512-CRYPT -p "$password" 2>/dev/null)
    fi
    
    # If doveadm is not available yet, use alternative method
    if [ -z "$hashed_password" ]; then
        print_warning "Doveadm not available, using alternative password hashing"
        # Use Python as fallback for password hashing
        if command -v python3 &> /dev/null; then
            hashed_password=$(python3 -c "
import crypt, getpass, pwd, random, string
salt = '\$6\$' + ''.join(random.choices(string.ascii_letters + string.digits, k=16)) + '\$'
print(crypt.crypt('$password', salt))
" 2>/dev/null)
        else
            # Use simple SHA256 as last resort (less secure)
            hashed_password=$(echo -n "$password" | sha256sum | cut -d' ' -f1)
            print_warning "Using simple SHA256 hash (less secure). Install python3 or dovecot for better security."
        fi
    fi
    
    print_message "Adding email user $email to MySQL database..."
    
    # Escape values for SQL
    email_escaped=$(echo "$email" | sed "s/'/\\\\'/g")
    domain_escaped=$(echo "$domain" | sed "s/'/\\\\'/g")
    hashed_password_escaped=$(echo "$hashed_password" | sed "s/'/\\\\'/g")
    
    cat > "$SQL_TMPFILE" <<EOF
USE mailserver;

-- Ensure domain exists
INSERT INTO virtual_domains (name) VALUES ('$domain_escaped')
ON DUPLICATE KEY UPDATE name=name;

-- Get domain ID
SET @domain_id = (SELECT id FROM virtual_domains WHERE name='$domain_escaped');

-- Insert user with pre-hashed password
INSERT INTO virtual_users (domain_id, email, password)
VALUES (@domain_id, '$email_escaped', '$hashed_password_escaped')
ON DUPLICATE KEY UPDATE password='$hashed_password_escaped';
EOF
    
    if mysql -u root < "$SQL_TMPFILE" 2>/dev/null; then
        print_message "Email user $email added successfully to MySQL database"
    else
        print_error "Failed to add email user $email to MySQL database"
        cat "$SQL_TMPFILE" # Show SQL for debugging
        rm -f "$SQL_TMPFILE"
        return 1
    fi
    
    rm -f "$SQL_TMPFILE"
    return 0
}

# Setup Dovecot for IMAP/POP3 with MySQL authentication
setup_dovecot() {
    local domain=$1
    local hostname=$2
    
    if [ -z "$domain" ] || [ -z "$hostname" ]; then
        print_error "Domain or hostname not provided to setup_dovecot"
        return 1
    fi
    
    print_header "Setting up Dovecot IMAP/POP3 Server"
    
    # Ensure DB_PASSWORD is available
    if [ -z "$DB_PASSWORD" ] && [ -f /root/.mail_db_password ]; then
        DB_PASSWORD=$(cat /root/.mail_db_password)
    fi
    
    if [ -z "$DB_PASSWORD" ]; then
        print_error "Database password not found for Dovecot configuration"
        return 1
    fi
    
    print_message "Installing Dovecot packages..."
    apt-get update
    apt-get install -y dovecot-core dovecot-imapd dovecot-pop3d dovecot-lmtpd dovecot-mysql dovecot-sieve dovecot-managesieved
    
    # Stop Dovecot during configuration
    systemctl stop dovecot 2>/dev/null || true
    
    # Create mail user and group
    print_message "Setting up mail user and directory..."
    groupadd -g 5000 vmail 2>/dev/null || true
    useradd -g vmail -u 5000 vmail -d /var/vmail -m 2>/dev/null || true
    
    # Create mail directories
    mkdir -p /var/vmail
    chmod 770 /var/vmail
    chown -R vmail:vmail /var/vmail
    
    # Backup original configuration
    for config_file in dovecot.conf conf.d/10-mail.conf conf.d/10-auth.conf conf.d/auth-sql.conf.ext dovecot-sql.conf.ext; do
        if [ -f "/etc/dovecot/$config_file" ]; then
            cp "/etc/dovecot/$config_file" "/etc/dovecot/${config_file}.backup.$(date +%Y%m%d)" 2>/dev/null || true
        fi
    done
    
    # Configure Dovecot main settings
    cat > /etc/dovecot/dovecot.conf <<EOF
# Dovecot configuration
# Generated by Mail Server Installer

# Protocols we want to be serving
protocols = imap pop3 lmtp

# Listen on all interfaces
listen = *, ::

# Base directory
base_dir = /var/run/dovecot/

# Greeting message
login_greeting = Mail Server Ready

# Include all the other configuration files
!include conf.d/*.conf

# Include mail server specific configuration
!include_try local.conf
EOF
    
    # Configure mail settings
    cat > /etc/dovecot/conf.d/10-mail.conf <<EOF
# Mail configuration
# Generated by Mail Server Installer

# Mail location
mail_location = maildir:/var/vmail/%d/%n
mail_privileged_group = vmail
first_valid_uid = 5000
first_valid_gid = 5000

# Mailbox settings
mailbox_list_index = yes
mailbox_idle_check_interval = 30 secs

# Maildir settings
maildir_stat_dirs = yes

# Mail processes
mail_max_userip_connections = 50

namespace inbox {
  inbox = yes
  separator = /
  
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
  mailbox "Sent Messages" {
    special_use = \\Sent
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
EOF
    
    # Configure authentication
    cat > /etc/dovecot/conf.d/10-auth.conf <<EOF
# Authentication configuration
# Generated by Mail Server Installer

# Disable LOGIN if not using SSL/TLS
disable_plaintext_auth = yes

# Authentication mechanisms
auth_mechanisms = plain login

# Authentication cache
auth_cache_size = 10M
auth_cache_ttl = 1 hour
auth_cache_negative_ttl = 1 hour

# User database configuration
userdb {
  driver = static
  args = uid=vmail gid=vmail home=/var/vmail/%d/%n allow_all_users=yes
}

# Password database configuration
passdb {
  driver = sql
  args = /etc/dovecot/dovecot-sql.conf.ext
}

# Auth services
service auth {
  unix_listener auth-userdb {
    mode = 0600
    user = vmail
    group = vmail
  }
  
  # Postfix smtp-auth
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
  
  # Auth process settings
  user = dovecot
}

service auth-worker {
  user = vmail
}

# Include SQL configuration
!include auth-sql.conf.ext
EOF
    
    # Configure SQL authentication
    cat > /etc/dovecot/conf.d/auth-sql.conf.ext <<EOF
# SQL authentication configuration
# Generated by Mail Server Installer

passdb {
  driver = sql
  args = /etc/dovecot/dovecot-sql.conf.ext
}

userdb {
  driver = static
  args = uid=vmail gid=vmail home=/var/vmail/%d/%n
}
EOF
    
    # Configure SQL connection with proper escaping
    cat > /etc/dovecot/dovecot-sql.conf.ext <<EOF
# SQL connection configuration
# Generated by Mail Server Installer

driver = mysql
connect = host=127.0.0.1 dbname=mailserver user=mailuser password=$DB_PASSWORD
default_pass_scheme = SHA512-CRYPT

# Password query
password_query = \\
  SELECT email as user, password \\
  FROM virtual_users WHERE email='%u';

# User query
user_query = \\
  SELECT concat('/var/vmail/', substring_index('%u', '@', -1), '/', substring_index('%u', '@', 1)) as home, \\
  5000 AS uid, \\
  5000 AS gid \\
  FROM virtual_users WHERE email='%u';

# Iterate query (for doveadm)
iterate_query = SELECT email as user FROM virtual_users;
EOF
    
    # Set proper permissions
    chown -R root:root /etc/dovecot
    chmod -R o-rwx /etc/dovecot
    chmod 640 /etc/dovecot/dovecot-sql.conf.ext
    chown root:dovecot /etc/dovecot/dovecot-sql.conf.ext
    
    # Configure SSL settings
    cat > /etc/dovecot/conf.d/10-ssl.conf <<EOF
# SSL configuration
# Generated by Mail Server Installer

ssl = required
ssl_prefer_server_ciphers = yes
ssl_min_protocol = TLSv1.2

# SSL ciphers
ssl_cipher_list = ECDHE+AESGCM:ECDHE+RSA+AESGCM:ECDHE+RSA+SHA256:ECDHE+RSA+SHA384

# DH parameters
ssl_dh = </etc/dovecot/dh.pem

# SSL certificates (will be updated after Let's Encrypt setup)
ssl_cert = </etc/ssl/certs/ssl-cert-snakeoil.pem
ssl_key = </etc/ssl/private/ssl-cert-snakeoil.key
EOF
    
    # Generate DH parameters if they don't exist
    if [ ! -f /etc/dovecot/dh.pem ]; then
        print_message "Generating DH parameters for SSL (this may take a few minutes)..."
        openssl dhparam -out /etc/dovecot/dh.pem 2048
    fi
    
    # Configure master process
    cat > /etc/dovecot/conf.d/10-master.conf <<EOF
# Master process configuration
# Generated by Mail Server Installer

service imap-login {
  inet_listener imap {
    port = 143
  }
  inet_listener imaps {
    port = 993
    ssl = yes
  }
  service_count = 1
  process_min_avail = 4
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

service imap {
  process_limit = 1024
}

service pop3 {
  process_limit = 1024
}

service auth {
  unix_listener auth-userdb {
    mode = 0600
    user = vmail
    group = vmail
  }
  
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
  
  user = dovecot
}

service auth-worker {
  user = vmail
}

service dict {
  unix_listener dict {
    mode = 0600
    user = vmail
  }
}
EOF
    
    # Configure logging
    cat > /etc/dovecot/conf.d/10-logging.conf <<EOF
# Logging configuration
# Generated by Mail Server Installer

log_path = /var/log/dovecot.log
info_log_path = /var/log/dovecot-info.log
debug_log_path = /var/log/dovecot-debug.log

# Log format
log_timestamp = "%Y-%m-%d %H:%M:%S "

# Authentication logging
auth_verbose = no
auth_verbose_passwords = no
auth_debug = no
auth_debug_passwords = no

# Mail logging
mail_debug = no
verbose_ssl = no
EOF
    
    # Create log files with proper permissions
    touch /var/log/dovecot.log /var/log/dovecot-info.log /var/log/dovecot-debug.log
    chown syslog:adm /var/log/dovecot*.log
    chmod 640 /var/log/dovecot*.log
    
    # Start and enable Dovecot
    systemctl start dovecot
    systemctl enable dovecot
    
    print_message "Dovecot setup completed"
    
    # Configure Postfix to work with Dovecot
    print_message "Configuring Postfix to work with Dovecot..."
    
    postconf -e "virtual_transport = lmtp:unix:private/dovecot-lmtp"
    postconf -e "mailbox_transport = lmtp:unix:private/dovecot-lmtp"
    postconf -e "smtpd_sasl_type = dovecot"
    postconf -e "smtpd_sasl_path = private/auth"
    postconf -e "smtpd_sasl_auth_enable = yes"
    postconf -e "smtpd_sasl_security_options = noanonymous"
    postconf -e "smtpd_sasl_local_domain = $domain"
    postconf -e "smtpd_tls_auth_only = yes"
    
    print_message "Dovecot integration with Postfix completed"
    return 0
}

# Export functions to make them available to other scripts
export -f setup_mysql add_domain_to_mysql add_email_user setup_dovecot
