#!/bin/bash

# =================================================================
# MYSQL AND DOVECOT CONFIGURATION MODULE
# Database setup, user authentication, and mail storage
# =================================================================

# Setup MySQL server for mail storage
setup_mysql() {
    print_header "Setting up MySQL Database Server"
    
    # Install MySQL server and client packages first
    print_message "Installing MySQL server and client packages..."
    apt-get update
    apt-get install -y mysql-server mysql-client
    
    # Now install postfix-mysql
    print_message "Installing postfix-mysql package..."
    apt-get install -y postfix-mysql
    
    # Make sure the postfix-mysql package is properly registered with Postfix
    print_message "Creating MySQL dynamic maps configuration for Postfix..."
    
    # First check if postfix-mysql is properly loaded
    postconf -m | grep -q mysql
    if [ $? -ne 0 ]; then
        print_warning "MySQL support not detected in Postfix, ensuring package is properly installed..."
        apt-get install --reinstall postfix-mysql
    fi
    
    # Create the directory if it doesn't exist
    mkdir -p /etc/postfix/dynamicmaps.cf.d
    
    # Check for duplicate mysql entries and remove them if found
    if [ -f /etc/postfix/dynamicmaps.cf.d/mysql ]; then
        print_message "Removing existing mysql dynamicmaps file to prevent duplicates..."
        rm -f /etc/postfix/dynamicmaps.cf.d/mysql
    fi
    
    # Create the MySQL dynamic maps configuration file with correct content
    cat > /etc/postfix/dynamicmaps.cf.d/mysql <<EOF
mysql   postfix-mysql.so.1.0.1   dict_mysql_open
EOF
    
    # Ensure dynamicmaps.cf is owned by root:root to avoid security warnings
    chown root:root /etc/postfix/dynamicmaps.cf.d/mysql
    chmod 644 /etc/postfix/dynamicmaps.cf.d/mysql
    
    # Also fix main dynamicmaps.cf file permissions
    if [ -f /etc/postfix/dynamicmaps.cf ]; then
        chown root:root /etc/postfix/dynamicmaps.cf
        chmod 644 /etc/postfix/dynamicmaps.cf
    fi
    
    # Create a secure random password for the mail user
    DB_PASSWORD=$(openssl rand -base64 32)
    
    print_message "Setting up MySQL database for mail server..."
    
    # Check if MySQL service is running
    if ! systemctl is-active --quiet mysql; then
        print_message "Starting MySQL service..."
        systemctl start mysql
        systemctl enable mysql
    fi
    
    # Create a secure temporary SQL file
    SQL_TMPFILE=$(mktemp)
    chmod 600 "$SQL_TMPFILE"
    
    # Prepare SQL commands to setup the database and permissions - Create tables first
    cat > "$SQL_TMPFILE" <<EOF
-- Create database if it doesn't exist
CREATE DATABASE IF NOT EXISTS mailserver CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Create tables if they don't exist
USE mailserver;

CREATE TABLE IF NOT EXISTS virtual_domains (
  id int NOT NULL auto_increment,
  name varchar(50) NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS virtual_users (
  id int NOT NULL auto_increment,
  domain_id int NOT NULL,
  password varchar(255) NOT NULL,
  email varchar(100) NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY email (email),
  FOREIGN KEY (domain_id) REFERENCES virtual_domains(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS virtual_aliases (
  id int NOT NULL auto_increment,
  domain_id int NOT NULL,
  source varchar(100) NOT NULL,
  destination varchar(100) NOT NULL,
  PRIMARY KEY (id),
  FOREIGN KEY (domain_id) REFERENCES virtual_domains(id) ON DELETE CASCADE,
  UNIQUE KEY source (source)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Create mail user with restricted permissions
CREATE USER IF NOT EXISTS 'mailuser'@'localhost' IDENTIFIED BY '$DB_PASSWORD';
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
        exit 1
    fi
    
    # Remove temporary SQL file
    rm -f "$SQL_TMPFILE"
    
    # Create MySQL configuration files for Postfix
    
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
    
    # Set proper permissions
    chmod 640 /etc/postfix/mysql-virtual-*.cf
    chown root:postfix /etc/postfix/mysql-virtual-*.cf
    
    # Save the database password for later use
    echo "$DB_PASSWORD" > /root/.mail_db_password
    chmod 600 /root/.mail_db_password
    
    print_message "MySQL setup for mail server completed"
    
    # Store DB variables for other functions
    export DB_PASSWORD
    
    # Fix root alias in /etc/aliases if needed
    if ! grep -q "^root:" /etc/aliases; then
        echo "root: $ADMIN_EMAIL" >> /etc/aliases
        newaliases
    fi
    
    # Verify mysql module is loaded
    if ! postconf -m | grep -q mysql; then
        print_error "MySQL module still not detected in Postfix after configuration"
        print_message "Attempting to fix by linking libraries..."
        
        # Check if the library exists
        POSTFIX_MYSQL_LIB=$(find /usr/lib -name "dict_mysql.so*" | head -1)
        if [ -n "$POSTFIX_MYSQL_LIB" ]; then
            print_message "Found MySQL library at $POSTFIX_MYSQL_LIB"
            # Update dynamicmaps.cf with correct path
            echo "mysql   $POSTFIX_MYSQL_LIB   dict_mysql_open" > /etc/postfix/dynamicmaps.cf.d/mysql
            chmod 644 /etc/postfix/dynamicmaps.cf.d/mysql
            chown root:root /etc/postfix/dynamicmaps.cf.d/mysql
        else
            print_error "Could not find MySQL library for Postfix"
            print_message "Installing dependencies and trying again..."
            apt-get install -y libsasl2-modules postfix-mysql
        fi
    fi
    
    # Restart Postfix
    systemctl restart postfix
}

# Add a domain to the MySQL database
add_domain_to_mysql() {
    local domain=$1
    local SQL_TMPFILE=$(mktemp)
    chmod 600 "$SQL_TMPFILE"
    
    print_message "Adding domain $domain to MySQL database..."
    
    cat > "$SQL_TMPFILE" <<EOF
USE mailserver;
INSERT INTO virtual_domains (name) VALUES ('$domain') ON DUPLICATE KEY UPDATE name=name;

-- Get the domain ID for the added domain
SET @domain_id = (SELECT id FROM virtual_domains WHERE name='$domain');

-- Ensure the postmaster alias exists for this domain
INSERT INTO virtual_aliases (domain_id, source, destination) 
VALUES (@domain_id, 'postmaster@$domain', 'root@localhost')
ON DUPLICATE KEY UPDATE destination='root@localhost';
EOF
    
    if mysql -u root < "$SQL_TMPFILE"; then
        print_message "Domain $domain added successfully to MySQL database"
    else
        print_error "Failed to add domain $domain to MySQL database"
    fi
    
    rm -f "$SQL_TMPFILE"
}

# Add an email user to the MySQL database
add_email_user() {
    local email=$1
    local password=$2
    local domain=$(echo "$email" | cut -d '@' -f 2)
    local username=$(echo "$email" | cut -d '@' -f 1)
    local SQL_TMPFILE=$(mktemp)
    chmod 600 "$SQL_TMPFILE"
    
    # Generate salted SHA512 password hash
    local hashed_password=$(doveadm pw -s SHA512-CRYPT -p "$password")
    
    print_message "Adding email user $email to MySQL database..."
    
    cat > "$SQL_TMPFILE" <<EOF
USE mailserver;
SET @domain_id = (SELECT id FROM virtual_domains WHERE name='$domain');
INSERT INTO virtual_users (domain_id, email, password)
VALUES (@domain_id, '$email', '$hashed_password')
ON DUPLICATE KEY UPDATE password='$hashed_password';
EOF
    
    if mysql -u root < "$SQL_TMPFILE"; then
        print_message "Email user $email added successfully to MySQL database"
    else
        print_error "Failed to add email user $email to MySQL database"
    fi
    
    rm -f "$SQL_TMPFILE"
}

# Setup Dovecot for IMAP/POP3 with MySQL authentication
setup_dovecot() {
    local domain=$1
    local hostname=$2
    
    print_header "Setting up Dovecot IMAP/POP3 Server"
    
    print_message "Installing Dovecot packages..."
    apt-get update
    apt-get install -y dovecot-core dovecot-imapd dovecot-pop3d dovecot-lmtpd dovecot-mysql dovecot-sieve dovecot-managesieved
    
    # Stop Dovecot during configuration
    systemctl stop dovecot
    
    # Create mail user and group
    print_message "Setting up mail user and directory..."
    groupadd -g 5000 vmail 2>/dev/null || true
    useradd -g vmail -u 5000 vmail -d /var/vmail -m 2>/dev/null || true
    
    # Create mail directories
    mkdir -p /var/vmail
    chmod 770 /var/vmail
    chown -R vmail:vmail /var/vmail
    
    # Backup original configuration
    backup_config "dovecot" "/etc/dovecot/dovecot.conf"
    backup_config "dovecot" "/etc/dovecot/conf.d/10-mail.conf"
    backup_config "dovecot" "/etc/dovecot/conf.d/10-auth.conf"
    backup_config "dovecot" "/etc/dovecot/conf.d/auth-sql.conf.ext"
    backup_config "dovecot" "/etc/dovecot/dovecot-sql.conf.ext"
    
    # Configure Dovecot main settings
    cat > /etc/dovecot/dovecot.conf <<EOF
# Dovecot configuration
# Generated by Mail Server Installer

# Protocols we want to be serving
protocols = imap pop3 lmtp

# Listen on all interfaces
listen = *

# User/group for running the server
first_valid_uid = 5000
first_valid_gid = 5000

# Mail location
mail_location = maildir:/var/vmail/%d/%n

# Include all the other configuration files
!include conf.d/*.conf

# Include mail server specific configuration
!include_try local.conf
EOF
    
    # Configure mail settings
    cat > /etc/dovecot/conf.d/10-mail.conf <<EOF
# Mail configuration
# Generated by Mail Server Installer

# Mailbox locations and namespaces
mail_location = maildir:/var/vmail/%d/%n
mail_privileged_group = vmail

# Mailbox settings
mailbox_list_index = yes
mailbox_idle_check_interval = 30 secs

# Maildir settings
maildir_stat_dirs = yes

namespace inbox {
  inbox = yes
  separator = /
  mailbox Drafts {
    special_use = \Drafts
    auto = subscribe
  }
  mailbox Junk {
    special_use = \Junk
    auto = subscribe
  }
  mailbox Sent {
    special_use = \Sent
    auto = subscribe
  }
  mailbox Trash {
    special_use = \Trash
    auto = subscribe
  }
  mailbox Archive {
    special_use = \Archive
    auto = subscribe
  }
}
EOF
    
    # Configure authentication - FIXED: Removed password_scheme from here
    cat > /etc/dovecot/conf.d/10-auth.conf <<EOF
# Authentication configuration
# Generated by Mail Server Installer

# Authentication mechanisms
auth_mechanisms = plain login

# Disable plaintext authentication
disable_plaintext_auth = yes

# Auth master process
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
}

# User database
userdb {
  driver = static
  args = uid=vmail gid=vmail home=/var/vmail/%d/%n
}

# Password database
passdb {
  driver = sql
  args = /etc/dovecot/dovecot-sql.conf.ext
}

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
    
    # Configure SQL connection - FIXED: Added default_pass_scheme here
    cat > /etc/dovecot/dovecot-sql.conf.ext <<EOF
# SQL connection configuration
# Generated by Mail Server Installer

driver = mysql
connect = host=127.0.0.1 dbname=mailserver user=mailuser password=$DB_PASSWORD
default_pass_scheme = SHA512-CRYPT

# Get user's password
password_query = SELECT email as user, password FROM virtual_users WHERE email='%u';

# Get user's home directory
user_query = SELECT concat('/var/vmail/', substring_index('%u', '@', -1), '/', substring_index('%u', '@', 1)) as home, 5000 AS uid, 5000 AS gid FROM virtual_users WHERE email='%u';
EOF
    
    # Set proper permissions
    chown -R root:root /etc/dovecot
    chmod -R o-rwx /etc/dovecot
    
    # Configure SSL settings - skip certificate reference if files don't exist yet
    cat > /etc/dovecot/conf.d/10-ssl.conf <<EOF
# SSL configuration
# Generated by Mail Server Installer

ssl = required
ssl_prefer_server_ciphers = yes
ssl_min_protocol = TLSv1.2

# SSL certificates will be configured after they're obtained
# For now, use snakeoil certificates
ssl_cert = </etc/ssl/certs/ssl-cert-snakeoil.pem
ssl_key = </etc/ssl/private/ssl-cert-snakeoil.key
EOF
    
    # Generate DH parameters (this might take some time)
    print_message "Generating DH parameters for SSL (this may take a few minutes)..."
    openssl dhparam -out /etc/dovecot/dh.pem 2048
    
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
}
EOF
    
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
    
    # Restart Postfix to apply changes
    systemctl restart postfix
    
    print_message "Dovecot integration with Postfix completed"
}

# Setup email aliases
setup_email_aliases() {
    print_message "Setting up email aliases..."
    
    # Backup existing aliases file
    if [ -f /etc/aliases ]; then
        cp /etc/aliases /etc/aliases.bak
    fi
    
    # Create basic aliases
    cat > /etc/aliases <<EOF
# Basic system aliases
mailer-daemon: postmaster
postmaster: root
nobody: root
hostmaster: root
usenet: root
news: root
webmaster: root
www: root
ftp: root
abuse: root
noc: root
security: root
root: $ADMIN_EMAIL
EOF
    
    # Ensure correct permissions before running newaliases
    if [ -f /etc/postfix/dynamicmaps.cf ]; then
        chown root:root /etc/postfix/dynamicmaps.cf
        chmod 644 /etc/postfix/dynamicmaps.cf
    fi
    
    if [ -f /etc/postfix/dynamicmaps.cf.d/mysql ]; then
        chown root:root /etc/postfix/dynamicmaps.cf.d/mysql
        chmod 644 /etc/postfix/dynamicmaps.cf.d/mysql
    fi
    
    # Update the aliases database
    newaliases
    
    print_message "Email aliases setup completed"
}

export -f setup_mysql add_domain_to_mysql add_email_user setup_dovecot setup_email_aliases
