#!/bin/bash

# =================================================================
# MYSQL AND DOVECOT SETUP MODULE
# Database setup and mail storage configuration
# =================================================================

# Setup MySQL for mail server
setup_mysql() {
    print_header "Setting up MySQL Database"

    # Install MySQL if not present
    if ! command -v mysql >/dev/null 2>&1; then
        print_message "Installing MySQL server..."
        apt-get update
        apt-get install -y mysql-server mysql-client
    fi

    # Install postfix-mysql package - CRITICAL for MySQL map support
    print_message "Installing postfix-mysql package..."
    apt-get install -y postfix-mysql

    # Verify postfix-mysql is properly installed
    if ! dpkg -l | grep -q postfix-mysql; then
        print_error "Failed to install postfix-mysql package. This is required for MySQL integration."
        exit 1
    fi

    # Check if dynamicmaps.cf contains mysql entry
    if ! grep -q "mysql" /etc/postfix/dynamicmaps.cf; then
        print_warning "MySQL not found in Postfix dynamic maps config. Adding it..."
        echo "mysql    mysql:/etc/postfix/postfix-mysql.cf.proto    dict    mysql" >> /etc/postfix/dynamicmaps.cf
    fi

    # Set MySQL root password securely
    local mysql_password=$(openssl rand -base64 32)
    
    # Check if MySQL is running
    if ! systemctl is-active --quiet mysql; then
        print_message "Starting MySQL service..."
        systemctl start mysql
        systemctl enable mysql
    fi

    # Secure MySQL installation
    print_message "Securing MySQL installation..."
    
    # Create database password for mail user
    local mail_db_password=$(openssl rand -base64 32)
    
    # Store passwords securely for the installation
    echo "${mysql_password}" > /root/.mysql_root_password
    chmod 600 /root/.mysql_root_password
    echo "${mail_db_password}" > /root/.mail_db_password
    chmod 600 /root/.mail_db_password
    
    # Setup mailserver database
    print_message "Creating mailserver database and tables..."
    
    # Check if database exists
    if mysql -u root -e "use mailserver" 2>/dev/null; then
        print_message "Mailserver database already exists. Skipping creation."
    else
        # Create database and user
        mysql -u root -e "CREATE DATABASE mailserver CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
        mysql -u root -e "CREATE USER 'mailuser'@'127.0.0.1' IDENTIFIED BY '${mail_db_password}';"
        mysql -u root -e "GRANT ALL PRIVILEGES ON mailserver.* TO 'mailuser'@'127.0.0.1';"
        mysql -u root -e "FLUSH PRIVILEGES;"
        
        # Create tables for mailserver
        mysql -u root mailserver << EOF
CREATE TABLE IF NOT EXISTS virtual_domains (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NULL ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY unique_domain (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS virtual_users (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    domain_id INT NOT NULL,
    email VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NULL ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY unique_email (email),
    FOREIGN KEY (domain_id) REFERENCES virtual_domains(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS virtual_aliases (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    domain_id INT NOT NULL,
    source VARCHAR(255) NOT NULL,
    destination VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NULL ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY unique_source (source),
    FOREIGN KEY (domain_id) REFERENCES virtual_domains(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS sender_access (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    email_pattern VARCHAR(255) NOT NULL,
    access VARCHAR(50) NOT NULL,
    UNIQUE KEY unique_email_pattern (email_pattern)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS ip_rotation (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    sender_pattern VARCHAR(255) NOT NULL,
    transport VARCHAR(50) NOT NULL,
    probability INT DEFAULT 100,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NULL ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY unique_sender_pattern (sender_pattern, transport)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
EOF
    fi
    
    # Configure Postfix to use MySQL
    print_message "Configuring Postfix to use MySQL..."
    
    # Create virtual domain configuration
    cat > /etc/postfix/mysql-virtual-mailbox-domains.cf << EOF
user = mailuser
password = ${mail_db_password}
hosts = 127.0.0.1
dbname = mailserver
query = SELECT 1 FROM virtual_domains WHERE name='%s'
EOF

    # Create virtual user configuration
    cat > /etc/postfix/mysql-virtual-mailbox-maps.cf << EOF
user = mailuser
password = ${mail_db_password}
hosts = 127.0.0.1
dbname = mailserver
query = SELECT 1 FROM virtual_users WHERE email='%s'
EOF

    # Create virtual alias configuration
    cat > /etc/postfix/mysql-virtual-alias-maps.cf << EOF
user = mailuser
password = ${mail_db_password}
hosts = 127.0.0.1
dbname = mailserver
query = SELECT destination FROM virtual_aliases WHERE source='%s'
EOF

    # Create sender access configuration
    cat > /etc/postfix/mysql-sender-access.cf << EOF
user = mailuser
password = ${mail_db_password}
hosts = 127.0.0.1
dbname = mailserver
query = SELECT access FROM sender_access WHERE email_pattern='%s'
EOF

    # Create sender-dependent transport configuration
    cat > /etc/postfix/mysql-sender-dependent-relayhost-maps.cf << EOF
user = mailuser
password = ${mail_db_password}
hosts = 127.0.0.1
dbname = mailserver
query = SELECT transport FROM ip_rotation WHERE sender_pattern='%s' ORDER BY RAND() LIMIT 1
EOF

    # Set correct permissions
    chmod 640 /etc/postfix/mysql-*
    chown root:postfix /etc/postfix/mysql-*
    
    # Configure postfix to use these maps
    postconf -e "virtual_mailbox_domains = mysql:/etc/postfix/mysql-virtual-mailbox-domains.cf"
    postconf -e "virtual_mailbox_maps = mysql:/etc/postfix/mysql-virtual-mailbox-maps.cf"
    postconf -e "virtual_alias_maps = mysql:/etc/postfix/mysql-virtual-alias-maps.cf"
    postconf -e "smtpd_sender_restrictions = check_sender_access mysql:/etc/postfix/mysql-sender-access.cf"
    postconf -e "sender_dependent_default_transport_maps = mysql:/etc/postfix/mysql-sender-dependent-relayhost-maps.cf"

    # Test the MySQL configuration
    print_message "Testing Postfix MySQL configuration..."
    
    if ! postmap -q "test" mysql:/etc/postfix/mysql-virtual-mailbox-domains.cf >/dev/null 2>&1; then
        print_warning "Postfix MySQL configuration test failed. Checking postfix-mysql installation..."
        
        # Ensure the mysql dynamic map module is loaded
        ldconfig
        if [ -f /usr/lib/postfix/dict_mysql.so ] || [ -f /usr/lib/postfix/modules/dict_mysql.so ]; then
            print_message "MySQL module file exists, ensuring it's properly linked..."
        else
            print_error "MySQL module file not found. Reinstalling postfix-mysql..."
            apt-get install --reinstall -y postfix-mysql
        fi
        
        # Make sure dynamicmaps.cf is properly configured
        if ! grep -q "mysql\s" /etc/postfix/dynamicmaps.cf; then
            print_message "Adding MySQL to dynamicmaps.cf..."
            echo "mysql    mysql:/etc/postfix/postfix-mysql.cf.proto    dict    mysql" >> /etc/postfix/dynamicmaps.cf
        fi
        
        # Restart Postfix to load the module
        systemctl restart postfix
    fi

    print_message "MySQL setup for mail server completed successfully"
}

# Add a domain to the mail database
add_domain_to_mysql() {
    local domain=$1
    local mail_db_password=$(cat /root/.mail_db_password)
    
    print_message "Adding domain ${domain} to MySQL database..."
    
    # Add domain if not exists
    local domain_exists=$(mysql -u mailuser -p"${mail_db_password}" -h 127.0.0.1 mailserver -sN -e "SELECT COUNT(*) FROM virtual_domains WHERE name='${domain}'")
    
    if [ "$domain_exists" -eq 0 ]; then
        mysql -u mailuser -p"${mail_db_password}" -h 127.0.0.1 mailserver -e "INSERT INTO virtual_domains (name) VALUES ('${domain}')"
        print_message "Domain ${domain} added to database"
    else
        print_message "Domain ${domain} already exists in database"
    fi

    # Create required aliases including postmaster
    print_message "Creating postmaster alias for ${domain}..."
    add_email_alias "postmaster@${domain}" "root@${domain}"

    # Test the alias setup
    print_message "Testing postmaster alias..."
    if postmap -q "postmaster@${domain}" mysql:/etc/postfix/mysql-virtual-alias-maps.cf > /dev/null 2>&1; then
        print_message "Postmaster alias for ${domain} successfully configured"
    else
        print_warning "Issue with postmaster alias configuration, attempting fix..."
        
        # Get domain ID
        local domain_id=$(mysql -u mailuser -p"${mail_db_password}" -h 127.0.0.1 mailserver -sN -e "SELECT id FROM virtual_domains WHERE name='${domain}'")
        
        # Manually add postmaster alias to ensure it exists
        mysql -u mailuser -p"${mail_db_password}" -h 127.0.0.1 mailserver -e "REPLACE INTO virtual_aliases (domain_id, source, destination) VALUES (${domain_id}, 'postmaster@${domain}', 'root@${domain}')"
        
        # Test again
        if postmap -q "postmaster@${domain}" mysql:/etc/postfix/mysql-virtual-alias-maps.cf > /dev/null 2>&1; then
            print_message "Postmaster alias fixed and configured properly"
        else
            print_error "Unable to configure postmaster alias. Check MySQL configuration."
        fi
    fi
}

# Add email alias
add_email_alias() {
    local source=$1
    local destination=$2
    local mail_db_password=$(cat /root/.mail_db_password)
    
    # Extract domain from source email
    local domain=$(echo "$source" | cut -d@ -f2)
    
    # Get domain_id
    local domain_id=$(mysql -u mailuser -p"${mail_db_password}" -h 127.0.0.1 mailserver -sN -e "SELECT id FROM virtual_domains WHERE name='${domain}'")
    
    if [ -z "$domain_id" ]; then
        print_error "Domain ${domain} not found in database"
        return 1
    fi
    
    # Check if alias exists
    local alias_exists=$(mysql -u mailuser -p"${mail_db_password}" -h 127.0.0.1 mailserver -sN -e "SELECT COUNT(*) FROM virtual_aliases WHERE source='${source}'")
    
    if [ "$alias_exists" -eq 0 ]; then
        mysql -u mailuser -p"${mail_db_password}" -h 127.0.0.1 mailserver -e "INSERT INTO virtual_aliases (domain_id, source, destination) VALUES (${domain_id}, '${source}', '${destination}')"
        print_message "Email alias ${source} -> ${destination} created"
    else
        mysql -u mailuser -p"${mail_db_password}" -h 127.0.0.1 mailserver -e "UPDATE virtual_aliases SET destination='${destination}' WHERE source='${source}'"
        print_message "Email alias ${source} updated to point to ${destination}"
    fi
}

# Add email user to mailserver
add_email_user() {
    local email=$1
    local password=$2
    local mail_db_password=$(cat /root/.mail_db_password)
    
    # Extract domain from email
    local domain=$(echo "$email" | cut -d@ -f2)
    
    print_message "Adding email user ${email}..."
    
    # Get domain_id
    local domain_id=$(mysql -u mailuser -p"${mail_db_password}" -h 127.0.0.1 mailserver -sN -e "SELECT id FROM virtual_domains WHERE name='${domain}'")
    
    if [ -z "$domain_id" ]; then
        print_error "Domain ${domain} not found in database"
        return 1
    fi
    
    # Hash the password
    local hashed_password=$(doveadm pw -s SHA512-CRYPT -p "${password}")
    
    # Check if user exists
    local user_exists=$(mysql -u mailuser -p"${mail_db_password}" -h 127.0.0.1 mailserver -sN -e "SELECT COUNT(*) FROM virtual_users WHERE email='${email}'")
    
    if [ "$user_exists" -eq 0 ]; then
        mysql -u mailuser -p"${mail_db_password}" -h 127.0.0.1 mailserver -e "INSERT INTO virtual_users (domain_id, email, password) VALUES (${domain_id}, '${email}', '${hashed_password}')"
        print_message "Email user ${email} created"
    else
        mysql -u mailuser -p"${mail_db_password}" -h 127.0.0.1 mailserver -e "UPDATE virtual_users SET password='${hashed_password}' WHERE email='${email}'"
        print_message "Email user ${email} password updated"
    fi
}

# Setup mail storage directories
setup_mail_directories() {
    print_message "Setting up mail directories..."
    
    # Create vmail user for mail storage
    if ! id -u vmail >/dev/null 2>&1; then
        useradd -r -u 5000 -g mail -d /var/mail/vmail -s /sbin/nologin -c "Virtual Mail User" vmail
    fi
    
    # Create mail directory
    mkdir -p /var/mail/vmail
    chmod -R 770 /var/mail/vmail
    chown -R vmail:mail /var/mail/vmail
    
    print_message "Mail directories configured"
}

# Setup Dovecot
setup_dovecot() {
    local domain=$1
    local hostname=$2
    local mail_db_password=$(cat /root/.mail_db_password)
    
    print_header "Setting up Dovecot IMAP/POP3 Server"
    
    # Install Dovecot if not already installed
    print_message "Installing Dovecot..."
    apt-get update
    apt-get install -y dovecot-core dovecot-imapd dovecot-pop3d dovecot-lmtpd dovecot-mysql
    
    # Backup original configurations
    backup_config "dovecot" "/etc/dovecot/dovecot.conf"
    backup_config "dovecot" "/etc/dovecot/conf.d/10-mail.conf"
    backup_config "dovecot" "/etc/dovecot/conf.d/10-auth.conf"
    backup_config "dovecot" "/etc/dovecot/conf.d/auth-sql.conf.ext"
    backup_config "dovecot" "/etc/dovecot/dovecot-sql.conf.ext"
    
    # Configure Dovecot main settings
    cat > /etc/dovecot/dovecot.conf <<EOF
# Dovecot configuration
# Generated by Mail Server Installer

# Protocols to enable
protocols = imap pop3 lmtp

# Logging
log_path = /var/log/dovecot.log
info_log_path = /var/log/dovecot-info.log
debug_log_path = /var/log/dovecot-debug.log

# SSL configuration
ssl = required
ssl_cert = </etc/letsencrypt/live/${hostname}/fullchain.pem
ssl_key = </etc/letsencrypt/live/${hostname}/privkey.pem
ssl_min_protocol = TLSv1.2
ssl_prefer_server_ciphers = yes

# Authentication
auth_mechanisms = plain login

# Mail location
mail_location = maildir:/var/mail/vmail/%d/%n

# User/group for mail processes
mail_uid = 5000
mail_gid = 8

# Allow plaintext authentication from local networks
auth_allow_cleartext = yes

# Include other configuration files
!include conf.d/*.conf

# Mailbox configuration
namespace inbox {
  inbox = yes
}
EOF
    
    # Configure mail settings
    cat > /etc/dovecot/conf.d/10-mail.conf <<EOF
# Mail configuration
# Generated by Mail Server Installer

mail_location = maildir:/var/mail/vmail/%d/%n
namespace inbox {
  inbox = yes
}

# Mailbox configuration
mailbox_list_index = yes
mail_privileged_group = mail
first_valid_uid = 5000
first_valid_gid = 8

# Mailbox auto creation
mailbox_autosubscribe = yes
mailbox_list_index = yes

# Performance settings
mail_fsync = optimized
mail_nfs_index = no
mail_nfs_storage = no
mmap_disable = no
EOF
    
    # Configure authentication
    cat > /etc/dovecot/conf.d/10-auth.conf <<EOF
# Authentication configuration
# Generated by Mail Server Installer

auth_mechanisms = plain login
!include auth-sql.conf.ext

disable_plaintext_auth = yes
auth_username_format = %n
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
  driver = sql
  args = /etc/dovecot/dovecot-sql.conf.ext
}
EOF
    
    # Configure SQL connection
    cat > /etc/dovecot/dovecot-sql.conf.ext <<EOF
# SQL connection configuration
# Generated by Mail Server Installer

driver = mysql
connect = host=127.0.0.1 dbname=mailserver user=mailuser password=${mail_db_password}
default_pass_scheme = SHA512-CRYPT

password_query = SELECT email as user, password FROM virtual_users WHERE email='%u';

user_query = SELECT CONCAT('/var/mail/vmail/', SUBSTRING_INDEX(email, '@', -1), '/', SUBSTRING_INDEX(email, '@', 1)) AS home, 5000 AS uid, 8 AS gid FROM virtual_users WHERE email='%u';

# For using doveadm -A:
iterate_query = SELECT email AS user FROM virtual_users;
EOF
    
    # Setup permissions
    chown -R vmail:dovecot /etc/dovecot
    chmod -R o-rwx /etc/dovecot
    
    # Restart Dovecot
    print_message "Restarting Dovecot..."
    systemctl restart dovecot
    systemctl enable dovecot
    
    print_message "Dovecot configuration completed successfully"
    
    # Add Postfix to deliver to Dovecot
    print_message "Configuring Postfix to deliver mail to Dovecot LMTP..."
    postconf -e "virtual_transport = lmtp:unix:private/dovecot-lmtp"
    postconf -e "mailbox_transport = lmtp:unix:private/dovecot-lmtp"
    
    # Restart Postfix
    systemctl restart postfix
}

# Create email forwarding
create_email_forward() {
    local source=$1
    local destination=$2
    
    print_message "Creating email forward from ${source} to ${destination}..."
    add_email_alias "${source}" "${destination}"
}

# Setup common email aliases
setup_email_aliases() {
    local mail_db_password=$(cat /root/.mail_db_password)
    
    print_header "Setting Up Common Email Aliases"
    
    # Get all domains in the database
    local domains=$(mysql -u mailuser -p"${mail_db_password}" -h 127.0.0.1 mailserver -sN -e "SELECT name FROM virtual_domains")
    
    for domain in ${domains}; do
        print_message "Setting up aliases for domain: ${domain}"
        
        # Get domain ID
        local domain_id=$(mysql -u mailuser -p"${mail_db_password}" -h 127.0.0.1 mailserver -sN -e "SELECT id FROM virtual_domains WHERE name='${domain}'")
        
        # Common aliases all point to postmaster initially
        local common_aliases=("abuse" "webmaster" "hostmaster" "info" "support" "admin")
        
        for alias in "${common_aliases[@]}"; do
            # Check if alias already exists
            local alias_exists=$(mysql -u mailuser -p"${mail_db_password}" -h 127.0.0.1 mailserver -sN -e "SELECT COUNT(*) FROM virtual_aliases WHERE source='${alias}@${domain}'")
            
            if [ "$alias_exists" -eq 0 ]; then
                # Forward to postmaster alias
                mysql -u mailuser -p"${mail_db_password}" -h 127.0.0.1 mailserver -e "INSERT INTO virtual_aliases (domain_id, source, destination) VALUES (${domain_id}, '${alias}@${domain}', 'postmaster@${domain}')"
                print_message "Created alias ${alias}@${domain} -> postmaster@${domain}"
            fi
        done
    done
    
    print_message "Common email aliases setup completed"
}

export -f setup_mysql add_domain_to_mysql add_email_user add_email_alias
export -f setup_mail_directories setup_dovecot create_email_forward setup_email_aliases
