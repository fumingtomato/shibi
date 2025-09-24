#!/bin/bash

# =================================================================
# MYSQL AND DOVECOT MODULE
# Database setup and IMAP server configuration
# =================================================================

# Setup MySQL database for mail server
setup_mysql_database() {
    print_message "Configuring MySQL..."

    # Prompt for MySQL password
    read -s -p "Enter a secure password for the MySQL user (or press Enter to generate a random one): " MYSQL_PASSWORD
    echo
    if [ -z "$MYSQL_PASSWORD" ]; then
        MYSQL_PASSWORD=$(openssl rand -base64 16)
        print_message "Generated random MySQL password: $MYSQL_PASSWORD"
    fi

    MYSQL_USER="mailuser"

    # Stop and start MySQL to ensure it's running
    systemctl stop mysql || true
    systemctl start mysql
    systemctl enable mysql

    # Make sure MySQL is running
    for i in {1..5}; do
        if systemctl is-active --quiet mysql; then
            print_message "MySQL is running."
            break
        else
            print_warning "MySQL not running. Attempting to start (try $i/5)..."
            systemctl start mysql
            sleep 3
        fi
    done

    # Check one final time
    if ! systemctl is-active --quiet mysql; then
        print_error "Failed to start MySQL. Please check MySQL service."
        exit 1
    fi

    # Create database and user
    mysql -e "CREATE DATABASE IF NOT EXISTS mailserver;"
    mysql -e "DROP USER IF EXISTS '$MYSQL_USER'@'localhost';" 2>/dev/null || true
    mysql -e "CREATE USER '$MYSQL_USER'@'localhost' IDENTIFIED BY '$MYSQL_PASSWORD';"
    mysql -e "GRANT ALL PRIVILEGES ON mailserver.* TO '$MYSQL_USER'@'localhost';"
    mysql -e "FLUSH PRIVILEGES;"

    # Create tables
    mysql mailserver -e "CREATE TABLE IF NOT EXISTS virtual_domains (
        id INT NOT NULL AUTO_INCREMENT,
        name VARCHAR(50) NOT NULL,
        PRIMARY KEY (id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;"

    mysql mailserver -e "CREATE TABLE IF NOT EXISTS virtual_users (
        id INT NOT NULL AUTO_INCREMENT,
        domain_id INT NOT NULL,
        password VARCHAR(255) NOT NULL,
        email VARCHAR(120) NOT NULL,
        PRIMARY KEY (id),
        UNIQUE KEY email (email),
        FOREIGN KEY (domain_id) REFERENCES virtual_domains(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;"

    mysql mailserver -e "CREATE TABLE IF NOT EXISTS virtual_aliases (
        id INT NOT NULL AUTO_INCREMENT,
        domain_id INT NOT NULL,
        source VARCHAR(100) NOT NULL,
        destination VARCHAR(100) NOT NULL,
        PRIMARY KEY (id),
        FOREIGN KEY (domain_id) REFERENCES virtual_domains(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;"

    # Create MySQL configuration files for Postfix
    cat > /etc/postfix/mysql-virtual-mailbox-domains.cf <<EOF
user = $MYSQL_USER
password = $MYSQL_PASSWORD
hosts = 127.0.0.1
dbname = mailserver
query = SELECT 1 FROM virtual_domains WHERE name='%s'
EOF

    cat > /etc/postfix/mysql-virtual-mailbox-maps.cf <<EOF
user = $MYSQL_USER
password = $MYSQL_PASSWORD
hosts = 127.0.0.1
dbname = mailserver
query = SELECT 1 FROM virtual_users WHERE email='%s'
EOF

    cat > /etc/postfix/mysql-virtual-alias-maps.cf <<EOF
user = $MYSQL_USER
password = $MYSQL_PASSWORD
hosts = 127.0.0.1
dbname = mailserver
query = SELECT destination FROM virtual_aliases WHERE source='%s'
EOF

    # Export for use in other modules
    export MYSQL_USER MYSQL_PASSWORD
    
    print_message "MySQL database setup completed with secure password configuration."
}

# Add domain and user to database
add_domain_and_user() {
    local domain=$1
    local username=$2
    local password=$3
    local server_ip=$4
    
    # Create account email and hash password
    local mail_account="${username}@${domain}"
    local hashed_password=$(doveadm pw -s SHA512-CRYPT -p "$password")
    
    # Add to database
    mysql mailserver -e "INSERT INTO virtual_domains (id, name) VALUES (1, '$domain');"
    mysql mailserver -e "INSERT INTO virtual_users (id, domain_id, password, email) 
                        VALUES (1, 1, '$hashed_password', '$mail_account');"
                        
    print_message "Added domain $domain and user $mail_account to database."
}

# Configure Dovecot IMAP server
setup_dovecot() {
    local domain=$1
    local hostname=$2
    
    print_message "Configuring Dovecot..."
    
    backup_config "dovecot" "/etc/dovecot/dovecot.conf"
    mv /etc/dovecot/dovecot.conf /etc/dovecot/dovecot.conf.orig || true
    
    # Main Dovecot configuration
    cat > /etc/dovecot/dovecot.conf <<EOF
!include_try /usr/share/dovecot/protocols.d/*.protocol
protocols = imap lmtp

!include conf.d/*.conf
!include_try local.conf
EOF
    
    # Authentication configuration
    cat > /etc/dovecot/conf.d/10-auth.conf <<EOF
disable_plaintext_auth = yes
auth_mechanisms = plain login
!include auth-sql.conf.ext
EOF
    
    # Mail location configuration
    cat > /etc/dovecot/conf.d/10-mail.conf <<EOF
mail_location = maildir:/var/mail/vhosts/%d/%n
namespace inbox {
  inbox = yes
}
mail_privileged_group = mail
EOF
    
    # Setup mail directories and permissions
    mkdir -p /var/mail/vhosts/$domain
    groupadd -g 5000 vmail 2>/dev/null || true
    useradd -g vmail -u 5000 vmail -d /var/mail/vhosts 2>/dev/null || true
    chown -R vmail:vmail /var/mail/vhosts
    
    # Master configuration (services)
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

service lmtp {
  unix_listener /var/spool/postfix/private/dovecot-lmtp {
    mode = 0600
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
    mode = 0666
    user = postfix
    group = postfix
  }

  user = dovecot
}

service auth-worker {
  user = vmail
}
EOF
    
    # SSL configuration
    cat > /etc/dovecot/conf.d/10-ssl.conf <<EOF
ssl = required
ssl_cert = </etc/letsencrypt/live/$hostname/fullchain.pem
ssl_key = </etc/letsencrypt/live/$hostname/privkey.pem
ssl_prefer_server_ciphers = yes
ssl_min_protocol = TLSv1.2
EOF
    
    # SQL authentication configuration
    cat > /etc/dovecot/conf.d/auth-sql.conf.ext <<EOF
passdb {
  driver = sql
  args = /etc/dovecot/dovecot-sql.conf.ext
}

userdb {
  driver = static
  args = uid=vmail gid=vmail home=/var/mail/vhosts/%d/%n
}
EOF
    
    # SQL connection configuration
    cat > /etc/dovecot/dovecot-sql.conf.ext <<EOF
driver = mysql
connect = host=localhost dbname=mailserver user=$MYSQL_USER password=$MYSQL_PASSWORD
default_pass_scheme = SHA512-CRYPT
password_query = SELECT email as user, password FROM virtual_users WHERE email='%u';
EOF
    
    # Set proper permissions
    chown -R vmail:dovecot /etc/dovecot
    chmod -R o-rwx /etc/dovecot
    
    print_message "Dovecot configuration completed with MySQL authentication."
}

# Configure OpenDKIM for email signing
setup_opendkim() {
    local domain=$1
    
    print_message "Configuring OpenDKIM with secure permissions..."
    
    # Create a dedicated group for DKIM keys
    groupadd dkim-keys 2>/dev/null || true
    
    # Create secure key directory with proper structure
    mkdir -p /etc/dkim-keys/$domain
    
    # Generate DNS-compatible 1024-bit DKIM keys
    cd /etc/dkim-keys/$domain
    print_message "Generating 1024-bit DKIM keys for DNS compatibility..."
    opendkim-genkey -b 1024 -d $domain -s mail -v
    
    # Extract the public key and ensure it's clean
    PUBKEY=$(grep -o 'p=.*' mail.txt | sed 's/p=//' | sed 's/"//g' | tr -d '\n\r\t ' | sed 's/);.*$//')
    echo "v=DKIM1; k=rsa; p=$PUBKEY" > mail.txt
    
    # Set ultra-secure ownership and permissions
    chown root:dkim-keys /etc/dkim-keys
    chmod 755 /etc/dkim-keys
    chown root:dkim-keys /etc/dkim-keys/$domain
    chmod 750 /etc/dkim-keys/$domain
    chown root:dkim-keys /etc/dkim-keys/$domain/mail.private
    chmod 640 /etc/dkim-keys/$domain/mail.private
    chown root:dkim-keys /etc/dkim-keys/$domain/mail.txt
    chmod 644 /etc/dkim-keys/$domain/mail.txt
    
    # Configure OpenDKIM to run as root
    mkdir -p /etc/systemd/system/opendkim.service.d/
    cat > /etc/systemd/system/opendkim.service.d/override.conf <<EOF
[Service]
User=root
Group=root
EOF

    systemctl daemon-reload
    
    # Main OpenDKIM configuration
    cat > /etc/opendkim.conf <<EOF
# OpenDKIM configuration with secure key storage
Syslog                  yes
UMask                   002
KeyTable                refile:/etc/opendkim/key.table
SigningTable            refile:/etc/opendkim/signing.table
ExternalIgnoreList      refile:/etc/opendkim/trusted.hosts
InternalHosts           refile:/etc/opendkim/trusted.hosts
Mode                    sv
PidFile                 /var/run/opendkim/opendkim.pid
Socket                  inet:12301@localhost
SignatureAlgorithm      rsa-sha256
OversignHeaders         From
Canonicalization        relaxed/simple
EOF
    
    # Create config directory with proper permissions
    mkdir -p /etc/opendkim
    chown root:root /etc/opendkim
    chmod 755 /etc/opendkim
    
    # Create signing table
    cat > /etc/opendkim/signing.table <<EOF
*@$domain mail._domainkey.$domain
EOF
    
    # Create key table
    cat > /etc/opendkim/key.table <<EOF
mail._domainkey.$domain $domain:mail:/etc/dkim-keys/$domain/mail.private
EOF
    
    # Create trusted hosts file
    cat > /etc/opendkim/trusted.hosts <<EOF
127.0.0.1
localhost
*.$domain
$domain
EOF
    
    # Add all configured IPs to trusted hosts
    for ip in "${IP_ADDRESSES[@]}"; do
        echo "$ip" >> /etc/opendkim/trusted.hosts
    done
    
    # Set proper permissions on config files
    chown root:root /etc/opendkim/key.table /etc/opendkim/signing.table /etc/opendkim/trusted.hosts
    chmod 644 /etc/opendkim/key.table /etc/opendkim/signing.table /etc/opendkim/trusted.hosts
    
    # Ensure runtime directory exists
    mkdir -p /var/run/opendkim
    chown root:root /var/run/opendkim
    chmod 755 /var/run/opendkim
    
    print_message "OpenDKIM configuration completed with secure permissions and DNS-compatible keys."
}

# Extract DKIM key for DNS record
get_dkim_value() {
    local domain=$1
    local dkim_value=$(grep -o "p=.*" /etc/dkim-keys/$domain/mail.txt | tr -d '\n\r\t "' | sed 's/p=//' | sed 's/);.*$//')
    echo "$dkim_value"
}

export -f setup_mysql_database add_domain_and_user setup_dovecot setup_opendkim get_dkim_value
