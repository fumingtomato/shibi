#!/bin/bash

# =================================================================
# UTILITY SCRIPTS MODULE - FIXED VERSION
# Management utilities, backup tools, and helper functions
# Fixed: Complete implementations, error handling, user management
# =================================================================

# Global utility variables
export BACKUP_DIR="/var/backups/mail-server"
export UTILITIES_DIR="/usr/local/bin"
export MAIL_DATA_DIR="/var/vmail"
export UTILITY_LOG="/var/log/mail-utilities.log"

# Initialize utility environment
init_utilities() {
    print_message "Initializing utility environment..."
    
    # Create directories
    mkdir -p "$BACKUP_DIR"
    chmod 750 "$BACKUP_DIR"
    
    # Initialize log
    touch "$UTILITY_LOG"
    chmod 640 "$UTILITY_LOG"
    
    print_message "✓ Utility environment initialized"
}

# Create backup utility
create_backup_utility() {
    cat > "${UTILITIES_DIR}/mail-backup" <<'EOF'
#!/bin/bash

# Mail Server Backup Utility
BACKUP_DIR="/var/backups/mail-server"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_NAME="mail-backup-${TIMESTAMP}"
BACKUP_PATH="${BACKUP_DIR}/${BACKUP_NAME}"

show_usage() {
    echo "Mail Server Backup Utility"
    echo "Usage: $0 [full|config|data|database] [destination]"
    echo ""
    echo "Types:"
    echo "  full     - Complete backup (config + data + database)"
    echo "  config   - Configuration files only"
    echo "  data     - Mail data only"
    echo "  database - Database only"
    echo ""
    echo "Default: full backup to $BACKUP_DIR"
    exit 1
}

backup_config() {
    echo "Backing up configuration files..."
    
    local config_dirs=(
        "/etc/postfix"
        "/etc/dovecot"
        "/etc/opendkim"
        "/etc/opendmarc"
        "/etc/fail2ban"
        "/etc/nginx"
        "/etc/apache2"
        "/etc/mysql"
        "/etc/ssl"
    )
    
    for dir in "${config_dirs[@]}"; do
        if [ -d "$dir" ]; then
            echo "  - $dir"
            tar -czf "${BACKUP_PATH}/$(basename $dir).tar.gz" "$dir" 2>/dev/null
        fi
    done
    
    # Backup system configs
    cp /etc/aliases "${BACKUP_PATH}/" 2>/dev/null
    cp /etc/hostname "${BACKUP_PATH}/" 2>/dev/null
    cp /etc/hosts "${BACKUP_PATH}/" 2>/dev/null
    crontab -l > "${BACKUP_PATH}/crontab.txt" 2>/dev/null
}

backup_data() {
    echo "Backing up mail data..."
    
    # Estimate size
    local size=$(du -sh /var/vmail 2>/dev/null | cut -f1)
    echo "  Mail data size: $size"
    
    # Backup with progress
    tar -czf "${BACKUP_PATH}/maildata.tar.gz" \
        --checkpoint=1000 \
        --checkpoint-action=echo="  %T" \
        /var/vmail 2>/dev/null
}

backup_database() {
    echo "Backing up databases..."
    
    # MySQL/MariaDB databases
    if command -v mysqldump &>/dev/null; then
        # Backup mail server database
        mysqldump --single-transaction --routines --triggers \
            mailserver > "${BACKUP_PATH}/mailserver.sql" 2>/dev/null
        
        # Backup user list
        mysql -e "SELECT user,host FROM mysql.user" > "${BACKUP_PATH}/mysql_users.txt" 2>/dev/null
    fi
    
    # SQLite databases (monitoring, sticky IP, etc.)
    for db in /var/lib/mail-monitoring/*.db /var/lib/postfix/*.db; do
        if [ -f "$db" ]; then
            echo "  - $(basename $db)"
            sqlite3 "$db" ".backup '${BACKUP_PATH}/$(basename $db)'"
        fi
    done
}

verify_backup() {
    echo "Verifying backup..."
    
    local errors=0
    
    # Check backup files
    for file in "${BACKUP_PATH}"/*; do
        if [ -f "$file" ]; then
            local size=$(stat -c%s "$file")
            if [ $size -eq 0 ]; then
                echo "  WARNING: Empty file: $(basename $file)"
                errors=$((errors + 1))
            fi
        fi
    done
    
    if [ $errors -eq 0 ]; then
        echo "  ✓ Backup verified successfully"
    else
        echo "  ⚠ Backup completed with $errors warnings"
    fi
}

# Main execution
TYPE="${1:-full}"
DESTINATION="${2:-$BACKUP_DIR}"

# Create backup directory
mkdir -p "$BACKUP_PATH"

echo "Starting $TYPE backup..."
echo "Destination: $BACKUP_PATH"
echo ""

case "$TYPE" in
    full)
        backup_config
        backup_data
        backup_database
        ;;
    config)
        backup_config
        ;;
    data)
        backup_data
        ;;
    database)
        backup_database
        ;;
    *)
        show_usage
        ;;
esac

# Compress entire backup
echo ""
echo "Compressing backup..."
cd "$BACKUP_DIR"
tar -czf "${BACKUP_NAME}.tar.gz" "$BACKUP_NAME"
rm -rf "$BACKUP_NAME"

# Show results
FINAL_SIZE=$(du -h "${BACKUP_DIR}/${BACKUP_NAME}.tar.gz" | cut -f1)
echo ""
echo "✓ Backup completed"
echo "  File: ${BACKUP_DIR}/${BACKUP_NAME}.tar.gz"
echo "  Size: $FINAL_SIZE"

# Cleanup old backups (keep last 7)
echo ""
echo "Cleaning old backups..."
ls -t "${BACKUP_DIR}"/mail-backup-*.tar.gz 2>/dev/null | tail -n +8 | xargs rm -f 2>/dev/null

echo "Done!"
EOF
    
    chmod +x "${UTILITIES_DIR}/mail-backup"
    print_message "✓ Backup utility created"
}

# Create restore utility
create_restore_utility() {
    cat > "${UTILITIES_DIR}/mail-restore" <<'EOF'
#!/bin/bash

# Mail Server Restore Utility
BACKUP_DIR="/var/backups/mail-server"

show_usage() {
    echo "Mail Server Restore Utility"
    echo "Usage: $0 <backup-file> [full|config|data|database]"
    echo ""
    echo "Types:"
    echo "  full     - Complete restore (config + data + database)"
    echo "  config   - Configuration files only"
    echo "  data     - Mail data only"
    echo "  database - Database only"
    echo ""
    echo "Example: $0 mail-backup-20240101-120000.tar.gz full"
    exit 1
}

if [ -z "$1" ]; then
    echo "Available backups:"
    ls -lh "${BACKUP_DIR}"/mail-backup-*.tar.gz 2>/dev/null
    echo ""
    show_usage
fi

BACKUP_FILE="$1"
TYPE="${2:-full}"

if [ ! -f "$BACKUP_FILE" ]; then
    if [ -f "${BACKUP_DIR}/$BACKUP_FILE" ]; then
        BACKUP_FILE="${BACKUP_DIR}/$BACKUP_FILE"
    else
        echo "Error: Backup file not found: $BACKUP_FILE"
        exit 1
    fi
fi

echo "WARNING: This will restore from backup and may overwrite current data!"
read -p "Continue? (yes/no): " confirm

if [ "$confirm" != "yes" ]; then
    echo "Restore cancelled"
    exit 0
fi

# Extract backup
TEMP_DIR=$(mktemp -d)
echo "Extracting backup..."
tar -xzf "$BACKUP_FILE" -C "$TEMP_DIR"

BACKUP_NAME=$(ls "$TEMP_DIR" | head -1)
EXTRACT_PATH="$TEMP_DIR/$BACKUP_NAME"

restore_config() {
    echo "Restoring configuration files..."
    
    # Stop services
    systemctl stop postfix dovecot opendkim
    
    # Restore configs
    for archive in "$EXTRACT_PATH"/*.tar.gz; do
        if [ -f "$archive" ]; then
            echo "  - $(basename $archive .tar.gz)"
            tar -xzf "$archive" -C / 2>/dev/null
        fi
    done
    
    # Restore individual files
    [ -f "$EXTRACT_PATH/aliases" ] && cp "$EXTRACT_PATH/aliases" /etc/
    [ -f "$EXTRACT_PATH/hostname" ] && cp "$EXTRACT_PATH/hostname" /etc/
    
    # Start services
    systemctl start postfix dovecot opendkim
}

restore_data() {
    echo "Restoring mail data..."
    
    if [ -f "$EXTRACT_PATH/maildata.tar.gz" ]; then
        # Stop mail services
        systemctl stop postfix dovecot
        
        # Backup current data
        mv /var/vmail "/var/vmail.backup.$(date +%s)" 2>/dev/null
        
        # Restore data
        tar -xzf "$EXTRACT_PATH/maildata.tar.gz" -C /
        
        # Fix permissions
        chown -R vmail:vmail /var/vmail
        
        # Start services
        systemctl start postfix dovecot
    else
        echo "  No mail data found in backup"
    fi
}

restore_database() {
    echo "Restoring databases..."
    
    # MySQL database
    if [ -f "$EXTRACT_PATH/mailserver.sql" ]; then
        echo "  - MySQL mailserver database"
        mysql mailserver < "$EXTRACT_PATH/mailserver.sql"
    fi
    
    # SQLite databases
    for db in "$EXTRACT_PATH"/*.db; do
        if [ -f "$db" ]; then
            local db_name=$(basename "$db")
            echo "  - SQLite: $db_name"
            
            if [[ "$db_name" == *"monitoring"* ]]; then
                cp "$db" "/var/lib/mail-monitoring/"
            elif [[ "$db_name" == *"sticky"* ]]; then
                cp "$db" "/var/lib/postfix/"
            fi
        fi
    done
}

# Perform restore
case "$TYPE" in
    full)
        restore_config
        restore_data
        restore_database
        ;;
    config)
        restore_config
        ;;
    data)
        restore_data
        ;;
    database)
        restore_database
        ;;
    *)
        show_usage
        ;;
esac

# Cleanup
rm -rf "$TEMP_DIR"

echo ""
echo "✓ Restore completed"
echo "  Please verify services are running correctly"
echo "  Run: systemctl status postfix dovecot opendkim"
EOF
    
    chmod +x "${UTILITIES_DIR}/mail-restore"
    print_message "✓ Restore utility created"
}

# Create email account management utility
create_email_management_utility() {
    cat > "${UTILITIES_DIR}/mail-account" <<'EOF'
#!/bin/bash

# Email Account Management Utility
DB_NAME="mailserver"

show_usage() {
    echo "Email Account Management"
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  add <email> <password>     Add email account"
    echo "  delete <email>             Delete email account"
    echo "  password <email> <new>     Change password"
    echo "  list [domain]              List accounts"
    echo "  quota <email> <size>       Set quota (e.g., 1G, 500M)"
    echo "  disable <email>            Disable account"
    echo "  enable <email>             Enable account"
    echo "  info <email>               Show account info"
    exit 1
}

hash_password() {
    local password=$1
    
    if command -v doveadm &>/dev/null; then
        doveadm pw -s SHA512-CRYPT -p "$password"
    else
        # Fallback to Python
        python3 -c "
import crypt, random, string
salt = '\$6\$' + ''.join(random.choices(string.ascii_letters + string.digits, k=16)) + '\$'
print(crypt.crypt('$password', salt))
"
    fi
}

add_account() {
    local email=$1
    local password=$2
    local domain="${email#*@}"
    
    # Validate email
    if ! [[ "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        echo "Error: Invalid email format"
        exit 1
    fi
    
    # Hash password
    local hashed=$(hash_password "$password")
    
    # Add to database
    mysql "$DB_NAME" <<SQL
-- Ensure domain exists
INSERT IGNORE INTO virtual_domains (name) VALUES ('$domain');

-- Add user
INSERT INTO virtual_users (domain_id, email, password)
SELECT id, '$email', '$hashed' FROM virtual_domains WHERE name = '$domain';
SQL
    
    if [ $? -eq 0 ]; then
        # Create maildir
        local maildir="/var/vmail/$domain/${email%@*}"
        mkdir -p "$maildir"
        chown -R vmail:vmail "$maildir"
        
        echo "✓ Account created: $email"
    else
        echo "Error: Failed to create account"
        exit 1
    fi
}

delete_account() {
    local email=$1
    
    read -p "Delete account $email and all its data? (yes/no): " confirm
    if [ "$confirm" != "yes" ]; then
        echo "Cancelled"
        exit 0
    fi
    
    # Delete from database
    mysql "$DB_NAME" -e "DELETE FROM virtual_users WHERE email='$email'"
    
    # Delete maildir
    local domain="${email#*@}"
    local user="${email%@*}"
    rm -rf "/var/vmail/$domain/$user"
    
    echo "✓ Account deleted: $email"
}

change_password() {
    local email=$1
    local password=$2
    
    local hashed=$(hash_password "$password")
    
    mysql "$DB_NAME" -e "UPDATE virtual_users SET password='$hashed' WHERE email='$email'"
    
    if [ $? -eq 0 ]; then
        echo "✓ Password updated for $email"
    else
        echo "Error: Failed to update password"
        exit 1
    fi
}

list_accounts() {
    local domain=$1
    
    if [ -z "$domain" ]; then
        echo "EMAIL ACCOUNTS"
        echo "=============="
        mysql -t "$DB_NAME" <<SQL
SELECT 
    email as 'Email',
    CASE enabled 
        WHEN 1 THEN 'Active' 
        ELSE 'Disabled' 
    END as 'Status',
    CONCAT(ROUND(quota/1024/1024), 'MB') as 'Quota',
    DATE(created_at) as 'Created'
FROM virtual_users
ORDER BY email;
SQL
    else
        echo "ACCOUNTS FOR DOMAIN: $domain"
        echo "=========================="
        mysql -t "$DB_NAME" <<SQL
SELECT 
    email as 'Email',
    CASE enabled 
        WHEN 1 THEN 'Active' 
        ELSE 'Disabled' 
    END as 'Status',
    CONCAT(ROUND(quota/1024/1024), 'MB') as 'Quota'
FROM virtual_users
WHERE email LIKE '%@$domain'
ORDER BY email;
SQL
    fi
}

set_quota() {
    local email=$1
    local quota=$2
    
    # Convert to bytes
    if [[ "$quota" =~ ^[0-9]+[Gg]$ ]]; then
        quota=$((${quota%[Gg]} * 1024 * 1024 * 1024))
    elif [[ "$quota" =~ ^[0-9]+[Mm]$ ]]; then
        quota=$((${quota%[Mm]} * 1024 * 1024))
    elif [[ "$quota" =~ ^[0-9]+[Kk]$ ]]; then
        quota=$((${quota%[Kk]} * 1024))
    fi
    
    mysql "$DB_NAME" -e "UPDATE virtual_users SET quota=$quota WHERE email='$email'"
    
    echo "✓ Quota set to $(($quota/1024/1024))MB for $email"
}

toggle_account() {
    local email=$1
    local enabled=$2
    
    mysql "$DB_NAME" -e "UPDATE virtual_users SET enabled=$enabled WHERE email='$email'"
    
    if [ "$enabled" -eq 1 ]; then
        echo "✓ Account enabled: $email"
    else
        echo "✓ Account disabled: $email"
    fi
}

show_info() {
    local email=$1
    
    echo "ACCOUNT INFORMATION"
    echo "==================="
    mysql -t "$DB_NAME" <<SQL
SELECT 
    email as 'Email',
    CASE enabled WHEN 1 THEN 'Active' ELSE 'Disabled' END as 'Status',
    CONCAT(ROUND(quota/1024/1024), 'MB') as 'Quota',
    created_at as 'Created',
    updated_at as 'Last Modified',
    last_login as 'Last Login'
FROM virtual_users
WHERE email = '$email';
SQL
    
    # Check maildir size
    local domain="${email#*@}"
    local user="${email%@*}"
    local maildir="/var/vmail/$domain/$user"
    
    if [ -d "$maildir" ]; then
        echo ""
        echo "Mailbox Size: $(du -sh "$maildir" 2>/dev/null | cut -f1)"
        echo "Message Count: $(find "$maildir" -type f -name "*.mail" 2>/dev/null | wc -l)"
    fi
}

# Main execution
case "$1" in
    add)
        [ -z "$2" ] || [ -z "$3" ] && show_usage
        add_account "$2" "$3"
        ;;
    delete)
        [ -z "$2" ] && show_usage
        delete_account "$2"
        ;;
    password)
        [ -z "$2" ] || [ -z "$3" ] && show_usage
        change_password "$2" "$3"
        ;;
    list)
        list_accounts "$2"
        ;;
    quota)
        [ -z "$2" ] || [ -z "$3" ] && show_usage
        set_quota "$2" "$3"
        ;;
    disable)
        [ -z "$2" ] && show_usage
        toggle_account "$2" 0
        ;;
    enable)
        [ -z "$2" ] && show_usage
        toggle_account "$2" 1
        ;;
    info)
        [ -z "$2" ] && show_usage
        show_info "$2"
        ;;
    *)
        show_usage
        ;;
esac
EOF
    
    chmod +x "${UTILITIES_DIR}/mail-account"
    print_message "✓ Email account management utility created"
}

# Create diagnostic utility
create_diagnostic_utility() {
    cat > "${UTILITIES_DIR}/mail-diagnostic" <<'EOF'
#!/bin/bash

# Mail Server Diagnostic Utility
echo "MAIL SERVER DIAGNOSTIC REPORT"
echo "============================="
echo "Generated: $(date)"
echo ""

# System Information
echo "SYSTEM INFORMATION:"
echo "------------------"
echo "Hostname: $(hostname -f)"
echo "OS: $(lsb_release -d | cut -f2)"
echo "Kernel: $(uname -r)"
echo "Uptime: $(uptime -p)"
echo "Load Average: $(cat /proc/loadavg | cut -d' ' -f1-3)"
echo ""

# Service Status
echo "SERVICE STATUS:"
echo "--------------"
services=("postfix" "dovecot" "mysql" "mariadb" "opendkim" "opendmarc" "fail2ban" "ufw")
for service in "${services[@]}"; do
    if systemctl list-units --full -all | grep -q "$service.service"; then
        printf "%-15s: " "$service"
        systemctl is-active "$service" || echo "STOPPED"
    fi
done
echo ""

# Port Connectivity
echo "PORT CONNECTIVITY:"
echo "-----------------"
ports=("25:SMTP" "587:Submission" "465:SMTPS" "110:POP3" "143:IMAP" "993:IMAPS" "995:POP3S")
for port_info in "${ports[@]}"; do
    port="${port_info%:*}"
    name="${port_info#*:}"
    printf "%-15s (%-4s): " "$name" "$port"
    nc -zv localhost "$port" 2>&1 | grep -q succeeded && echo "✓ Open" || echo "✗ Closed"
done
echo ""

# DNS Records
echo "DNS VERIFICATION:"
echo "----------------"
DOMAIN=$(hostname -d)
if [ ! -z "$DOMAIN" ]; then
    echo "Domain: $DOMAIN"
    echo -n "  MX Record: "
    dig +short MX "$DOMAIN" | head -1 || echo "Not found"
    echo -n "  SPF Record: "
    dig +short TXT "$DOMAIN" | grep "v=spf1" || echo "Not found"
    echo -n "  DKIM Record: "
    dig +short TXT "mail._domainkey.$DOMAIN" | head -1 || echo "Not found"
    echo -n "  DMARC Record: "
    dig +short TXT "_dmarc.$DOMAIN" | head -1 || echo "Not found"
fi
echo ""

# Mail Queue
echo "MAIL QUEUE STATUS:"
echo "-----------------"
mailq | tail -1
echo "Active: $(mailq | grep -c '^[A-F0-9]' || echo 0)"
echo "Deferred: $(find /var/spool/postfix/deferred -type f 2>/dev/null | wc -l)"
echo ""

# Disk Usage
echo "DISK USAGE:"
echo "----------"
df -h / /var/vmail 2>/dev/null | grep -v Filesystem
echo ""

# Recent Errors
echo "RECENT ERRORS (Last 10):"
echo "------------------------"
grep -i error /var/log/mail.log | tail -10
echo ""

# Configuration Tests
echo "CONFIGURATION TESTS:"
echo "-------------------"
echo -n "Postfix config: "
postfix check 2>&1 | grep -q "error\|warning" && echo "✗ Issues found" || echo "✓ OK"

echo -n "Dovecot config: "
doveconf -n 2>&1 | grep -q "error\|warning" && echo "✗ Issues found" || echo "✓ OK"

echo -n "OpenDKIM test: "
opendkim-testkey -d "$DOMAIN" -s mail -vvv 2>&1 | grep -q "key OK" && echo "✓ OK" || echo "✗ Check needed"

echo ""
echo "RECOMMENDATIONS:"
echo "---------------"

# Check for common issues
issues=0

if ! systemctl is-active --quiet postfix; then
    echo "- Postfix is not running. Start with: systemctl start postfix"
    issues=$((issues + 1))
fi

if ! systemctl is-active --quiet dovecot; then
    echo "- Dovecot is not running. Start with: systemctl start dovecot"
    issues=$((issues + 1))
fi

queue_size=$(mailq | grep -c '^[A-F0-9]' || echo 0)
if [ "$queue_size" -gt 100 ]; then
    echo "- Large mail queue detected ($queue_size messages). Check for issues."
    issues=$((issues + 1))
fi

disk_usage=$(df / | awk 'NR==2 {print int($5)}')
if [ "$disk_usage" -gt 80 ]; then
    echo "- Disk usage is high (${disk_usage}%). Consider cleanup."
    issues=$((issues + 1))
fi

if [ $issues -eq 0 ]; then
    echo "✓ No immediate issues detected"
fi

echo ""
echo "For detailed logs, check:"
echo "  /var/log/mail.log"
echo "  /var/log/mail.err"
echo "  /var/log/syslog"
EOF
    
    chmod +x "${UTILITIES_DIR}/mail-diagnostic"
    print_message "✓ Diagnostic utility created"
}

# Create queue management utility
create_queue_management_utility() {
    cat > "${UTILITIES_DIR}/mail-queue" <<'EOF'
#!/bin/bash

# Mail Queue Management Utility
show_usage() {
    echo "Mail Queue Management"
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  status              Show queue status"
    echo "  list [filter]       List queued messages"
    echo "  flush               Flush mail queue"
    echo "  delete <id>         Delete specific message"
    echo "  hold <id>           Hold message"
    echo "  release <id>        Release held message"
    echo "  requeue <id>        Requeue message"
    echo "  inspect <id>        Show message details"
    echo "  clean               Remove bounce messages"
    exit 1
}

show_status() {
    echo "MAIL QUEUE STATUS"
    echo "================="
    
    mailq | tail -1
    echo ""
    
    echo "Queue breakdown:"
    echo "  Active: $(find /var/spool/postfix/active -type f 2>/dev/null | wc -l)"
    echo "  Deferred: $(find /var/spool/postfix/deferred -type f 2>/dev/null | wc -l)"
    echo "  Hold: $(find /var/spool/postfix/hold -type f 2>/dev/null | wc -l)"
    echo "  Corrupt: $(find /var/spool/postfix/corrupt -type f 2>/dev/null | wc -l)"
    echo ""
    
    echo "Top deferred reasons:"
    find /var/spool/postfix/deferred -type f -exec postcat -q {} \; 2>/dev/null | \
        grep "reason=" | cut -d'=' -f2 | sort | uniq -c | sort -rn | head -5
}

list_queue() {
    local filter=$1
    
    if [ -z "$filter" ]; then
        mailq
    else
        mailq | grep -i "$filter"
    fi
}

flush_queue() {
    echo "Flushing mail queue..."
    postqueue -f
    echo "✓ Queue flush initiated"
}

delete_message() {
    local id=$1
    
    if [ -z "$id" ]; then
        echo "Error: Message ID required"
        exit 1
    fi
    
    postsuper -d "$id"
    echo "✓ Message $id deleted"
}

hold_message() {
    local id=$1
    
    postsuper -h "$id"
    echo "✓ Message $id held"
}

release_message() {
    local id=$1
    
    postsuper -H "$id"
    echo "✓ Message $id released"
}

requeue_message() {
    local id=$1
    
    postsuper -r "$id"
    echo "✓ Message $id requeued"
}

inspect_message() {
    local id=$1
    
    echo "MESSAGE DETAILS: $id"
    echo "=================="
    postcat -q "$id"
}

clean_bounces() {
    echo "Removing bounce messages..."
    
    # Remove all bounce messages
    postqueue -p | grep MAILER-DAEMON | awk '{print $1}' | \
        grep -v "^(" | postsuper -d -
    
    echo "✓ Bounce messages removed"
}

# Main execution
case "$1" in
    status|"")
        show_status
        ;;
    list)
        list_queue "$2"
        ;;
    flush)
        flush_queue
        ;;
    delete)
        delete_message "$2"
        ;;
    hold)
        hold_message "$2"
        ;;
    release)
        release_message "$2"
        ;;
    requeue)
        requeue_message "$2"
        ;;
    inspect)
        inspect_message "$2"
        ;;
    clean)
        clean_bounces
        ;;
    *)
        show_usage
        ;;
esac
EOF
    
    chmod +x "${UTILITIES_DIR}/mail-queue"
    print_message "✓ Queue management utility created"
}

# Create test email utility
create_test_email_utility() {
    cat > "${UTILITIES_DIR}/test-email" <<'EOF'
#!/bin/bash

# Email Testing Utility
show_usage() {
    echo "Email Testing Utility"
    echo "Usage: $0 <recipient> [options]"
    echo ""
    echo "Options:"
    echo "  -f <from>      From address (default: test@$(hostname -d))"
    echo "  -s <subject>   Subject (default: Test Email)"
    echo "  -b <body>      Body text (default: auto-generated)"
    echo "  -a <file>      Attach file"
    echo "  -t             Include timestamp in subject"
    echo "  -v             Verbose SMTP session"
    echo "  -p <port>      SMTP port (default: 25)"
    echo "  -h             Show this help"
    echo ""
    echo "Examples:"
    echo "  $0 user@example.com"
    echo "  $0 user@example.com -f sender@domain.com -s 'Test' -t"
    echo "  $0 check-auth@verifier.port25.com -v"
    exit 1
}

# Default values
TO=""
FROM="test@$(hostname -d)"
SUBJECT="Test Email"
BODY=""
ATTACHMENT=""
TIMESTAMP=""
VERBOSE=""
PORT="25"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -f) FROM="$2"; shift 2 ;;
        -s) SUBJECT="$2"; shift 2 ;;
        -b) BODY="$2"; shift 2 ;;
        -a) ATTACHMENT="$2"; shift 2 ;;
        -t) TIMESTAMP="1"; shift ;;
        -v) VERBOSE="-v"; shift ;;
        -p) PORT="$2"; shift 2 ;;
        -h) show_usage ;;
        -*) echo "Unknown option: $1"; show_usage ;;
        *) TO="$1"; shift ;;
    esac
done

if [ -z "$TO" ]; then
    show_usage
fi

# Add timestamp if requested
if [ "$TIMESTAMP" = "1" ]; then
    SUBJECT="$SUBJECT - $(date '+%Y-%m-%d %H:%M:%S')"
fi

# Generate body if not provided
if [ -z "$BODY" ]; then
    BODY="This is a test email sent from $(hostname -f) at $(date).

Server Information:
- Hostname: $(hostname -f)
- IP Address: $(hostname -I | awk '{print $1}')
- Mail Server: Postfix $(postconf -d mail_version | cut -d' ' -f3)

This email was sent to verify mail server functionality.
"
fi

# Send email
echo "Sending test email..."
echo "  From: $FROM"
echo "  To: $TO"
echo "  Subject: $SUBJECT"

if [ ! -z "$ATTACHMENT" ] && [ -f "$ATTACHMENT" ]; then
    # Send with attachment
    echo "$BODY" | mail -s "$SUBJECT" -a "$ATTACHMENT" -r "$FROM" $VERBOSE "$TO"
else
    # Send without attachment
    echo "$BODY" | mail -s "$SUBJECT" -r "$FROM" $VERBOSE "$TO"
fi

if [ $? -eq 0 ]; then
    echo "✓ Email sent successfully"
    
    # Check queue
    sleep 2
    if mailq | grep -q "$TO"; then
        echo "⚠ Email is queued for delivery"
    fi
else
    echo "✗ Failed to send email"
    exit 1
fi

# For verbose mode, show recent log entries
if [ "$VERBOSE" = "-v" ]; then
    echo ""
    echo "Recent mail log entries:"
    grep "$TO" /var/log/mail.log | tail -5
fi
EOF
    
    chmod +x "${UTILITIES_DIR}/test-email"
    print_message "✓ Test email utility created"
}

# Create all utility scripts
create_all_utilities() {
    print_header "Creating Utility Scripts"
    
    # Initialize environment
    init_utilities
    
    # Create individual utilities
    create_backup_utility
    create_restore_utility
    create_email_management_utility
    create_diagnostic_utility
    create_queue_management_utility
    create_test_email_utility
    
    print_message "✓ All utility scripts created"
    print_message ""
    print_message "Available utilities:"
    print_message "  mail-backup      - Backup mail server"
    print_message "  mail-restore     - Restore from backup"
    print_message "  mail-account     - Manage email accounts"
    print_message "  mail-diagnostic  - Run diagnostics"
    print_message "  mail-queue       - Manage mail queue"
    print_message "  test-email       - Send test emails"
}

# Export functions
export -f init_utilities create_backup_utility create_restore_utility
export -f create_email_management_utility create_diagnostic_utility
export -f create_queue_management_utility create_test_email_utility
export -f create_all_utilities

# Export variables
export BACKUP_DIR UTILITIES_DIR MAIL_DATA_DIR UTILITY_LOG
