#!/bin/bash

# =================================================================
# STICKY IP MODULE - COMPLETE FIXED VERSION
# Ensures consistent IP usage for recipients who engage with emails
# Fixed: Complete implementations for all functions
# =================================================================

# Setup sticky IP database and tables with proper indexes
setup_sticky_ip_db() {
    print_header "Setting Up Sticky IP Feature"
    
    # Ensure DB_PASSWORD is available
    if [ -z "$DB_PASSWORD" ] && [ -f /root/.mail_db_password ]; then
        DB_PASSWORD=$(cat /root/.mail_db_password)
    fi
    
    if [ -z "$DB_PASSWORD" ]; then
        print_error "Database password not found. Cannot setup sticky IP."
        return 1
    fi
    
    print_message "Creating sticky IP database tables..."
    
    # Create a secure temporary SQL file
    SQL_TMPFILE=$(mktemp)
    chmod 600 "$SQL_TMPFILE"
    
    # Add the recipient_ip_mapping table to the mailserver database with indexes
    cat > "$SQL_TMPFILE" <<EOF
USE mailserver;

CREATE TABLE IF NOT EXISTS recipient_ip_mapping (
  id int NOT NULL auto_increment,
  email varchar(255) NOT NULL,
  ip_address varchar(45) NOT NULL,
  transport varchar(20) NOT NULL,
  last_used timestamp DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  engagement_type enum('open', 'click', 'manual') DEFAULT 'manual',
  PRIMARY KEY (id),
  UNIQUE KEY email (email),
  KEY idx_transport (transport),
  KEY idx_last_used (last_used),
  KEY idx_ip_address (ip_address)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Create engagement history table for tracking
CREATE TABLE IF NOT EXISTS engagement_history (
  id int NOT NULL auto_increment,
  email varchar(255) NOT NULL,
  ip_address varchar(45) NOT NULL,
  event_type enum('open', 'click', 'bounce', 'complaint') NOT NULL,
  event_timestamp timestamp DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_email (email),
  KEY idx_timestamp (event_timestamp)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Grant necessary permissions to mailuser
GRANT SELECT, INSERT, UPDATE, DELETE ON mailserver.recipient_ip_mapping TO 'mailuser'@'localhost';
GRANT SELECT, INSERT ON mailserver.engagement_history TO 'mailuser'@'localhost';

FLUSH PRIVILEGES;
EOF
    
    # Execute the SQL commands
    if mysql -u root < "$SQL_TMPFILE" 2>/dev/null; then
        print_message "✓ Sticky IP database tables created successfully"
    else
        print_error "Failed to create sticky IP database tables"
        cat "$SQL_TMPFILE" # Show SQL for debugging
        rm -f "$SQL_TMPFILE"
        return 1
    fi
    
    # Remove temporary SQL file
    rm -f "$SQL_TMPFILE"
    
    # Create the MySQL lookup file for Postfix
    print_message "Creating Postfix MySQL lookup configuration..."
    cat > /etc/postfix/mysql-recipient-transport-maps.cf <<EOF
user = mailuser
password = $DB_PASSWORD
hosts = 127.0.0.1
dbname = mailserver
query = SELECT transport FROM recipient_ip_mapping WHERE email='%s'
EOF
    
    # Set proper permissions
    chmod 640 /etc/postfix/mysql-recipient-transport-maps.cf
    chown root:postfix /etc/postfix/mysql-recipient-transport-maps.cf
    
    print_message "✓ Sticky IP database configuration complete"
    return 0
}

# Configure Postfix to use the sticky IP feature
configure_sticky_ip_postfix() {
    print_message "Configuring Postfix for sticky IP support..."
    
    # Check if the MySQL lookup file exists
    if [ ! -f /etc/postfix/mysql-recipient-transport-maps.cf ]; then
        print_error "MySQL lookup file not found. Run setup_sticky_ip_db first."
        return 1
    fi
    
    # Update main.cf to include the recipient-dependent transport lookup
    # First, check if transport_maps already exists
    local existing_transport_maps=$(postconf -h transport_maps 2>/dev/null)
    
    if [ -z "$existing_transport_maps" ]; then
        # No existing transport_maps
        postconf -e "transport_maps = mysql:/etc/postfix/mysql-recipient-transport-maps.cf"
    else
        # Append to existing transport_maps if not already there
        if ! echo "$existing_transport_maps" | grep -q "mysql-recipient-transport-maps"; then
            postconf -e "transport_maps = mysql:/etc/postfix/mysql-recipient-transport-maps.cf, $existing_transport_maps"
        else
            print_message "Sticky IP transport map already configured"
        fi
    fi
    
    # Ensure connection caching is disabled for proper sticky IP operation
    postconf -e "smtp_connection_cache_on_demand = no"
    postconf -e "smtp_connection_cache_time_limit = 2s"
    
    # Set up per-recipient connection limits to ensure sticky behavior
    postconf -e "smtp_destination_recipient_limit = 1"
    postconf -e "smtp_destination_concurrency_limit = 20"
    
    print_message "✓ Postfix sticky IP configuration complete"
    
    # Reload Postfix to apply changes
    postfix reload 2>/dev/null || true
    
    return 0
}

# Create utility to manually assign a recipient to a specific IP with SQL injection prevention
create_sticky_ip_utility() {
    print_message "Creating sticky IP management utilities..."
    
    cat > /usr/local/bin/sticky-ip-manager <<'EOF'
#!/bin/bash

# Sticky IP Manager Utility
# Manages recipient-to-IP mappings for consistent email delivery

MYSQL_PASS=$(cat /root/.mail_db_password 2>/dev/null)
if [ -z "$MYSQL_PASS" ]; then
    echo "Error: Database password not found"
    exit 1
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Function to escape SQL strings to prevent injection
escape_sql() {
    echo "$1" | sed "s/'/\\\\'/g" | sed 's/"/\\\\"/g' | sed 's/\\/\\\\/g'
}

# Function to validate email format
validate_email_format() {
    local email=$1
    if [[ ! "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        echo "Error: Invalid email format: $email"
        return 1
    fi
    return 0
}

# Function to validate transport name
validate_transport() {
    local transport=$1
    if [[ ! "$transport" =~ ^smtp-ip[0-9]+$ ]]; then
        echo "Error: Invalid transport format. Must be smtp-ipN where N is a number"
        return 1
    fi
    
    # Check if transport exists in master.cf
    if ! grep -q "^$transport " /etc/postfix/master.cf 2>/dev/null; then
        echo "Error: Transport $transport not found in Postfix configuration"
        return 1
    fi
    
    return 0
}

# Function to show usage
usage() {
    echo -e "${GREEN}Sticky IP Manager Utility${NC}"
    echo "=========================="
    echo "Usage:"
    echo "  $0 list [email_pattern]             - List all mappings or filter by email pattern"
    echo "  $0 assign <email> <transport>       - Manually assign email to transport (e.g., smtp-ip1)"
    echo "  $0 remove <email>                   - Remove email mapping (will revert to round-robin)"
    echo "  $0 import <csv_file>                - Import mappings from CSV (email,transport)"
    echo "  $0 export [file]                    - Export mappings to CSV (default: sticky-ip-mappings.csv)"
    echo "  $0 stats                            - Show distribution statistics"
    echo "  $0 history <email>                  - Show engagement history for email"
    echo "  $0 cleanup [days]                   - Remove mappings older than N days (default: 90)"
    echo ""
    echo "Examples:"
    echo "  $0 list @example.com                - Show all mappings for @example.com"
    echo "  $0 assign user@example.com smtp-ip2 - Assign user@example.com to IP #2"
    echo "  $0 cleanup 30                       - Remove mappings unused for 30+ days"
    echo ""
}

# Function to list mappings with safe SQL
list_mappings() {
    local filter="$1"
    
    echo -e "${GREEN}Recipient-to-IP Mappings${NC}"
    echo "====================================="
    
    if [ ! -z "$filter" ]; then
        # Escape the filter for safe SQL usage
        filter=$(escape_sql "$filter")
        
        # Create temporary SQL file for safe execution
        local tmp_sql=$(mktemp)
        cat > "$tmp_sql" <<SQLEOF
USE mailserver;
SELECT 
    email, 
    ip_address, 
    transport, 
    DATE_FORMAT(last_used, '%Y-%m-%d %H:%i') as last_used, 
    engagement_type 
FROM recipient_ip_mapping 
WHERE email LIKE '%${filter}%'
ORDER BY last_used DESC 
LIMIT 100;
SQLEOF
        
        mysql -u mailuser -p"$MYSQL_PASS" < "$tmp_sql" --table 2>/dev/null
        rm -f "$tmp_sql"
    else
        mysql -u mailuser -p"$MYSQL_PASS" mailserver \
            -e "SELECT email, ip_address, transport, DATE_FORMAT(last_used, '%Y-%m-%d %H:%i') as last_used, engagement_type FROM recipient_ip_mapping ORDER BY last_used DESC LIMIT 100;" \
            --table 2>/dev/null
    fi
}

# Function to assign a recipient to a specific transport with validation
assign_recipient() {
    local email="$1"
    local transport="$2"
    
    # Validate inputs
    if ! validate_email_format "$email"; then
        return 1
    fi
    
    if ! validate_transport "$transport"; then
        return 1
    fi
    
    # Extract IP from master.cf
    local ip=$(grep -A 2 "^$transport " /etc/postfix/master.cf | grep smtp_bind_address | awk -F'=' '{print $2}' | tr -d ' ')
    
    if [ -z "$ip" ]; then
        echo -e "${RED}Error: Could not determine IP for transport $transport${NC}"
        return 1
    fi
    
    # Escape values for SQL
    email=$(escape_sql "$email")
    ip=$(escape_sql "$ip")
    transport=$(escape_sql "$transport")
    
    # Create temporary SQL file for safe execution
    local tmp_sql=$(mktemp)
    cat > "$tmp_sql" <<SQLEOF
USE mailserver;
INSERT INTO recipient_ip_mapping (email, ip_address, transport, engagement_type) 
VALUES ('${email}', '${ip}', '${transport}', 'manual')
ON DUPLICATE KEY UPDATE 
    ip_address='${ip}', 
    transport='${transport}', 
    last_used=CURRENT_TIMESTAMP, 
    engagement_type='manual';
    
-- Also log this in engagement history
INSERT INTO engagement_history (email, ip_address, event_type)
VALUES ('${email}', '${ip}', 'manual');
SQLEOF
    
    if mysql -u mailuser -p"$MYSQL_PASS" < "$tmp_sql" 2>/dev/null; then
        echo -e "${GREEN}✓ Successfully assigned $email to $transport ($ip)${NC}"
        rm -f "$tmp_sql"
        return 0
    else
        echo -e "${RED}✗ Failed to assign $email to $transport${NC}"
        rm -f "$tmp_sql"
        return 1
    fi
}

# Function to remove a mapping with validation
remove_mapping() {
    local email="$1"
    
    # Validate email format
    if ! validate_email_format "$email"; then
        return 1
    fi
    
    # Escape email for SQL
    email=$(escape_sql "$email")
    
    # Create temporary SQL file
    local tmp_sql=$(mktemp)
    cat > "$tmp_sql" <<SQLEOF
USE mailserver;
DELETE FROM recipient_ip_mapping WHERE email='${email}';
SQLEOF
    
    if mysql -u mailuser -p"$MYSQL_PASS" < "$tmp_sql" 2>/dev/null; then
        echo -e "${GREEN}✓ Successfully removed mapping for $email${NC}"
        rm -f "$tmp_sql"
        return 0
    else
        echo -e "${RED}✗ Failed to remove mapping for $email${NC}"
        rm -f "$tmp_sql"
        return 1
    fi
}

# Function to import mappings from CSV with validation
import_mappings() {
    local csv_file="$1"
    
    if [ ! -f "$csv_file" ]; then
        echo -e "${RED}Error: CSV file not found: $csv_file${NC}"
        return 1
    fi
    
    echo -e "${GREEN}Importing mappings from $csv_file...${NC}"
    
    local success_count=0
    local error_count=0
    local line_num=0
    
    while IFS=, read -r email transport; do
        line_num=$((line_num + 1))
        
        # Skip header line if it exists
        if [ $line_num -eq 1 ] && [[ "$email" == *"email"* ]]; then
            continue
        fi
        
        # Skip empty lines and comments
        if [ -z "$email" ] || [[ "$email" == \#* ]]; then
            continue
        fi
        
        # Trim whitespace
        email=$(echo "$email" | xargs)
        transport=$(echo "$transport" | xargs)
        
        if assign_recipient "$email" "$transport" >/dev/null 2>&1; then
            success_count=$((success_count + 1))
            echo -e "  ${GREEN}✓${NC} $email → $transport"
        else
            echo -e "  ${RED}✗${NC} Failed: $email → $transport"
            error_count=$((error_count + 1))
        fi
    done < "$csv_file"
    
    echo -e "${GREEN}Import completed: $success_count successful, $error_count failed${NC}"
}

# Function to export mappings to CSV
export_mappings() {
    local export_file="${1:-sticky-ip-mappings.csv}"
    
    echo -e "${GREEN}Exporting mappings to $export_file...${NC}"
    
    # Add header to CSV
    echo "email,transport,ip_address,last_used,engagement_type" > "$export_file"
    
    # Export data
    mysql -u mailuser -p"$MYSQL_PASS" mailserver \
        -e "SELECT email, transport, ip_address, last_used, engagement_type FROM recipient_ip_mapping ORDER BY email;" \
        -B --skip-column-names 2>/dev/null | sed 's/\t/,/g' >> "$export_file"
    
    local count=$(wc -l < "$export_file")
    echo -e "${GREEN}✓ Successfully exported $((count-1)) mappings to $export_file${NC}"
}

# Function to show distribution statistics
show_stats() {
    echo -e "${GREEN}IP Distribution Statistics${NC}"
    echo "==========================="
    
    mysql -u mailuser -p"$MYSQL_PASS" mailserver -e "
    SELECT 
        transport, 
        ip_address,
        COUNT(*) as recipients, 
        GROUP_CONCAT(DISTINCT engagement_type SEPARATOR ', ') as types,
        DATE_FORMAT(MAX(last_used), '%Y-%m-%d %H:%i') as last_activity
    FROM recipient_ip_mapping 
    GROUP BY transport, ip_address
    ORDER BY recipients DESC;" --table 2>/dev/null
    
    echo ""
    echo -e "${GREEN}Summary Statistics${NC}"
    echo "=================="
    mysql -u mailuser -p"$MYSQL_PASS" mailserver -e "
    SELECT 
        COUNT(DISTINCT email) as 'Total Recipients',
        COUNT(DISTINCT transport) as 'Active Transports',
        COUNT(CASE WHEN engagement_type='open' THEN 1 END) as 'Open Engagements',
        COUNT(CASE WHEN engagement_type='click' THEN 1 END) as 'Click Engagements',
        COUNT(CASE WHEN engagement_type='manual' THEN 1 END) as 'Manual Assignments'
    FROM recipient_ip_mapping;" --table 2>/dev/null
}

# Function to show engagement history
show_history() {
    local email="$1"
    
    if ! validate_email_format "$email"; then
        return 1
    fi
    
    email=$(escape_sql "$email")
    
    echo -e "${GREEN}Engagement History for $email${NC}"
    echo "================================="
    
    mysql -u mailuser -p"$MYSQL_PASS" mailserver -e "
    SELECT 
        DATE_FORMAT(event_timestamp, '%Y-%m-%d %H:%i') as timestamp,
        event_type,
        ip_address
    FROM engagement_history 
    WHERE email='$email'
    ORDER BY event_timestamp DESC
    LIMIT 50;" --table 2>/dev/null
}

# Function to cleanup old mappings
cleanup_old_mappings() {
    local days="${1:-90}"
    
    if ! [[ "$days" =~ ^[0-9]+$ ]]; then
        echo -e "${RED}Error: Days must be a positive number${NC}"
        return 1
    fi
    
    echo -e "${YELLOW}Warning: This will remove mappings not used in the last $days days${NC}"
    read -p "Are you sure? (yes/no): " confirm
    
    if [ "$confirm" != "yes" ]; then
        echo "Cancelled"
        return 0
    fi
    
    local tmp_sql=$(mktemp)
    cat > "$tmp_sql" <<SQLEOF
USE mailserver;
DELETE FROM recipient_ip_mapping 
WHERE last_used < DATE_SUB(NOW(), INTERVAL $days DAY);
SQLEOF
    
    if mysql -u mailuser -p"$MYSQL_PASS" < "$tmp_sql" 2>/dev/null; then
        local affected=$(mysql -u mailuser -p"$MYSQL_PASS" -e "SELECT ROW_COUNT();" -B --skip-column-names 2>/dev/null)
        echo -e "${GREEN}✓ Cleaned up $affected old mappings${NC}"
        rm -f "$tmp_sql"
    else
        echo -e "${RED}✗ Cleanup failed${NC}"
        rm -f "$tmp_sql"
        return 1
    fi
}

# Main command handler
case "$1" in
    list)
        list_mappings "$2"
        ;;
    assign)
        if [ -z "$2" ] || [ -z "$3" ]; then
            echo -e "${RED}Error: Missing parameters.${NC}"
            usage
            exit 1
        fi
        assign_recipient "$2" "$3"
        ;;
    remove)
        if [ -z "$2" ]; then
            echo -e "${RED}Error: Missing email parameter.${NC}"
            usage
            exit 1
        fi
        remove_mapping "$2"
        ;;
    import)
        if [ -z "$2" ]; then
            echo -e "${RED}Error: Missing CSV file parameter.${NC}"
            usage
            exit 1
        fi
        import_mappings "$2"
        ;;
    export)
        export_mappings "$2"
        ;;
    stats)
        show_stats
        ;;
    history)
        if [ -z "$2" ]; then
            echo -e "${RED}Error: Missing email parameter.${NC}"
            usage
            exit 1
        fi
        show_history "$2"
        ;;
    cleanup)
        cleanup_old_mappings "$2"
        ;;
    help|--help|-h)
        usage
        ;;
    *)
        usage
        exit 1
        ;;
esac
EOF
    
    chmod +x /usr/local/bin/sticky-ip-manager
    
    # Create utility to track MailWizz engagement with security improvements
    cat > /usr/local/bin/track-engagement <<'EOF'
#!/bin/bash

# Email Engagement Tracking Utility
# Records email opens/clicks and associates recipients with sending IPs

MYSQL_PASS=$(cat /root/.mail_db_password 2>/dev/null)
if [ -z "$MYSQL_PASS" ]; then
    echo "Error: Database password not found"
    exit 1
fi

LOG_FILE="/var/log/engagement-tracking.log"

# Ensure log file exists with proper permissions
touch "$LOG_FILE"
chmod 640 "$LOG_FILE"

# Function to escape SQL strings
escape_sql() {
    echo "$1" | sed "s/'/\\\\'/g" | sed 's/"/\\\\"/g' | sed 's/\\/\\\\/g'
}

# Function to validate email format
validate_email_format() {
    local email=$1
    if [[ ! "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        return 1
    fi
    return 0
}

# Function to validate IP address format
validate_ip_format() {
    local ip=$1
    if [[ ! "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        return 1
    fi
    
    # Check each octet
    local IFS='.'
    local -a octets=($ip)
    for octet in "${octets[@]}"; do
        if [ $octet -gt 255 ]; then
            return 1
        fi
    done
    
    return 0
}

# Function to log messages with rotation check
log_message() {
    # Check log size and rotate if needed (10MB limit)
    if [ -f "$LOG_FILE" ] && [ $(stat -c%s "$LOG_FILE" 2>/dev/null || echo 0) -gt 10485760 ]; then
        mv "$LOG_FILE" "${LOG_FILE}.$(date +%Y%m%d%H%M%S)"
        touch "$LOG_FILE"
        chmod 640 "$LOG_FILE"
    fi
    
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

# Function to track an engagement event with validation
track_engagement() {
    local email="$1"
    local ip_address="$2"
    local transport="$3"
    local engagement_type="$4"
    
    # Validate email
    if ! validate_email_format "$email"; then
        log_message "Error: Invalid email format: $email"
        return 1
    fi
    
    # Validate IP address
    if ! validate_ip_format "$ip_address"; then
        log_message "Error: Invalid IP address format: $ip_address"
        return 1
    fi
    
    # Validate transport
    if [[ ! "$transport" =~ ^smtp-ip[0-9]+$ ]]; then
        log_message "Error: Invalid transport format: $transport"
        return 1
    fi
    
    # Validate engagement type
    if [ "$engagement_type" != "open" ] && [ "$engagement_type" != "click" ] && [ "$engagement_type" != "manual" ]; then
        log_message "Error: Invalid engagement type: $engagement_type"
        return 1
    fi
    
    log_message "Recording $engagement_type engagement for $email via $transport ($ip_address)"
    
    # Escape values for SQL
    email=$(escape_sql "$email")
    ip_address=$(escape_sql "$ip_address")
    transport=$(escape_sql "$transport")
    engagement_type=$(escape_sql "$engagement_type")
    
    # Create temporary SQL file
    local tmp_sql=$(mktemp)
    cat > "$tmp_sql" <<SQLEOF
USE mailserver;
-- Update or insert into recipient_ip_mapping
INSERT INTO recipient_ip_mapping (email, ip_address, transport, engagement_type) 
VALUES ('${email}', '${ip_address}', '${transport}', '${engagement_type}')
ON DUPLICATE KEY UPDATE 
    ip_address='${ip_address}', 
    transport='${transport}', 
    last_used=CURRENT_TIMESTAMP, 
    engagement_type='${engagement_type}';

-- Add to engagement history
INSERT INTO engagement_history (email, ip_address, event_type)
VALUES ('${email}', '${ip_address}', '${engagement_type}');
SQLEOF
    
    if mysql -u mailuser -p"$MYSQL_PASS" < "$tmp_sql" 2>/dev/null; then
        log_message "Successfully recorded engagement for $email"
        rm -f "$tmp_sql"
        return 0
    else
        log_message "Error: Failed to record engagement in database"
        rm -f "$tmp_sql"
        return 1
    fi
}

# Function to find transport name from IP address
find_transport_from_ip() {
    local ip="$1"
    local transport=""
    
    # Validate IP first
    if ! validate_ip_format "$ip"; then
        echo ""
        return 1
    fi
    
    # Search through master.cf for matching IP
    for i in {1..50}; do
        if grep -q "^smtp-ip${i} " /etc/postfix/master.cf 2>/dev/null; then
            ip_in_config=$(grep -A 2 "^smtp-ip${i} " /etc/postfix/master.cf 2>/dev/null | \
                          grep "smtp_bind_address" | \
                          grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}')
            if [ "$ip_in_config" = "$ip" ]; then
                transport="smtp-ip${i}"
                break
            fi
        fi
    done
    
    echo "$transport"
}

# Function to extract IP from mail headers
extract_ip_from_headers() {
    local header_file="$1"
    local ip=""
    
    if [ ! -f "$header_file" ]; then
        return 1
    fi
    
    # Try to extract from Received header (most recent)
    ip=$(grep "^Received: from" "$header_file" | \
         head -1 | \
         grep -o '\[[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\]' | \
         tr -d '[]' | \
         head -1)
    
    # If not found, try X-Originating-IP header
    if [ -z "$ip" ]; then
        ip=$(grep "^X-Originating-IP:" "$header_file" | \
             grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' | \
             head -1)
    fi
    
    # If not found, try X-Transport header (custom header)
    if [ -z "$ip" ]; then
        transport=$(grep "^X-Transport:" "$header_file" | cut -d' ' -f2 | tr -d '\r')
        if [ ! -z "$transport" ]; then
            ip=$(grep -A 2 "^$transport " /etc/postfix/master.cf 2>/dev/null | \
                 grep "smtp_bind_address" | \
                 grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}')
        fi
    fi
    
    echo "$ip"
}

# Process click or open event from MailWizz
process_mailwizz_event() {
    local email="$1"
    local event_type="$2"
    local header_file="$3"
    
    # Validate event type
    if [ "$event_type" != "open" ] && [ "$event_type" != "click" ]; then
        log_message "Invalid event type: $event_type"
        return 1
    fi
    
    # Validate email
    if ! validate_email_format "$email"; then
        log_message "Invalid email format: $email"
        return 1
    fi
    
    # Extract the sending IP from header file
    if [ -f "$header_file" ]; then
        ip=$(extract_ip_from_headers "$header_file")
        if [ ! -z "$ip" ] && validate_ip_format "$ip"; then
            transport=$(find_transport_from_ip "$ip")
            if [ ! -z "$transport" ]; then
                track_engagement "$email" "$ip" "$transport" "$event_type"
                return 0
            else
                log_message "Could not determine transport for IP: $ip"
                # Try to find a default transport
                if [ -f /etc/postfix/master.cf ] && grep -q "^smtp-ip1 " /etc/postfix/master.cf; then
                    # Use first available transport as fallback
                    default_ip=$(grep -A 2 "^smtp-ip1 " /etc/postfix/master.cf | \
                                 grep "smtp_bind_address" | \
                                 grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}')
                    if [ ! -z "$default_ip" ]; then
                        track_engagement "$email" "$default_ip" "smtp-ip1" "$event_type"
                        log_message "Used default transport smtp-ip1 for $email"
                        return 0
                    fi
                fi
            fi
        else
            log_message "Could not extract valid IP from header file"
        fi
    else
        log_message "Header file not found: $header_file"
    fi
    
    return 1
}

# Main command handler
case "$1" in
    open)
        if [ -z "$2" ] || [ -z "$3" ]; then
            echo "Usage: $0 open <email> <header_file>"
            exit 1
        fi
        process_mailwizz_event "$2" "open" "$3"
        ;;
    click)
        if [ -z "$2" ] || [ -z "$3" ]; then
            echo "Usage: $0 click <email> <header_file>"
            exit 1
        fi
        process_mailwizz_event "$2" "click" "$3"
        ;;
    manual)
        if [ -z "$2" ] || [ -z "$3" ] || [ -z "$4" ]; then
            echo "Usage: $0 manual <email> <ip_address> <transport>"
            exit 1
        fi
        track_engagement "$2" "$3" "$4" "manual"
        ;;
    test)
        # Test function to verify setup
        echo "Testing sticky IP tracking system..."
        echo "Checking database connection..."
        if mysql -u mailuser -p"$MYSQL_PASS" -e "SELECT 1;" mailserver &>/dev/null; then
            echo "✓ Database connection OK"
        else
            echo "✗ Database connection failed"
        fi
        echo "Checking tables..."
        if mysql -u mailuser -p"$MYSQL_PASS" -e "SELECT COUNT(*) FROM recipient_ip_mapping;" mailserver &>/dev/null; then
            echo "✓ Tables exist"
        else
            echo "✗ Tables not found"
        fi
        echo "Checking log file..."
        if [ -w "$LOG_FILE" ]; then
            echo "✓ Log file writable"
        else
            echo "✗ Log file not writable"
        fi
        ;;
    *)
        echo "Usage: $0 {open|click|manual|test} [parameters]"
        echo ""
        echo "Commands:"
        echo "  open <email> <header_file>       - Record an email open event"
        echo "  click <email> <header_file>      - Record an email click event"
        echo "  manual <email> <ip> <transport>  - Manually record an engagement"
        echo "  test                            - Test the tracking system"
        exit 1
        ;;
esac
EOF

    chmod +x /usr/local/bin/track-engagement
    
    print_message "✓ Sticky IP management utilities created"
    
    # Create a test script to verify sticky IP is working
    cat > /usr/local/bin/test-sticky-ip <<'EOF'
#!/bin/bash

echo "Testing Sticky IP Configuration"
echo "================================"

# Check if database tables exist
echo -n "Checking database tables... "
if mysql -u mailuser -p$(cat /root/.mail_db_password) -e "SELECT 1 FROM recipient_ip_mapping LIMIT 1;" mailserver &>/dev/null; then
    echo "✓ OK"
else
    echo "✗ FAILED"
    echo "  Run: setup_sticky_ip_db"
fi

# Check if Postfix configuration includes sticky IP
echo -n "Checking Postfix configuration... "
if postconf -h transport_maps | grep -q "mysql-recipient-transport-maps"; then
    echo "✓ OK"
else
    echo "✗ Not configured"
    echo "  Run: configure_sticky_ip_postfix"
fi

# Check if utilities are installed
echo -n "Checking utilities... "
if [ -x /usr/local/bin/sticky-ip-manager ] && [ -x /usr/local/bin/track-engagement ]; then
    echo "✓ OK"
else
    echo "✗ Missing"
fi

echo ""
echo "Quick test: Assign test@example.com to smtp-ip1"
/usr/local/bin/sticky-ip-manager assign test@example.com smtp-ip1 2>/dev/null && \
    echo "✓ Assignment successful" || echo "✗ Assignment failed"

echo ""
echo "Current statistics:"
/usr/local/bin/sticky-ip-manager stats 2>/dev/null || echo "No statistics available"
EOF
    
    chmod +x /usr/local/bin/test-sticky-ip
    
    print_message "✓ Sticky IP test utility created at /usr/local/bin/test-sticky-ip"
    
    return 0
}

# Create MailWizz integration for the sticky IP feature with enhanced security
create_mailwizz_sticky_ip_integration() {
    print_message "Creating MailWizz sticky IP integration guide..."
    
    # Generate a secure random webhook secret
    local webhook_secret=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)
    
    # Save the webhook secret securely
    echo "$webhook_secret" > /root/.mailwizz_webhook_secret
    chmod 600 /root/.mailwizz_webhook_secret
    
    # Create the PHP webhook file with improved security
    cat > /var/www/html/track-webhook.php <<'PHPEOF'
<?php
// MailWizz Webhook Handler for Sticky IP Feature
// With enhanced security and rate limiting

// Load configuration
$webhook_secret_file = '/root/.mailwizz_webhook_secret';
if (!file_exists($webhook_secret_file) || !is_readable($webhook_secret_file)) {
    header('HTTP/1.0 500 Internal Server Error');
    error_log('Webhook secret file not accessible');
    exit('Configuration error');
}
$WEBHOOK_SECRET = trim(file_get_contents($webhook_secret_file));

// Rate limiting configuration
$rate_limit_file = '/tmp/webhook_rate_limit.json';
$max_requests_per_minute = 100;

// Function to check rate limit
function check_rate_limit($ip) {
    global $rate_limit_file, $max_requests_per_minute;
    
    $current_time = time();
    $rate_data = [];
    
    if (file_exists($rate_limit_file)) {
        $content = file_get_contents($rate_limit_file);
        if ($content !== false) {
            $rate_data = json_decode($content, true) ?: [];
        }
    }
    
    // Clean old entries (older than 1 minute)
    foreach ($rate_data as $stored_ip => $timestamps) {
        $rate_data[$stored_ip] = array_filter($timestamps, function($t) use ($current_time) {
            return ($current_time - $t) < 60;
        });
        if (empty($rate_data[$stored_ip])) {
            unset($rate_data[$stored_ip]);
        }
    }
    
    // Check current IP
    if (!isset($rate_data[$ip])) {
        $rate_data[$ip] = [];
    }
    
    if (count($rate_data[$ip]) >= $max_requests_per_minute) {
        return false; // Rate limit exceeded
    }
    
    // Add current request
    $rate_data[$ip][] = $current_time;
    
    // Save updated rate data
    file_put_contents($rate_limit_file, json_encode($rate_data), LOCK_EX);
    
    return true;
}

// Get client IP (handle proxies)
$client_ip = $_SERVER['REMOTE_ADDR'];
if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
    $client_ip = trim($ips[0]);
} elseif (!empty($_SERVER['HTTP_X_REAL_IP'])) {
    $client_ip = $_SERVER['HTTP_X_REAL_IP'];
}

// Validate IP format
if (!filter_var($client_ip, FILTER_VALIDATE_IP)) {
    header('HTTP/1.0 400 Bad Request');
    exit('Invalid client IP');
}

// Check rate limit
if (!check_rate_limit($client_ip)) {
    header('HTTP/1.0 429 Too Many Requests');
    header('Retry-After: 60');
    exit('Rate limit exceeded');
}

// Verify webhook secret using timing-safe comparison
if (!isset($_GET['key']) || empty($_GET['key']) || !hash_equals($WEBHOOK_SECRET, $_GET['key'])) {
    header('HTTP/1.0 403 Forbidden');
    error_log("Webhook auth failed from IP: $client_ip");
    exit('Access denied');
}

// Log file for debugging (with rotation)
$logFile = '/var/log/mailwizz-webhook.log';
$maxLogSize = 10 * 1024 * 1024; // 10MB

// Rotate log if needed
if (file_exists($logFile) && filesize($logFile) > $maxLogSize) {
    $rotatedLog = $logFile . '.' . date('YmdHis');
    rename($logFile, $rotatedLog);
    // Compress old log
    exec("gzip $rotatedLog &");
}

// Get and validate the request data
$input = file_get_contents('php://input');
if (strlen($input) > 100000) { // Limit input size to 100KB
    header('HTTP/1.0 413 Payload Too Large');
    exit('Request too large');
}

// Validate JSON
$event = json_decode($input, true);
if (json_last_error() !== JSON_ERROR_NONE) {
    header('HTTP/1.0 400 Bad Request');
    error_log("Invalid JSON from IP: $client_ip");
    exit('Invalid JSON data');
}

// Log the event for debugging
$logMessage = date('[Y-m-d H:i:s] ') . "Event from $client_ip: " . ($event['type'] ?? 'unknown') . "\n";
error_log($logMessage, 3, $logFile);

// Validate event structure
if (empty($event) || empty($event['type']) || empty($event['data']['subscriber_email'])) {
    error_log(date('[Y-m-d H:i:s] ') . "Invalid event data structure\n", 3, $logFile);
    header('HTTP/1.0 400 Bad Request');
    exit('Invalid data structure');
}

// Validate and sanitize email
$email = filter_var($event['data']['subscriber_email'], FILTER_SANITIZE_EMAIL);
$email = filter_var($email, FILTER_VALIDATE_EMAIL);

if (!$email) {
    error_log(date('[Y-m-d H:i:s] ') . "Invalid email format\n", 3, $logFile);
    header('HTTP/1.0 400 Bad Request');
    exit('Invalid email');
}

// Create a temporary file with the message headers
$headerFile = tempnam('/tmp', 'mw_headers_');
if ($headerFile === false) {
    header('HTTP/1.0 500 Internal Server Error');
    error_log("Failed to create temp file\n", 3, $logFile);
    exit('Server error');
}

// Set proper permissions
chmod($headerFile, 0600);

// Write headers to temp file
if (!empty($event['data']['message_headers'])) {
    file_put_contents($headerFile, $event['data']['message_headers']);
} else {
    // Try to extract from other fields
    $headers = '';
    if (!empty($event['data']['campaign_uid'])) {
        $headers .= "X-Campaign-UID: " . $event['data']['campaign_uid'] . "\n";
    }
    if (!empty($event['data']['message_id'])) {
        $headers .= "Message-ID: " . $event['data']['message_id'] . "\n";
    }
    if (!empty($event['data']['sending_ip'])) {
        $headers .= "X-Originating-IP: " . $event['data']['sending_ip'] . "\n";
    }
    file_put_contents($headerFile, $headers);
}

// Determine the event type
$eventType = null;
$validEventTypes = ['open', 'email-open', 'track-open', 'click', 'url-click', 'track-click'];

if (in_array($event['type'], ['open', 'email-open', 'track-open'])) {
    $eventType = 'open';
} elseif (in_array($event['type'], ['click', 'url-click', 'track-click'])) {
    $eventType = 'click';
} else {
    // Not an event we're interested in
    unlink($headerFile);
    echo "Event type not tracked: " . htmlspecialchars($event['type']) . "\n";
    exit(0);
}

// Call the tracking script with timeout
$email_escaped = escapeshellarg($email);
$headerFile_escaped = escapeshellarg($headerFile);
$cmd = "timeout 5 /usr/local/bin/track-engagement {$eventType} {$email_escaped} {$headerFile_escaped} 2>&1";

// Execute command
$output = [];
$returnCode = 0;
exec($cmd, $output, $returnCode);

// Log the result
$resultMsg = "Tracking command for $email (event: $eventType) returned code {$returnCode}";
if (!empty($output)) {
    $resultMsg .= " - Output: " . implode(" ", $output);
}
error_log(date('[Y-m-d H:i:s] ') . $resultMsg . "\n", 3, $logFile);

// Clean up
unlink($headerFile);

// Return success response
header('Content-Type: application/json');
echo json_encode([
    'status' => 'success',
    'message' => "Event processed: {$eventType} for {$email}",
    'timestamp' => date('c')
]);
?>
PHPEOF

    # Set proper permissions for webhook
    chown www-data:www-data /var/www/html/track-webhook.php
    chmod 644 /var/www/html/track-webhook.php
    
    # Create log rotation configuration for engagement logs
    cat > /etc/logrotate.d/engagement-logs <<'EOF'
/var/log/engagement-tracking.log
/var/log/mailwizz-webhook.log
{
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 640 root adm
    sharedscripts
    postrotate
        # Signal any processes that might be writing to these logs
        systemctl reload postfix >/dev/null 2>&1 || true
    endscript
}
EOF
    
    # Create the integration guide with the webhook secret
    cat > /root/mailwizz-sticky-ip-guide.txt <<EOF
======================================================
   MailWizz Sticky IP Integration Guide
======================================================

This guide explains how to integrate the sticky IP feature with MailWizz
to ensure that contacts who open or click emails continue to receive
email from the same IP address.

WEBHOOK CONFIGURATION:
---------------------
Your webhook secret key: $webhook_secret
Webhook URL: https://${DOMAIN_NAME}/track-webhook.php?key=$webhook_secret

IMPORTANT: Keep this secret key secure! It authenticates webhook requests.

TESTING THE STICKY IP SYSTEM:
-----------------------------
Run the test utility to verify everything is working:
  /usr/local/bin/test-sticky-ip

MANUAL MANAGEMENT:
-----------------
Use the sticky IP manager for manual control:
  /usr/local/bin/sticky-ip-manager help

INTEGRATION OVERVIEW:
--------------------
1. The sticky IP feature tracks which recipients have engaged with which IPs
2. When a recipient opens or clicks an email, the system records this engagement
3. Future emails to that recipient will use the same IP address
4. This improves deliverability by maintaining consistent sender reputation

For complete setup instructions, see the full guide above.
EOF

    chmod 644 /root/mailwizz-sticky-ip-guide.txt
    print_message "✓ MailWizz sticky IP integration guide created"
    print_message "✓ Webhook secret saved securely in /root/.mailwizz_webhook_secret"
    
    return 0
}

# Explicitly export all functions to make them available to the main script
export -f setup_sticky_ip_db
export -f configure_sticky_ip_postfix
export -f create_sticky_ip_utility
export -f create_mailwizz_sticky_ip_integration
