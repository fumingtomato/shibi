#!/bin/bash

# =================================================================
# STICKY IP MODULE
# Ensures consistent IP usage for recipients who engage with emails
# =================================================================

# Setup sticky IP database and tables with proper indexes
setup_sticky_ip_db() {
    print_header "Setting Up Sticky IP Feature"
    
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

-- Grant necessary permissions to mailuser
GRANT SELECT, INSERT, UPDATE, DELETE ON mailserver.recipient_ip_mapping TO 'mailuser'@'localhost';

FLUSH PRIVILEGES;
EOF
    
    # Execute the SQL commands
    if mysql -u root < "$SQL_TMPFILE"; then
        print_message "Sticky IP database tables created successfully"
    else
        print_error "Failed to create sticky IP database tables"
        rm -f "$SQL_TMPFILE"
        exit 1
    fi
    
    # Remove temporary SQL file
    rm -f "$SQL_TMPFILE"
    
    # Create the MySQL lookup file for Postfix
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
    
    print_message "Sticky IP database configuration complete"
}

# Configure Postfix to use the sticky IP feature
configure_sticky_ip_postfix() {
    print_message "Configuring Postfix for sticky IP support..."
    
    # Update main.cf to include the recipient-dependent transport lookup
    postconf -e "transport_maps = mysql:/etc/postfix/mysql-recipient-transport-maps.cf, hash:/etc/postfix/transport_maps/domain_transport"
    
    # Update main.cf to prevent connection caching for different recipients
    # This ensures that each recipient gets their own connection
    postconf -e "smtp_connection_cache_on_demand = no"
    
    print_message "Postfix sticky IP configuration complete"
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
    return 0
}

# Function to show usage
usage() {
    echo "Sticky IP Manager Utility"
    echo "=========================="
    echo "Usage:"
    echo "  $0 list [email_pattern]             - List all mappings or filter by email pattern"
    echo "  $0 assign <email> <transport>       - Manually assign email to transport (e.g., smtp-ip1)"
    echo "  $0 remove <email>                   - Remove email mapping (will revert to round-robin)"
    echo "  $0 import <csv_file>                - Import mappings from CSV (email,transport)"
    echo "  $0 export [file]                    - Export mappings to CSV (default: sticky-ip-mappings.csv)"
    echo "  $0 stats                            - Show distribution statistics"
    echo ""
    echo "Examples:"
    echo "  $0 list @example.com                - Show all mappings for @example.com"
    echo "  $0 assign user@example.com smtp-ip2 - Assign user@example.com to IP #2"
    echo ""
}

# Function to list mappings with safe SQL
list_mappings() {
    local filter="$1"
    
    if [ ! -z "$filter" ]; then
        # Escape the filter for safe SQL usage
        filter=$(escape_sql "$filter")
        
        # Create temporary SQL file for safe execution
        local tmp_sql=$(mktemp)
        cat > "$tmp_sql" <<SQLEOF
USE mailserver;
SELECT email, ip_address, transport, last_used, engagement_type 
FROM recipient_ip_mapping 
WHERE email LIKE '%${filter}%'
ORDER BY last_used DESC 
LIMIT 50;
SQLEOF
        
        echo "Recipient-to-IP Mappings (filtered):"
        echo "====================================="
        mysql -u mailuser -p"$MYSQL_PASS" < "$tmp_sql" --table
        rm -f "$tmp_sql"
    else
        echo "Recipient-to-IP Mappings:"
        echo "========================="
        mysql -u mailuser -p"$MYSQL_PASS" mailserver \
            -e "SELECT email, ip_address, transport, last_used, engagement_type FROM recipient_ip_mapping ORDER BY last_used DESC LIMIT 50;" \
            --table
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
    local ip=$(grep -A 2 "$transport " /etc/postfix/master.cf | grep smtp_bind_address | awk -F'=' '{print $2}' | tr -d ' ')
    
    if [ -z "$ip" ]; then
        echo "Error: Transport $transport not found in Postfix configuration."
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
SQLEOF
    
    if mysql -u mailuser -p"$MYSQL_PASS" < "$tmp_sql"; then
        echo "Successfully assigned $email to $transport ($ip)"
        rm -f "$tmp_sql"
        return 0
    else
        echo "Error: Failed to assign $email to $transport"
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
    
    if mysql -u mailuser -p"$MYSQL_PASS" < "$tmp_sql"; then
        echo "Successfully removed mapping for $email"
        rm -f "$tmp_sql"
        return 0
    else
        echo "Error: Failed to remove mapping for $email"
        rm -f "$tmp_sql"
        return 1
    fi
}

# Function to import mappings from CSV with validation
import_mappings() {
    local csv_file="$1"
    
    if [ ! -f "$csv_file" ]; then
        echo "Error: CSV file not found: $csv_file"
        return 1
    fi
    
    echo "Importing mappings from $csv_file..."
    
    local success_count=0
    local error_count=0
    local line_num=0
    
    while IFS=, read -r email transport; do
        line_num=$((line_num + 1))
        
        # Skip empty lines and comments
        if [ -z "$email" ] || [[ "$email" == \#* ]]; then
            continue
        fi
        
        # Trim whitespace
        email=$(echo "$email" | xargs)
        transport=$(echo "$transport" | xargs)
        
        if assign_recipient "$email" "$transport"; then
            success_count=$((success_count + 1))
        else
            echo "Error on line $line_num: Failed to assign $email to $transport"
            error_count=$((error_count + 1))
        fi
    done < "$csv_file"
    
    echo "Import completed: $success_count successful, $error_count failed"
}

# Function to export mappings to CSV
export_mappings() {
    local export_file="${1:-sticky-ip-mappings.csv}"
    
    echo "Exporting mappings to $export_file..."
    
    # Create temporary SQL file
    local tmp_sql=$(mktemp)
    cat > "$tmp_sql" <<SQLEOF
USE mailserver;
SELECT email, transport 
FROM recipient_ip_mapping 
ORDER BY email;
SQLEOF
    
    if mysql -u mailuser -p"$MYSQL_PASS" < "$tmp_sql" -B --skip-column-names > "$export_file"; then
        echo "Successfully exported mappings to $export_file"
        rm -f "$tmp_sql"
        return 0
    else
        echo "Error: Failed to export mappings"
        rm -f "$tmp_sql"
        return 1
    fi
}

# Function to show distribution statistics
show_stats() {
    echo "IP Distribution Statistics:"
    echo "==========================="
    
    mysql -u mailuser -p"$MYSQL_PASS" mailserver -e "
    SELECT 
        transport, 
        COUNT(*) as count, 
        GROUP_CONCAT(DISTINCT engagement_type SEPARATOR ', ') as engagement_types 
    FROM recipient_ip_mapping 
    GROUP BY transport 
    ORDER BY count DESC;" --table
    
    echo ""
    mysql -u mailuser -p"$MYSQL_PASS" mailserver -e "
    SELECT COUNT(*) as 'Total Recipients with Assigned IPs' 
    FROM recipient_ip_mapping;" --table
}

# Main command handler
case "$1" in
    list)
        list_mappings "$2"
        ;;
    assign)
        if [ -z "$2" ] || [ -z "$3" ]; then
            echo "Error: Missing parameters."
            usage
            exit 1
        fi
        assign_recipient "$2" "$3"
        ;;
    remove)
        if [ -z "$2" ]; then
            echo "Error: Missing email parameter."
            usage
            exit 1
        fi
        remove_mapping "$2"
        ;;
    import)
        if [ -z "$2" ]; then
            echo "Error: Missing CSV file parameter."
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

# Function to log messages with rotation check
log_message() {
    # Check log size and rotate if needed (10MB limit)
    if [ -f "$LOG_FILE" ] && [ $(stat -c%s "$LOG_FILE") -gt 10485760 ]; then
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
    if [[ ! "$ip_address" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
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
INSERT INTO recipient_ip_mapping (email, ip_address, transport, engagement_type) 
VALUES ('${email}', '${ip_address}', '${transport}', '${engagement_type}')
ON DUPLICATE KEY UPDATE 
    ip_address='${ip_address}', 
    transport='${transport}', 
    last_used=CURRENT_TIMESTAMP, 
    engagement_type='${engagement_type}';
SQLEOF
    
    if mysql -u mailuser -p"$MYSQL_PASS" < "$tmp_sql"; then
        log_message "Successfully recorded engagement"
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
    
    for i in {1..20}; do
        ip_in_config=$(grep -A 2 "smtp-ip${i}" /etc/postfix/master.cf 2>/dev/null | \
                      grep "smtp_bind_address" | \
                      grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}')
        if [ "$ip_in_config" = "$ip" ]; then
            transport="smtp-ip${i}"
            break
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
    
    # Try to extract from Received header
    ip=$(grep -m 1 "Received: from" "$header_file" | \
         grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' | \
         head -1)
    
    # If not found, try X-Transport header (if added during send)
    if [ -z "$ip" ]; then
        transport=$(grep -m 1 "X-Transport:" "$header_file" | cut -d' ' -f2)
        if [ ! -z "$transport" ]; then
            ip=$(grep -A 2 "$transport" /etc/postfix/master.cf 2>/dev/null | \
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
    
    # Extract the sending IP from header file
    if [ -f "$header_file" ]; then
        ip=$(extract_ip_from_headers "$header_file")
        if [ ! -z "$ip" ]; then
            transport=$(find_transport_from_ip "$ip")
            if [ ! -z "$transport" ]; then
                track_engagement "$email" "$ip" "$transport" "$event_type"
                return 0
            else
                log_message "Could not determine transport for IP: $ip"
            fi
        else
            log_message "Could not extract IP from header file"
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
    *)
        echo "Usage: $0 {open|click|manual} [parameters]"
        echo ""
        echo "Commands:"
        echo "  open <email> <header_file>       - Record an email open event"
        echo "  click <email> <header_file>      - Record an email click event"
        echo "  manual <email> <ip> <transport>  - Manually record an engagement"
        exit 1
        ;;
esac
EOF

    chmod +x /usr/local/bin/track-engagement
    
    print_message "Sticky IP management utilities created"
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
if (!file_exists($webhook_secret_file)) {
    header('HTTP/1.0 500 Internal Server Error');
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
        $rate_data = json_decode(file_get_contents($rate_limit_file), true) ?: [];
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
    file_put_contents($rate_limit_file, json_encode($rate_data));
    
    return true;
}

// Get client IP
$client_ip = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'];

// Check rate limit
if (!check_rate_limit($client_ip)) {
    header('HTTP/1.0 429 Too Many Requests');
    exit('Rate limit exceeded');
}

// Verify webhook secret using timing-safe comparison
if (!isset($_GET['key']) || !hash_equals($WEBHOOK_SECRET, $_GET['key'])) {
    header('HTTP/1.0 403 Forbidden');
    exit('Access denied');
}

// Log file for debugging (with rotation)
$logFile = '/var/log/mailwizz-webhook.log';
$maxLogSize = 10 * 1024 * 1024; // 10MB

// Rotate log if needed
if (file_exists($logFile) && filesize($logFile) > $maxLogSize) {
    rename($logFile, $logFile . '.' . date('YmdHis'));
}

// Get and validate the request data
$input = file_get_contents('php://input');
if (strlen($input) > 100000) { // Limit input size to 100KB
    header('HTTP/1.0 413 Payload Too Large');
    exit('Request too large');
}

$event = json_decode($input, true);

// Log the event for debugging
error_log(date('[Y-m-d H:i:s] ') . "Received event from $client_ip\n", 3, $logFile);

// Validate event structure
if (empty($event) || empty($event['type']) || empty($event['data']['subscriber_email'])) {
    error_log(date('[Y-m-d H:i:s] ') . "Invalid event data\n", 3, $logFile);
    header('HTTP/1.0 400 Bad Request');
    exit('Invalid data');
}

// Validate email format
$email = filter_var($event['data']['subscriber_email'], FILTER_VALIDATE_EMAIL);
if (!$email) {
    error_log(date('[Y-m-d H:i:s] ') . "Invalid email format\n", 3, $logFile);
    header('HTTP/1.0 400 Bad Request');
    exit('Invalid email');
}

// Create a temporary file with the message headers
$headerFile = tempnam('/tmp', 'mw_headers_');
if ($headerFile) {
    // If we have message headers, save them to the temp file
    if (!empty($event['data']['message_headers'])) {
        file_put_contents($headerFile, $event['data']['message_headers']);
    } else {
        // We don't have headers, but we need to create a file anyway
        file_put_contents($headerFile, "X-Transport: unknown\n");
    }
    
    // Determine the event type
    $eventType = null;
    switch ($event['type']) {
        case 'open':
        case 'email-open':
        case 'track-open':
            $eventType = 'open';
            break;
        case 'click':
        case 'url-click':
        case 'track-click':
            $eventType = 'click';
            break;
        default:
            // Not an event we're interested in
            unlink($headerFile);
            echo "Event type not tracked: " . $event['type'] . "\n";
            exit(0);
    }
    
    // Call the tracking script
    $email_escaped = escapeshellarg($email);
    $headerFile_escaped = escapeshellarg($headerFile);
    $cmd = "/usr/local/bin/track-engagement {$eventType} {$email_escaped} {$headerFile_escaped} 2>&1";
    
    // Execute with timeout
    $output = [];
    $returnCode = 0;
    exec("timeout 5 $cmd", $output, $returnCode);
    
    // Log the result
    $resultMsg = "Tracking command executed for $email with result code {$returnCode}: " . implode("\n", $output);
    error_log(date('[Y-m-d H:i:s] ') . $resultMsg . "\n", 3, $logFile);
    
    // Clean up
    unlink($headerFile);
    
    // Return success
    echo "Event processed: {$eventType} for {$email}\n";
} else {
    error_log(date('[Y-m-d H:i:s] ') . "Failed to create temp file\n", 3, $logFile);
    header('HTTP/1.0 500 Internal Server Error');
    exit('Failed to process event');
}
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

INTEGRATION OVERVIEW:
--------------------
1. The sticky IP feature tracks which recipients have engaged with which IPs
2. When a recipient opens or clicks an email, the system records this engagement
3. Future emails to that recipient will use the same IP address
4. This improves deliverability by maintaining consistent sender reputation

SETUP STEPS:
-----------

1. CONFIGURE MAILWIZZ TRACKING DOMAIN:
   a. In MailWizz backend, go to "Settings" → "Tracking domains"
   b. Make sure your tracking domain is properly configured
   c. Ensure the tracking domain uses HTTPS for secure tracking

2. SETUP EMAIL HEADERS:
   Configure your MailWizz delivery servers to add custom headers:
   
   a. In each SMTP delivery server configuration:
      - Add a custom header: X-Transport: smtp-ipN
      (where N is the IP number, matching your Postfix configuration)

3. CONFIGURE MAILWIZZ WEBHOOKS:
   a. In MailWizz backend, go to "Settings" → "Webhooks"
   
   b. Create a new webhook for "Email open" events:
      - URL: https://${DOMAIN_NAME}/track-webhook.php?key=$webhook_secret
      - Method: POST
      - Status: Enabled
   
   c. Create another webhook for "Link clicked" events:
      - URL: https://${DOMAIN_NAME}/track-webhook.php?key=$webhook_secret
      - Method: POST
      - Status: Enabled

4. TEST THE INTEGRATION:
   a. Send a test email to yourself through MailWizz
   b. Open the email and click on a link
   c. Check if the engagement was recorded:
      sudo /usr/local/bin/sticky-ip-manager list youremail@example.com
   d. Check the webhook log:
      sudo tail -f /var/log/mailwizz-webhook.log

USING THE STICKY IP FEATURE:
--------------------------

1. LIST CURRENT MAPPINGS:
   sudo /usr/local/bin/sticky-ip-manager list

2. MANUALLY ASSIGN A RECIPIENT TO A SPECIFIC IP:
   sudo /usr/local/bin/sticky-ip-manager assign user@example.com smtp-ip2

3. REMOVE A RECIPIENT MAPPING (WILL REVERT TO ROUND-ROBIN):
   sudo /usr/local/bin/sticky-ip-manager remove user@example.com

4. IMPORT MAPPINGS FROM CSV:
   Create a CSV file with format: email,transport
   sudo /usr/local/bin/sticky-ip-manager import mappings.csv

5. EXPORT MAPPINGS TO CSV:
   sudo /usr/local/bin/sticky-ip-manager export exported-mappings.csv

6. SHOW DISTRIBUTION STATISTICS:
   sudo /usr/local/bin/sticky-ip-manager stats

MONITORING AND TROUBLESHOOTING:
-------------------------------

1. CHECK THE LOGS:
   - Engagement tracking: tail -f /var/log/engagement-tracking.log
   - Webhook activity: tail -f /var/log/mailwizz-webhook.log
   - Mail delivery: tail -f /var/log/mail.log

2. VERIFY POSTFIX CONFIGURATION:
   grep -A 1 "transport_maps" /etc/postfix/main.cf

3. TEST DATABASE CONNECTIVITY:
   echo "SELECT COUNT(*) FROM recipient_ip_mapping;" | \\
   mysql -u mailuser -p\$(cat /root/.mail_db_password) mailserver

4. CHECK IP ASSIGNMENTS:
   for i in {1..10}; do
     grep -A 2 "smtp-ip\$i" /etc/postfix/master.cf 2>/dev/null
   done

5. MONITOR WEBHOOK RATE LIMITING:
   The webhook endpoint allows max 100 requests per minute per IP.
   Check /tmp/webhook_rate_limit.json for current limits.

PERFORMANCE OPTIMIZATION:
------------------------

1. DATABASE INDEXES:
   The sticky IP tables are properly indexed for fast lookups.
   Regularly optimize the database:
   mysqlcheck -o mailserver

2. LOG ROTATION:
   Logs are automatically rotated daily to prevent disk space issues.
   Check: ls -la /var/log/engagement-tracking.log*

3. CLEANUP OLD MAPPINGS:
   Remove mappings older than 90 days:
   echo "DELETE FROM recipient_ip_mapping WHERE last_used < DATE_SUB(NOW(), INTERVAL 90 DAY);" | \\
   mysql -u mailuser -p\$(cat /root/.mail_db_password) mailserver

SECURITY CONSIDERATIONS:
------------------------

1. The webhook endpoint uses a secret key for authentication
2. Rate limiting prevents abuse (100 requests/minute per IP)
3. Input validation prevents SQL injection
4. Logs are rotated to prevent disk exhaustion

For support and questions, contact your system administrator.
EOF

    chmod 644 /root/mailwizz-sticky-ip-guide.txt
    print_message "MailWizz sticky IP integration guide created at /root/mailwizz-sticky-ip-guide.txt"
    print_message "Webhook secret saved securely in /root/.mailwizz_webhook_secret"
}

# Explicitly export all functions to make them available to the main script
export -f setup_sticky_ip_db configure_sticky_ip_postfix create_sticky_ip_utility create_mailwizz_sticky_ip_integration
