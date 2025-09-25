#!/bin/bash

# =================================================================
# STICKY IP MODULE
# Ensures consistent IP usage for recipients who engage with emails
# =================================================================

# Setup sticky IP database and tables
setup_sticky_ip_db() {
    print_header "Setting Up Sticky IP Feature"
    
    # Create a secure temporary SQL file
    SQL_TMPFILE=$(mktemp)
    chmod 600 "$SQL_TMPFILE"
    
    # Add the recipient_ip_mapping table to the mailserver database
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
  UNIQUE KEY email (email)
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
    
    # Ensure sticky IP transport is checked before sender-dependent transport
    postconf -e "transport_maps_rbl_domains = mysql:/etc/postfix/mysql-recipient-transport-maps.cf"
    
    # Update main.cf to prevent connection caching for different recipients
    # This ensures that each recipient gets their own connection
    postconf -e "smtp_connection_cache_on_demand = no"
    
    print_message "Postfix sticky IP configuration complete"
}

# Create utility to manually assign a recipient to a specific IP
create_sticky_ip_utility() {
    print_message "Creating sticky IP management utilities..."
    
    cat > /usr/local/bin/sticky-ip-manager <<'EOF'
#!/bin/bash

# Sticky IP Manager Utility
# Manages recipient-to-IP mappings for consistent email delivery

MYSQL_PASS=$(cat /root/.mail_db_password)

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

# Function to list mappings
list_mappings() {
    local filter="$1"
    local query="SELECT email, ip_address, transport, last_used, engagement_type FROM recipient_ip_mapping"
    
    if [ ! -z "$filter" ]; then
        query="$query WHERE email LIKE '%$filter%'"
    fi
    
    query="$query ORDER BY last_used DESC LIMIT 50;"
    
    echo "Recipient-to-IP Mappings:"
    echo "========================="
    mysql -u mailuser -p"$MYSQL_PASS" mailserver -e "$query" --table
}

# Function to assign a recipient to a specific transport
assign_recipient() {
    local email="$1"
    local transport="$2"
    
    # Extract IP from master.cf
    local ip=$(grep -A 2 "$transport " /etc/postfix/master.cf | grep smtp_bind_address | awk -F'=' '{print $2}' | tr -d ' ')
    
    if [ -z "$ip" ]; then
        echo "Error: Transport $transport not found in Postfix configuration."
        return 1
    fi
    
    local query="INSERT INTO recipient_ip_mapping (email, ip_address, transport, engagement_type) 
                VALUES ('$email', '$ip', '$transport', 'manual')
                ON DUPLICATE KEY UPDATE ip_address='$ip', transport='$transport', 
                last_used=CURRENT_TIMESTAMP, engagement_type='manual';"
    
    if mysql -u mailuser -p"$MYSQL_PASS" mailserver -e "$query"; then
        echo "Successfully assigned $email to $transport ($ip)"
    else
        echo "Error: Failed to assign $email to $transport"
        return 1
    fi
}

# Function to remove a mapping
remove_mapping() {
    local email="$1"
    local query="DELETE FROM recipient_ip_mapping WHERE email='$email';"
    
    if mysql -u mailuser -p"$MYSQL_PASS" mailserver -e "$query"; then
        echo "Successfully removed mapping for $email"
    else
        echo "Error: Failed to remove mapping for $email"
        return 1
    fi
}

# Function to import mappings from CSV
import_mappings() {
    local csv_file="$1"
    
    if [ ! -f "$csv_file" ]; then
        echo "Error: CSV file not found: $csv_file"
        return 1
    fi
    
    echo "Importing mappings from $csv_file..."
    
    while IFS=, read -r email transport; do
        assign_recipient "$email" "$transport"
    done < "$csv_file"
    
    echo "Import completed."
}

# Function to export mappings to CSV
export_mappings() {
    local export_file="${1:-sticky-ip-mappings.csv}"
    local query="SELECT email, transport FROM recipient_ip_mapping ORDER BY email;"
    
    if mysql -u mailuser -p"$MYSQL_PASS" mailserver -e "$query" -B --skip-column-names > "$export_file"; then
        echo "Successfully exported mappings to $export_file"
    else
        echo "Error: Failed to export mappings"
        return 1
    fi
}

# Function to show distribution statistics
show_stats() {
    local query="SELECT transport, COUNT(*) as count, 
                GROUP_CONCAT(DISTINCT engagement_type SEPARATOR ', ') as engagement_types 
                FROM recipient_ip_mapping 
                GROUP BY transport 
                ORDER BY count DESC;"
    
    echo "IP Distribution Statistics:"
    echo "==========================="
    mysql -u mailuser -p"$MYSQL_PASS" mailserver -e "$query" --table
    
    echo ""
    local total_query="SELECT COUNT(*) as 'Total Recipients with Assigned IPs' FROM recipient_ip_mapping;"
    mysql -u mailuser -p"$MYSQL_PASS" mailserver -e "$total_query" --table
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
    
    # Create utility to track MailWizz engagement
    cat > /usr/local/bin/track-engagement <<'EOF'
#!/bin/bash

# Email Engagement Tracking Utility
# Records email opens/clicks and associates recipients with sending IPs

MYSQL_PASS=$(cat /root/.mail_db_password)
LOG_FILE="/var/log/engagement-tracking.log"

# Function to log messages
log_message() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

# Function to track an engagement event
track_engagement() {
    local email="$1"
    local ip_address="$2"
    local transport="$3"
    local engagement_type="$4"
    
    log_message "Recording $engagement_type engagement for $email via $transport ($ip_address)"
    
    local query="INSERT INTO recipient_ip_mapping (email, ip_address, transport, engagement_type) 
                VALUES ('$email', '$ip_address', '$transport', '$engagement_type')
                ON DUPLICATE KEY UPDATE ip_address='$ip_address', transport='$transport', 
                last_used=CURRENT_TIMESTAMP, engagement_type='$engagement_type';"
    
    if mysql -u mailuser -p"$MYSQL_PASS" mailserver -e "$query"; then
        log_message "Successfully recorded engagement"
        return 0
    else
        log_message "Error: Failed to record engagement"
        return 1
    fi
}

# Function to find transport name from IP address
find_transport_from_ip() {
    local ip="$1"
    local transport=""
    
    for i in {1..20}; do
        ip_in_config=$(grep -A 2 "smtp-ip${i}" /etc/postfix/master.cf | grep "smtp_bind_address" | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}')
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
    
    # Try to extract from Received header
    ip=$(grep -m 1 "Received: from" "$header_file" | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' | head -1)
    
    # If not found, try X-Transport header (if added during send)
    if [ -z "$ip" ]; then
        transport=$(grep -m 1 "X-Transport:" "$header_file" | cut -d' ' -f2)
        if [ ! -z "$transport" ]; then
            ip=$(grep -A 2 "$transport" /etc/postfix/master.cf | grep "smtp_bind_address" | grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}')
        fi
    fi
    
    echo "$ip"
}

# Process click or open event from MailWizz
process_mailwizz_event() {
    local email="$1"
    local event_type="$2"
    local header_file="$3"
    
    # Make sure the event type is valid
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

# Create MailWizz integration for the sticky IP feature
create_mailwizz_sticky_ip_integration() {
    print_message "Creating MailWizz sticky IP integration guide..."
    
    cat > /root/mailwizz-sticky-ip-guide.txt <<'EOF'
======================================================
   MailWizz Sticky IP Integration Guide
======================================================

This guide explains how to integrate the sticky IP feature with MailWizz
to ensure that contacts who open or click emails continue to receive
email from the same IP address.

INTEGRATION OVERVIEW:
--------------------
1. The sticky IP feature tracks which recipients have engaged with which IPs
2. When a recipient opens or clicks an email, the system records this engagement
3. Future emails to that recipient will use the same IP address
4. This improves deliverability by maintaining consistent sender reputation

SETUP STEPS:
-----------

1. CONFIGURE MAILWIZZ TRACKING DOMAIN:
   a. In MailWizz admin area, go to "Settings" → "Tracking domains"
   b. Make sure your tracking domain is properly configured
   c. Ensure the tracking domain uses HTTPS for secure tracking

2. SETUP EMAIL HEADERS:
   Make sure your MailWizz delivery servers add custom headers to track which
   IP sent each email:
   
   a. In each SMTP delivery server configuration:
      - Add a custom header: X-Transport: smtp-ipN
      (where N is the IP number, matching your Postfix configuration)

3. CREATE WEBHOOK INTEGRATION:
   Create webhook scripts to capture open and click events from MailWizz
   and update the sticky IP database.

   a. Create a new file /var/www/html/track-webhook.php with the following content:

<?php
// Define secret key to secure the webhook (change this to a random value!)
define('WEBHOOK_SECRET', 'CHANGE_THIS_TO_A_RANDOM_SECRET_STRING');

// Log file for debugging
$logFile = '/var/log/mailwizz-webhook.log';

// Verify the request
if (!isset($_GET['key']) || $_GET['key'] !== WEBHOOK_SECRET) {
    header('HTTP/1.0 403 Forbidden');
    exit('Access denied');
}

// Get the request data
$data = file_get_contents('php://input');
$event = json_decode($data, true);

// Log the event for debugging
file_put_contents($logFile, date('[Y-m-d H:i:s] ') . "Received event: " . print_r($event, true) . "\n", FILE_APPEND);

// Make sure we have the required data
if (empty($event) || empty($event['type']) || empty($event['data']['subscriber_email'])) {
    file_put_contents($logFile, date('[Y-m-d H:i:s] ') . "Invalid event data\n", FILE_APPEND);
    header('HTTP/1.0 400 Bad Request');
    exit('Invalid data');
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
    $eventType = 'unknown';
    switch ($event['type']) {
        case 'open':
            $eventType = 'open';
            break;
        case 'click':
            $eventType = 'click';
            break;
        default:
            // Not an event we're interested in
            unlink($headerFile);
            exit('Event type not tracked');
    }
    
    // Call the tracking script
    $email = escapeshellarg($event['data']['subscriber_email']);
    $cmd = "/usr/local/bin/track-engagement {$eventType} {$email} {$headerFile}";
    exec($cmd, $output, $returnCode);
    
    // Log the result
    $resultMsg = "Tracking command executed with result code {$returnCode}: " . implode("\n", $output);
    file_put_contents($logFile, date('[Y-m-d H:i:s] ') . $resultMsg . "\n", FILE_APPEND);
    
    // Clean up
    unlink($headerFile);
    
    // Return success
    echo "Event processed: {$eventType} for {$event['data']['subscriber_email']}\n";
} else {
    file_put_contents($logFile, date('[Y-m-d H:i:s] ') . "Failed to create temp file\n", FILE_APPEND);
    header('HTTP/1.0 500 Internal Server Error');
    exit('Failed to process event');
}
?>

4. CONFIGURE MAILWIZZ WEBHOOKS:
   a. In MailWizz admin area, go to "Settings" → "Webhooks"
   b. Create a new webhook for "Email open" events:
      - URL: https://yourdomain.com/track-webhook.php?key=YOUR_SECRET_KEY
      - Method: POST
      - Status: Enabled
   
   c. Create another webhook for "Link clicked" events:
      - URL: https://yourdomain.com/track-webhook.php?key=YOUR_SECRET_KEY
      - Method: POST
      - Status: Enabled

5. TEST THE INTEGRATION:
   a. Send a test email to yourself through MailWizz
   b. Open the email and click on a link
   c. Check if the engagement was recorded:
      sudo /usr/local/bin/sticky-ip-manager list youremail@example.com

USING THE STICKY IP FEATURE:
--------------------------

1. LIST CURRENT MAPPINGS:
   sudo /usr/local/bin/sticky-ip-manager list

2. MANUALLY ASSIGN A RECIPIENT TO A SPECIFIC IP:
   sudo /usr/local/bin/sticky-ip-manager assign user@example.com smtp-ip2

3. REMOVE A RECIPIENT MAPPING (WILL REVERT TO ROUND-ROBIN):
   sudo /usr/local/bin/sticky-ip-manager remove user@example.com

4. IMPORT MAPPINGS FROM CSV:
   sudo /usr/local/bin/sticky-ip-manager import mappings.csv

5. EXPORT MAPPINGS TO CSV:
   sudo /usr/local/bin/sticky-ip-manager export exported-mappings.csv

6. SHOW DISTRIBUTION STATISTICS:
   sudo /usr/local/bin/sticky-ip-manager stats

TROUBLESHOOTING:
--------------

1. CHECK THE LOGS:
   - Engagement tracking log: /var/log/engagement-tracking.log
   - Webhook log: /var/log/mailwizz-webhook.log
   - Mail log: /var/log/mail.log

2. VERIFY POSTFIX CONFIGURATION:
   grep -A 1 "transport_maps" /etc/postfix/main.cf

3. TEST DATABASE LOOKUP:
   echo "SELECT * FROM recipient_ip_mapping LIMIT 5;" | mysql -u mailuser -p mailserver

4. VERIFY IP USAGE IN POSTFIX:
   grep -A 2 "smtp-ip" /etc/postfix/master.cf

For support and questions, contact your system administrator.
EOF

    chmod 644 /root/mailwizz-sticky-ip-guide.txt
    print_message "MailWizz sticky IP integration guide created at /root/mailwizz-sticky-ip-guide.txt"
}

# Export functions
export -f setup_sticky_ip_db configure_sticky_ip_postfix create_sticky_ip_utility create_mailwizz_sticky_ip_integration
