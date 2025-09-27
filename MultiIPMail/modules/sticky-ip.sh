#!/bin/bash

# =================================================================
# STICKY IP CONFIGURATION MODULE - FIXED VERSION
# Persistent sender-to-IP mapping for consistent email delivery
# Fixed: Database schema, IP assignment logic, rotation management
# =================================================================

# Global variables for sticky IP
export STICKY_IP_ENABLED=${ENABLE_STICKY_IP:-"n"}
export STICKY_IP_DB="/var/lib/postfix/sticky_ip.db"
export STICKY_IP_LOG="/var/log/postfix/sticky_ip.log"
export STICKY_IP_EXPIRE_DAYS=30
export STICKY_IP_MAX_SENDERS_PER_IP=100

# Initialize sticky IP database
init_sticky_ip_database() {
    print_message "Initializing sticky IP database..."
    
    # Create directory if not exists
    local db_dir=$(dirname "$STICKY_IP_DB")
    mkdir -p "$db_dir"
    chown postfix:postfix "$db_dir"
    
    # Create SQLite database for sticky IP mappings
    sqlite3 "$STICKY_IP_DB" <<EOF
-- Sticky IP mapping table
CREATE TABLE IF NOT EXISTS sticky_mappings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_email TEXT NOT NULL UNIQUE,
    sender_domain TEXT NOT NULL,
    assigned_ip TEXT NOT NULL,
    ip_index INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    message_count INTEGER DEFAULT 0,
    INDEX idx_sender_email (sender_email),
    INDEX idx_sender_domain (sender_domain),
    INDEX idx_assigned_ip (assigned_ip),
    INDEX idx_last_used (last_used)
);

-- IP pool table
CREATE TABLE IF NOT EXISTS ip_pool (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL UNIQUE,
    ip_index INTEGER NOT NULL,
    hostname TEXT,
    active INTEGER DEFAULT 1,
    sender_count INTEGER DEFAULT 0,
    total_messages INTEGER DEFAULT 0,
    last_assigned TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_ip_address (ip_address),
    INDEX idx_active (active),
    INDEX idx_sender_count (sender_count)
);

-- Usage statistics table
CREATE TABLE IF NOT EXISTS usage_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL,
    date DATE NOT NULL,
    message_count INTEGER DEFAULT 0,
    sender_count INTEGER DEFAULT 0,
    bounce_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(ip_address, date),
    INDEX idx_date (date),
    INDEX idx_ip_date (ip_address, date)
);

-- Rotation log table
CREATE TABLE IF NOT EXISTS rotation_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_email TEXT NOT NULL,
    old_ip TEXT,
    new_ip TEXT NOT NULL,
    reason TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_sender (sender_email),
    INDEX idx_created (created_at)
);

-- Create views for monitoring
CREATE VIEW IF NOT EXISTS ip_load_balance AS
SELECT 
    ip_address,
    sender_count,
    total_messages,
    ROUND(CAST(sender_count AS FLOAT) / ${STICKY_IP_MAX_SENDERS_PER_IP} * 100, 2) as load_percent
FROM ip_pool
WHERE active = 1
ORDER BY sender_count ASC;

CREATE VIEW IF NOT EXISTS sender_activity AS
SELECT 
    sender_email,
    assigned_ip,
    message_count,
    datetime(last_used) as last_activity,
    CAST((julianday('now') - julianday(last_used)) AS INTEGER) as days_inactive
FROM sticky_mappings
ORDER BY last_used DESC;
EOF
    
    # Set proper permissions
    chown postfix:postfix "$STICKY_IP_DB"
    chmod 660 "$STICKY_IP_DB"
    
    # Initialize IP pool with configured IPs
    populate_ip_pool
    
    print_message "✓ Sticky IP database initialized"
}

# Populate IP pool with available IPs
populate_ip_pool() {
    print_message "Populating IP pool..."
    
    local index=0
    for ip in "${IP_ADDRESSES[@]}"; do
        local hostname="${HOSTNAMES[$index]:-mail-$index.$DOMAIN_NAME}"
        
        sqlite3 "$STICKY_IP_DB" <<EOF
INSERT OR IGNORE INTO ip_pool (ip_address, ip_index, hostname, active, sender_count)
VALUES ('$ip', $index, '$hostname', 1, 0);
EOF
        
        index=$((index + 1))
    done
    
    print_message "✓ IP pool populated with ${#IP_ADDRESSES[@]} addresses"
}

# Setup sticky IP for Postfix
setup_sticky_ip() {
    print_header "Setting up Sticky IP Configuration"
    
    if [ "$STICKY_IP_ENABLED" != "y" ] && [ "$STICKY_IP_ENABLED" != "yes" ]; then
        print_message "Sticky IP is disabled. Skipping configuration."
        return 0
    fi
    
    # Initialize database
    init_sticky_ip_database
    
    # Create sticky IP policy service
    create_sticky_ip_policy_service
    
    # Create IP assignment script
    create_ip_assignment_script
    
    # Configure Postfix to use sticky IP
    configure_postfix_sticky_ip
    
    # Create maintenance scripts
    create_sticky_ip_maintenance_scripts
    
    # Setup monitoring
    setup_sticky_ip_monitoring
    
    # Create management commands
    create_sticky_ip_management_commands
    
    print_message "✓ Sticky IP configuration completed"
}

# Create sticky IP policy service
create_sticky_ip_policy_service() {
    print_message "Creating sticky IP policy service..."
    
    cat > /usr/local/bin/sticky-ip-policy <<'EOF'
#!/usr/bin/env python3

import sys
import sqlite3
import syslog
import random
from datetime import datetime, timedelta

# Configuration
DB_PATH = '/var/lib/postfix/sticky_ip.db'
MAX_SENDERS_PER_IP = 100
EXPIRE_DAYS = 30

def log_message(msg, priority=syslog.LOG_INFO):
    """Log message to syslog"""
    syslog.openlog("sticky-ip-policy")
    syslog.syslog(priority, msg)
    syslog.closelog()

def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def get_least_loaded_ip(conn):
    """Get IP with least senders assigned"""
    cursor = conn.cursor()
    cursor.execute("""
        SELECT ip_address, sender_count 
        FROM ip_pool 
        WHERE active = 1 AND sender_count < ?
        ORDER BY sender_count ASC, RANDOM()
        LIMIT 1
    """, (MAX_SENDERS_PER_IP,))
    
    result = cursor.fetchone()
    if result:
        return result['ip_address']
    
    # If all IPs are at max capacity, return random IP
    cursor.execute("""
        SELECT ip_address FROM ip_pool 
        WHERE active = 1 
        ORDER BY RANDOM() LIMIT 1
    """)
    result = cursor.fetchone()
    return result['ip_address'] if result else None

def get_sticky_ip(sender_email, conn):
    """Get or assign sticky IP for sender"""
    cursor = conn.cursor()
    
    # Extract domain from email
    sender_domain = sender_email.split('@')[-1] if '@' in sender_email else 'unknown'
    
    # Check existing mapping
    cursor.execute("""
        SELECT assigned_ip, last_used 
        FROM sticky_mappings 
        WHERE sender_email = ?
    """, (sender_email,))
    
    result = cursor.fetchone()
    
    if result:
        # Check if mapping is expired
        last_used = datetime.strptime(result['last_used'], '%Y-%m-%d %H:%M:%S')
        if datetime.now() - last_used > timedelta(days=EXPIRE_DAYS):
            # Expired - reassign
            old_ip = result['assigned_ip']
            new_ip = get_least_loaded_ip(conn)
            
            if new_ip:
                # Update mapping
                cursor.execute("""
                    UPDATE sticky_mappings 
                    SET assigned_ip = ?, last_used = datetime('now'), ip_index = 
                        (SELECT ip_index FROM ip_pool WHERE ip_address = ?)
                    WHERE sender_email = ?
                """, (new_ip, new_ip, sender_email))
                
                # Update IP pool counters
                cursor.execute("UPDATE ip_pool SET sender_count = sender_count - 1 WHERE ip_address = ?", (old_ip,))
                cursor.execute("UPDATE ip_pool SET sender_count = sender_count + 1 WHERE ip_address = ?", (new_ip,))
                
                # Log rotation
                cursor.execute("""
                    INSERT INTO rotation_log (sender_email, old_ip, new_ip, reason)
                    VALUES (?, ?, ?, 'expired')
                """, (sender_email, old_ip, new_ip))
                
                conn.commit()
                log_message(f"Rotated expired IP for {sender_email}: {old_ip} -> {new_ip}")
                return new_ip
        else:
            # Valid mapping exists - update last used
            cursor.execute("""
                UPDATE sticky_mappings 
                SET last_used = datetime('now'), message_count = message_count + 1
                WHERE sender_email = ?
            """, (sender_email,))
            conn.commit()
            return result['assigned_ip']
    
    # No existing mapping - assign new IP
    new_ip = get_least_loaded_ip(conn)
    
    if new_ip:
        cursor.execute("""
            INSERT INTO sticky_mappings (sender_email, sender_domain, assigned_ip, ip_index)
            SELECT ?, ?, ?, ip_index FROM ip_pool WHERE ip_address = ?
        """, (sender_email, sender_domain, new_ip, new_ip))
        
        cursor.execute("UPDATE ip_pool SET sender_count = sender_count + 1 WHERE ip_address = ?", (new_ip,))
        conn.commit()
        
        log_message(f"Assigned new IP for {sender_email}: {new_ip}")
        return new_ip
    
    log_message(f"No available IP for {sender_email}", syslog.LOG_WARNING)
    return None

def process_policy_request():
    """Process Postfix policy request"""
    request = {}
    
    # Read request from stdin
    while True:
        line = sys.stdin.readline().strip()
        if not line:
            break
        
        if '=' in line:
            key, value = line.split('=', 1)
            request[key] = value
    
    # Get sender
    sender = request.get('sender', '').lower()
    
    if not sender:
        print("action=DUNNO")
        print("")
        return
    
    try:
        # Get database connection
        conn = get_db_connection()
        
        # Get sticky IP
        assigned_ip = get_sticky_ip(sender, conn)
        
        if assigned_ip:
            # Return IP as transport
            print(f"action=FILTER smtp:[{assigned_ip}]")
            log_message(f"Policy: {sender} -> {assigned_ip}")
        else:
            print("action=DUNNO")
            log_message(f"Policy: No IP for {sender}", syslog.LOG_WARNING)
        
        conn.close()
    except Exception as e:
        log_message(f"Policy error: {str(e)}", syslog.LOG_ERR)
        print("action=DUNNO")
    
    print("")
    sys.stdout.flush()

if __name__ == "__main__":
    try:
        process_policy_request()
    except Exception as e:
        log_message(f"Fatal error: {str(e)}", syslog.LOG_ERR)
        print("action=DUNNO")
        print("")
EOF
    
    chmod +x /usr/local/bin/sticky-ip-policy
    
    print_message "✓ Sticky IP policy service created"
}

# Create IP assignment script
create_ip_assignment_script() {
    print_message "Creating IP assignment script..."
    
    cat > /usr/local/bin/assign-sticky-ip <<'EOF'
#!/bin/bash

# Manual sticky IP assignment script
SENDER="$1"
IP="$2"
DB="/var/lib/postfix/sticky_ip.db"

if [ -z "$SENDER" ] || [ -z "$IP" ]; then
    echo "Usage: $0 <sender@email> <ip_address>"
    exit 1
fi

# Check if IP exists in pool
IP_EXISTS=$(sqlite3 "$DB" "SELECT COUNT(*) FROM ip_pool WHERE ip_address='$IP' AND active=1")

if [ "$IP_EXISTS" -eq 0 ]; then
    echo "Error: IP $IP not found in active pool"
    exit 1
fi

# Check existing assignment
CURRENT_IP=$(sqlite3 "$DB" "SELECT assigned_ip FROM sticky_mappings WHERE sender_email='$SENDER'")

if [ ! -z "$CURRENT_IP" ]; then
    echo "Updating assignment for $SENDER: $CURRENT_IP -> $IP"
    
    # Update assignment
    sqlite3 "$DB" <<SQL
UPDATE sticky_mappings SET assigned_ip='$IP', last_used=datetime('now') WHERE sender_email='$SENDER';
UPDATE ip_pool SET sender_count = sender_count - 1 WHERE ip_address='$CURRENT_IP';
UPDATE ip_pool SET sender_count = sender_count + 1 WHERE ip_address='$IP';
INSERT INTO rotation_log (sender_email, old_ip, new_ip, reason) VALUES ('$SENDER', '$CURRENT_IP', '$IP', 'manual');
SQL
else
    echo "Creating new assignment for $SENDER: $IP"
    
    # Create new assignment
    DOMAIN="${SENDER#*@}"
    sqlite3 "$DB" <<SQL
INSERT INTO sticky_mappings (sender_email, sender_domain, assigned_ip, ip_index)
SELECT '$SENDER', '$DOMAIN', '$IP', ip_index FROM ip_pool WHERE ip_address='$IP';
UPDATE ip_pool SET sender_count = sender_count + 1 WHERE ip_address='$IP';
SQL
fi

echo "✓ Assignment completed"

# Show current stats
echo ""
echo "Current IP load:"
sqlite3 -column -header "$DB" "SELECT ip_address, sender_count, load_percent || '%' as load FROM ip_load_balance"
EOF
    
    chmod +x /usr/local/bin/assign-sticky-ip
    
    print_message "✓ IP assignment script created"
}

# Configure Postfix to use sticky IP
configure_postfix_sticky_ip() {
    print_message "Configuring Postfix for sticky IP..."
    
    # Add policy service to master.cf
    if ! grep -q "sticky-ip-policy" /etc/postfix/master.cf; then
        cat >> /etc/postfix/master.cf <<EOF

# Sticky IP policy service
sticky-ip-policy unix - n n - 0 spawn
  user=postfix argv=/usr/local/bin/sticky-ip-policy
EOF
    fi
    
    # Configure main.cf
    postconf -e "smtpd_sender_restrictions = check_policy_service unix:private/sticky-ip-policy, permit"
    
    # Create transport map updater
    cat > /usr/local/bin/update-sticky-transports <<'EOF'
#!/bin/bash

# Update Postfix transport maps from sticky IP database
DB="/var/lib/postfix/sticky_ip.db"
TRANSPORT_FILE="/etc/postfix/sticky_transport"

echo "# Sticky IP transport map - Generated $(date)" > "$TRANSPORT_FILE"
echo "" >> "$TRANSPORT_FILE"

# Export active mappings
sqlite3 "$DB" <<SQL | while read line; do
SELECT sender_email || ' smtp:[' || assigned_ip || ']'
FROM sticky_mappings
WHERE datetime(last_used) >= datetime('now', '-30 days');
SQL
    echo "$line" >> "$TRANSPORT_FILE"
done

# Compile the map
postmap "$TRANSPORT_FILE"

# Reload Postfix
postfix reload

echo "✓ Transport map updated with $(wc -l < $TRANSPORT_FILE) entries"
EOF
    
    chmod +x /usr/local/bin/update-sticky-transports
    
    # Run initial update
    /usr/local/bin/update-sticky-transports
    
    print_message "✓ Postfix configured for sticky IP"
}

# Create sticky IP maintenance scripts
create_sticky_ip_maintenance_scripts() {
    print_message "Creating maintenance scripts..."
    
    # Cleanup script
    cat > /usr/local/bin/sticky-ip-cleanup <<'EOF'
#!/bin/bash

# Sticky IP database cleanup
DB="/var/lib/postfix/sticky_ip.db"
EXPIRE_DAYS=30

echo "Cleaning up sticky IP database..."

# Remove expired mappings
DELETED=$(sqlite3 "$DB" <<SQL
DELETE FROM sticky_mappings 
WHERE datetime(last_used) < datetime('now', '-${EXPIRE_DAYS} days');
SELECT changes();
SQL
)

echo "Removed $DELETED expired mappings"

# Update sender counts
sqlite3 "$DB" <<SQL
UPDATE ip_pool SET sender_count = (
    SELECT COUNT(*) FROM sticky_mappings 
    WHERE assigned_ip = ip_pool.ip_address
);
SQL

# Vacuum database
sqlite3 "$DB" "VACUUM;"

# Update statistics
DATE=$(date +%Y-%m-%d)
sqlite3 "$DB" <<SQL
INSERT OR REPLACE INTO usage_stats (ip_address, date, sender_count, message_count)
SELECT 
    p.ip_address,
    '$DATE',
    p.sender_count,
    COALESCE(SUM(m.message_count), 0)
FROM ip_pool p
LEFT JOIN sticky_mappings m ON m.assigned_ip = p.ip_address
GROUP BY p.ip_address;
SQL

echo "✓ Cleanup completed"

# Show current statistics
echo ""
echo "IP Pool Status:"
sqlite3 -column -header "$DB" "SELECT * FROM ip_load_balance"
EOF
    
    chmod +x /usr/local/bin/sticky-ip-cleanup
    
    # Add to cron for daily cleanup
    if ! crontab -l 2>/dev/null | grep -q "sticky-ip-cleanup"; then
        (crontab -l 2>/dev/null; echo "0 2 * * * /usr/local/bin/sticky-ip-cleanup >> $STICKY_IP_LOG 2>&1") | crontab -
    fi
    
    print_message "✓ Maintenance scripts created"
}

# Setup sticky IP monitoring
setup_sticky_ip_monitoring() {
    print_message "Setting up sticky IP monitoring..."
    
    # Create monitoring script
    cat > /usr/local/bin/monitor-sticky-ip <<'EOF'
#!/bin/bash

# Sticky IP monitoring script
DB="/var/lib/postfix/sticky_ip.db"

echo "STICKY IP MONITORING REPORT"
echo "==========================="
echo "Generated: $(date)"
echo ""

echo "IP POOL STATUS:"
echo "---------------"
sqlite3 -column -header "$DB" <<SQL
SELECT 
    ip_address as 'IP Address',
    sender_count as 'Senders',
    load_percent || '%' as 'Load',
    CASE active WHEN 1 THEN 'Active' ELSE 'Inactive' END as 'Status'
FROM ip_load_balance;
SQL

echo ""
echo "TOP SENDERS (Last 24 hours):"
echo "----------------------------"
sqlite3 -column -header "$DB" <<SQL
SELECT 
    sender_email as 'Sender',
    assigned_ip as 'Assigned IP',
    message_count as 'Messages',
    datetime(last_used) as 'Last Activity'
FROM sticky_mappings
WHERE datetime(last_used) >= datetime('now', '-1 day')
ORDER BY message_count DESC
LIMIT 10;
SQL

echo ""
echo "RECENT ROTATIONS:"
echo "-----------------"
sqlite3 -column -header "$DB" <<SQL
SELECT 
    datetime(created_at) as 'Time',
    sender_email as 'Sender',
    old_ip as 'Old IP',
    new_ip as 'New IP',
    reason as 'Reason'
FROM rotation_log
ORDER BY created_at DESC
LIMIT 10;
SQL

echo ""
echo "DAILY STATISTICS:"
echo "-----------------"
sqlite3 -column -header "$DB" <<SQL
SELECT 
    date as 'Date',
    SUM(message_count) as 'Total Messages',
    SUM(sender_count) as 'Total Senders',
    COUNT(DISTINCT ip_address) as 'Active IPs'
FROM usage_stats
WHERE date >= date('now', '-7 days')
GROUP BY date
ORDER BY date DESC;
SQL
EOF
    
    chmod +x /usr/local/bin/monitor-sticky-ip
    
    print_message "✓ Monitoring setup completed"
}

# Create sticky IP management commands
create_sticky_ip_management_commands() {
    print_message "Creating management commands..."
    
    # List assignments
    cat > /usr/local/bin/list-sticky-ip <<'EOF'
#!/bin/bash
DB="/var/lib/postfix/sticky_ip.db"

echo "CURRENT STICKY IP ASSIGNMENTS"
echo "============================="
sqlite3 -column -header "$DB" <<SQL
SELECT 
    sender_email as 'Sender Email',
    assigned_ip as 'Assigned IP',
    message_count as 'Messages',
    datetime(last_used) as 'Last Used',
    days_inactive as 'Days Inactive'
FROM sender_activity
LIMIT ${1:-50};
SQL
EOF
    
    chmod +x /usr/local/bin/list-sticky-ip
    
    # Reset sender
    cat > /usr/local/bin/reset-sticky-ip <<'EOF'
#!/bin/bash
SENDER="$1"
DB="/var/lib/postfix/sticky_ip.db"

if [ -z "$SENDER" ]; then
    echo "Usage: $0 <sender@email>"
    exit 1
fi

echo "Resetting sticky IP for $SENDER..."

# Get current IP
CURRENT_IP=$(sqlite3 "$DB" "SELECT assigned_ip FROM sticky_mappings WHERE sender_email='$SENDER'")

if [ -z "$CURRENT_IP" ]; then
    echo "No assignment found for $SENDER"
    exit 1
fi

# Delete assignment
sqlite3 "$DB" <<SQL
DELETE FROM sticky_mappings WHERE sender_email='$SENDER';
UPDATE ip_pool SET sender_count = sender_count - 1 WHERE ip_address='$CURRENT_IP';
INSERT INTO rotation_log (sender_email, old_ip, new_ip, reason) 
VALUES ('$SENDER', '$CURRENT_IP', 'REMOVED', 'manual_reset');
SQL

echo "✓ Assignment removed for $SENDER (was using $CURRENT_IP)"
EOF
    
    chmod +x /usr/local/bin/reset-sticky-ip
    
    # Enable/disable IP
    cat > /usr/local/bin/toggle-sticky-ip-pool <<'EOF'
#!/bin/bash
IP="$1"
ACTION="$2"
DB="/var/lib/postfix/sticky_ip.db"

if [ -z "$IP" ] || [ -z "$ACTION" ]; then
    echo "Usage: $0 <ip_address> {enable|disable}"
    exit 1
fi

case "$ACTION" in
    enable)
        sqlite3 "$DB" "UPDATE ip_pool SET active=1 WHERE ip_address='$IP'"
        echo "✓ IP $IP enabled in pool"
        ;;
    disable)
        sqlite3 "$DB" "UPDATE ip_pool SET active=0 WHERE ip_address='$IP'"
        echo "✓ IP $IP disabled in pool"
        ;;
    *)
        echo "Invalid action. Use 'enable' or 'disable'"
        exit 1
        ;;
esac

# Show current pool status
echo ""
echo "Current IP pool:"
sqlite3 -column -header "$DB" "SELECT ip_address, CASE active WHEN 1 THEN 'Active' ELSE 'Inactive' END as status FROM ip_pool"
EOF
    
    chmod +x /usr/local/bin/toggle-sticky-ip-pool
    
    print_message "✓ Management commands created"
    print_message ""
    print_message "Available commands:"
    print_message "  assign-sticky-ip     - Manually assign IP to sender"
    print_message "  list-sticky-ip       - List current assignments"
    print_message "  reset-sticky-ip      - Remove assignment for sender"
    print_message "  monitor-sticky-ip    - Show monitoring report"
    print_message "  toggle-sticky-ip-pool - Enable/disable IP in pool"
}

# Test sticky IP configuration
test_sticky_ip() {
    print_header "Testing Sticky IP Configuration"
    
    local all_good=true
    
    # Check database
    if [ -f "$STICKY_IP_DB" ]; then
        print_message "✓ Sticky IP database exists"
        
        # Check IP pool
        local pool_count=$(sqlite3 "$STICKY_IP_DB" "SELECT COUNT(*) FROM ip_pool")
        if [ "$pool_count" -gt 0 ]; then
            print_message "✓ IP pool contains $pool_count addresses"
        else
            print_error "✗ IP pool is empty"
            all_good=false
        fi
    else
        print_error "✗ Sticky IP database not found"
        all_good=false
    fi
    
    # Check policy service
    if [ -x /usr/local/bin/sticky-ip-policy ]; then
        print_message "✓ Policy service script exists"
    else
        print_error "✗ Policy service script not found"
        all_good=false
    fi
    
    # Check Postfix configuration
    if postconf -n | grep -q "sticky-ip-policy"; then
        print_message "✓ Postfix configured for sticky IP"
    else
        print_warning "⚠ Postfix configuration may need updating"
    fi
    
    if [ "$all_good" = true ]; then
        print_message "✓ Sticky IP test passed"
        return 0
    else
        print_error "Sticky IP test failed"
        return 1
    fi
}

# Export functions
export -f init_sticky_ip_database populate_ip_pool setup_sticky_ip
export -f create_sticky_ip_policy_service create_ip_assignment_script
export -f configure_postfix_sticky_ip create_sticky_ip_maintenance_scripts
export -f setup_sticky_ip_monitoring create_sticky_ip_management_commands
export -f test_sticky_ip

# Export variables
export STICKY_IP_ENABLED STICKY_IP_DB STICKY_IP_LOG
export STICKY_IP_EXPIRE_DAYS STICKY_IP_MAX_SENDERS_PER_IP
