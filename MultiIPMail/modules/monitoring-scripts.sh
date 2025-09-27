#!/bin/bash

# =================================================================
# MONITORING AND IP WARMUP MODULE - FIXED VERSION
# System monitoring, performance tracking, and IP warmup automation
# Fixed: Complete implementations, proper data tracking, warmup scheduling
# =================================================================

# Global variables for monitoring
export MONITORING_DIR="/var/lib/mail-monitoring"
export WARMUP_DB="${MONITORING_DIR}/ip_warmup.db"
export STATS_DB="${MONITORING_DIR}/mail_stats.db"
export MONITORING_LOG="/var/log/mail-monitoring.log"
export WARMUP_SCHEDULE_FILE="${MONITORING_DIR}/warmup_schedule.json"

# Initialize monitoring directories and databases
init_monitoring() {
    print_message "Initializing monitoring system..."
    
    # Create directories
    mkdir -p "$MONITORING_DIR"
    mkdir -p "$(dirname "$MONITORING_LOG")"
    
    # Set permissions
    chmod 750 "$MONITORING_DIR"
    chown postfix:postfix "$MONITORING_DIR"
    
    # Initialize databases
    init_warmup_database
    init_stats_database
    
    print_message "✓ Monitoring system initialized"
}

# Initialize IP warmup database
init_warmup_database() {
    sqlite3 "$WARMUP_DB" <<'EOF'
-- IP warmup tracking table
CREATE TABLE IF NOT EXISTS ip_warmup (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL UNIQUE,
    hostname TEXT,
    start_date DATE NOT NULL,
    current_day INTEGER DEFAULT 1,
    current_volume INTEGER DEFAULT 0,
    max_volume INTEGER DEFAULT 50,
    reputation_score REAL DEFAULT 0.0,
    status TEXT DEFAULT 'warming',
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_ip (ip_address),
    INDEX idx_status (status)
);

-- Warmup history table
CREATE TABLE IF NOT EXISTS warmup_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL,
    date DATE NOT NULL,
    day_number INTEGER,
    emails_sent INTEGER DEFAULT 0,
    emails_planned INTEGER,
    bounces INTEGER DEFAULT 0,
    complaints INTEGER DEFAULT 0,
    opens INTEGER DEFAULT 0,
    clicks INTEGER DEFAULT 0,
    reputation_change REAL DEFAULT 0.0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(ip_address, date),
    INDEX idx_ip_date (ip_address, date)
);

-- Warmup schedule table
CREATE TABLE IF NOT EXISTS warmup_schedule (
    day INTEGER PRIMARY KEY,
    daily_volume INTEGER NOT NULL,
    hourly_limit INTEGER NOT NULL,
    description TEXT
);

-- Insert default warmup schedule (30-day plan)
INSERT OR IGNORE INTO warmup_schedule (day, daily_volume, hourly_limit, description) VALUES
(1, 50, 10, 'Day 1: Initial warm-up'),
(2, 100, 20, 'Day 2: Double volume'),
(3, 150, 30, 'Day 3: Gradual increase'),
(4, 200, 40, 'Day 4: Steady growth'),
(5, 300, 60, 'Day 5: Larger increment'),
(6, 400, 80, 'Day 6: Continue scaling'),
(7, 500, 100, 'Day 7: Week 1 complete'),
(8, 750, 150, 'Week 2: Accelerated growth'),
(9, 1000, 200, 'Week 2: 1K milestone'),
(10, 1250, 250, 'Week 2: Continued growth'),
(11, 1500, 300, 'Week 2: Mid-point'),
(12, 1750, 350, 'Week 2: Approaching 2K'),
(13, 2000, 400, 'Week 2: 2K milestone'),
(14, 2500, 500, 'Week 2: Complete'),
(15, 3000, 600, 'Week 3: Scaling up'),
(16, 3500, 700, 'Week 3: Growth continues'),
(17, 4000, 800, 'Week 3: 4K milestone'),
(18, 4500, 900, 'Week 3: Steady progress'),
(19, 5000, 1000, 'Week 3: 5K milestone'),
(20, 6000, 1200, 'Week 3: Rapid growth'),
(21, 7000, 1400, 'Week 3: Complete'),
(22, 8000, 1600, 'Week 4: Final push'),
(23, 9000, 1800, 'Week 4: Near completion'),
(24, 10000, 2000, 'Week 4: 10K milestone'),
(25, 12500, 2500, 'Week 4: Exceeding targets'),
(26, 15000, 3000, 'Week 4: High volume'),
(27, 17500, 3500, 'Week 4: Near maximum'),
(28, 20000, 4000, 'Week 4: Complete'),
(29, 22500, 4500, 'Final days: Near full capacity'),
(30, 25000, 5000, 'Warmup complete: Full capacity');

-- Reputation factors table
CREATE TABLE IF NOT EXISTS reputation_factors (
    factor TEXT PRIMARY KEY,
    weight REAL NOT NULL,
    description TEXT
);

INSERT OR IGNORE INTO reputation_factors (factor, weight, description) VALUES
('bounce_rate', -5.0, 'Hard bounce rate impact'),
('complaint_rate', -10.0, 'Spam complaint rate impact'),
('open_rate', 2.0, 'Email open rate impact'),
('click_rate', 3.0, 'Click-through rate impact'),
('engagement_rate', 4.0, 'Overall engagement impact'),
('blacklist_status', -20.0, 'Blacklist presence impact'),
('authentication_pass', 5.0, 'SPF/DKIM/DMARC pass rate');
EOF
    
    chmod 660 "$WARMUP_DB"
    chown postfix:postfix "$WARMUP_DB"
}

# Initialize statistics database
init_stats_database() {
    sqlite3 "$STATS_DB" <<'EOF'
-- Mail statistics table
CREATE TABLE IF NOT EXISTS mail_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip_address TEXT,
    hostname TEXT,
    emails_sent INTEGER DEFAULT 0,
    emails_deferred INTEGER DEFAULT 0,
    emails_bounced INTEGER DEFAULT 0,
    emails_rejected INTEGER DEFAULT 0,
    queue_size INTEGER DEFAULT 0,
    avg_delivery_time REAL,
    INDEX idx_timestamp (timestamp),
    INDEX idx_ip (ip_address)
);

-- Hourly aggregates
CREATE TABLE IF NOT EXISTS hourly_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hour_timestamp TIMESTAMP NOT NULL,
    ip_address TEXT,
    total_sent INTEGER DEFAULT 0,
    total_deferred INTEGER DEFAULT 0,
    total_bounced INTEGER DEFAULT 0,
    total_rejected INTEGER DEFAULT 0,
    avg_queue_size INTEGER DEFAULT 0,
    unique_senders INTEGER DEFAULT 0,
    unique_recipients INTEGER DEFAULT 0,
    UNIQUE(hour_timestamp, ip_address),
    INDEX idx_hour (hour_timestamp),
    INDEX idx_ip (ip_address)
);

-- Daily summaries
CREATE TABLE IF NOT EXISTS daily_summary (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    date DATE NOT NULL,
    ip_address TEXT,
    total_sent INTEGER DEFAULT 0,
    total_deferred INTEGER DEFAULT 0,
    total_bounced INTEGER DEFAULT 0,
    total_rejected INTEGER DEFAULT 0,
    bounce_rate REAL DEFAULT 0.0,
    delivery_rate REAL DEFAULT 0.0,
    reputation_score REAL DEFAULT 0.0,
    UNIQUE(date, ip_address),
    INDEX idx_date (date)
);

-- Alert log
CREATE TABLE IF NOT EXISTS alert_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    ip_address TEXT,
    message TEXT NOT NULL,
    resolved INTEGER DEFAULT 0,
    resolved_at TIMESTAMP,
    INDEX idx_timestamp (timestamp),
    INDEX idx_severity (severity),
    INDEX idx_resolved (resolved)
);
EOF
    
    chmod 660 "$STATS_DB"
    chown postfix:postfix "$STATS_DB"
}

# Create IP warmup management scripts
create_ip_warmup_scripts() {
    print_header "Creating IP Warmup Scripts"
    
    # Main warmup manager
    cat > /usr/local/bin/ip-warmup-manager <<'EOF'
#!/bin/bash

# IP Warmup Manager
WARMUP_DB="/var/lib/mail-monitoring/ip_warmup.db"

show_usage() {
    echo "IP Warmup Manager"
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  init <ip>          Initialize warmup for IP"
    echo "  status [ip]        Show warmup status"
    echo "  update <ip> <sent> Update send count for IP"
    echo "  advance <ip>       Advance to next warmup day"
    echo "  pause <ip>         Pause warmup for IP"
    echo "  resume <ip>        Resume warmup for IP"
    echo "  reset <ip>         Reset warmup for IP"
    echo "  schedule           Show warmup schedule"
    echo "  report [ip]        Generate warmup report"
    exit 1
}

init_warmup() {
    local ip=$1
    local hostname="${2:-$(hostname -f)}"
    
    echo "Initializing warmup for IP: $ip"
    
    sqlite3 "$WARMUP_DB" <<SQL
INSERT OR REPLACE INTO ip_warmup (ip_address, hostname, start_date, current_day, current_volume, max_volume, status)
VALUES ('$ip', '$hostname', date('now'), 1, 0, 50, 'warming');
SQL
    
    echo "✓ Warmup initialized for $ip"
    echo "  Starting volume: 50 emails/day"
    echo "  Duration: 30 days"
}

show_status() {
    local ip=$1
    
    if [ -z "$ip" ]; then
        echo "IP WARMUP STATUS"
        echo "================"
        sqlite3 -column -header "$WARMUP_DB" <<SQL
SELECT 
    ip_address as 'IP Address',
    current_day as 'Day',
    current_volume || '/' || max_volume as 'Volume',
    printf('%.1f', reputation_score) as 'Rep',
    status as 'Status',
    date(start_date) as 'Started'
FROM ip_warmup
ORDER BY start_date DESC;
SQL
    else
        sqlite3 -column -header "$WARMUP_DB" <<SQL
SELECT 
    ip_address as 'IP Address',
    hostname as 'Hostname',
    'Day ' || current_day || ' of 30' as 'Progress',
    current_volume || ' / ' || max_volume as 'Today\'s Volume',
    printf('%.1f%%', reputation_score) as 'Reputation',
    status as 'Status',
    datetime(last_updated) as 'Last Updated'
FROM ip_warmup
WHERE ip_address = '$ip';
SQL
    fi
}

update_volume() {
    local ip=$1
    local sent=$2
    
    sqlite3 "$WARMUP_DB" <<SQL
UPDATE ip_warmup 
SET current_volume = current_volume + $sent,
    last_updated = datetime('now')
WHERE ip_address = '$ip';

INSERT INTO warmup_history (ip_address, date, day_number, emails_sent)
VALUES ('$ip', date('now'), 
    (SELECT current_day FROM ip_warmup WHERE ip_address = '$ip'),
    $sent)
ON CONFLICT(ip_address, date) DO UPDATE SET
    emails_sent = emails_sent + $sent;
SQL
    
    echo "✓ Updated volume for $ip: +$sent emails"
}

advance_day() {
    local ip=$1
    
    # Get next day's limits
    local next_day=$(sqlite3 "$WARMUP_DB" "SELECT current_day + 1 FROM ip_warmup WHERE ip_address = '$ip'")
    local next_volume=$(sqlite3 "$WARMUP_DB" "SELECT daily_volume FROM warmup_schedule WHERE day = $next_day")
    
    if [ -z "$next_volume" ]; then
        echo "Warmup complete for $ip!"
        sqlite3 "$WARMUP_DB" "UPDATE ip_warmup SET status = 'warmed' WHERE ip_address = '$ip'"
    else
        sqlite3 "$WARMUP_DB" <<SQL
UPDATE ip_warmup 
SET current_day = $next_day,
    current_volume = 0,
    max_volume = $next_volume,
    last_updated = datetime('now')
WHERE ip_address = '$ip';
SQL
        echo "✓ Advanced $ip to day $next_day (limit: $next_volume emails)"
    fi
}

show_schedule() {
    echo "IP WARMUP SCHEDULE (30-Day Plan)"
    echo "================================"
    sqlite3 -column -header "$WARMUP_DB" <<SQL
SELECT 
    'Day ' || day as 'Day',
    daily_volume as 'Daily Limit',
    hourly_limit as 'Hourly Limit',
    description as 'Description'
FROM warmup_schedule
ORDER BY day;
SQL
}

generate_report() {
    local ip=$1
    
    echo "IP WARMUP REPORT"
    echo "================"
    echo "Generated: $(date)"
    echo ""
    
    if [ -z "$ip" ]; then
        # Overall report
        echo "OVERALL WARMUP STATUS:"
        sqlite3 -column -header "$WARMUP_DB" <<SQL
SELECT 
    COUNT(*) as 'Total IPs',
    SUM(CASE WHEN status = 'warming' THEN 1 ELSE 0 END) as 'Warming',
    SUM(CASE WHEN status = 'warmed' THEN 1 ELSE 0 END) as 'Warmed',
    SUM(CASE WHEN status = 'paused' THEN 1 ELSE 0 END) as 'Paused'
FROM ip_warmup;
SQL
    else
        # IP-specific report
        echo "Report for IP: $ip"
        echo ""
        
        echo "CURRENT STATUS:"
        show_status "$ip"
        echo ""
        
        echo "LAST 7 DAYS HISTORY:"
        sqlite3 -column -header "$WARMUP_DB" <<SQL
SELECT 
    date as 'Date',
    day_number as 'Day',
    emails_sent as 'Sent',
    emails_planned as 'Planned',
    CASE 
        WHEN emails_planned > 0 
        THEN printf('%.1f%%', (emails_sent * 100.0 / emails_planned))
        ELSE '0%'
    END as 'Achieved'
FROM warmup_history
WHERE ip_address = '$ip'
ORDER BY date DESC
LIMIT 7;
SQL
    fi
}

# Main execution
case "$1" in
    init) init_warmup "$2" "$3" ;;
    status) show_status "$2" ;;
    update) update_volume "$2" "$3" ;;
    advance) advance_day "$2" ;;
    pause) sqlite3 "$WARMUP_DB" "UPDATE ip_warmup SET status = 'paused' WHERE ip_address = '$2'" ;;
    resume) sqlite3 "$WARMUP_DB" "UPDATE ip_warmup SET status = 'warming' WHERE ip_address = '$2'" ;;
    reset) init_warmup "$2" ;;
    schedule) show_schedule ;;
    report) generate_report "$2" ;;
    *) show_usage ;;
esac
EOF
    
    chmod +x /usr/local/bin/ip-warmup-manager
    
    # Automatic warmup advancement script
    cat > /usr/local/bin/auto-advance-warmup <<'EOF'
#!/bin/bash

# Automatically advance warmup to next day
WARMUP_DB="/var/lib/mail-monitoring/ip_warmup.db"

echo "[$(date)] Starting automatic warmup advancement..."

# Get all IPs in warming status
sqlite3 "$WARMUP_DB" "SELECT ip_address FROM ip_warmup WHERE status = 'warming'" | while read ip; do
    echo "Processing $ip..."
    /usr/local/bin/ip-warmup-manager advance "$ip"
done

echo "[$(date)] Warmup advancement complete"
EOF
    
    chmod +x /usr/local/bin/auto-advance-warmup
    
    # Add to cron for daily execution
    if ! crontab -l 2>/dev/null | grep -q "auto-advance-warmup"; then
        (crontab -l 2>/dev/null; echo "0 0 * * * /usr/local/bin/auto-advance-warmup >> $MONITORING_LOG 2>&1") | crontab -
    fi
    
    print_message "✓ IP warmup scripts created"
}

# Create monitoring scripts for multi-IP setup
create_monitoring_scripts() {
    print_header "Creating Monitoring Scripts"
    
    # Main monitoring dashboard
    cat > /usr/local/bin/mail-stats <<'EOF'
#!/bin/bash

# Mail Server Statistics Dashboard
STATS_DB="/var/lib/mail-monitoring/mail_stats.db"
WARMUP_DB="/var/lib/mail-monitoring/ip_warmup.db"

show_usage() {
    echo "Mail Server Statistics"
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  dashboard          Show overall dashboard"
    echo "  ip <address>       Show stats for specific IP"
    echo "  queue              Show mail queue status"
    echo "  errors             Show recent errors"
    echo "  performance        Show performance metrics"
    echo "  report [date]      Generate daily report"
    exit 1
}

show_dashboard() {
    clear
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║           MAIL SERVER MONITORING DASHBOARD                   ║"
    echo "║                  $(date '+%Y-%m-%d %H:%M:%S')                          ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    
    # System status
    echo "SYSTEM STATUS:"
    echo "─────────────"
    echo -n "Postfix:  "; systemctl is-active postfix || echo "STOPPED"
    echo -n "Dovecot:  "; systemctl is-active dovecot || echo "STOPPED"
    echo -n "OpenDKIM: "; systemctl is-active opendkim || echo "STOPPED"
    echo -n "MySQL:    "; systemctl is-active mysql || systemctl is-active mariadb || echo "STOPPED"
    echo ""
    
    # Queue status
    echo "MAIL QUEUE:"
    echo "──────────"
    local queue_active=$(mailq | grep -c '^[A-F0-9]' 2>/dev/null || echo 0)
    local queue_deferred=$(find /var/spool/postfix/deferred -type f 2>/dev/null | wc -l)
    echo "Active:   $queue_active"
    echo "Deferred: $queue_deferred"
    echo ""
    
    # Today's statistics
    echo "TODAY'S STATISTICS:"
    echo "──────────────────"
    sqlite3 -column "$STATS_DB" <<SQL 2>/dev/null || echo "No data available"
SELECT 
    printf('%-15s', 'Total Sent:') || SUM(emails_sent) as '',
    printf('%-15s', 'Bounced:') || SUM(emails_bounced) as '',
    printf('%-15s', 'Deferred:') || SUM(emails_deferred) as ''
FROM mail_stats
WHERE date(timestamp) = date('now');
SQL
    echo ""
    
    # IP Statistics
    echo "IP ADDRESS STATISTICS:"
    echo "─────────────────────"
    sqlite3 -column -header "$STATS_DB" <<SQL 2>/dev/null || echo "No data available"
SELECT 
    ip_address as 'IP Address',
    SUM(emails_sent) as 'Sent',
    SUM(emails_bounced) as 'Bounced',
    SUM(emails_deferred) as 'Deferred',
    printf('%.2f%%', (SUM(emails_bounced) * 100.0 / NULLIF(SUM(emails_sent), 0))) as 'Bounce Rate'
FROM mail_stats
WHERE date(timestamp) = date('now')
GROUP BY ip_address;
SQL
}

show_queue_status() {
    echo "MAIL QUEUE STATUS"
    echo "================="
    echo ""
    
    echo "Queue summary:"
    mailq | tail -1
    echo ""
    
    echo "Deferred messages by reason:"
    find /var/spool/postfix/deferred -type f -exec postcat -q {} \; 2>/dev/null | \
        grep "reason=" | cut -d'=' -f2 | sort | uniq -c | sort -rn | head -10
}

show_errors() {
    echo "RECENT MAIL ERRORS"
    echo "=================="
    echo ""
    
    echo "Last 20 errors from mail.log:"
    grep -E "error|failed|rejected|bounced" /var/log/mail.log | tail -20
}

show_performance() {
    echo "PERFORMANCE METRICS"
    echo "==================="
    echo ""
    
    # Delivery times
    echo "Average delivery times (last hour):"
    sqlite3 -column -header "$STATS_DB" <<SQL 2>/dev/null
SELECT 
    ip_address as 'IP Address',
    printf('%.2f sec', AVG(avg_delivery_time)) as 'Avg Delivery Time',
    MAX(queue_size) as 'Max Queue Size'
FROM mail_stats
WHERE timestamp >= datetime('now', '-1 hour')
GROUP BY ip_address;
SQL
    echo ""
    
    # Resource usage
    echo "Current resource usage:"
    echo "CPU: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}')"
    echo "Memory: $(free -h | awk '/^Mem:/ {print $3 " / " $2}')"
    echo "Disk: $(df -h / | awk 'NR==2 {print $3 " / " $2 " (" $5 ")"}')"
}

generate_report() {
    local report_date=${1:-$(date +%Y-%m-%d)}
    
    echo "DAILY MAIL REPORT - $report_date"
    echo "================================"
    echo ""
    
    # Summary statistics
    sqlite3 "$STATS_DB" <<SQL
.mode column
.headers on

SELECT 
    'Total Emails Sent' as 'Metric',
    SUM(emails_sent) as 'Value'
FROM mail_stats
WHERE date(timestamp) = '$report_date'
UNION ALL
SELECT 
    'Total Bounced',
    SUM(emails_bounced)
FROM mail_stats
WHERE date(timestamp) = '$report_date'
UNION ALL
SELECT 
    'Total Deferred',
    SUM(emails_deferred)
FROM mail_stats
WHERE date(timestamp) = '$report_date'
UNION ALL
SELECT 
    'Bounce Rate',
    printf('%.2f%%', (SUM(emails_bounced) * 100.0 / NULLIF(SUM(emails_sent), 0)))
FROM mail_stats
WHERE date(timestamp) = '$report_date';
SQL
    
    echo ""
    echo "Per-IP Breakdown:"
    sqlite3 -column -header "$STATS_DB" <<SQL
SELECT 
    ip_address as 'IP Address',
    SUM(emails_sent) as 'Sent',
    SUM(emails_bounced) as 'Bounced',
    SUM(emails_deferred) as 'Deferred',
    printf('%.2f%%', (SUM(emails_bounced) * 100.0 / NULLIF(SUM(emails_sent), 0))) as 'Bounce Rate'
FROM mail_stats
WHERE date(timestamp) = '$report_date'
GROUP BY ip_address
ORDER BY SUM(emails_sent) DESC;
SQL
}

# Main execution
case "$1" in
    dashboard|"") show_dashboard ;;
    ip) show_ip_stats "$2" ;;
    queue) show_queue_status ;;
    errors) show_errors ;;
    performance) show_performance ;;
    report) generate_report "$2" ;;
    *) show_usage ;;
esac
EOF
    
    chmod +x /usr/local/bin/mail-stats
    
    # Real-time mail log analyzer
    cat > /usr/local/bin/mail-log-analyzer <<'EOF'
#!/usr/bin/env python3

import re
import sys
import sqlite3
from datetime import datetime
from collections import defaultdict

STATS_DB = '/var/lib/mail-monitoring/mail_stats.db'
LOG_FILE = '/var/log/mail.log'

def parse_log_line(line):
    """Parse a mail log line for relevant information"""
    data = {}
    
    # Extract timestamp
    timestamp_match = re.match(r'^(\w+\s+\d+\s+\d+:\d+:\d+)', line)
    if timestamp_match:
        data['timestamp'] = timestamp_match.group(1)
    
    # Extract message ID
    msg_id_match = re.search(r'([A-F0-9]{10,})', line)
    if msg_id_match:
        data['msg_id'] = msg_id_match.group(1)
    
    # Extract from address
    from_match = re.search(r'from=<([^>]*)>', line)
    if from_match:
        data['from'] = from_match.group(1)
    
    # Extract to address
    to_match = re.search(r'to=<([^>]*)>', line)
    if to_match:
        data['to'] = to_match.group(1)
    
    # Extract status
    status_match = re.search(r'status=(\w+)', line)
    if status_match:
        data['status'] = status_match.group(1)
    
    # Extract relay info
    relay_match = re.search(r'relay=([^\[,]+)(?:\[([^\]]+)\])?', line)
    if relay_match:
        data['relay'] = relay_match.group(1)
        if relay_match.group(2):
            data['relay_ip'] = relay_match.group(2)
    
    return data

def update_stats(stats):
    """Update statistics in database"""
    conn = sqlite3.connect(STATS_DB)
    cursor = conn.cursor()
    
    for ip, ip_stats in stats.items():
        cursor.execute("""
            INSERT INTO mail_stats 
            (timestamp, ip_address, emails_sent, emails_deferred, emails_bounced, emails_rejected)
            VALUES (datetime('now'), ?, ?, ?, ?, ?)
        """, (ip, ip_stats['sent'], ip_stats['deferred'], 
              ip_stats['bounced'], ip_stats['rejected']))
    
    conn.commit()
    conn.close()

def analyze_log():
    """Analyze mail log and extract statistics"""
    stats = defaultdict(lambda: {
        'sent': 0, 'deferred': 0, 'bounced': 0, 'rejected': 0
    })
    
    try:
        with open(LOG_FILE, 'r') as f:
            # Read last 1000 lines
            lines = f.readlines()[-1000:]
            
            for line in lines:
                data = parse_log_line(line)
                
                if 'status' in data and 'relay_ip' in data:
                    ip = data['relay_ip']
                    status = data['status']
                    
                    if status == 'sent':
                        stats[ip]['sent'] += 1
                    elif status == 'deferred':
                        stats[ip]['deferred'] += 1
                    elif status == 'bounced':
                        stats[ip]['bounced'] += 1
                    else:
                        stats[ip]['rejected'] += 1
    
    except FileNotFoundError:
        print(f"Log file {LOG_FILE} not found")
        sys.exit(1)
    
    return stats

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--continuous":
        # Continuous monitoring mode
        import time
        while True:
            stats = analyze_log()
            update_stats(stats)
            print(f"[{datetime.now()}] Updated statistics for {len(stats)} IPs")
            time.sleep(60)  # Update every minute
    else:
        # One-time analysis
        stats = analyze_log()
        print("Mail Log Analysis Summary:")
        print("-" * 50)
        for ip, ip_stats in stats.items():
            print(f"IP: {ip}")
            print(f"  Sent: {ip_stats['sent']}")
            print(f"  Deferred: {ip_stats['deferred']}")
            print(f"  Bounced: {ip_stats['bounced']}")
            print(f"  Rejected: {ip_stats['rejected']}")
            print()
EOF
    
    chmod +x /usr/local/bin/mail-log-analyzer
    
    # Health check script
    cat > /usr/local/bin/mail-health-check <<'EOF'
#!/bin/bash

# Mail Server Health Check
ALERT_EMAIL="${ADMIN_EMAIL:-root@localhost}"

check_service() {
    local service=$1
    if ! systemctl is-active --quiet "$service"; then
        echo "CRITICAL: $service is not running" | mail -s "Mail Server Alert: $service down" "$ALERT_EMAIL"
        return 1
    fi
    return 0
}

check_queue() {
    local queue_size=$(mailq | grep -c '^[A-F0-9]' 2>/dev/null || echo 0)
    if [ "$queue_size" -gt 1000 ]; then
        echo "WARNING: Mail queue size is $queue_size" | mail -s "Mail Server Alert: Large queue" "$ALERT_EMAIL"
        return 1
    fi
    return 0
}

check_disk() {
    local usage=$(df / | awk 'NR==2 {print int($5)}')
    if [ "$usage" -gt 90 ]; then
        echo "CRITICAL: Disk usage is ${usage}%" | mail -s "Mail Server Alert: Disk space low" "$ALERT_EMAIL"
        return 1
    fi
    return 0
}

# Run all checks
ERRORS=0
check_service postfix || ERRORS=$((ERRORS + 1))
check_service dovecot || ERRORS=$((ERRORS + 1))
check_service opendkim || ERRORS=$((ERRORS + 1))
check_queue || ERRORS=$((ERRORS + 1))
check_disk || ERRORS=$((ERRORS + 1))

if [ $ERRORS -eq 0 ]; then
    echo "[$(date)] All health checks passed" >> /var/log/mail-monitoring.log
else
    echo "[$(date)] Health check failed with $ERRORS errors" >> /var/log/mail-monitoring.log
fi

exit $ERRORS
EOF
    
    chmod +x /usr/local/bin/mail-health-check
    
    # Add health check to cron
    if ! crontab -l 2>/dev/null | grep -q "mail-health-check"; then
        (crontab -l 2>/dev/null; echo "*/15 * * * * /usr/local/bin/mail-health-check") | crontab -
    fi
    
    print_message "✓ Monitoring scripts created"
}

# Initialize monitoring for all configured IPs
init_ip_monitoring() {
    print_message "Initializing IP monitoring..."
    
    # Initialize warmup for each IP
    for ip in "${IP_ADDRESSES[@]}"; do
        /usr/local/bin/ip-warmup-manager init "$ip" 2>/dev/null || true
    done
    
    # Start continuous log analyzer
    if ! pgrep -f "mail-log-analyzer.*--continuous" >/dev/null; then
        nohup /usr/local/bin/mail-log-analyzer --continuous >> "$MONITORING_LOG" 2>&1 &
        print_message "✓ Log analyzer started"
    fi
    
    print_message "✓ IP monitoring initialized for ${#IP_ADDRESSES[@]} addresses"
}

# Create performance tuning script
create_performance_tuning_script() {
    cat > /usr/local/bin/tune-mail-performance <<'EOF'
#!/bin/bash

# Mail Server Performance Tuning
echo "Mail Server Performance Tuning"
echo "=============================="

# Postfix tuning
echo "Tuning Postfix..."
postconf -e "default_destination_concurrency_limit = 20"
postconf -e "default_destination_recipient_limit = 50"
postconf -e "smtp_destination_concurrency_limit = 20"
postconf -e "smtp_destination_rate_delay = 1s"
postconf -e "smtp_extra_recipient_limit = 100"

# System tuning
echo "Tuning system parameters..."

# Increase file descriptors
echo "fs.file-max = 100000" >> /etc/sysctl.conf
echo "* soft nofile 65536" >> /etc/security/limits.conf
echo "* hard nofile 65536" >> /etc/security/limits.conf

# Network tuning
cat >> /etc/sysctl.conf <<SYSCTL
net.ipv4.tcp_fin_timeout = 20
net.ipv4.tcp_tw_reuse = 1
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.core.netdev_max_backlog = 65535
SYSCTL

sysctl -p

echo "✓ Performance tuning applied"
echo "  Please restart services for changes to take effect"
EOF
    
    chmod +x /usr/local/bin/tune-mail-performance
    print_message "✓ Performance tuning script created"
}

# Export functions
export -f init_monitoring init_warmup_database init_stats_database
export -f create_ip_warmup_scripts create_monitoring_scripts
export -f init_ip_monitoring create_performance_tuning_script

# Export variables
export MONITORING_DIR WARMUP_DB STATS_DB MONITORING_LOG WARMUP_SCHEDULE_FILE
