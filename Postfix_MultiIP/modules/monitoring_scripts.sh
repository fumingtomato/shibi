#!/bin/bash

# =================================================================
# MONITORING SCRIPTS MODULE
# IP warmup management, statistics collection, and monitoring
# =================================================================

# Create IP warmup scripts for gradual volume increase
create_ip_warmup_scripts() {
    print_header "Creating IP Warmup Management Scripts"
    
    # Create warmup configuration directory
    mkdir -p /etc/postfix/warmup
    
    # Create IP warmup tracker
    cat > /usr/local/bin/ip-warmup-manager <<'EOF'
#!/bin/bash

# IP Warmup Manager for Bulk Mail Server
# Manages gradual volume increase for new IPs

WARMUP_CONFIG="/etc/postfix/warmup/config.json"
WARMUP_LOG="/var/log/mail-warmup.log"

# Initialize warmup configuration
init_warmup() {
    local ip=$1
    local start_date=$(date +%Y-%m-%d)
    
    cat > "$WARMUP_CONFIG.$ip" <<EOL
{
    "ip": "$ip",
    "start_date": "$start_date",
    "current_day": 1,
    "daily_limit": 50,
    "sent_today": 0,
    "reputation_score": "new",
    "status": "warming"
}
EOL
    echo "[$(date)] Initialized warmup for IP $ip" >> "$WARMUP_LOG"
}

# Get current daily limit for IP
get_daily_limit() {
    local ip=$1
    local config_file="$WARMUP_CONFIG.$ip"
    
    if [ ! -f "$config_file" ]; then
        echo "unlimited"
        return
    fi
    
    local current_day=$(grep '"current_day"' "$config_file" | grep -o '[0-9]*')
    local daily_limit=50
    
    # Gradual increase schedule (30-day warmup)
    if [ $current_day -le 3 ]; then
        daily_limit=50
    elif [ $current_day -le 7 ]; then
        daily_limit=100
    elif [ $current_day -le 14 ]; then
        daily_limit=500
    elif [ $current_day -le 21 ]; then
        daily_limit=1000
    elif [ $current_day -le 30 ]; then
        daily_limit=5000
    else
        daily_limit="unlimited"
    fi
    
    echo $daily_limit
}

# Update sent count for IP
update_sent_count() {
    local ip=$1
    local count=$2
    local config_file="$WARMUP_CONFIG.$ip"
    
    if [ -f "$config_file" ]; then
        local current_sent=$(grep '"sent_today"' "$config_file" | grep -o '[0-9]*')
        local new_sent=$((current_sent + count))
        sed -i "s/\"sent_today\": [0-9]*/\"sent_today\": $new_sent/" "$config_file"
        echo "[$(date)] IP $ip: Sent $count emails (Total today: $new_sent)" >> "$WARMUP_LOG"
    fi
}

# Reset daily counters
reset_daily_counters() {
    for config_file in $WARMUP_CONFIG.*; do
        if [ -f "$config_file" ]; then
            sed -i 's/"sent_today": [0-9]*/"sent_today": 0/' "$config_file"
            
            # Increment day counter
            local current_day=$(grep '"current_day"' "$config_file" | grep -o '[0-9]*')
            local new_day=$((current_day + 1))
            sed -i "s/\"current_day\": [0-9]*/\"current_day\": $new_day/" "$config_file"
        fi
    done
    echo "[$(date)] Reset daily counters for all IPs" >> "$WARMUP_LOG"
}

# Check IP reputation
check_reputation() {
    local ip=$1
    
    # Check against common blacklists
    local blacklists=(
        "zen.spamhaus.org"
        "bl.spamcop.net"
        "b.barracudacentral.org"
        "dnsbl.sorbs.net"
    )
    
    local listed=false
    for bl in "${blacklists[@]}"; do
        if host "${ip}.${bl}" &>/dev/null; then
            echo "[$(date)] WARNING: IP $ip is listed on $bl" >> "$WARMUP_LOG"
            listed=true
        fi
    done
    
    if [ "$listed" = false ]; then
        echo "[$(date)] IP $ip reputation check: CLEAN" >> "$WARMUP_LOG"
    fi
}

# Main command handler
case "$1" in
    init)
        init_warmup "$2"
        ;;
    limit)
        get_daily_limit "$2"
        ;;
    update)
        update_sent_count "$2" "$3"
        ;;
    reset)
        reset_daily_counters
        ;;
    check)
        check_reputation "$2"
        ;;
    status)
        echo "=== IP Warmup Status ==="
        for config_file in $WARMUP_CONFIG.*; do
            if [ -f "$config_file" ]; then
                ip=$(basename "$config_file" | cut -d'.' -f3)
                echo "IP: $ip"
                cat "$config_file" | python3 -m json.tool 2>/dev/null || cat "$config_file"
                echo "---"
            fi
        done
        ;;
    *)
        echo "Usage: $0 {init|limit|update|reset|check|status} [ip] [count]"
        exit 1
        ;;
esac
EOF
    
    chmod +x /usr/local/bin/ip-warmup-manager
    
    # Create cron job for daily reset
    cat > /etc/cron.d/ip-warmup <<EOF
# Reset IP warmup counters daily at midnight
0 0 * * * root /usr/local/bin/ip-warmup-manager reset

# Check IP reputation daily at 6 AM
0 6 * * * root for ip in ${IP_ADDRESSES[@]}; do /usr/local/bin/ip-warmup-manager check \$ip; done
EOF
    
    # Initialize warmup for all configured IPs
    for ip in "${IP_ADDRESSES[@]}"; do
        /usr/local/bin/ip-warmup-manager init "$ip"
    done
    
    print_message "IP warmup management system created"
}

# Create monitoring scripts for multi-IP setup
create_monitoring_scripts() {
    print_header "Creating Monitoring and Statistics Scripts"
    
    # Create statistics collector
    cat > /usr/local/bin/mail-stats <<'EOF'
#!/bin/bash

# Mail Statistics Collector for Multi-IP Server

LOG_FILE="/var/log/mail.log"
STATS_DIR="/var/log/mail-stats"
mkdir -p "$STATS_DIR"

# Function to get stats for specific IP
get_ip_stats() {
    local ip=$1
    local date=${2:-$(date +%Y-%m-%d)}
    
    echo "=== Statistics for IP: $ip on $date ==="
    
    # Count sent emails
    local sent=$(grep "$date" "$LOG_FILE" | grep "smtp-ip" | grep "$ip" | grep "status=sent" | wc -l)
    echo "Emails sent: $sent"
    
    # Count bounced emails
    local bounced=$(grep "$date" "$LOG_FILE" | grep "smtp-ip" | grep "$ip" | grep "status=bounced" | wc -l)
    echo "Emails bounced: $bounced"
    
    # Count deferred emails
    local deferred=$(grep "$date" "$LOG_FILE" | grep "smtp-ip" | grep "$ip" | grep "status=deferred" | wc -l)
    echo "Emails deferred: $deferred"
    
    # Calculate success rate
    if [ $sent -gt 0 ]; then
        local total=$((sent + bounced))
        local success_rate=$(echo "scale=2; $sent * 100 / $total" | bc)
        echo "Success rate: ${success_rate}%"
    fi
    
    echo ""
}

# Function to get overall statistics
get_overall_stats() {
    local date=${1:-$(date +%Y-%m-%d)}
    
    echo "=== Overall Mail Statistics for $date ==="
    
    # Total emails
    local total_sent=$(grep "$date" "$LOG_FILE" | grep "status=sent" | wc -l)
    local total_bounced=$(grep "$date" "$LOG_FILE" | grep "status=bounced" | wc -l)
    local total_deferred=$(grep "$date" "$LOG_FILE" | grep "status=deferred" | wc -l)
    
    echo "Total sent: $total_sent"
    echo "Total bounced: $total_bounced"
    echo "Total deferred: $total_deferred"
    
    # Queue size
    local queue_size=$(mailq | tail -1 | awk '{print $5}')
    echo "Current queue size: ${queue_size:-0}"
    
    # Top sending domains
    echo -e "\nTop 5 recipient domains:"
    grep "$date" "$LOG_FILE" | grep "status=sent" | grep -oP 'to=<[^@]+@\K[^>]+' | sort | uniq -c | sort -rn | head -5
    
    echo ""
}

# Function to generate HTML report
generate_html_report() {
    local report_file="$STATS_DIR/report-$(date +%Y%m%d).html"
    
    cat > "$report_file" <<HTML
<!DOCTYPE html>
<html>
<head>
    <title>Mail Server Statistics - $(date +%Y-%m-%d)</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #4CAF50; color: white; }
        .warning { color: orange; }
        .error { color: red; }
        .success { color: green; }
    </style>
</head>
<body>
    <h1>Mail Server Statistics Report</h1>
    <p>Generated: $(date)</p>
    
    <h2>Server Information</h2>
    <p>Hostname: $(hostname)</p>
    <p>Uptime: $(uptime)</p>
    
    <h2>Queue Status</h2>
    <pre>$(mailq | tail -5)</pre>
    
    <h2>System Resources</h2>
    <pre>$(top -bn1 | head -10)</pre>
    
</body>
</html>
HTML
    
    echo "HTML report generated: $report_file"
}

# Main execution
case "$1" in
    ip)
        get_ip_stats "$2" "$3"
        ;;
    overall)
        get_overall_stats "$2"
        ;;
    report)
        generate_html_report
        ;;
    live)
        # Live monitoring
        watch -n 5 "$0 overall"
        ;;
    *)
        echo "Usage: $0 {ip <ip_address> [date]|overall [date]|report|live}"
        echo "  ip <ip_address> [date] - Show stats for specific IP"
        echo "  overall [date]        - Show overall statistics"
        echo "  report                - Generate HTML report"
        echo "  live                  - Live monitoring"
        exit 1
        ;;
esac
EOF
    
    chmod +x /usr/local/bin/mail-stats
    
    # Create daily stats cron job
    cat > /etc/cron.d/mail-stats <<EOF
# Generate daily mail statistics report
59 23 * * * root /usr/local/bin/mail-stats report

# Send daily summary email
0 7 * * * root /usr/local/bin/mail-stats overall | mail -s "Daily Mail Stats - $(hostname)" $ADMIN_EMAIL
EOF
    
    print_message "Monitoring and statistics scripts created"
}

export -f create_ip_warmup_scripts create_monitoring_scripts
