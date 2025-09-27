#!/bin/bash

# =================================================================
# POSTFIX SETUP MODULE
# Main Postfix configuration and multi-IP setup
# =================================================================

# Setup Postfix for multi-IP configuration
setup_postfix_multi_ip() {
    local domain=$1
    local hostname=$2
    
    print_header "Configuring Postfix for Multi-IP Bulk Mailing"
    
    # Backup existing configuration
    backup_config "postfix" "/etc/postfix/main.cf"
    backup_config "postfix" "/etc/postfix/master.cf"
    
    # Install Postfix if not already installed
    apt-get update
    apt-get install -y postfix postfix-mysql
    
    # Stop Postfix during configuration
    systemctl stop postfix
    
    # Create master.cf with multiple SMTP instances
    print_message "Creating master.cf with multiple SMTP instances..."
    
    cat > /etc/postfix/master.cf <<'EOF'
# ==========================================================================
# service type  private unpriv  chroot  wakeup  maxproc command + args
# ==========================================================================
smtp      inet  n       -       y       -       -       smtpd
submission inet n       -       y       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_tls_auth_only=yes
  -o smtpd_reject_unlisted_recipient=no
  -o smtpd_recipient_restrictions=
  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING
smtps     inet  n       -       y       -       -       smtpd
  -o syslog_name=postfix/smtps
  -o smtpd_tls_wrappermode=yes
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_reject_unlisted_recipient=no
  -o smtpd_recipient_restrictions=
  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING
pickup    unix  n       -       y       60      1       pickup
cleanup   unix  n       -       y       -       0       cleanup
qmgr      unix  n       -       n       300     1       qmgr
tlsmgr    unix  -       -       y       1000?   1       tlsmgr
rewrite   unix  -       -       y       -       -       trivial-rewrite
bounce    unix  -       -       y       -       0       bounce
defer     unix  -       -       y       -       0       bounce
trace     unix  -       -       y       -       0       bounce
verify    unix  -       -       y       -       1       verify
flush     unix  n       -       y       1000?   0       flush
proxymap  unix  -       -       n       -       -       proxymap
proxywrite unix -       -       n       -       1       proxymap
smtp      unix  -       -       y       -       -       smtp
relay     unix  -       -       y       -       -       smtp
  -o syslog_name=postfix/$service_name
showq     unix  n       -       y       -       -       showq
error     unix  -       -       y       -       -       error
retry     unix  -       -       y       -       -       error
discard   unix  -       -       y       -       -       discard
local     unix  -       n       n       -       -       local
virtual   unix  -       n       n       -       -       virtual
lmtp      unix  -       -       y       -       -       lmtp
anvil     unix  -       -       y       -       1       anvil
scache    unix  -       -       y       -       1       scache
postlog   unix-dgram n  -       n       -       1       postlogd
maildrop  unix  -       n       n       -       -       pipe
  flags=DRXhu user=vmail argv=/usr/bin/maildrop -d ${recipient}
uucp      unix  -       n       n       -       -       pipe
  flags=Fqhu user=uucp argv=uux -r -n -z -a$sender - $nexthop!rmail ($recipient)
ifmail    unix  -       n       n       -       -       pipe
  flags=F user=ftn argv=/usr/lib/ifmail/ifmail -r $nexthop ($recipient)
bsmtp     unix  -       n       n       -       -       pipe
  flags=Fq. user=bsmtp argv=/usr/lib/bsmtp/bsmtp -t$nexthop -f$sender $recipient
scalemail-backend unix -       n       n       -       2       pipe
  flags=R user=scalemail argv=/usr/lib/scalemail/bin/scalemail-store ${nexthop} ${user} ${extension}
mailman   unix  -       n       n       -       -       pipe
  flags=FRX user=list argv=/usr/lib/mailman/bin/postfix-to-mailman.py ${nexthop} ${user}

# Multiple SMTP instances for different IPs
EOF
    
    # Add SMTP instances for each IP with new hostname format
    local transport_count=0
    for ip in "${IP_ADDRESSES[@]}"; do
        transport_count=$((transport_count + 1))
        
        # Determine the HELO hostname based on IP index
        local helo_name
        if [ $transport_count -eq 1 ]; then
            # First IP uses primary hostname (subdomain.domain)
            helo_name="${HOSTNAME}"
        else
            # Additional IPs use numbered format (subdomain001.domain, subdomain002.domain, etc.)
            local suffix=$(printf "%03d" $((transport_count - 1)))
            helo_name="${SUBDOMAIN}${suffix}.${domain}"
        fi
        
        cat >> /etc/postfix/master.cf <<EOF
smtp-ip${transport_count} unix - - y - - smtp
  -o syslog_name=postfix/smtp-ip${transport_count}
  -o smtp_bind_address=${ip}
  -o smtp_helo_name=${helo_name}

EOF
    done
    
    print_message "Created ${transport_count} SMTP transport instances with proper HELO names"
    
    # Create transport maps directory
    mkdir -p /etc/postfix/transport_maps
    
    # Initialize transport configuration
    > /etc/postfix/transport_maps/domain_transport
    
    # Initialize sender dependent transport maps
    > /etc/postfix/sender_dependent_default_transport_maps
    
    # Hash the transport maps
    postmap hash:/etc/postfix/transport_maps/domain_transport
    postmap hash:/etc/postfix/sender_dependent_default_transport_maps
    
    # Configure main.cf
    configure_postfix_main_cf "$domain" "$hostname"
    
    # Remove duplicate lines from main.cf
    awk '!seen[$0]++' /etc/postfix/main.cf > /tmp/main.cf.tmp && mv /tmp/main.cf.tmp /etc/postfix/main.cf
    
    # Fix aliases
    sed -i '/^postmaster:/d' /etc/aliases 2>/dev/null || true
    echo "postmaster: root" >> /etc/aliases
    newaliases
    
    # Set permissions
    chown -R root:root /etc/postfix
    chmod 644 /etc/postfix/main.cf
    chmod 644 /etc/postfix/master.cf
    chmod -R 644 /etc/postfix/transport_maps/
    chown -R root:postfix /etc/postfix/mysql-virtual-*.cf 2>/dev/null || true
    chmod 640 /etc/postfix/mysql-virtual-*.cf 2>/dev/null || true
    
    # Create Postfix monitoring script
    create_postfix_monitor
    
    print_message "Postfix multi-IP configuration completed"
    
    # Create a reference file with the configuration
    create_postfix_reference_file "$domain"
}

# Configure Postfix main.cf
configure_postfix_main_cf() {
    local domain=$1
    local hostname=$2
    
    print_message "Configuring Postfix main.cf..."
    
    # Ensure DB_PASSWORD is available
    if [ -z "$DB_PASSWORD" ] && [ -f /root/.mail_db_password ]; then
        DB_PASSWORD=$(cat /root/.mail_db_password)
    fi
    
    cat > /etc/postfix/main.cf <<EOF
# =================================================================
# POSTFIX MAIN CONFIGURATION - BULK MAIL SERVER
# Generated by Multi-IP Bulk Mail Server Installer
# Date: $(date)
# =================================================================

# Basic Configuration
smtpd_banner = \$myhostname ESMTP \$mail_name
biff = no
append_dot_mydomain = no
readme_directory = no
compatibility_level = 3.6

# Host and Domain Settings
myhostname = ${hostname}
mydomain = ${domain}
myorigin = \$mydomain
mydestination = \$myhostname, localhost.\$mydomain, localhost
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128 ${IP_ADDRESSES[*]}
inet_interfaces = all
inet_protocols = ipv4

# Mail Box Settings
home_mailbox = Maildir/
mailbox_size_limit = 0
recipient_delimiter = +
message_size_limit = 52428800

# Virtual Domain Configuration (MySQL already configured in mysql_dovecot.sh)
virtual_mailbox_domains = mysql:/etc/postfix/mysql-virtual-mailbox-domains.cf
virtual_mailbox_maps = mysql:/etc/postfix/mysql-virtual-mailbox-maps.cf
virtual_alias_maps = mysql:/etc/postfix/mysql-virtual-alias-maps.cf
virtual_transport = lmtp:unix:private/dovecot-lmtp

# SMTP Authentication
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_auth_enable = yes
smtpd_sasl_security_options = noanonymous
smtpd_sasl_local_domain = \$mydomain
broken_sasl_auth_clients = yes

# TLS Configuration
smtpd_tls_cert_file = /etc/ssl/certs/ssl-cert-snakeoil.pem
smtpd_tls_key_file = /etc/ssl/private/ssl-cert-snakeoil.key
smtpd_use_tls = yes
smtpd_tls_auth_only = yes
smtp_tls_security_level = may
smtpd_tls_security_level = may
smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtpd_tls_session_cache_database = btree:\${data_directory}/smtpd_scache
smtp_tls_session_cache_database = btree:\${data_directory}/smtp_scache
smtp_tls_note_starttls_offer = yes
smtpd_tls_received_header = yes

# Relay and Restrictions
smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, defer_unauth_destination
smtpd_recipient_restrictions = 
    permit_mynetworks,
    permit_sasl_authenticated,
    reject_unauth_destination,
    reject_unknown_recipient_domain,
    reject_unverified_recipient,
    check_policy_service unix:private/policyd-spf,
    permit

# Client Connection Restrictions
smtpd_client_restrictions = permit_mynetworks, permit_sasl_authenticated

# Sender Restrictions
smtpd_sender_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unknown_sender_domain

# HELO Restrictions
smtpd_helo_required = yes
smtpd_helo_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_invalid_helo_hostname

# Rate Limiting for Bulk Mail
smtpd_client_connection_rate_limit = 100
smtpd_client_message_rate_limit = 1000
smtpd_client_recipient_rate_limit = 1000
smtpd_client_event_limit_exceptions = \$mynetworks
anvil_rate_time_unit = 60s

# Queue Configuration for Bulk Mail
maximal_queue_lifetime = 3d
bounce_queue_lifetime = 2d
maximal_backoff_time = 4000s
minimal_backoff_time = 300s
queue_run_delay = 300s

# Performance Tuning for Bulk Mail
default_process_limit = 100
qmgr_message_active_limit = 20000
qmgr_message_recipient_limit = 20000
smtp_destination_concurrency_limit = 20
smtp_destination_rate_delay = 1s
smtp_extra_recipient_limit = 10
smtp_connection_cache_on_demand = no
smtp_connection_cache_time_limit = 2s
smtp_connection_cache_destinations = 

# Transport Maps for Multi-IP Routing
transport_maps = hash:/etc/postfix/transport_maps/domain_transport

# Sender Dependent Configuration
sender_dependent_default_transport_maps = hash:/etc/postfix/sender_dependent_default_transport_maps

# DKIM Milter Configuration (will be updated by dkim_spf.sh)
milter_protocol = 6
milter_default_action = accept
smtpd_milters = inet:localhost:8891
non_smtpd_milters = inet:localhost:8891

# Additional Settings
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases
mailbox_command = /usr/lib/dovecot/deliver

# Bounce Handling
notify_classes = bounce, delay, policy, protocol, resource, software
bounce_notice_recipient = postmaster
delay_notice_recipient = postmaster
error_notice_recipient = postmaster

# Header Checks
header_checks = regexp:/etc/postfix/header_checks

# Body Checks
body_checks = regexp:/etc/postfix/body_checks

# Logging
maillog_file = /var/log/mail.log
debug_peer_level = 2

# Address Verification
address_verify_negative_cache = yes
address_verify_negative_expire_time = 3d
address_verify_negative_refresh_time = 3h
address_verify_positive_expire_time = 31d
address_verify_positive_refresh_time = 7d
EOF
    
    # Create header and body check files
    create_check_files
    
    print_message "Postfix main.cf configuration completed"
}

# Create header and body check files
create_check_files() {
    print_message "Creating header and body check files..."
    
    # Header checks
    cat > /etc/postfix/header_checks <<EOF
# Header checks for spam prevention
/^Received:.*with ESMTPSA/ IGNORE
/^X-Originating-IP:/ IGNORE
/^X-Mailer:.*bulk/ IGNORE
/^Precedence:.*bulk/ IGNORE
EOF
    
    # Body checks (less aggressive for bulk mail)
    cat > /etc/postfix/body_checks <<EOF
# Body checks for spam prevention
# Keep minimal to avoid blocking legitimate bulk mail
EOF
    
    # Set permissions
    chmod 644 /etc/postfix/header_checks /etc/postfix/body_checks
}

# Test Postfix configuration
test_postfix_config() {
    print_header "Testing Postfix Configuration"
    
    postfix check
    if [ $? -eq 0 ]; then
        print_message "✓ Postfix configuration syntax is valid"
    else
        print_error "✗ Postfix configuration has errors"
        return 1
    fi
    
    # Test SMTP connectivity
    for ip in "${IP_ADDRESSES[@]}"; do
        if timeout 5 nc -zv "$ip" 25 2>/dev/null; then
            print_message "✓ Port 25 is accessible on $ip"
        else
            print_warning "⚠ Port 25 may not be accessible on $ip (firewall or binding issue)"
        fi
    done
    
    return 0
}

# Create Postfix reference file with new hostname format
create_postfix_reference_file() {
    local domain=$1
    
    cat > /root/postfix-ip-assignments.txt <<EOF
=================================================
Postfix Multi-IP Configuration Summary
=================================================
Generated: $(date)
Total IPs Configured: ${#IP_ADDRESSES[@]}
Subdomain: ${SUBDOMAIN}

IP Transport Mappings:
----------------------
EOF
    
    local idx=1
    for ip in "${IP_ADDRESSES[@]}"; do
        local helo_name
        if [ $idx -eq 1 ]; then
            helo_name="${HOSTNAME}"
        else
            local suffix=$(printf "%03d" $((idx - 1)))
            helo_name="${SUBDOMAIN}${suffix}.$domain"
        fi
        
        echo "Transport: smtp-ip${idx}" >> /root/postfix-ip-assignments.txt
        echo "IP Address: $ip" >> /root/postfix-ip-assignments.txt
        echo "HELO Name: $helo_name" >> /root/postfix-ip-assignments.txt
        echo "" >> /root/postfix-ip-assignments.txt
        idx=$((idx + 1))
    done
    
    cat >> /root/postfix-ip-assignments.txt <<EOF

Configuration Files:
--------------------
Main config: /etc/postfix/main.cf
Master config: /etc/postfix/master.cf
Transport maps: /etc/postfix/transport_maps/
MySQL configs: /etc/postfix/mysql-virtual-*.cf

Testing Commands:
-----------------
# Check configuration:
postfix check

# View current configuration:
postconf -n

# Test specific transport:
echo "test" | mail -s "test" -S smtp=smtp-ip1: test@example.com

# Monitor mail queue:
mailq

# View mail log:
tail -f /var/log/mail.log

# Flush queue:
postqueue -f

# Check HELO names for each transport:
grep -A1 "smtp-ip[0-9]" /etc/postfix/master.cf | grep smtp_helo_name

=================================================
EOF
    
    print_message "Configuration summary saved to /root/postfix-ip-assignments.txt"
}

# Create Postfix monitoring script with new hostname format awareness
create_postfix_monitor() {
    cat > /usr/local/bin/monitor-postfix <<'EOF'
#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "==================================================="
echo "         Postfix Multi-IP Status Monitor          "
echo "==================================================="

# Check Postfix service status
echo -e "\n${GREEN}[Service Status]${NC}"
if systemctl is-active --quiet postfix; then
    echo -e "${GREEN}✓${NC} Postfix is running"
    systemctl status postfix --no-pager | head -n 3
else
    echo -e "${RED}✗${NC} Postfix is not running"
fi

# Check mail queue
echo -e "\n${GREEN}[Mail Queue]${NC}"
queue_info=$(mailq | tail -n 1)
if echo "$queue_info" | grep -q "empty"; then
    echo "Mail queue is empty"
else
    echo "$queue_info"
    echo ""
    echo "Queue details (first 10):"
    mailq | head -n 20
fi

# Check recent logs
echo -e "\n${GREEN}[Recent Mail Activity]${NC}"
if [ -f /var/log/mail.log ]; then
    echo "Last 5 sent messages:"
    grep "status=sent" /var/log/mail.log 2>/dev/null | tail -n 5 | awk '{print $1, $2, $3, $7}'
else
    echo "Mail log not found"
fi

# Check for recent errors
echo -e "\n${YELLOW}[Recent Errors]${NC}"
if [ -f /var/log/mail.log ]; then
    error_count=$(grep -c "error\|failed\|fatal" /var/log/mail.log 2>/dev/null || echo 0)
    if [ "$error_count" -gt 0 ]; then
        echo "Found $error_count errors in mail log"
        echo "Last 5 errors:"
        grep -i "error\|failed\|fatal" /var/log/mail.log 2>/dev/null | tail -n 5
    else
        echo "No recent errors found"
    fi
else
    echo "Mail log not found"
fi

# Check IP transport configuration with HELO names
echo -e "\n${GREEN}[IP Transport Configuration]${NC}"
transport_count=0
for i in {1..20}; do
    if grep -q "smtp-ip${i} " /etc/postfix/master.cf 2>/dev/null; then
        ip_addr=$(grep -A2 "smtp-ip${i} " /etc/postfix/master.cf | grep smtp_bind_address | awk -F'=' '{print $2}' | tr -d ' ')
        helo_name=$(grep -A2 "smtp-ip${i} " /etc/postfix/master.cf | grep smtp_helo_name | awk -F'=' '{print $2}' | tr -d ' ')
        if [ ! -z "$ip_addr" ]; then
            echo "smtp-ip${i}: $ip_addr (HELO: $helo_name)"
            transport_count=$((transport_count + 1))
        fi
    fi
done
echo "Total transports configured: $transport_count"

# Check MySQL connectivity
echo -e "\n${GREEN}[Database Connectivity]${NC}"
if [ -f /root/.mail_db_password ]; then
    db_pass=$(cat /root/.mail_db_password)
    if mysql -u mailuser -p"$db_pass" -e "SELECT 1;" mailserver &>/dev/null; then
        echo -e "${GREEN}✓${NC} MySQL connection successful"
    else
        echo -e "${RED}✗${NC} MySQL connection failed"
    fi
else
    echo -e "${YELLOW}⚠${NC} Database password file not found"
fi

echo -e "\n==================================================="
EOF
    
    chmod +x /usr/local/bin/monitor-postfix
    print_message "Created Postfix monitoring script: /usr/local/bin/monitor-postfix"
}

export -f setup_postfix_multi_ip configure_postfix_main_cf
export -f create_check_files test_postfix_config
export -f create_postfix_reference_file create_postfix_monitor
