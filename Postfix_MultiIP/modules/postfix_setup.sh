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
    backup_config "postfix/main.cf"
    backup_config "postfix/master.cf"
    
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
    
    # Add SMTP instances for each IP
    local transport_count=0
    for ip in "${IP_ADDRESSES[@]}"; do
        transport_count=$((transport_count + 1))
        cat >> /etc/postfix/master.cf <<EOF
smtp-ip${transport_count} unix - - y - - smtp
  -o syslog_name=postfix/smtp-ip${transport_count}
  -o smtp_bind_address=${ip}
  -o smtp_helo_name=mail${transport_count}.${domain}

EOF
    done
    
    print_message "Created ${transport_count} SMTP transport instances"
    
    # Create transport maps directory
    mkdir -p /etc/postfix/transport_maps
    
    # Create domain-based transport routing with IP removal after assignment
    print_message "Creating transport maps..."
    > /etc/postfix/transport_maps/domain_transport
    
    print_message "\nDo you want to configure specific domains to use specific IPs?"
    print_message "Each IP can only be assigned to ONE domain."
    read -p "Enter 'yes' to configure domain routing, or 'no' to skip: " configure_domains
    
    # Create arrays to track available and used IPs
    declare -a available_transports=()
    declare -a available_ips=()
    declare -a used_transports=()
    
    # Initialize available transports
    for i in $(seq 1 ${#IP_ADDRESSES[@]}); do
        available_transports+=("smtp-ip${i}")
        available_ips+=("${IP_ADDRESSES[$((i-1))]}")
    done
    
    if [[ "$configure_domains" == "yes" || "$configure_domains" == "y" ]]; then
        while [ ${#available_transports[@]} -gt 0 ]; do
            read -p "Enter domain (or press Enter to finish): " sender_domain
            
            if [ -z "$sender_domain" ]; then
                break
            fi
            
            if [ ${#available_transports[@]} -eq 0 ]; then
                print_warning "All IPs have been assigned. No more available IPs."
                break
            fi
            
            echo "Available transports:"
            for i in $(seq 0 $((${#available_transports[@]} - 1))); do
                echo "  $((i + 1))) ${available_transports[$i]} (IP: ${available_ips[$i]})"
            done
            
            read -p "Select transport number for ${sender_domain}: " transport_choice
            
            # Validate choice
            if [[ "$transport_choice" -ge 1 && "$transport_choice" -le ${#available_transports[@]} ]]; then
                local idx=$((transport_choice - 1))
                local selected_transport="${available_transports[$idx]}"
                local selected_ip="${available_ips[$idx]}"
                
                echo "${sender_domain}    ${selected_transport}:" >> /etc/postfix/transport_maps/domain_transport
                print_message "Assigned ${sender_domain} → ${selected_transport} (IP: ${selected_ip})"
                
                # Add to used list
                used_transports+=("${selected_transport} (${sender_domain} - IP: ${selected_ip})")
                
                # Remove from available arrays
                unset 'available_transports[$idx]'
                unset 'available_ips[$idx]'
                
                # Rebuild arrays without gaps
                available_transports=("${available_transports[@]}")
                available_ips=("${available_ips[@]}")
                
                echo ""
                print_message "Remaining available IPs: ${#available_transports[@]}"
                
                if [ ${#available_transports[@]} -eq 0 ]; then
                    print_message "All IPs have been assigned!"
                    break
                fi
            else
                print_error "Invalid selection. Please choose a number between 1 and ${#available_transports[@]}"
            fi
        done
        
        # Show summary of assignments
        if [ ${#used_transports[@]} -gt 0 ]; then
            print_header "Domain-IP Assignment Summary"
            for assignment in "${used_transports[@]}"; do
                echo "  ✓ $assignment"
            done
        fi
        
        # If there are remaining IPs, show them
        if [ ${#available_transports[@]} -gt 0 ]; then
            print_message "\nUnassigned IPs (will be used for round-robin):"
            for i in $(seq 0 $((${#available_transports[@]} - 1))); do
                echo "  - ${available_transports[$i]} (IP: ${available_ips[$i]})"
            done
        fi
    fi
    
    # Hash the transport map
    postmap hash:/etc/postfix/transport_maps/domain_transport
    
    # Configure main.cf
    configure_postfix_main_cf "$domain" "$hostname"
    
    # Remove duplicate lines from main.cf
    awk '!seen[$0]++' /etc/postfix/main.cf > /tmp/main.cf.tmp && mv /tmp/main.cf.tmp /etc/postfix/main.cf
    
    # Fix aliases
    sed -i '/^postmaster:/d' /etc/aliases
    echo "postmaster: root" >> /etc/aliases
    newaliases
    # Set permissions
    chown -R postfix:postfix /etc/postfix
    chmod 644 /etc/postfix/main.cf
    chmod 644 /etc/postfix/master.cf
    
    # Start Postfix
    systemctl start postfix
    systemctl enable postfix
    
    print_message "Postfix multi-IP configuration completed"
    
    # Create a reference file with the configuration
    cat > /root/postfix-ip-assignments.txt <<EOF
=================================================
Postfix Multi-IP Configuration Summary
=================================================
Generated: $(date)
Total IPs Configured: ${#IP_ADDRESSES[@]}

IP-Domain Assignments:
EOF
    
    if [ ${#used_transports[@]} -gt 0 ]; then
        for assignment in "${used_transports[@]}"; do
            echo "$assignment" >> /root/postfix-ip-assignments.txt
        done
    else
        echo "No specific domain assignments configured." >> /root/postfix-ip-assignments.txt
    fi
    
    if [ ${#available_transports[@]} -gt 0 ]; then
        echo -e "\nUnassigned IPs (Round-Robin Pool):" >> /root/postfix-ip-assignments.txt
        for i in $(seq 0 $((${#available_transports[@]} - 1))); do
            echo "${available_transports[$i]} - IP: ${available_ips[$i]}" >> /root/postfix-ip-assignments.txt
        done
    fi
    
    echo -e "\n=================================================\n" >> /root/postfix-ip-assignments.txt
    
    print_message "Configuration summary saved to /root/postfix-ip-assignments.txt"
}

# Configure Postfix main.cf
configure_postfix_main_cf() {
    local domain=$1
    local hostname=$2
    
    print_message "Configuring Postfix main.cf..."
    
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
mydestination = \$myhostname, localhost.\$mydomain, localhost, \$mydomain
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128 ${IP_ADDRESSES[*]}
inet_interfaces = all
inet_protocols = ipv4

# Mail Box Settings
home_mailbox = Maildir/
mailbox_size_limit = 0
recipient_delimiter = +
message_size_limit = 52428800

# Virtual Domain Configuration
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

# Relay and Restrictions
smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination
smtpd_recipient_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination, reject_unknown_recipient_domain, reject_unverified_recipient

# Client Connection Restrictions
smtpd_client_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unknown_client_hostname

# Sender Restrictions
smtpd_sender_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unknown_sender_domain

# HELO Restrictions
smtpd_helo_required = yes
smtpd_helo_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_invalid_helo_hostname, reject_non_fqdn_helo_hostname

# Rate Limiting for Bulk Mail
smtpd_client_connection_rate_limit = 100
smtpd_client_message_rate_limit = 100
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

# Transport Maps for Multi-IP Routing
transport_maps = hash:/etc/postfix/transport_maps/domain_transport

# Sender Dependent Configuration
sender_dependent_default_transport_maps = hash:/etc/postfix/sender_dependent_default_transport_maps

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
EOF
    
    # Create MySQL configuration files
    create_mysql_config_files
    
    # Create header and body check files
    create_check_files
    
    print_message "Postfix main.cf configuration completed"
}

# Create MySQL configuration files for Postfix
create_mysql_config_files() {
    print_message "Creating MySQL configuration files for Postfix..."
    
    # Virtual mailbox domains
    cat > /etc/postfix/mysql-virtual-mailbox-domains.cf <<EOF
user = mailuser
password = ${DB_PASSWORD}
hosts = 127.0.0.1
dbname = mailserver
query = SELECT 1 FROM virtual_domains WHERE name='%s'
EOF
    
    # Virtual mailbox maps
    cat > /etc/postfix/mysql-virtual-mailbox-maps.cf <<EOF
user = mailuser
password = ${DB_PASSWORD}
hosts = 127.0.0.1
dbname = mailserver
query = SELECT 1 FROM virtual_users WHERE email='%s'
EOF
    
    # Virtual alias maps
    cat > /etc/postfix/mysql-virtual-alias-maps.cf <<EOF
user = mailuser
password = ${DB_PASSWORD}
hosts = 127.0.0.1
dbname = mailserver
query = SELECT destination FROM virtual_aliases WHERE source='%s'
EOF
    
    # Set permissions
    chmod 640 /etc/postfix/mysql-*.cf
    chown root:postfix /etc/postfix/mysql-*.cf
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
/^List-Unsubscribe:/ IGNORE
EOF
    
    # Body checks
    cat > /etc/postfix/body_checks <<EOF
# Body checks for spam prevention
/^(.*)viagra(.*)/ REJECT Spam detected
/^(.*)cialis(.*)/ REJECT Spam detected
EOF
    
    # Set permissions
    chmod 644 /etc/postfix/header_checks /etc/postfix/body_checks
}

# Create sender_dependent_default_transport_maps
create_sender_transport_maps() {
    print_message "Creating sender-dependent transport maps..."
    
    > /etc/postfix/sender_dependent_default_transport_maps
    
    # Hash the file
    postmap hash:/etc/postfix/sender_dependent_default_transport_maps
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
        if timeout 5 telnet "$ip" 25 2>/dev/null | grep -q "220"; then
            print_message "✓ SMTP is responding on $ip:25"
        else
            print_warning "✗ SMTP not responding on $ip:25 (may need firewall adjustment)"
        fi
    done
    
    return 0
}

# Create Postfix monitoring script
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
systemctl status postfix --no-pager | head -n 3

# Check mail queue
echo -e "\n${GREEN}[Mail Queue]${NC}"
queue_count=$(mailq | tail -n 1 | awk '{print $5}')
if [ "$queue_count" == "empty" ]; then
    echo "Mail queue is empty"
else
    echo "Messages in queue: $queue_count"
    echo "Queue details:"
    mailq | head -n 20
fi

# Check recent logs
echo -e "\n${GREEN}[Recent Mail Activity]${NC}"
echo "Last 10 sent messages:"
grep "status=sent" /var/log/mail.log | tail -n 10 | awk '{print $1, $2, $3, $7, $10, $11}'

# Check for errors
echo -e "\n${YELLOW}[Recent Errors]${NC}"
error_count=$(grep -c "error\|failed\|fatal" /var/log/mail.log 2>/dev/null || echo 0)
if [ "$error_count" -gt 0 ]; then
    echo "Found $error_count errors in mail log"
    echo "Last 5 errors:"
    grep -i "error\|failed\|fatal" /var/log/mail.log | tail -n 5
else
    echo "No recent errors found"
fi

# Check IP bindings
echo -e "\n${GREEN}[IP Transport Status]${NC}"
for i in {1..20}; do
    if grep -q "smtp-ip${i}" /etc/postfix/master.cf 2>/dev/null; then
        ip_addr=$(grep -A2 "smtp-ip${i}" /etc/postfix/master.cf | grep smtp_bind_address | awk -F'=' '{print $2}')
        echo "smtp-ip${i}: $ip_addr"
    fi
done

echo -e "\n==================================================="
EOF
    
    chmod +x /usr/local/bin/monitor-postfix
    print_message "Created Postfix monitoring script: /usr/local/bin/monitor-postfix"
}

export -f setup_postfix_multi_ip configure_postfix_main_cf
export -f create_mysql_config_files create_check_files
export -f create_sender_transport_maps test_postfix_config
export -f create_postfix_monitor
