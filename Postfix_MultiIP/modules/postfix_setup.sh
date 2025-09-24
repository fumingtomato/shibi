#!/bin/bash

# =================================================================
# POSTFIX SETUP MODULE
# Multi-IP Postfix configuration with transport maps
# =================================================================

# Configure Postfix for multiple IPs
setup_postfix_multi_ip() {
    local domain=$1
    local hostname=$2
    
    print_header "Configuring Postfix for Multi-IP Bulk Mailing"
    
    backup_config "postfix" "/etc/postfix/main.cf"
    backup_config "postfix" "/etc/postfix/master.cf"
    
    cat > /etc/postfix/main.cf <<EOF
# Postfix Configuration for Multi-IP Bulk Mail Server
# Optimized for MailWizz with multiple IP support

# Basic configuration
smtpd_banner = \$myhostname ESMTP \$mail_name
biff = no
append_dot_mydomain = no
readme_directory = no

# TLS parameters
smtpd_tls_cert_file=/etc/letsencrypt/live/$hostname/fullchain.pem
smtpd_tls_key_file=/etc/letsencrypt/live/$hostname/privkey.pem
smtpd_tls_security_level = may
smtp_tls_security_level = may
smtpd_tls_session_cache_database = btree:\${data_directory}/smtpd_scache
smtp_tls_session_cache_database = btree:\${data_directory}/smtp_scache

# Authentication
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_auth_enable = yes

# Restrictions
smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject
smtpd_recipient_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination

# Network settings
myhostname = $hostname
mydomain = $domain
myorigin = \$mydomain
mydestination = localhost.\$mydomain, localhost
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
inet_interfaces = all
inet_protocols = all

# Multi-IP configuration
smtp_bind_address_enforce = yes

# Sender-dependent transport maps for IP rotation
sender_dependent_default_transport_maps = hash:/etc/postfix/sender_dependent_default_transport_maps

# Transport maps for domain-based routing
transport_maps = hash:/etc/postfix/transport

# Connection pooling for better performance with multiple IPs
smtp_connection_cache_on_demand = yes
smtp_connection_cache_time_limit = 30s
smtp_connection_reuse_time_limit = 300s
smtp_connection_cache_destinations = 

# Virtual domains
virtual_transport = lmtp:unix:private/dovecot-lmtp
virtual_mailbox_domains = mysql:/etc/postfix/mysql-virtual-mailbox-domains.cf
virtual_mailbox_maps = mysql:/etc/postfix/mysql-virtual-mailbox-maps.cf
virtual_alias_maps = mysql:/etc/postfix/mysql-virtual-alias-maps.cf

# DKIM milter
milter_default_action = accept
milter_protocol = 6
smtpd_milters = inet:127.0.0.1:12301
non_smtpd_milters = inet:127.0.0.1:12301

# Bulk mail optimizations
maximal_queue_lifetime = 3d
bounce_queue_lifetime = 1d
maximal_backoff_time = 15m
minimal_backoff_time = 5m
queue_run_delay = 5m

# High volume settings
default_process_limit = 200
smtp_destination_concurrency_limit = 50
smtp_destination_recipient_limit = 100
default_destination_concurrency_limit = 50

# Queue management
qmgr_message_active_limit = 40000
qmgr_message_recipient_limit = 40000

# Disable unnecessary checks for performance
disable_vrfy_command = yes
smtpd_helo_required = yes

# Rate limiting per source IP
smtpd_client_connection_count_limit = 100
smtpd_client_connection_rate_limit = 100
anvil_rate_time_unit = 60s

# Message size limits
message_size_limit = 52428800
mailbox_size_limit = 0
EOF
    
    create_master_cf_multi_ip
    create_transport_maps "$domain"
    
    postmap /etc/postfix/transport
    if [ -f /etc/postfix/sender_dependent_default_transport_maps ]; then
        postmap /etc/postfix/sender_dependent_default_transport_maps
    fi
    
    print_message "Postfix multi-IP configuration completed"
}

# Create master.cf with multiple SMTP transport instances
create_master_cf_multi_ip() {
    print_message "Creating master.cf with multiple SMTP instances..."
    
    cat > /etc/postfix/master.cf <<'EOF'
# ==========================================================================
# service type  private unpriv  chroot  wakeup  maxproc command + args
#               (yes)   (yes)   (no)    (never) (100)
# ==========================================================================

# Standard SMTP service listening on all IPs
smtp      inet  n       -       y       -       -       smtpd
  -o smtpd_client_connection_count_limit=20
  -o smtpd_client_connection_rate_limit=60

# Submission port with authentication
submission inet n       -       y       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_tls_auth_only=yes
  -o smtpd_reject_unlisted_recipient=no
  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING

# SMTPS service
smtps     inet  n       -       y       -       -       smtpd
  -o syslog_name=postfix/smtps
  -o smtpd_tls_wrappermode=yes
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_reject_unlisted_recipient=no
  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING

# Core services
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

# Default SMTP client
smtp      unix  -       -       y       -       -       smtp
  -o smtp_connection_cache_on_demand=yes

relay     unix  -       -       y       -       -       smtp
showq     unix  n       -       y       -       -       showq
error     unix  -       -       y       -       -       error
retry     unix  -       -       y       -       -       error
discard   unix  -       -       y       -       -       discard
local     unix  -       n       n       -       -       local
virtual   unix  -       n       n       -       -       virtual
lmtp      unix  -       -       y       -       -       lmtp
anvil     unix  -       -       y       -       1       anvil
scache    unix  -       -       y       -       1       scache

EOF
    
    # Add SMTP transport instances for each IP
    local transport_index=0
    for ip in "${IP_ADDRESSES[@]}"; do
        transport_index=$((transport_index + 1))
        
        cat >> /etc/postfix/master.cf <<EOF
# SMTP transport for IP $ip
smtp-ip${transport_index} unix  -       -       y       -       -       smtp
  -o syslog_name=postfix/smtp-ip${transport_index}
  -o smtp_bind_address=$ip
  -o smtp_helo_name=mail${transport_index}.\$mydomain
  -o smtp_connection_cache_on_demand=yes

EOF
    done
    
    print_message "Created ${transport_index} SMTP transport instances"
}

# Create transport maps for domain routing
create_transport_maps() {
    local primary_domain=$1
    
    print_message "Creating transport maps..."
    
    cat > /etc/postfix/transport <<EOF
# Transport map for domain-based routing
# Format: domain transport:nexthop

# Local domains
$primary_domain    virtual:
localhost          local:
localhost.localdomain local:

# Default transport for all other domains
*                  smtp:
EOF
    
    # Add any additional domain-specific routing
    if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
        print_message "\nDo you want to configure specific domains to use specific IPs?"
        read -p "Enter 'yes' to configure domain routing, or 'no' to skip: " domain_routing
        
        if [[ "$domain_routing" == "yes" || "$domain_routing" == "y" ]]; then
            while true; do
                read -p "Enter domain (or press Enter to finish): " route_domain
                if [ -z "$route_domain" ]; then
                    break
                fi
                
                print_message "Available transports:"
                local idx=1
                for ip in "${IP_ADDRESSES[@]}"; do
                    echo "  $idx) smtp-ip${idx} (IP: $ip)"
                    idx=$((idx + 1))
                done
                
                read -p "Select transport number for $route_domain: " transport_num
                echo "$route_domain    smtp-ip${transport_num}:" >> /etc/postfix/transport
            done
        fi
    fi
}

export -f setup_postfix_multi_ip create_master_cf_multi_ip create_transport_maps
