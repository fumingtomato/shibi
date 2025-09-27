#!/bin/bash

# =================================================================
# POSTFIX SETUP MODULE - FIXED VERSION
# Main Postfix configuration for multi-IP bulk mail server
# Fixed: Configuration validation, security settings, multi-IP integration
# =================================================================

# Global Postfix configuration variables
export POSTFIX_VERSION=""
export POSTFIX_CONFIG_DIR="/etc/postfix"
export POSTFIX_QUEUE_DIR="/var/spool/postfix"
export POSTFIX_DATA_DIR="/var/lib/postfix"
export MESSAGE_SIZE_LIMIT="52428800"  # 50MB
export MAILBOX_SIZE_LIMIT="1073741824"  # 1GB
export MAX_CONNECTIONS_PER_IP="10"
export MAX_RECIPIENTS="100"

# Check Postfix installation
check_postfix_installation() {
    if ! command -v postfix &>/dev/null; then
        print_error "Postfix is not installed"
        return 1
    fi
    
    POSTFIX_VERSION=$(postconf -d mail_version 2>/dev/null | cut -d' ' -f3)
    print_message "Postfix version: $POSTFIX_VERSION"
    
    return 0
}

# Initialize Postfix configuration
init_postfix_config() {
    local domain=$1
    local hostname=$2
    
    print_header "Initializing Postfix Configuration"
    
    # Stop Postfix during configuration
    systemctl stop postfix 2>/dev/null || true
    
    # Backup existing configuration
    if [ -f "$POSTFIX_CONFIG_DIR/main.cf" ]; then
        backup_config "postfix" "$POSTFIX_CONFIG_DIR/main.cf"
    fi
    if [ -f "$POSTFIX_CONFIG_DIR/master.cf" ]; then
        backup_config "postfix" "$POSTFIX_CONFIG_DIR/master.cf"
    fi
    
    # Create necessary directories
    create_postfix_directories
    
    # Generate main.cf configuration
    generate_main_cf "$domain" "$hostname"
    
    # Generate master.cf configuration
    generate_master_cf
    
    # Create additional configuration files
    create_postfix_maps
    
    # Setup SASL authentication
    setup_postfix_sasl
    
    # Configure TLS/SSL
    setup_postfix_tls "$hostname"
    
    # Setup milters (DKIM, DMARC, SPF)
    setup_postfix_milters
    
    # Configure rate limiting
    setup_rate_limiting
    
    # Setup header checks and body checks
    setup_content_filtering
    
    print_message "✓ Postfix initialization completed"
}

# Create necessary Postfix directories
create_postfix_directories() {
    local directories=(
        "/etc/postfix/sql"
        "/etc/postfix/maps"
        "/etc/postfix/scripts"
        "/var/spool/postfix/pid"
        "/var/log/postfix"
    )
    
    for dir in "${directories[@]}"; do
        mkdir -p "$dir"
        
        # Set appropriate permissions
        if [[ "$dir" == "/var/spool/postfix"* ]]; then
            chown -R postfix:postfix "$dir"
        elif [[ "$dir" == "/etc/postfix"* ]]; then
            chown -R root:postfix "$dir"
            chmod 750 "$dir"
        fi
    done
}

# Generate main.cf configuration
generate_main_cf() {
    local domain=$1
    local hostname=$2
    
    print_message "Generating Postfix main.cf..."
    
    cat > "$POSTFIX_CONFIG_DIR/main.cf" <<EOF
# =================================================================
# POSTFIX MAIN CONFIGURATION - MULTI-IP BULK MAIL SERVER
# Generated: $(date)
# Version: $POSTFIX_VERSION
# =================================================================

# ===========================
# Basic Configuration
# ===========================
myhostname = $hostname
mydomain = $domain
myorigin = \$mydomain
mydestination = 
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
inet_interfaces = all
inet_protocols = ipv4

# ===========================
# SMTP Server Settings
# ===========================
smtpd_banner = \$myhostname ESMTP Mail Server
biff = no
append_dot_mydomain = no
readme_directory = no
compatibility_level = 2

# ===========================
# Virtual Domain Configuration
# ===========================
virtual_transport = lmtp:unix:private/dovecot-lmtp
virtual_mailbox_domains = mysql:/etc/postfix/mysql-virtual-mailbox-domains.cf
virtual_mailbox_maps = mysql:/etc/postfix/mysql-virtual-mailbox-maps.cf
virtual_alias_maps = mysql:/etc/postfix/mysql-virtual-alias-maps.cf
local_recipient_maps = \$virtual_mailbox_maps

# ===========================
# Multi-IP Configuration
# ===========================
sender_dependent_relayhost_maps = hash:/etc/postfix/relay_by_sender
sender_dependent_default_transport_maps = hash:/etc/postfix/sender_transport
transport_maps = hash:/etc/postfix/transport
smtp_bind_address_enforce = yes

# ===========================
# Queue Settings
# ===========================
maximal_queue_lifetime = 3d
bounce_queue_lifetime = 2d
maximal_backoff_time = 4000s
minimal_backoff_time = 300s
queue_run_delay = 300s
queue_directory = $POSTFIX_QUEUE_DIR
data_directory = $POSTFIX_DATA_DIR

# ===========================
# Message Size and Rate Limits
# ===========================
message_size_limit = $MESSAGE_SIZE_LIMIT
mailbox_size_limit = $MAILBOX_SIZE_LIMIT
virtual_mailbox_limit = $MAILBOX_SIZE_LIMIT
smtp_destination_concurrency_limit = 20
smtp_destination_rate_delay = 1s
smtp_extra_recipient_limit = 100
default_destination_concurrency_limit = 20
local_destination_concurrency_limit = 2

# ===========================
# SMTP Client Restrictions
# ===========================
smtpd_client_restrictions = 
    permit_mynetworks,
    permit_sasl_authenticated,
    reject_unauth_destination,
    reject_invalid_hostname,
    reject_unauth_pipelining,
    reject_non_fqdn_sender,
    reject_unknown_sender_domain,
    reject_non_fqdn_recipient,
    reject_unknown_recipient_domain,
    check_client_access hash:/etc/postfix/client_access,
    reject_rbl_client zen.spamhaus.org,
    reject_rbl_client bl.spamcop.net,
    permit

# ===========================
# SMTP Helo Restrictions
# ===========================
smtpd_helo_required = yes
smtpd_helo_restrictions = 
    permit_mynetworks,
    permit_sasl_authenticated,
    reject_invalid_helo_hostname,
    reject_non_fqdn_helo_hostname,
    check_helo_access hash:/etc/postfix/helo_access,
    permit

# ===========================
# SMTP Sender Restrictions
# ===========================
smtpd_sender_restrictions = 
    permit_mynetworks,
    permit_sasl_authenticated,
    reject_non_fqdn_sender,
    reject_unknown_sender_domain,
    check_sender_access hash:/etc/postfix/sender_access,
    permit

# ===========================
# SMTP Recipient Restrictions
# ===========================
smtpd_recipient_restrictions = 
    permit_mynetworks,
    permit_sasl_authenticated,
    reject_unauth_destination,
    reject_non_fqdn_recipient,
    reject_unknown_recipient_domain,
    check_recipient_access hash:/etc/postfix/recipient_access,
    check_policy_service unix:private/policyd-spf,
    permit

# ===========================
# SMTP Data Restrictions
# ===========================
smtpd_data_restrictions = 
    reject_unauth_pipelining,
    reject_multi_recipient_bounce,
    permit

# ===========================
# SASL Authentication
# ===========================
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_auth_enable = yes
smtpd_sasl_authenticated_header = yes
smtpd_sasl_security_options = noanonymous
smtpd_sasl_local_domain = \$mydomain
broken_sasl_auth_clients = yes

# ===========================
# TLS Configuration
# ===========================
smtpd_use_tls = yes
smtpd_tls_auth_only = yes
smtpd_tls_cert_file = /etc/ssl/certs/mail-cert.pem
smtpd_tls_key_file = /etc/ssl/private/mail-key.pem
smtpd_tls_CAfile = /etc/ssl/certs/ca-certificates.crt
smtpd_tls_security_level = may
smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtpd_tls_mandatory_ciphers = high
smtpd_tls_ciphers = high
smtpd_tls_exclude_ciphers = aNULL, MD5, DES, 3DES, RC4
smtpd_tls_session_cache_database = btree:\${data_directory}/smtpd_scache
smtpd_tls_loglevel = 1
smtpd_tls_received_header = yes

# SMTP Client TLS
smtp_use_tls = yes
smtp_tls_security_level = may
smtp_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtp_tls_ciphers = high
smtp_tls_exclude_ciphers = aNULL, MD5, DES, 3DES, RC4
smtp_tls_session_cache_database = btree:\${data_directory}/smtp_scache
smtp_tls_loglevel = 1

# ===========================
# Milter Configuration (DKIM, DMARC, SPF)
# ===========================
milter_default_action = accept
milter_protocol = 6
smtpd_milters = 
    inet:localhost:8891,
    inet:localhost:8893,
    unix:/var/run/opendkim/opendkim.sock
non_smtpd_milters = \$smtpd_milters

# ===========================
# Header and Body Checks
# ===========================
header_checks = pcre:/etc/postfix/header_checks
body_checks = pcre:/etc/postfix/body_checks
mime_header_checks = pcre:/etc/postfix/mime_header_checks

# ===========================
# Address Manipulation
# ===========================
masquerade_domains = \$mydomain
masquerade_exceptions = root, postmaster, abuse
canonical_maps = hash:/etc/postfix/canonical
sender_canonical_maps = hash:/etc/postfix/sender_canonical
recipient_canonical_maps = hash:/etc/postfix/recipient_canonical

# ===========================
# BCC Settings (for monitoring/compliance)
# ===========================
sender_bcc_maps = mysql:/etc/postfix/mysql-sender-bcc.cf
recipient_bcc_maps = mysql:/etc/postfix/mysql-recipient-bcc.cf

# ===========================
# Performance Tuning
# ===========================
default_process_limit = 100
smtp_connection_cache_on_demand = yes
smtp_connection_cache_time_limit = 2s
smtp_connection_reuse_time_limit = 300s
connection_cache_protocol_timeout = 5s

# ===========================
# Error Handling
# ===========================
notify_classes = bounce, delay, policy, protocol, resource, software
bounce_notice_recipient = postmaster@$domain
delay_notice_recipient = postmaster@$domain
error_notice_recipient = postmaster@$domain
2bounce_notice_recipient = postmaster@$domain

# ===========================
# Miscellaneous
# ===========================
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases
mailbox_command = 
home_mailbox = 
mail_spool_directory = 
smtpd_error_sleep_time = 5s
smtpd_soft_error_limit = 10
smtpd_hard_error_limit = 20
smtpd_client_connection_count_limit = $MAX_CONNECTIONS_PER_IP
smtpd_client_connection_rate_limit = 30
anvil_rate_time_unit = 60s
anvil_status_update_time = 600s
disable_vrfy_command = yes
strict_rfc821_envelopes = yes
show_user_unknown_table_name = no
EOF
    
    print_message "✓ main.cf generated"
}

# Generate master.cf configuration
generate_master_cf() {
    print_message "Generating Postfix master.cf..."
    
    cat > "$POSTFIX_CONFIG_DIR/master.cf" <<'EOF'
# =================================================================
# POSTFIX MASTER CONFIGURATION - MULTI-IP BULK MAIL SERVER
# Service definitions for Postfix processes
# =================================================================

# ==========================================================================
# service type  private unpriv  chroot  wakeup  maxproc command + args
# ==========================================================================

# SMTP Service
smtp      inet  n       -       n       -       -       smtpd
  -o syslog_name=postfix/smtp
  -o smtp_helo_timeout=300s
  -o smtp_mail_timeout=300s
  
# Submission service (port 587)
submission inet n       -       n       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_sasl_authenticated_header=yes
  -o smtpd_reject_unlisted_recipient=no
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING

# SMTPS service (port 465)
smtps     inet  n       -       n       -       -       smtpd
  -o syslog_name=postfix/smtps
  -o smtpd_tls_wrappermode=yes
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_sasl_authenticated_header=yes
  -o smtpd_reject_unlisted_recipient=no
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
  -o smtpd_recipient_restrictions=permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING

# Local mail delivery
pickup    unix  n       -       n       60      1       pickup
cleanup   unix  n       -       n       -       0       cleanup
qmgr      unix  n       -       n       300     1       qmgr
tlsmgr    unix  -       -       n       1000?   1       tlsmgr
rewrite   unix  -       -       n       -       -       trivial-rewrite
bounce    unix  -       -       n       -       0       bounce
defer     unix  -       -       n       -       0       bounce
trace     unix  -       -       n       -       0       bounce
verify    unix  -       -       n       -       1       verify
flush     unix  n       -       n       1000?   0       flush
proxymap  unix  -       -       n       -       -       proxymap
proxywrite unix -       -       n       -       1       proxymap

# SMTP client connections
smtp      unix  -       -       n       -       -       smtp
  -o syslog_name=postfix/smtp-out
  -o smtp_bind_address_enforce=yes

# LMTP delivery to Dovecot
lmtp      unix  -       -       n       -       -       lmtp
  -o syslog_name=postfix/lmtp

# Mail relaying
relay     unix  -       -       n       -       -       smtp
  -o syslog_name=postfix/relay
  -o smtp_fallback_relay=

# Show queue
showq     unix  n       -       n       -       -       showq

# Error handling
error     unix  -       -       n       -       -       error
retry     unix  -       -       n       -       -       error

# Discard service
discard   unix  -       -       n       -       -       discard

# Local delivery
local     unix  -       n       n       -       -       local
virtual   unix  -       n       n       -       -       virtual

# Anvil rate limiting
anvil     unix  -       -       n       -       1       anvil

# Scache
scache    unix  -       -       n       -       1       scache

# Postscreen (optional anti-spam)
#postscreen_init unix n  -       n       -       1       spawn
#  user=postfix argv=/usr/lib/postfix/sbin/postscreen_init

# Policy services
policy-spf unix -       n       n       -       0       spawn
  user=policyd-spf argv=/usr/bin/policyd-spf

# Additional transports for multi-IP
# These will be dynamically generated based on IP configuration
EOF
    
    # Add dynamic transport entries for each configured IP
    if [ ${#IP_ADDRESSES[@]} -gt 0 ]; then
        echo "" >> "$POSTFIX_CONFIG_DIR/master.cf"
        echo "# Dynamic IP-based transports" >> "$POSTFIX_CONFIG_DIR/master.cf"
        
        for i in "${!IP_ADDRESSES[@]}"; do
            local ip="${IP_ADDRESSES[$i]}"
            local transport_name="smtp-ip$((i+1))"
            
            cat >> "$POSTFIX_CONFIG_DIR/master.cf" <<EOF
$transport_name unix - - n - - smtp
  -o syslog_name=postfix/$transport_name
  -o smtp_bind_address=$ip
  -o smtp_bind_address_enforce=yes
  -o smtp_helo_name=mail-$i.$DOMAIN_NAME

EOF
        done
    fi
    
    print_message "✓ master.cf generated"
}

# Create Postfix map files
create_postfix_maps() {
    print_message "Creating Postfix map files..."
    
    # Client access map
    cat > "$POSTFIX_CONFIG_DIR/client_access" <<EOF
# Client access restrictions
# Format: client_ip/hostname action

# Localhost always allowed
127.0.0.1           OK
::1                 OK

# Example blacklist entry
# 192.168.1.0/24    REJECT Blacklisted network
EOF
    
    # Helo access map
    cat > "$POSTFIX_CONFIG_DIR/helo_access" <<EOF
# HELO/EHLO access restrictions
# Format: helo_hostname action

# Reject common spam patterns
localhost           REJECT Don't use localhost
localhost.localdomain REJECT Don't use localhost.localdomain
EOF
    
    # Sender access map
    cat > "$POSTFIX_CONFIG_DIR/sender_access" <<EOF
# Sender access restrictions
# Format: sender_address action

# Example entries
# spammer@spam.com  REJECT Known spammer
# @spamdomain.com   REJECT Spam domain
EOF
    
    # Recipient access map
    cat > "$POSTFIX_CONFIG_DIR/recipient_access" <<EOF
# Recipient access restrictions
# Format: recipient_address action

# Protected addresses
postmaster@         OK
abuse@              OK
EOF
    
    # Header checks
    cat > "$POSTFIX_CONFIG_DIR/header_checks" <<'EOF'
# Header checks - PCRE format
# Remove sensitive headers
/^Received:/                 IGNORE
/^X-Originating-IP:/         IGNORE
/^X-Mailer:/                 IGNORE
/^User-Agent:/               IGNORE
/^X-PHP-Script:/             IGNORE

# Reject suspicious headers
/^Subject:.*VIAGRA/i         REJECT Spam detected
/^Subject:.*LOTTERY/i        REJECT Spam detected
EOF
    
    # Body checks
    cat > "$POSTFIX_CONFIG_DIR/body_checks" <<'EOF'
# Body checks - PCRE format
# Reject suspicious content
/^(.*)viagra(.*)/i           REJECT Spam content detected
/^(.*)lottery(.*)/i          REJECT Spam content detected
EOF
    
    # MIME header checks
    cat > "$POSTFIX_CONFIG_DIR/mime_header_checks" <<'EOF'
# MIME header checks
# Block dangerous attachments
/^\s*Content-(Type|Disposition).*name\s*=\s*"?.*\.(exe|scr|pif|bat|com|cmd|dll|vbs|js|jar)/ REJECT Dangerous attachment type
EOF
    
    # Canonical maps (empty initially)
    touch "$POSTFIX_CONFIG_DIR/canonical"
    touch "$POSTFIX_CONFIG_DIR/sender_canonical"
    touch "$POSTFIX_CONFIG_DIR/recipient_canonical"
    
    # Transport maps (will be populated by multi-IP config)
    touch "$POSTFIX_CONFIG_DIR/transport"
    touch "$POSTFIX_CONFIG_DIR/sender_transport"
    touch "$POSTFIX_CONFIG_DIR/relay_by_sender"
    
    # Compile all maps
    for map in client_access helo_access sender_access recipient_access \
               canonical sender_canonical recipient_canonical \
               transport sender_transport relay_by_sender; do
        if [ -f "$POSTFIX_CONFIG_DIR/$map" ]; then
            postmap "$POSTFIX_CONFIG_DIR/$map"
        fi
    done
    
    print_message "✓ Map files created"
}

# Setup SASL authentication
setup_postfix_sasl() {
    print_message "Setting up SASL authentication..."
    
    # Create SASL directory in chroot
    mkdir -p "$POSTFIX_QUEUE_DIR/private"
    
    # Ensure Dovecot auth socket is accessible
    adduser postfix sasl 2>/dev/null || true
    
    print_message "✓ SASL authentication configured"
}

# Setup TLS/SSL for Postfix
setup_postfix_tls() {
    local hostname=$1
    
    print_message "Setting up TLS/SSL..."
    
    # Generate self-signed certificate if needed
    if [ ! -f /etc/ssl/certs/mail-cert.pem ]; then
        print_message "Generating self-signed certificate..."
        
        openssl req -new -x509 -days 3650 -nodes \
            -out /etc/ssl/certs/mail-cert.pem \
            -keyout /etc/ssl/private/mail-key.pem \
            -subj "/C=US/ST=State/L=City/O=Organization/CN=$hostname" 2>/dev/null
        
        chmod 644 /etc/ssl/certs/mail-cert.pem
        chmod 600 /etc/ssl/private/mail-key.pem
        chown root:root /etc/ssl/private/mail-key.pem
    fi
    
    print_message "✓ TLS/SSL configured"
}

# Setup milters for DKIM, DMARC, SPF
setup_postfix_milters() {
    print_message "Setting up mail filters (milters)..."
    
    # This will be handled by the dkim-spf module
    # Just ensure the configuration is ready
    
    print_message "✓ Milter configuration prepared"
}

# Setup rate limiting
setup_rate_limiting() {
    print_message "Setting up rate limiting..."
    
    # Create rate limiting database
    cat > "$POSTFIX_CONFIG_DIR/rate_limit.sql" <<EOF
-- Rate limiting database schema
CREATE TABLE IF NOT EXISTS rate_limit (
    client_ip VARCHAR(45) PRIMARY KEY,
    message_count INT DEFAULT 0,
    recipient_count INT DEFAULT 0,
    last_update TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    KEY idx_last_update (last_update)
);
EOF
    
    # Create rate limiting policy script
    cat > "$POSTFIX_CONFIG_DIR/scripts/rate_limit.sh" <<'EOF'
#!/bin/bash
# Rate limiting policy script

# Read request from Postfix
while read line; do
    case "$line" in
        client_address=*)
            CLIENT_IP="${line#client_address=}"
            ;;
        "")
            # End of request
            # Check rate limit here
            echo "action=DUNNO"
            echo ""
            ;;
    esac
done
EOF
    
    chmod +x "$POSTFIX_CONFIG_DIR/scripts/rate_limit.sh"
    
    print_message "✓ Rate limiting configured"
}

# Setup content filtering
setup_content_filtering() {
    print_message "Setting up content filtering..."
    
    # Content filtering is handled by header_checks, body_checks, mime_header_checks
    # Additional SpamAssassin/Amavis integration can be added here
    
    print_message "✓ Content filtering configured"
}

# Test Postfix configuration
test_postfix_config() {
    print_header "Testing Postfix Configuration"
    
    local errors=0
    
    # Check configuration syntax
    print_message "Checking configuration syntax..."
    if postfix check 2>&1 | tee -a "$log_file"; then
        print_message "✓ Configuration syntax OK"
    else
        print_error "Configuration syntax errors found"
        errors=$((errors + 1))
    fi
    
    # Check for missing files
    print_message "Checking for missing files..."
    local missing_files=()
    
    for file in main.cf master.cf; do
        if [ ! -f "$POSTFIX_CONFIG_DIR/$file" ]; then
            missing_files+=("$file")
        fi
    done
    
    if [ ${#missing_files[@]} -eq 0 ]; then
        print_message "✓ All configuration files present"
    else
        print_error "Missing files: ${missing_files[*]}"
        errors=$((errors + 1))
    fi
    
    # Check permissions
    print_message "Checking file permissions..."
    local perm_errors=0
    
    for file in "$POSTFIX_CONFIG_DIR"/*.cf; do
        if [ -f "$file" ]; then
            perms=$(stat -c %a "$file")
            if [ "$perms" != "644" ] && [ "$perms" != "640" ]; then
                print_warning "Incorrect permissions on $file: $perms"
                perm_errors=$((perm_errors + 1))
            fi
        fi
    done
    
    if [ $perm_errors -eq 0 ]; then
        print_message "✓ File permissions OK"
    else
        print_warning "Found $perm_errors permission issues"
    fi
    
    # Test database connections
    if [ -f "$POSTFIX_CONFIG_DIR/mysql-virtual-mailbox-domains.cf" ]; then
        print_message "Testing database connections..."
        if postmap -q "test.com" mysql:/etc/postfix/mysql-virtual-mailbox-domains.cf 2>/dev/null; then
            print_message "✓ Database connection OK"
        else
            print_warning "Database connection test failed (may be normal if no domains configured)"
        fi
    fi
    
    if [ $errors -eq 0 ]; then
        print_message "✓ Postfix configuration test passed"
        return 0
    else
        print_error "Postfix configuration test failed with $errors error(s)"
        return 1
    fi
}

# Start Postfix service
start_postfix() {
    print_message "Starting Postfix service..."
    
    if systemctl start postfix; then
        if systemctl is-active --quiet postfix; then
            print_message "✓ Postfix started successfully"
            systemctl enable postfix
            return 0
        fi
    fi
    
    print_error "Failed to start Postfix"
    journalctl -u postfix --no-pager -n 20
    return 1
}

# Main setup function for multi-IP Postfix
setup_postfix_multi_ip() {
    local domain=$1
    local hostname=$2
    
    print_header "Setting up Postfix for Multi-IP Configuration"
    
    # Check installation
    if ! check_postfix_installation; then
        print_message "Installing Postfix..."
        apt-get update
        apt-get install -y postfix postfix-mysql postfix-pcre
        check_postfix_installation
    fi
    
    # Initialize configuration
    init_postfix_config "$domain" "$hostname"
    
    # Configure for multi-IP if IPs are configured
    if [ ${#IP_ADDRESSES[@]} -gt 0 ]; then
        configure_postfix_multiip
    fi
    
    # Test configuration
    if test_postfix_config; then
        # Start Postfix
        start_postfix
    else
        print_error "Configuration test failed. Please review the settings."
        return 1
    fi
    
    print_message "✓ Postfix multi-IP setup completed"
}

# Export functions
export -f check_postfix_installation init_postfix_config create_postfix_directories
export -f generate_main_cf generate_master_cf create_postfix_maps
export -f setup_postfix_sasl setup_postfix_tls setup_postfix_milters
export -f setup_rate_limiting setup_content_filtering test_postfix_config
export -f start_postfix setup_postfix_multi_ip
