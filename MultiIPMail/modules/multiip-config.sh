#!/bin/bash

# =================================================================
# MULTI-IP CONFIGURATION MODULE - FIXED VERSION
# Network interface management, IP rotation, and transport mapping
# Fixed: Network detection, IP validation, transport map generation
# =================================================================

# Global variables for IP configuration
declare -ga CONFIGURED_IPS=()
declare -ga TRANSPORT_MAPS=()
declare -g PRIMARY_INTERFACE=""
declare -g IP_ROTATION_ENABLED=false
declare -g ROTATION_INTERVAL=60

# Detect primary network interface
detect_primary_interface() {
    local interface=""
    
    # Try multiple methods to detect the interface
    # Method 1: Get interface with default route
    interface=$(ip route | grep '^default' | awk '{print $5}' | head -1)
    
    # Method 2: Get interface with public IP
    if [ -z "$interface" ]; then
        interface=$(ip addr | grep 'state UP' | grep -v 'lo:' | awk -F': ' '{print $2}' | head -1)
    fi
    
    # Method 3: Common interface names
    if [ -z "$interface" ]; then
        for iface in eth0 ens3 ens5 enp0s3 enp0s8 eth1 eno1; do
            if ip link show "$iface" &>/dev/null; then
                interface="$iface"
                break
            fi
        done
    fi
    
    if [ -z "$interface" ]; then
        print_error "Could not detect primary network interface"
        return 1
    fi
    
    PRIMARY_INTERFACE="$interface"
    print_message "Primary network interface: $PRIMARY_INTERFACE"
    return 0
}

# Validate and check if IP is available
check_ip_availability() {
    local ip=$1
    
    # Validate IP format
    if ! validate_ip_address "$ip"; then
        print_error "Invalid IP address format: $ip"
        return 1
    fi
    
    # Check if IP is already configured on system
    if ip addr show | grep -q "inet $ip/"; then
        print_warning "IP $ip is already configured on the system"
        return 2
    fi
    
    # Ping test to check if IP is in use (optional)
    if ping -c 1 -W 1 "$ip" &>/dev/null; then
        print_warning "IP $ip appears to be in use (responds to ping)"
        read -p "Continue anyway? (y/n): " continue_anyway
        if [[ "$continue_anyway" != "y" ]]; then
            return 1
        fi
    fi
    
    return 0
}

# Add IP address to network interface
add_ip_to_interface() {
    local ip=$1
    local interface=${2:-$PRIMARY_INTERFACE}
    local netmask=${3:-24}
    
    print_message "Adding IP $ip to interface $interface..."
    
    # Check if IP is already configured
    if ip addr show "$interface" | grep -q "inet $ip/"; then
        print_warning "IP $ip already configured on $interface"
        return 0
    fi
    
    # Add the IP address
    if ip addr add "$ip/$netmask" dev "$interface" 2>/dev/null; then
        print_message "✓ IP $ip added to $interface"
        CONFIGURED_IPS+=("$ip")
        
        # Make configuration persistent
        make_ip_persistent "$ip" "$interface" "$netmask"
        
        return 0
    else
        print_error "Failed to add IP $ip to $interface"
        return 1
    fi
}

# Make IP configuration persistent across reboots
make_ip_persistent() {
    local ip=$1
    local interface=$2
    local netmask=$3
    
    # Detect network configuration system
    if [ -d /etc/netplan ]; then
        # Ubuntu 18.04+ uses Netplan
        configure_netplan_ip "$ip" "$interface" "$netmask"
    elif [ -f /etc/network/interfaces ]; then
        # Debian/older Ubuntu uses interfaces file
        configure_interfaces_ip "$ip" "$interface" "$netmask"
    elif [ -d /etc/sysconfig/network-scripts ]; then
        # RedHat/CentOS uses network-scripts
        configure_rhel_ip "$ip" "$interface" "$netmask"
    else
        print_warning "Unknown network configuration system. IP may not persist after reboot."
        
        # Create systemd service as fallback
        create_ip_systemd_service "$ip" "$interface" "$netmask"
    fi
}

# Configure IP in Netplan (Ubuntu 18.04+)
configure_netplan_ip() {
    local ip=$1
    local interface=$2
    local netmask=$3
    
    local netplan_file="/etc/netplan/99-additional-ips.yaml"
    
    # Create or update Netplan configuration
    if [ ! -f "$netplan_file" ]; then
        cat > "$netplan_file" <<EOF
# Additional IP addresses configuration
network:
  version: 2
  ethernets:
    $interface:
      addresses:
        - $ip/$netmask
EOF
    else
        # Add IP to existing configuration
        # This is a simplified approach - in production, use a YAML parser
        if ! grep -q "$ip/$netmask" "$netplan_file"; then
            sed -i "/addresses:/a\\        - $ip/$netmask" "$netplan_file"
        fi
    fi
    
    # Apply Netplan configuration
    netplan apply 2>/dev/null || true
}

# Configure IP in /etc/network/interfaces
configure_interfaces_ip() {
    local ip=$1
    local interface=$2
    local netmask=$3
    
    local interfaces_file="/etc/network/interfaces"
    local alias_num=0
    
    # Find next available alias number
    while grep -q "^auto ${interface}:${alias_num}" "$interfaces_file" 2>/dev/null; do
        alias_num=$((alias_num + 1))
    done
    
    # Add interface alias configuration
    cat >> "$interfaces_file" <<EOF

# Additional IP $ip
auto ${interface}:${alias_num}
iface ${interface}:${alias_num} inet static
    address $ip
    netmask 255.255.255.$(echo $((256 - 2**(32-$netmask))))
EOF
    
    # Bring up the interface
    ifup "${interface}:${alias_num}" 2>/dev/null || true
}

# Create systemd service for IP persistence
create_ip_systemd_service() {
    local ip=$1
    local interface=$2
    local netmask=$3
    
    cat > "/etc/systemd/system/add-ip-${ip//\./-}.service" <<EOF
[Unit]
Description=Add IP address $ip to $interface
After=network.target

[Service]
Type=oneshot
ExecStart=/sbin/ip addr add $ip/$netmask dev $interface
RemainAfterExit=yes
ExecStop=/sbin/ip addr del $ip/$netmask dev $interface

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable "add-ip-${ip//\./-}.service"
    systemctl start "add-ip-${ip//\./-}.service"
}

# Setup multiple IP addresses
setup_multiple_ips() {
    print_header "Configuring Multiple IP Addresses"
    
    # Detect primary interface
    if ! detect_primary_interface; then
        return 1
    fi
    
    # Get list of IP addresses to configure
    local ip_count=${#IP_ADDRESSES[@]}
    
    if [ $ip_count -eq 0 ]; then
        print_warning "No additional IP addresses to configure"
        return 0
    fi
    
    print_message "Configuring $ip_count IP addresses..."
    
    local failed_ips=()
    
    for i in "${!IP_ADDRESSES[@]}"; do
        local ip="${IP_ADDRESSES[$i]}"
        local hostname="${HOSTNAMES[$i]:-mail-$i.$DOMAIN_NAME}"
        
        print_message "[$((i+1))/$ip_count] Configuring IP: $ip"
        
        if check_ip_availability "$ip"; then
            if add_ip_to_interface "$ip"; then
                # Add reverse DNS entry if possible
                setup_reverse_dns "$ip" "$hostname"
                
                # Create transport map entry
                create_transport_map_entry "$ip" "$hostname"
            else
                failed_ips+=("$ip")
            fi
        else
            failed_ips+=("$ip")
        fi
    done
    
    if [ ${#failed_ips[@]} -gt 0 ]; then
        print_warning "Failed to configure IPs: ${failed_ips[*]}"
    fi
    
    # Generate Postfix transport maps
    generate_postfix_transport_maps
    
    # Setup IP rotation if requested
    if [ "$IP_ROTATION_ENABLED" = true ]; then
        setup_ip_rotation
    fi
    
    print_message "✓ Multiple IP configuration completed"
}

# Setup reverse DNS for IP
setup_reverse_dns() {
    local ip=$1
    local hostname=$2
    
    # This would typically involve API calls to your hosting provider
    # Here we'll just log the requirement
    
    print_message "Reverse DNS setup required for $ip -> $hostname"
    
    # Create a record file for manual configuration
    echo "$ip $hostname" >> /root/reverse-dns-setup.txt
}

# Create transport map entry for IP
create_transport_map_entry() {
    local ip=$1
    local hostname=$2
    
    # Create transport entry
    local transport_entry="$hostname smtp:[$ip]"
    TRANSPORT_MAPS+=("$transport_entry")
    
    # Create sender_dependent_relayhost_maps entry
    echo "@$hostname [$ip]:25" >> /etc/postfix/sender_relay
}

# Generate Postfix transport maps for multi-IP setup
generate_postfix_transport_maps() {
    print_message "Generating Postfix transport maps..."
    
    local transport_file="/etc/postfix/transport"
    local sender_transport_file="/etc/postfix/sender_transport"
    local relay_by_sender="/etc/postfix/relay_by_sender"
    
    # Create transport file header
    cat > "$transport_file" <<EOF
# Postfix transport map for multi-IP configuration
# Generated by Mail Server Installer
# Date: $(date)

EOF
    
    # Add transport entries for each domain/IP
    for i in "${!IP_ADDRESSES[@]}"; do
        local ip="${IP_ADDRESSES[$i]}"
        local domain="${IP_DOMAINS[$i]:-$DOMAIN_NAME}"
        local hostname="${HOSTNAMES[$i]:-mail-$i.$domain}"
        
        # Transport map entry
        echo "$domain smtp:[$ip]" >> "$transport_file"
        echo ".$domain smtp:[$ip]" >> "$transport_file"
        
        # Sender dependent transport
        echo "@$domain smtp:[$ip]:25" >> "$sender_transport_file"
    done
    
    # Create relay_by_sender map for sticky IP feature
    cat > "$relay_by_sender" <<EOF
# Sender-based relay host mapping
# Format: sender@domain [IP]:port

EOF
    
    # Add entries for each configured email address
    for i in "${!IP_ADDRESSES[@]}"; do
        local ip="${IP_ADDRESSES[$i]}"
        local domain="${IP_DOMAINS[$i]:-$DOMAIN_NAME}"
        
        echo "@$domain [$ip]:25" >> "$relay_by_sender"
    done
    
    # Compile the maps
    for map_file in "$transport_file" "$sender_transport_file" "$relay_by_sender"; do
        if [ -f "$map_file" ]; then
            postmap "$map_file"
            chmod 644 "$map_file" "${map_file}.db"
        fi
    done
    
    print_message "✓ Transport maps generated"
}

# Configure Postfix for multi-IP sending
configure_postfix_multiip() {
    print_header "Configuring Postfix for Multi-IP"
    
    local postfix_main="/etc/postfix/main.cf"
    
    # Backup current configuration
    backup_config "postfix" "$postfix_main"
    
    # Add multi-IP configuration
    cat >> "$postfix_main" <<EOF

# ============================================
# Multi-IP Configuration
# ============================================

# Enable sender-dependent relay host
sender_dependent_relayhost_maps = hash:/etc/postfix/relay_by_sender

# Transport maps
transport_maps = hash:/etc/postfix/transport

# Sender dependent default transport
sender_dependent_default_transport_maps = hash:/etc/postfix/sender_transport

# SMTP bind address (rotate through IPs)
smtp_bind_address =

# Enable connection caching for performance
smtp_connection_cache_on_demand = yes
smtp_connection_cache_time_limit = 2s
smtp_connection_reuse_time_limit = 300s

# Connection pooling
smtp_connection_cache_destinations = 

# Rate limiting per destination
smtp_destination_concurrency_limit = 2
smtp_destination_rate_delay = 1s
smtp_extra_recipient_limit = 10

# Process limits for multi-IP
default_process_limit = 100
smtp_process_limit = 100

# Queue configuration for multi-IP
maximal_queue_lifetime = 3d
bounce_queue_lifetime = 3d
maximal_backoff_time = 4000s
minimal_backoff_time = 300s
queue_run_delay = 300s

EOF
    
    # Create IP pool configuration
    create_ip_pool_config
    
    # Reload Postfix
    postfix reload
    
    print_message "✓ Postfix multi-IP configuration completed"
}

# Create IP pool configuration for rotation
create_ip_pool_config() {
    local pool_file="/etc/postfix/ip_pool"
    
    cat > "$pool_file" <<EOF
# IP Pool Configuration
# IPs available for rotation

EOF
    
    for ip in "${IP_ADDRESSES[@]}"; do
        echo "$ip" >> "$pool_file"
    done
    
    chmod 644 "$pool_file"
}

# Setup IP rotation for load balancing
setup_ip_rotation() {
    print_header "Setting up IP Rotation"
    
    # Create rotation script
    cat > /usr/local/bin/rotate-sending-ip.sh <<'EOF'
#!/bin/bash

# IP Rotation Script for Postfix
# Rotates sending IP for load balancing

POOL_FILE="/etc/postfix/ip_pool"
CURRENT_IP_FILE="/var/lib/postfix/current_ip"
LOCK_FILE="/var/lock/ip-rotation.lock"

# Acquire lock
exec 200>"$LOCK_FILE"
flock -n 200 || exit 1

# Read IP pool
if [ ! -f "$POOL_FILE" ]; then
    echo "IP pool file not found"
    exit 1
fi

# Get list of IPs
mapfile -t IP_POOL < <(grep -v '^#' "$POOL_FILE" | grep -v '^$')

if [ ${#IP_POOL[@]} -eq 0 ]; then
    echo "No IPs in pool"
    exit 1
fi

# Get current IP index
CURRENT_INDEX=0
if [ -f "$CURRENT_IP_FILE" ]; then
    CURRENT_INDEX=$(cat "$CURRENT_IP_FILE")
fi

# Calculate next index
NEXT_INDEX=$(( (CURRENT_INDEX + 1) % ${#IP_POOL[@]} ))

# Get next IP
NEXT_IP="${IP_POOL[$NEXT_INDEX]}"

# Update Postfix configuration
postconf -e "smtp_bind_address=$NEXT_IP"
postfix reload

# Save current index
echo "$NEXT_INDEX" > "$CURRENT_IP_FILE"

# Log rotation
logger -t ip-rotation "Rotated to IP $NEXT_IP (index $NEXT_INDEX)"

# Release lock
flock -u 200
EOF
    
    chmod +x /usr/local/bin/rotate-sending-ip.sh
    
    # Create systemd timer for rotation
    cat > /etc/systemd/system/ip-rotation.service <<EOF
[Unit]
Description=Rotate sending IP address
After=postfix.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/rotate-sending-ip.sh
User=root
EOF
    
    cat > /etc/systemd/system/ip-rotation.timer <<EOF
[Unit]
Description=Rotate sending IP every ${ROTATION_INTERVAL} seconds
After=postfix.service

[Timer]
OnBootSec=${ROTATION_INTERVAL}s
OnUnitActiveSec=${ROTATION_INTERVAL}s

[Install]
WantedBy=timers.target
EOF
    
    # Enable and start the timer
    systemctl daemon-reload
    systemctl enable ip-rotation.timer
    systemctl start ip-rotation.timer
    
    print_message "✓ IP rotation configured (interval: ${ROTATION_INTERVAL}s)"
}

# Test multi-IP configuration
test_multiip_config() {
    print_header "Testing Multi-IP Configuration"
    
    local test_results=()
    local all_good=true
    
    # Test each configured IP
    for ip in "${CONFIGURED_IPS[@]}"; do
        print_message "Testing IP $ip..."
        
        # Check if IP is configured on interface
        if ip addr show | grep -q "inet $ip/"; then
            test_results+=("✓ $ip: Configured on interface")
        else
            test_results+=("✗ $ip: Not configured on interface")
            all_good=false
        fi
        
        # Test outbound connectivity from IP
        if curl --interface "$ip" -s -o /dev/null -w "%{http_code}" https://www.google.com | grep -q "200"; then
            test_results+=("✓ $ip: Outbound connectivity OK")
        else
            test_results+=("✗ $ip: Outbound connectivity failed")
            all_good=false
        fi
        
        # Check if transport map exists
        if [ -f /etc/postfix/transport.db ]; then
            test_results+=("✓ $ip: Transport map configured")
        else
            test_results+=("✗ $ip: Transport map missing")
            all_good=false
        fi
    done
    
    # Display test results
    print_message ""
    print_message "Test Results:"
    for result in "${test_results[@]}"; do
        echo "  $result"
    done
    
    if [ "$all_good" = true ]; then
        print_message "✓ All tests passed"
        return 0
    else
        print_warning "Some tests failed. Please review the configuration."
        return 1
    fi
}

# Remove IP address from system
remove_ip_address() {
    local ip=$1
    local interface=${2:-$PRIMARY_INTERFACE}
    
    print_message "Removing IP $ip from $interface..."
    
    # Remove IP from interface
    ip addr del "$ip/24" dev "$interface" 2>/dev/null || true
    
    # Remove from persistent configuration
    if [ -d /etc/netplan ]; then
        # Remove from Netplan
        sed -i "/$ip/d" /etc/netplan/99-additional-ips.yaml 2>/dev/null || true
        netplan apply 2>/dev/null || true
    elif [ -f /etc/network/interfaces ]; then
        # Remove from interfaces file
        sed -i "/$ip/,+3d" /etc/network/interfaces 2>/dev/null || true
    fi
    
    # Remove systemd service if exists
    systemctl stop "add-ip-${ip//\./-}.service" 2>/dev/null || true
    systemctl disable "add-ip-${ip//\./-}.service" 2>/dev/null || true
    rm -f "/etc/systemd/system/add-ip-${ip//\./-}.service"
    
    print_message "✓ IP $ip removed"
}

# List all configured IPs
list_configured_ips() {
    print_header "Configured IP Addresses"
    
    print_message "System IP addresses:"
    ip -4 addr show | grep inet | grep -v "127.0.0.1" | awk '{print "  - " $2 " on " $NF}'
    
    if [ -f /etc/postfix/ip_pool ]; then
        print_message ""
        print_message "IP pool for rotation:"
        grep -v '^#' /etc/postfix/ip_pool | grep -v '^$' | while read ip; do
            echo "  - $ip"
        done
    fi
    
    if [ -f /etc/postfix/transport ]; then
        print_message ""
        print_message "Transport mappings:"
        grep -v '^#' /etc/postfix/transport | head -10
    fi
}

# Export functions
export -f detect_primary_interface check_ip_availability add_ip_to_interface
export -f make_ip_persistent configure_netplan_ip configure_interfaces_ip
export -f create_ip_systemd_service setup_multiple_ips setup_reverse_dns
export -f create_transport_map_entry generate_postfix_transport_maps
export -f configure_postfix_multiip create_ip_pool_config setup_ip_rotation
export -f test_multiip_config remove_ip_address list_configured_ips

# Export variables
export PRIMARY_INTERFACE CONFIGURED_IPS TRANSPORT_MAPS
export IP_ROTATION_ENABLED ROTATION_INTERVAL
