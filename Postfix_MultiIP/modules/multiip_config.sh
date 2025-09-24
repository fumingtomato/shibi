#!/bin/bash

# =================================================================
# MULTI-IP CONFIGURATION MODULE
# IP detection, network interface setup, rotation configuration
# =================================================================

# Function to get all server IPs
get_all_server_ips() {
    print_header "Detecting Server IP Addresses"
    
    local all_ips=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1')
    
    print_message "Currently configured IP addresses on this server:"
    echo "$all_ips"
    
    PRIMARY_IP=$(get_public_ip)
    print_message "Primary public IP: $PRIMARY_IP"
    
    print_message "\nDo you want to configure multiple IP addresses for bulk mailing?"
    read -p "Enter 'yes' to configure multiple IPs, or 'no' for single IP setup: " multi_ip_choice
    
    if [[ "$multi_ip_choice" == "yes" || "$multi_ip_choice" == "y" ]]; then
        print_message "\nEnter ALL IP addresses you want to use (including ones not yet configured)."
        print_message "The installer will configure them for you."
        print_message "Press Enter with empty input when done."
        
        IP_ADDRESSES+=("$PRIMARY_IP")
        IP_COUNT=1
        
        while true; do
            read -p "Enter IP address #$((IP_COUNT + 1)) (or press Enter to finish): " ip_addr
            
            if [ -z "$ip_addr" ]; then
                break
            fi
            
            if [[ $ip_addr =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
                IP_ADDRESSES+=("$ip_addr")
                IP_COUNT=$((IP_COUNT + 1))
                print_message "Added IP: $ip_addr (will be configured during installation)"
            else
                print_error "Invalid IP format. Please enter a valid IPv4 address."
            fi
        done
    else
        IP_ADDRESSES+=("$PRIMARY_IP")
        IP_COUNT=1
    fi
    
    export IP_ADDRESSES
    export IP_COUNT
    print_message "\nWill configure ${IP_COUNT} IP address(es) for mail server."
}

# Configure network interfaces for multiple IPs
configure_network_interfaces() {
    print_header "Configuring Network Interfaces for Multiple IPs"
    
    if [ ${#IP_ADDRESSES[@]} -le 1 ]; then
        print_message "Single IP configuration - skipping network interface setup"
        return
    fi
    
    local primary_interface=$(ip route | grep default | awk '{print $5}' | head -1)
    print_message "Primary network interface: $primary_interface"
    
    print_message "Configuring additional IP addresses..."
    
    # For Ubuntu 24.04, we'll use netplan or ip commands
    local os_version=$(lsb_release -rs)
    
    if [[ "$os_version" == "24.04" ]] || [[ "$os_version" > "20.04" ]]; then
        print_message "Detected Ubuntu $os_version - using netplan configuration"
        
        # Check if netplan config exists
        if [ -d "/etc/netplan" ]; then
            # Create a backup of existing netplan config
            cp /etc/netplan/*.yaml /etc/netplan/backup-$(date +%Y%m%d).yaml 2>/dev/null || true
            
            # Get the existing netplan file
            local netplan_file=$(ls /etc/netplan/*.yaml | head -1)
            
            if [ -z "$netplan_file" ]; then
                netplan_file="/etc/netplan/99-multiip.yaml"
                print_message "Creating new netplan configuration: $netplan_file"
                
                cat > "$netplan_file" <<EOF
network:
  version: 2
  ethernets:
    $primary_interface:
      addresses:
EOF
                
                for ip in "${IP_ADDRESSES[@]}"; do
                    read -p "Enter subnet mask for $ip (e.g., 24 for /24 or 255.255.255.0): " subnet
                    
                    if [[ "$subnet" =~ ^[0-9]+$ ]]; then
                        echo "        - $ip/$subnet" >> "$netplan_file"
                    else
                        # Convert subnet mask to CIDR
                        case "$subnet" in
                            "255.255.255.0") cidr=24 ;;
                            "255.255.255.128") cidr=25 ;;
                            "255.255.255.192") cidr=26 ;;
                            "255.255.255.224") cidr=27 ;;
                            "255.255.255.240") cidr=28 ;;
                            "255.255.255.248") cidr=29 ;;
                            "255.255.255.252") cidr=30 ;;
                            *) cidr=24 ;;
                        esac
                        echo "        - $ip/$cidr" >> "$netplan_file"
                    fi
                done
                
                # Add gateway if needed
                local gateway=$(ip route | grep default | awk '{print $3}' | head -1)
                if [ ! -z "$gateway" ]; then
                    cat >> "$netplan_file" <<EOF
      routes:
        - to: default
          via: $gateway
      nameservers:
        addresses: [8.8.8.8, 8.8.4.4]
EOF
                fi
            else
                print_warning "Existing netplan configuration found. Manual configuration may be required."
                print_message "Please add the following IPs to $netplan_file:"
                for ip in "${IP_ADDRESSES[@]:1}"; do
                    echo "  - $ip/24  # Adjust subnet as needed"
                done
            fi
            
            print_message "Applying netplan configuration..."
            netplan apply
            
        else
            # Fallback to traditional IP commands for immediate configuration
            print_message "Using ip commands for immediate configuration..."
            
            for ip in "${IP_ADDRESSES[@]:1}"; do
                print_message "Adding IP $ip to interface $primary_interface..."
                ip addr add "$ip/24" dev "$primary_interface" 2>/dev/null || print_warning "IP $ip might already be configured"
            done
        fi
        
    else
        # For older Ubuntu versions, use traditional method
        print_message "Creating persistent network configuration..."
        
        backup_config "network" "/etc/network/interfaces"
        
        cat > /etc/network/interfaces.d/50-multi-ip.cfg <<EOF
# Multi-IP configuration for bulk mail server
# Generated by $INSTALLER_NAME v$INSTALLER_VERSION
# Date: $(date)

EOF
        
        local ip_index=0
        for ip in "${IP_ADDRESSES[@]:1}"; do
            ip_index=$((ip_index + 1))
            
            read -p "Enter subnet mask for $ip (e.g., 255.255.255.0 or 24): " subnet
            
            if [[ "$subnet" =~ ^[0-9]+$ ]]; then
                case $subnet in
                    24) netmask="255.255.255.0" ;;
                    25) netmask="255.255.255.128" ;;
                    26) netmask="255.255.255.192" ;;
                    27) netmask="255.255.255.224" ;;
                    28) netmask="255.255.255.240" ;;
                    29) netmask="255.255.255.248" ;;
                    30) netmask="255.255.255.252" ;;
                    *) netmask="255.255.255.0" ;;
                esac
            else
                netmask=$subnet
            fi
            
            cat >> /etc/network/interfaces.d/50-multi-ip.cfg <<EOF
auto ${primary_interface}:${ip_index}
iface ${primary_interface}:${ip_index} inet static
    address $ip
    netmask $netmask

EOF
        done
    fi
    
    # Verify IPs are configured
    print_message "\nVerifying IP configuration..."
    for ip in "${IP_ADDRESSES[@]}"; do
        if ip addr show | grep -q "$ip"; then
            print_message "✓ IP $ip is configured"
        else
            print_warning "✗ IP $ip may need manual configuration or system restart"
        fi
    done
    
    print_message "Network interface configuration completed"
    print_warning "You may need to restart networking or reboot for all IPs to become fully active"
}

# Create IP rotation configuration (rest of the file remains the same)
create_ip_rotation_config() {
    print_header "Creating IP Rotation Configuration"
    
    if [ ${#IP_ADDRESSES[@]} -le 1 ]; then
        print_message "Single IP configuration - IP rotation not needed"
        return
    fi
    
    mkdir -p /etc/postfix/transport_maps
    
    print_message "Creating sender-dependent transport configuration..."
    
    cat > /etc/postfix/sender_dependent_default_transport_maps <<EOF
# Sender-dependent transport configuration for IP rotation
# Generated by $INSTALLER_NAME v$INSTALLER_VERSION

EOF
    
    local transport_index=0
    for ip in "${IP_ADDRESSES[@]}"; do
        transport_index=$((transport_index + 1))
        local transport_name="smtp-ip${transport_index}"
        
        print_message "\nConfiguring IP: $ip"
        read -p "Enter domain(s) to send from this IP (comma-separated, or 'all' for round-robin): " ip_domains
        
        if [ "$ip_domains" == "all" ]; then
            echo "# IP $ip - Used for round-robin delivery" >> /etc/postfix/sender_dependent_default_transport_maps
        else
            IFS=',' read -ra DOMAINS <<< "$ip_domains"
            for domain in "${DOMAINS[@]}"; do
                domain=$(echo "$domain" | xargs)
                echo "@${domain}    ${transport_name}:" >> /etc/postfix/sender_dependent_default_transport_maps
            done
        fi
    done
    
    create_random_transport_selector
    
    print_message "IP rotation configuration created"
}

# Create random transport selector script
create_random_transport_selector() {
    cat > /usr/local/bin/postfix-random-transport <<'EOF'
#!/bin/bash
# Random transport selector for load balancing

transports=()
for i in {1..20}; do
    if grep -q "smtp-ip${i}" /etc/postfix/master.cf; then
        transports+=("smtp-ip${i}")
    fi
done

if [ ${#transports[@]} -gt 0 ]; then
    random_index=$((RANDOM % ${#transports[@]}))
    echo "${transports[$random_index]}:"
else
    echo "smtp:"
fi
EOF
    
    chmod +x /usr/local/bin/postfix-random-transport
}

# Configure reverse DNS instructions
create_ptr_instructions() {
    local output_file="/root/ptr-records-setup.txt"
    
    cat > "$output_file" <<EOF
==========================================================
REVERSE DNS (PTR) RECORDS CONFIGURATION
==========================================================

IMPORTANT: PTR records must be configured with your hosting provider.
They cannot be set through Cloudflare or standard DNS management.

Your IP addresses and suggested PTR records:

EOF
    
    local idx=1
    for ip in "${IP_ADDRESSES[@]}"; do
        cat >> "$output_file" <<EOF
IP Address #$idx: $ip
Suggested PTR: mail${idx}.$DOMAIN_NAME

EOF
        idx=$((idx + 1))
    done
    
    cat >> "$output_file" <<EOF
==========================================================
HOW TO CONFIGURE:

1. Contact your hosting provider's support
2. Request PTR record configuration for each IP
3. Provide the IP address and desired hostname
4. Wait for confirmation (usually 24-48 hours)

VERIFICATION:

Once configured, verify with:
dig -x IP_ADDRESS

or:
host IP_ADDRESS

==========================================================
EOF
    
    print_message "PTR record instructions saved to $output_file"
}

export -f get_all_server_ips configure_network_interfaces create_ip_rotation_config
export -f create_random_transport_selector create_ptr_instructions
