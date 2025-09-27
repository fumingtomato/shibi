#!/bin/bash

# =================================================================
# MULTI-IP CONFIGURATION MODULE
# IP detection, network interface setup, rotation configuration
# =================================================================

# Function to get all server IPs with IP range support
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
        print_message "\nEnter IP addresses you want to use."
        print_message "Formats accepted:"
        print_message "  - Single IP: 208.115.249.246"
        print_message "  - IP Range: 208.115.249.246-250 (will add .246, .247, .248, .249, .250)"
        print_message "  - CIDR: 208.115.249.0/29 (will add all IPs in subnet)"
        print_message "Press Enter with empty input when done."
        
        IP_ADDRESSES+=("$PRIMARY_IP")
        IP_COUNT=1
        
        while true; do
            read -p "Enter IP address #$((IP_COUNT + 1)) or range (or press Enter to finish): " ip_input
            
            if [ -z "$ip_input" ]; then
                break
            fi
            
            # Check if it's a range (e.g., 208.115.249.246-250)
            if [[ "$ip_input" =~ ^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)([0-9]{1,3})-([0-9]{1,3})$ ]]; then
                local ip_base="${BASH_REMATCH[1]}"
                local start_octet="${BASH_REMATCH[2]}"
                local end_octet="${BASH_REMATCH[3]}"
                
                if [ "$start_octet" -le "$end_octet" ] && [ "$end_octet" -le 255 ]; then
                    print_message "Adding IP range: ${ip_base}${start_octet} to ${ip_base}${end_octet}"
                    for ((i=start_octet; i<=end_octet; i++)); do
                        local full_ip="${ip_base}${i}"
                        # Skip if it's the primary IP (already added)
                        if [ "$full_ip" != "$PRIMARY_IP" ]; then
                            IP_ADDRESSES+=("$full_ip")
                            IP_COUNT=$((IP_COUNT + 1))
                            print_message "  Added IP: $full_ip"
                        else
                            print_message "  Skipping $full_ip (already added as primary)"
                        fi
                    done
                else
                    print_error "Invalid range. End must be >= start and <= 255"
                fi
                
            # Check if it's CIDR notation (e.g., 208.115.249.0/29)
            elif [[ "$ip_input" =~ ^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/([0-9]{1,2})$ ]]; then
                local network="${BASH_REMATCH[1]}"
                local cidr="${BASH_REMATCH[2]}"
                
                if command -v ipcalc &> /dev/null; then
                    print_message "Processing CIDR block: $ip_input"
                    # Use ipcalc to get all IPs in range
                    local ip_list=$(ipcalc -nb "$ip_input" | grep -E "^HostMin:|^HostMax:" | awk '{print $2}')
                    if [ ! -z "$ip_list" ]; then
                        local min_ip=$(echo "$ip_list" | head -1)
                        local max_ip=$(echo "$ip_list" | tail -1)
                        
                        # Convert IPs to integers for iteration
                        IFS='.' read -r -a min_parts <<< "$min_ip"
                        IFS='.' read -r -a max_parts <<< "$max_ip"
                        
                        local min_last="${min_parts[3]}"
                        local max_last="${max_parts[3]}"
                        local ip_prefix="${min_parts[0]}.${min_parts[1]}.${min_parts[2]}."
                        
                        for ((i=min_last; i<=max_last; i++)); do
                            local full_ip="${ip_prefix}${i}"
                            if [ "$full_ip" != "$PRIMARY_IP" ]; then
                                IP_ADDRESSES+=("$full_ip")
                                IP_COUNT=$((IP_COUNT + 1))
                                print_message "  Added IP: $full_ip"
                            fi
                        done
                    fi
                else
                    print_warning "ipcalc not found. Installing it for CIDR support..."
                    apt-get install -y ipcalc &>/dev/null
                    print_message "Please re-enter the CIDR notation."
                fi
                
            # Check if it's a simple range like 246-250 (assume same subnet as primary)
            elif [[ "$ip_input" =~ ^([0-9]{1,3})-([0-9]{1,3})$ ]]; then
                local start_octet="${BASH_REMATCH[1]}"
                local end_octet="${BASH_REMATCH[2]}"
                
                # Extract base from primary IP
                local ip_base=$(echo "$PRIMARY_IP" | cut -d'.' -f1-3)
                
                if [ "$start_octet" -le "$end_octet" ] && [ "$end_octet" -le 255 ]; then
                    print_message "Adding IP range: ${ip_base}.${start_octet} to ${ip_base}.${end_octet}"
                    for ((i=start_octet; i<=end_octet; i++)); do
                        local full_ip="${ip_base}.${i}"
                        if [ "$full_ip" != "$PRIMARY_IP" ]; then
                            IP_ADDRESSES+=("$full_ip")
                            IP_COUNT=$((IP_COUNT + 1))
                            print_message "  Added IP: $full_ip"
                        else
                            print_message "  Skipping $full_ip (already added as primary)"
                        fi
                    done
                else
                    print_error "Invalid range. End must be >= start and <= 255"
                fi
                
            # Single IP address
            elif [[ "$ip_input" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
                # Skip if it's the primary IP (already added)
                if [ "$ip_input" != "$PRIMARY_IP" ]; then
                    IP_ADDRESSES+=("$ip_input")
                    IP_COUNT=$((IP_COUNT + 1))
                    print_message "Added IP: $ip_input (will be configured during installation)"
                else
                    print_message "Skipping $ip_input (already added as primary)"
                fi
            else
                print_error "Invalid format. Use single IP (208.115.249.246), range (208.115.249.246-250), or simple range (246-250)"
            fi
        done
    else
        IP_ADDRESSES+=("$PRIMARY_IP")
        IP_COUNT=1
    fi
    
    # Remove duplicates
    local unique_ips=($(printf "%s\n" "${IP_ADDRESSES[@]}" | sort -u))
    IP_ADDRESSES=("${unique_ips[@]}")
    IP_COUNT=${#IP_ADDRESSES[@]}
    
    export IP_ADDRESSES
    export IP_COUNT
    
    print_message "\nTotal unique IPs to be configured: ${IP_COUNT}"
    print_message "IP addresses:"
    for ip in "${IP_ADDRESSES[@]}"; do
        echo "  - $ip"
    done
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

# Create IP rotation configuration
create_ip_rotation_config() {
    print_header "Creating IP Rotation Configuration"
    
    if [ ${#IP_ADDRESSES[@]} -le 1 ]; then
        print_message "Single IP configuration - IP rotation not needed"
        return
    fi
    
    mkdir -p /etc/postfix/transport_maps
    
    print_message "Setting up round-robin IP rotation by default..."
    
    # Create sender-dependent transport configuration, defaulting to round-robin
    cat > /etc/postfix/sender_dependent_default_transport_maps <<EOF
# Sender-dependent transport configuration for IP rotation
# Generated by $INSTALLER_NAME v$INSTALLER_VERSION
# Default configuration: Round-Robin IP rotation

# This file will be populated with any domain-specific IP assignments
EOF
    
    # No need to prompt for domain assignment - we're defaulting to round-robin
    print_message "IP rotation will use round-robin by default"
    print_message "You can assign specific domains to specific IPs later using:"
    print_message "  - Edit /etc/postfix/sender_dependent_default_transport_maps"
    print_message "  - Run 'postmap /etc/postfix/sender_dependent_default_transport_maps'"
    print_message "  - Restart Postfix 'systemctl restart postfix'"
    
    # Create the random transport selector script
    create_random_transport_selector
    
    print_message "IP rotation configuration created with round-robin default"
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

# Configure reverse DNS instructions with numbered subdomain format
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
    
    # Use the new numbered subdomain format for PTR records
    for ((i=0; i<${#IP_ADDRESSES[@]}; i++)); do
        local ip="${IP_ADDRESSES[$i]}"
        local ptr_hostname
        
        if [ $i -eq 0 ]; then
            # Primary IP uses the main subdomain
            ptr_hostname="${SUBDOMAIN}.${DOMAIN_NAME}"
        else
            # Additional IPs use numbered format (subdomain001, subdomain002, etc.)
            local suffix=$(printf "%03d" $i)
            ptr_hostname="${SUBDOMAIN}${suffix}.${DOMAIN_NAME}"
        fi
        
        cat >> "$output_file" <<EOF
IP Address #$((i+1)): $ip
Suggested PTR: $ptr_hostname

EOF
    done
    
    cat >> "$output_file" <<EOF
==========================================================
WHY THE NUMBERED FORMAT?

The numbered subdomain format (${SUBDOMAIN}001, ${SUBDOMAIN}002, etc.)
provides several benefits:

1. Clean Organization: Easy to identify which hostname belongs to which IP
2. Professional Appearance: Looks more professional than mail1, mail2, etc.
3. Scalability: Can easily add more IPs up to 999 without naming conflicts
4. Consistency: Matches the HELO hostname used by each IP in Postfix

==========================================================
HOW TO CONFIGURE:

1. Contact your hosting provider's support
2. Request PTR record configuration for each IP
3. Provide the IP address and desired hostname exactly as shown above
4. Wait for confirmation (usually 24-48 hours)

VERIFICATION:

Once configured, verify each PTR record with:
EOF
    
    # Add verification commands for each IP
    for ip in "${IP_ADDRESSES[@]}"; do
        echo "dig -x $ip" >> "$output_file"
    done
    
    echo "" >> "$output_file"
    echo "or:" >> "$output_file"
    echo "" >> "$output_file"
    
    for ip in "${IP_ADDRESSES[@]}"; do
        echo "host $ip" >> "$output_file"
    done
    
    cat >> "$output_file" <<EOF

EXPECTED RESULTS:

The commands above should return the hostname you configured.
For example:
  dig -x ${IP_ADDRESSES[0]} 
  Should return: ${SUBDOMAIN}.${DOMAIN_NAME}

==========================================================
TROUBLESHOOTING:

If PTR records are not resolving correctly:

1. Wait at least 48 hours for propagation
2. Verify with your hosting provider that records were set
3. Check for typos in the hostname
4. Ensure the forward DNS (A record) also exists for each hostname

IMPORTANCE FOR EMAIL DELIVERY:

Proper PTR records are CRITICAL for email delivery:
- Many mail servers reject email from IPs without PTR records
- PTR must match the HELO hostname used by your mail server
- Mismatched PTR records can trigger spam filters

==========================================================
QUICK REFERENCE:

Subdomain: ${SUBDOMAIN}
Domain: ${DOMAIN_NAME}
Number of IPs: ${#IP_ADDRESSES[@]}

Hostname Format:
- Primary: ${SUBDOMAIN}.${DOMAIN_NAME}
- Additional: ${SUBDOMAIN}XXX.${DOMAIN_NAME} (where XXX is 001, 002, etc.)

==========================================================
EOF
    
    print_message "PTR record instructions saved to $output_file"
    
    # Also create a simple CSV file for easy copy/paste
    local csv_file="/root/ptr-records.csv"
    echo "IP Address,PTR Record" > "$csv_file"
    
    for ((i=0; i<${#IP_ADDRESSES[@]}; i++)); do
        local ip="${IP_ADDRESSES[$i]}"
        local ptr_hostname
        
        if [ $i -eq 0 ]; then
            ptr_hostname="${SUBDOMAIN}.${DOMAIN_NAME}"
        else
            local suffix=$(printf "%03d" $i)
            ptr_hostname="${SUBDOMAIN}${suffix}.${DOMAIN_NAME}"
        fi
        
        echo "$ip,$ptr_hostname" >> "$csv_file"
    done
    
    print_message "PTR records CSV saved to $csv_file (for easy copy/paste)"
}

export -f get_all_server_ips configure_network_interfaces create_ip_rotation_config
export -f create_random_transport_selector create_ptr_instructions
