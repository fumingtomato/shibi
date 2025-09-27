#!/bin/bash

# =================================================================
# MULTI-IP CONFIGURATION MODULE - FIXED VERSION
# IP detection, network interface setup, rotation configuration
# Fixed: Added IP validation, network rollback, and proper error handling
# =================================================================

# Function to validate IP address format
validate_ip() {
    local ip=$1
    if [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        for octet in $(echo $ip | tr '.' ' '); do
            if [ $octet -gt 255 ]; then
                return 1
            fi
        done
        return 0
    fi
    return 1
}

# Function to test network connectivity
test_network_connectivity() {
    local max_attempts=3
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if ping -c 1 -W 2 8.8.8.8 &>/dev/null || ping -c 1 -W 2 1.1.1.1 &>/dev/null; then
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 1
    done
    return 1
}

# Function to backup network configuration
backup_network_config() {
    local backup_dir="/root/network-backups"
    local timestamp=$(date +%Y%m%d-%H%M%S)
    
    mkdir -p "$backup_dir"
    
    # Backup netplan if it exists
    if [ -d "/etc/netplan" ]; then
        cp -r /etc/netplan "$backup_dir/netplan-$timestamp"
        print_message "Backed up netplan configuration to $backup_dir/netplan-$timestamp"
    fi
    
    # Backup network interfaces
    if [ -f "/etc/network/interfaces" ]; then
        cp /etc/network/interfaces "$backup_dir/interfaces-$timestamp"
    fi
    
    # Backup current IP configuration
    ip addr show > "$backup_dir/ip-addr-$timestamp.txt"
    ip route show > "$backup_dir/ip-route-$timestamp.txt"
    
    echo "$timestamp" > "$backup_dir/latest-backup.txt"
    return 0
}

# Function to restore network configuration
restore_network_config() {
    local backup_dir="/root/network-backups"
    
    if [ ! -f "$backup_dir/latest-backup.txt" ]; then
        print_error "No backup found to restore"
        return 1
    fi
    
    local timestamp=$(cat "$backup_dir/latest-backup.txt")
    
    print_warning "Restoring network configuration from backup $timestamp..."
    
    # Restore netplan if backup exists
    if [ -d "$backup_dir/netplan-$timestamp" ]; then
        rm -rf /etc/netplan/*
        cp -r "$backup_dir/netplan-$timestamp"/* /etc/netplan/
        netplan apply
    fi
    
    # Restore network interfaces if backup exists
    if [ -f "$backup_dir/interfaces-$timestamp" ]; then
        cp "$backup_dir/interfaces-$timestamp" /etc/network/interfaces
        systemctl restart networking
    fi
    
    return 0
}

# Function to get all server IPs with IP range support and validation
get_all_server_ips() {
    print_header "Detecting Server IP Addresses"
    
    # Initialize array
    IP_ADDRESSES=()
    
    local all_ips=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1')
    
    print_message "Currently configured IP addresses on this server:"
    echo "$all_ips"
    
    PRIMARY_IP=$(get_public_ip)
    if [ -z "$PRIMARY_IP" ]; then
        print_error "Could not determine primary public IP"
        exit 1
    fi
    
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
                        if validate_ip "$full_ip"; then
                            # Skip if it's the primary IP (already added)
                            if [ "$full_ip" != "$PRIMARY_IP" ]; then
                                IP_ADDRESSES+=("$full_ip")
                                IP_COUNT=$((IP_COUNT + 1))
                                print_message "  Added IP: $full_ip"
                            else
                                print_message "  Skipping $full_ip (already added as primary)"
                            fi
                        else
                            print_warning "  Invalid IP: $full_ip (skipped)"
                        fi
                    done
                else
                    print_error "Invalid range. End must be >= start and <= 255"
                fi
                
            # Check if it's CIDR notation (e.g., 208.115.249.0/29)
            elif [[ "$ip_input" =~ ^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/([0-9]{1,2})$ ]]; then
                local network="${BASH_REMATCH[1]}"
                local cidr="${BASH_REMATCH[2]}"
                
                # Validate CIDR range
                if [ $cidr -lt 8 ] || [ $cidr -gt 32 ]; then
                    print_error "Invalid CIDR range. Must be between /8 and /32"
                    continue
                fi
                
                # Install ipcalc if not available
                if ! command -v ipcalc &> /dev/null; then
                    print_message "Installing ipcalc for CIDR support..."
                    apt-get install -y ipcalc &>/dev/null || {
                        print_warning "Could not install ipcalc. Skipping CIDR range."
                        continue
                    }
                fi
                
                print_message "Processing CIDR block: $ip_input"
                # Use ipcalc to get all IPs in range
                local ip_list=$(ipcalc -nb "$ip_input" 2>/dev/null | grep -E "^HostMin:|^HostMax:" | awk '{print $2}')
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
                        if validate_ip "$full_ip" && [ "$full_ip" != "$PRIMARY_IP" ]; then
                            IP_ADDRESSES+=("$full_ip")
                            IP_COUNT=$((IP_COUNT + 1))
                            print_message "  Added IP: $full_ip"
                        fi
                    done
                else
                    print_error "Could not process CIDR block"
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
                        if validate_ip "$full_ip" && [ "$full_ip" != "$PRIMARY_IP" ]; then
                            IP_ADDRESSES+=("$full_ip")
                            IP_COUNT=$((IP_COUNT + 1))
                            print_message "  Added IP: $full_ip"
                        fi
                    done
                else
                    print_error "Invalid range. End must be >= start and <= 255"
                fi
                
            # Single IP address
            elif validate_ip "$ip_input"; then
                # Skip if it's the primary IP (already added)
                if [ "$ip_input" != "$PRIMARY_IP" ]; then
                    IP_ADDRESSES+=("$ip_input")
                    IP_COUNT=$((IP_COUNT + 1))
                    print_message "Added IP: $ip_input"
                else
                    print_message "Skipping $ip_input (already added as primary)"
                fi
            else
                print_error "Invalid IP format: $ip_input"
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
    
    # Validate we have at least one IP
    if [ ${#IP_ADDRESSES[@]} -eq 0 ]; then
        print_error "No valid IP addresses configured"
        exit 1
    fi
    
    export IP_ADDRESSES
    export IP_COUNT
    export PRIMARY_IP
    
    print_message "\nTotal unique IPs to be configured: ${IP_COUNT}"
    print_message "IP addresses:"
    for ip in "${IP_ADDRESSES[@]}"; do
        echo "  - $ip"
    done
}

# Configure network interfaces for multiple IPs with safety checks
configure_network_interfaces() {
    print_header "Configuring Network Interfaces for Multiple IPs"
    
    if [ ${#IP_ADDRESSES[@]} -le 1 ]; then
        print_message "Single IP configuration - skipping network interface setup"
        return 0
    fi
    
    local primary_interface=$(ip route | grep default | awk '{print $5}' | head -1)
    if [ -z "$primary_interface" ]; then
        print_error "Could not determine primary network interface"
        return 1
    fi
    
    print_message "Primary network interface: $primary_interface"
    
    # Backup current network configuration
    print_message "Backing up current network configuration..."
    backup_network_config
    
    print_message "Configuring additional IP addresses..."
    
    # Store initial connectivity state
    local initial_connectivity=false
    if test_network_connectivity; then
        initial_connectivity=true
    fi
    
    # Detect OS version and use appropriate method
    local os_version=$(lsb_release -rs 2>/dev/null)
    
    if [[ "$os_version" == "24.04" ]] || [[ "$os_version" > "20.04" ]]; then
        print_message "Detected Ubuntu $os_version - using netplan configuration"
        
        # Configure with netplan
        if [ -d "/etc/netplan" ]; then
            # Get the existing netplan file
            local netplan_file=$(ls /etc/netplan/*.yaml 2>/dev/null | head -1)
            
            if [ -z "$netplan_file" ]; then
                netplan_file="/etc/netplan/99-multiip.yaml"
                print_message "Creating new netplan configuration: $netplan_file"
                
                cat > "$netplan_file" <<EOF
network:
  version: 2
  ethernets:
    $primary_interface:
      dhcp4: no
      addresses:
EOF
                
                for ip in "${IP_ADDRESSES[@]}"; do
                    # Ask for subnet if not provided
                    read -p "Enter subnet mask for $ip (e.g., 24 for /24, or press Enter for /24): " subnet
                    subnet=${subnet:-24}
                    
                    if [[ "$subnet" =~ ^[0-9]+$ ]] && [ $subnet -ge 8 ] && [ $subnet -le 32 ]; then
                        echo "        - $ip/$subnet" >> "$netplan_file"
                    else
                        print_warning "Invalid subnet, using /24"
                        echo "        - $ip/24" >> "$netplan_file"
                    fi
                done
                
                # Add gateway and nameservers
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
                print_warning "Existing netplan configuration found at $netplan_file"
                print_message "Manual configuration may be required."
                print_message "Please add the following IPs to $netplan_file:"
                for ip in "${IP_ADDRESSES[@]:1}"; do
                    echo "  - $ip/24  # Adjust subnet as needed"
                done
                
                read -p "Press Enter when you've updated the configuration, or 'skip' to skip: " user_input
                if [ "$user_input" = "skip" ]; then
                    return 0
                fi
            fi
            
            print_message "Testing netplan configuration..."
            if netplan try --timeout 30; then
                print_message "✓ Netplan configuration test successful"
                netplan apply
            else
                print_error "Netplan configuration test failed"
                print_message "Rolling back changes..."
                restore_network_config
                return 1
            fi
            
        else
            # Fallback to traditional IP commands for immediate configuration
            print_message "Using ip commands for immediate configuration..."
            
            local failed_ips=()
            for ip in "${IP_ADDRESSES[@]:1}"; do
                print_message "Adding IP $ip to interface $primary_interface..."
                if ip addr add "$ip/24" dev "$primary_interface" 2>/dev/null; then
                    print_message "✓ Added $ip"
                else
                    print_warning "✗ Could not add $ip (may already be configured)"
                    failed_ips+=("$ip")
                fi
            done
            
            if [ ${#failed_ips[@]} -eq $((${#IP_ADDRESSES[@]} - 1)) ]; then
                print_error "Failed to add all additional IPs"
                return 1
            fi
        fi
        
    else
        # For older Ubuntu versions, use traditional method
        print_message "Using traditional network configuration..."
        
        backup_config "network" "/etc/network/interfaces"
        
        # Create interfaces configuration
        cat > /etc/network/interfaces.d/50-multi-ip.cfg <<EOF
# Multi-IP configuration for bulk mail server
# Generated by Mail Server Installer
# Date: $(date)

EOF
        
        local ip_index=0
        for ip in "${IP_ADDRESSES[@]:1}"; do
            ip_index=$((ip_index + 1))
            
            read -p "Enter subnet mask for $ip (e.g., 255.255.255.0 or press Enter for default): " subnet
            subnet=${subnet:-255.255.255.0}
            
            cat >> /etc/network/interfaces.d/50-multi-ip.cfg <<EOF
auto ${primary_interface}:${ip_index}
iface ${primary_interface}:${ip_index} inet static
    address $ip
    netmask $subnet

EOF
        done
        
        # Restart networking
        print_message "Applying network configuration..."
        systemctl restart networking
    fi
    
    # Test connectivity after changes
    print_message "Testing network connectivity after changes..."
    sleep 3
    
    if test_network_connectivity; then
        print_message "✓ Network connectivity verified"
    else
        print_error "✗ Network connectivity lost!"
        
        if [ "$initial_connectivity" = true ]; then
            print_warning "Attempting to restore network configuration..."
            restore_network_config
            
            sleep 5
            if test_network_connectivity; then
                print_message "✓ Network connectivity restored"
            else
                print_error "✗ Could not restore network connectivity"
                print_error "Manual intervention may be required"
            fi
        fi
        return 1
    fi
    
    # Verify IPs are configured
    print_message "\nVerifying IP configuration..."
    local configured_count=0
    for ip in "${IP_ADDRESSES[@]}"; do
        if ip addr show | grep -q "$ip"; then
            print_message "✓ IP $ip is configured"
            configured_count=$((configured_count + 1))
        else
            print_warning "✗ IP $ip is not configured"
        fi
    done
    
    if [ $configured_count -eq ${#IP_ADDRESSES[@]} ]; then
        print_message "✓ All IPs successfully configured"
    elif [ $configured_count -gt 0 ]; then
        print_warning "⚠ Some IPs may need manual configuration or system restart"
    else
        print_error "✗ No IPs were successfully configured"
        return 1
    fi
    
    print_message "Network interface configuration completed"
    return 0
}

# Create IP rotation configuration
create_ip_rotation_config() {
    print_header "Creating IP Rotation Configuration"
    
    if [ ${#IP_ADDRESSES[@]} -le 1 ]; then
        print_message "Single IP configuration - IP rotation not needed"
        return 0
    fi
    
    mkdir -p /etc/postfix/transport_maps
    
    print_message "Setting up round-robin IP rotation by default..."
    
    # Create sender-dependent transport configuration
    cat > /etc/postfix/sender_dependent_default_transport_maps <<EOF
# Sender-dependent transport configuration for IP rotation
# Generated by Mail Server Installer
# Default configuration: Round-Robin IP rotation

# Format: sender@domain transport:
# Example: newsletter@example.com smtp-ip2:
# This file will be populated with any domain-specific IP assignments
EOF
    
    print_message "IP rotation will use round-robin by default"
    print_message ""
    print_message "To assign specific senders to specific IPs later:"
    print_message "1. Edit /etc/postfix/sender_dependent_default_transport_maps"
    print_message "2. Add entries like: sender@domain smtp-ipN:"
    print_message "3. Run: postmap /etc/postfix/sender_dependent_default_transport_maps"
    print_message "4. Restart Postfix: systemctl restart postfix"
    
    # Create the random transport selector script
    create_random_transport_selector
    
    print_message "IP rotation configuration created with round-robin default"
    return 0
}

# Create random transport selector script
create_random_transport_selector() {
    cat > /usr/local/bin/postfix-random-transport <<'EOF'
#!/bin/bash
# Random transport selector for load balancing

transports=()
for i in {1..50}; do
    if grep -q "^smtp-ip${i} " /etc/postfix/master.cf 2>/dev/null; then
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
    print_message "Random transport selector created"
}

# Configure reverse DNS instructions with numbered subdomain format
create_ptr_instructions() {
    local output_file="/root/ptr-records-setup.txt"
    
    if [ -z "$DOMAIN_NAME" ] || [ -z "$SUBDOMAIN" ]; then
        print_error "Domain or subdomain not set for PTR instructions"
        return 1
    fi
    
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
Provider Setup: Contact your hosting provider to set PTR for $ip

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
HOW TO CONFIGURE WITH VARIOUS PROVIDERS:

AWS/EC2:
--------
1. Go to EC2 Console → Elastic IPs
2. Select your IP → Actions → Update reverse DNS
3. Enter the hostname exactly as shown above

DigitalOcean:
-------------
1. Go to Networking → PTR Records
2. Click on the IP address
3. Enter the hostname in the PTR record field

Linode:
-------
1. Go to Networking → IP Management
2. Click "Edit RDNS" for the IP
3. Enter the hostname

OVH/SoYouStart:
---------------
1. Go to IP Management in control panel
2. Click on the gear icon next to the IP
3. Select "Modify the reverse"

Hetzner:
--------
1. Go to Robot → IPs
2. Click on the IP
3. Enter PTR record in "Reverse DNS" field

Generic VPS/Dedicated Server:
-----------------------------
1. Open a support ticket with your provider
2. Request: "Please set PTR record for IP [IP] to [hostname]"
3. Wait for confirmation (usually 24-48 hours)

==========================================================
VERIFICATION:

Once configured, verify each PTR record with:
EOF
    
    # Add verification commands for each IP
    for ip in "${IP_ADDRESSES[@]}"; do
        echo "dig -x $ip +short" >> "$output_file"
    done
    
    echo "" >> "$output_file"
    echo "Or use host command:" >> "$output_file"
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
5. Some providers require the trailing dot: hostname.domain.com.

IMPORTANCE FOR EMAIL DELIVERY:

Proper PTR records are CRITICAL for email delivery:
✓ Many mail servers reject email from IPs without PTR records
✓ PTR must match the HELO hostname used by your mail server
✓ Mismatched PTR records can trigger spam filters
✓ Gmail, Yahoo, and Outlook all check PTR records

==========================================================
TESTING EMAIL AUTHENTICATION:

After PTR records are configured:
1. Send test email to: check-auth@verifier.port25.com
2. Check the report for PTR/rDNS status
3. Use mail-tester.com for comprehensive testing

==========================================================
QUICK REFERENCE:

Subdomain: ${SUBDOMAIN}
Domain: ${DOMAIN_NAME}
Number of IPs: ${#IP_ADDRESSES[@]}

Hostname Format:
- Primary: ${SUBDOMAIN}.${DOMAIN_NAME}
- Additional: ${SUBDOMAIN}XXX.${DOMAIN_NAME} (where XXX is 001, 002, etc.)

Support Script:
Run '/usr/local/bin/check-ptr' to verify all PTR records (after creating)

==========================================================
EOF
    
    print_message "PTR record instructions saved to $output_file"
    
    # Create a CSV file for easy copy/paste
    local csv_file="/root/ptr-records.csv"
    echo "IP Address,PTR Record,Status" > "$csv_file"
    
    for ((i=0; i<${#IP_ADDRESSES[@]}; i++)); do
        local ip="${IP_ADDRESSES[$i]}"
        local ptr_hostname
        
        if [ $i -eq 0 ]; then
            ptr_hostname="${SUBDOMAIN}.${DOMAIN_NAME}"
        else
            local suffix=$(printf "%03d" $i)
            ptr_hostname="${SUBDOMAIN}${suffix}.${DOMAIN_NAME}"
        fi
        
        echo "$ip,$ptr_hostname,Pending" >> "$csv_file"
    done
    
    print_message "PTR records CSV saved to $csv_file"
    
    # Create PTR checking script
    cat > /usr/local/bin/check-ptr <<'EOF'
#!/bin/bash

echo "Checking PTR Records Configuration"
echo "==================================="

source /root/mail-server-config.json 2>/dev/null || true

if [ -f /root/ptr-records.csv ]; then
    echo ""
    echo "Configured PTR records:"
    while IFS=, read -r ip ptr status; do
        if [ "$ip" != "IP Address" ]; then
            echo -n "IP $ip -> $ptr: "
            actual_ptr=$(dig -x $ip +short 2>/dev/null | sed 's/\.$//')
            if [ "$actual_ptr" = "$ptr" ]; then
                echo "✓ Configured correctly"
            elif [ ! -z "$actual_ptr" ]; then
                echo "✗ Mismatch (found: $actual_ptr)"
            else
                echo "✗ Not configured"
            fi
        fi
    done < /root/ptr-records.csv
else
    echo "PTR records CSV not found"
fi

echo ""
echo "For detailed setup instructions: cat /root/ptr-records-setup.txt"
EOF
    
    chmod +x /usr/local/bin/check-ptr
    print_message "PTR checking script created at /usr/local/bin/check-ptr"
    
    return 0
}

# Export all functions
export -f validate_ip test_network_connectivity backup_network_config restore_network_config
export -f get_all_server_ips configure_network_interfaces create_ip_rotation_config
export -f create_random_transport_selector create_ptr_instructions
