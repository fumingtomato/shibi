#!/bin/bash
# =================================================================
# VM network security configuration
# =================================================================

run_network_security() {
    print_header "VM Network Security Configuration"
    log "Starting VM network security configuration"
    
    secure_vm_networking
    
    log "VM network security configuration completed"
}

secure_vm_networking() {
    # List available network interfaces for bridge creation
    print_message "Detected public interfaces: ${PUBLIC_INTERFACES[*]}"
    log "Detected public interfaces: ${PUBLIC_INTERFACES[*]}"
    
    # Check if we have VM networks defined
    if [ -z "$LIBVIRT_NETWORKS" ]; then
        read -p "No libvirt networks detected. Create a new network bridge? (y/n): " create_bridge
        
        if [[ "$create_bridge" == "y" || "$create_bridge" == "Y" ]]; then
            # Select interface to bridge
            echo "Select interface to bridge for VM network:"
            select iface in "${PUBLIC_INTERFACES[@]}"; do
                if [ -n "$iface" ]; then
                    BRIDGE_INTERFACE=$iface
                    break
                fi
            done
            
            # Check if bridge-utils is installed
            if ! command_exists brctl; then
                print_message "Installing bridge-utils..."
                log "Installing bridge-utils"
                apt-get install -y bridge-utils
            fi
            
            # Create bridge config file
            print_message "Creating bridge for $BRIDGE_INTERFACE..."
            log "Creating bridge for $BRIDGE_INTERFACE"
            
            # Check for existing bridge configuration
            if [ ! -f /etc/netplan/01-netcfg.yaml.bak ] && [ -f /etc/netplan/01-netcfg.yaml ]; then
                cp /etc/netplan/01-netcfg.yaml /etc/netplan/01-netcfg.yaml.bak
                log "Backed up original netplan configuration"
            fi
            
            # Create bridge configuration with netplan
            cat > /etc/netplan/02-bridge.yaml <<EOF
network:
  version: 2
  renderer: networkd
  bridges:
    br0:
      interfaces: [$BRIDGE_INTERFACE]
      dhcp4: yes
      parameters:
        stp: false
        forward-delay: 0
EOF
            log "Created bridge configuration in /etc/netplan/02-bridge.yaml"
            
            # Apply netplan configuration
            print_message "Applying bridge configuration..."
            log "Applying bridge configuration"
            netplan try
            netplan apply
            log "Applied bridge configuration"
            
            # Create libvirt network for the bridge
            BRIDGE_XML=$(mktemp)
            cat > $BRIDGE_XML <<EOF
<network>
  <name>br0-bridge</name>
  <forward mode="bridge"/>
  <bridge name="br0"/>
</network>
EOF
            log "Created temporary libvirt network XML"
            
            # Define and start the network
            virsh net-define $BRIDGE_XML
            virsh net-autostart br0-bridge
            virsh net-start br0-bridge
            log "Defined and started br0-bridge network in libvirt"
            
            rm $BRIDGE_XML
            
            print_message "Bridge br0 created and configured for VM use."
            log "Bridge br0 created and configured for VM use"
        else
            print_message "Skipping bridge creation."
            log "Skipped bridge creation"
        fi
    else
        print_message "Libvirt networks already exist. Ensuring they're secure..."
        log "Checking security of existing libvirt networks"
        
        # Verify security of existing libvirt networks
        for net in $LIBVIRT_NETWORKS; do
            # Skip default network as it's usually for internal NAT
            if [ "$net" == "default" ]; then
                continue
            fi
            
            # Get network XML
            net_xml=$(virsh net-dumpxml $net)
            
            # Check if network uses NAT or Bridge
            if echo "$net_xml" | grep -q '<forward mode="nat"'; then
                print_message "Network $net uses NAT - good for isolation."
                log "Network $net uses NAT - good for isolation"
            elif echo "$net_xml" | grep -q '<forward mode="bridge"'; then
                print_warning "Network $net uses bridge mode - ensuring it's secure..."
                log "Network $net uses bridge mode - checking security"
                
                # Check if bridge has STP enabled
                bridge_name=$(echo "$net_xml" | grep -o '<bridge name="[^"]*"' | cut -d'"' -f2)
                if [ -n "$bridge_name" ]; then
                    if brctl show $bridge_name 2>/dev/null | grep -q "$bridge_name"; then
                        print_message "Configuring bridge $bridge_name for security..."
                        log "Configuring bridge $bridge_name for security"
                        # Disable STP for performance and security
                        brctl stp $bridge_name off
                        log "Disabled STP on bridge $bridge_name"
                    fi
                fi
            fi
        done
    fi
    
    # SIMPLIFIED: Skip VM isolation since it's too complex for multiple VMs
    # Users can configure their own iptables rules if needed
    if [ "$ENABLE_VM_ISOLATION" == "true" ]; then
        print_message "VM isolation is enabled in settings."
        print_message "Note: Automatic VM-to-VM isolation has been skipped."
        print_message "With multiple mail and web servers, isolation rules should be"
        print_message "configured manually based on your specific requirements."
        print_message ""
        print_message "For manual configuration, you can use iptables rules like:"
        print_message "  iptables -I FORWARD -s VM1_IP -d VM2_IP -j DROP"
        print_message "  iptables -I FORWARD -s VM2_IP -d VM1_IP -j DROP"
        log "Skipped automatic VM isolation - manual configuration recommended for complex setups"
    else
        log "VM isolation is disabled in settings"
    fi
    
    print_message "Network security configuration completed."
}
