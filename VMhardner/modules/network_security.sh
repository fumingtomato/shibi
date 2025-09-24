#!/bin/bash

# =================================================================
# SECTION 6: NETWORK SECURITY CONFIGURATION
# =================================================================

secure_vm_networking() {
    print_header "VM Network Security Configuration"
    
    # List available network interfaces for bridge creation
    print_message "Detected public interfaces: ${PUBLIC_INTERFACES[*]}"
    
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
            if ! command -v brctl &> /dev/null; then
                print_message "Installing bridge-utils..."
                apt-get install -y bridge-utils
            fi
            
            # Create bridge config file
            print_message "Creating bridge for $BRIDGE_INTERFACE..."
            
            # Check for existing bridge configuration
            if [ ! -f /etc/netplan/01-netcfg.yaml.bak ] && [ -f /etc/netplan/01-netcfg.yaml ]; then
                backup_config_file /etc/netplan/01-netcfg.yaml
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
            
            # Apply netplan configuration
            print_message "Applying bridge configuration..."
            netplan try
            netplan apply
            
            # Create libvirt network for the bridge
            BRIDGE_XML=$(mktemp)
            cat > $BRIDGE_XML <<EOF
<network>
  <name>br0-bridge</name>
  <forward mode="bridge"/>
  <bridge name="br0"/>
</network>
EOF
            
            # Define and start the network
            virsh net-define $BRIDGE_XML
            virsh net-autostart br0-bridge
            virsh net-start br0-bridge
            
            rm $BRIDGE_XML
            
            print_message "Bridge br0 created and configured for VM use."
        else
            print_message "Skipping bridge creation."
        fi
    else
        print_message "Libvirt networks already exist. Ensuring they're secure..."
        
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
            elif echo "$net_xml" | grep -q '<forward mode="bridge"'; then
                print_warning "Network $net uses bridge mode - ensuring it's secure..."
                
                # Check if bridge has STP enabled
                bridge_name=$(echo "$net_xml" | grep -o '<bridge name="[^"]*"' | cut -d'"' -f2)
                if [ -n "$bridge_name" ]; then
                    if brctl show $bridge_name 2>/dev/null | grep -q "$bridge_name"; then
                        print_message "Configuring bridge $bridge_name for security..."
                        # Disable STP for performance and security
                        brctl stp $bridge_name off
                    fi
                fi
            fi
        done
    fi
    
    # Set up traffic filtering between VMs if needed
    print_message "Configuring VM traffic isolation..."
    
    # Check if we have multiple VMs that should be isolated
    if [ "$(echo "$VM_LIST" | wc -l)" -gt 1 ]; then
        read -p "Do you want to isolate traffic between the mail server and web server VMs? (y/n): " isolate_vms
        
        if [[ "$isolate_vms" == "y" || "$isolate_vms" == "Y" ]]; then
            # List available VMs
            print_message "Available VMs:"
            echo "$VM_LIST"
            
            read -p "Enter the name of your mail server VM: " MAIL_VM
            read -p "Enter the name of your web server VM: " WEB_VM
            
            if virsh dominfo "$MAIL_VM" &>/dev/null && virsh dominfo "$WEB_VM" &>/dev/null; then
                print_message "Creating VM isolation rules..."
                
                # Get MAC addresses of the VMs
                MAIL_MAC=$(virsh domiflist "$MAIL_VM" | grep -o -E "([0-9a-f]{2}:){5}([0-9a-f]{2})" | head -1)
                WEB_MAC=$(virsh domiflist "$WEB_VM" | grep -o -E "([0-9a-f]{2}:){5}([0-9a-f]{2})" | head -1)
                
                # Create custom chain for VM filtering
                iptables -N VM_ISOLATION 2>/dev/null || true
                
                # Clear the chain
                iptables -F VM_ISOLATION
                
                # Allow established connections
                iptables -A VM_ISOLATION -m state --state ESTABLISHED,RELATED -j ACCEPT
                
                # Allow mail server ports to web server (for email sending)
                iptables -A VM_ISOLATION -p tcp -m mac --mac-source $MAIL_MAC -m multiport --dports 80,443 -j ACCEPT
                
                # Allow web server to mail server only on mail ports
                iptables -A VM_ISOLATION -p tcp -m mac --mac-source $WEB_MAC -m multiport --dports 25,587,465 -j ACCEPT
                
                # Block other traffic between VMs
                iptables -A VM_ISOLATION -j DROP
                
                # Apply the chain to the forward table
                iptables -C FORWARD -j VM_ISOLATION 2>/dev/null || iptables -A FORWARD -j VM_ISOLATION
                
                # Save iptables rules for persistence
                if command -v iptables-save > /dev/null; then
                    print_message "Saving iptables rules..."
                    mkdir -p /etc/iptables/
                    iptables-save > /etc/iptables/rules.v4
                    
                    # Ensure rules are loaded at boot
                    if [ ! -f /etc/systemd/system/iptables-restore.service ]; then
                        cat > /etc/systemd/system/iptables-restore.service <<EOF
[Unit]
Description=Restore iptables firewall rules
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart=/sbin/iptables-restore /etc/iptables/rules.v4
ExecStartPost=/sbin/ip6tables-restore /etc/iptables/rules.v6 || true

[Install]
WantedBy=multi-user.target
EOF
                        systemctl daemon-reload
                        systemctl enable iptables-restore
                    fi
                else
                    print_warning "iptables-save not found. Rules will not persist across reboots."
                fi
                
                print_message "VM traffic isolation rules created."
            else
                print_error "One or both of the specified VMs do not exist."
            fi
        fi
    fi
}
