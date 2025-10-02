#!/bin/bash
# =================================================================
# VM Host Hardener v2.0 - Module 04: Firewall Configuration
#
# Description: This module configures the Uncomplicated Firewall (UFW)
# with rules based on settings.conf to protect the host while
# allowing traffic to the specified VM services.
# =================================================================

run_firewall_configuration() {
    if [ "${ENABLE_UFW}" != "true" ]; then
        print_message "Skipping firewall configuration as per settings."
        log "UFW configuration skipped (ENABLE_UFW is not 'true')."
        return
    fi

    print_header "Module 04: Configuring Firewall (UFW)"
    log "Starting UFW configuration."

    configure_ufw_rules
    configure_bridge_filtering
    enable_ufw

    log "Firewall configuration completed."
}

# Sets up the main UFW rules based on settings.conf.
configure_ufw_rules() {
    print_message "Configuring UFW rules..."

    # Reset UFW to a clean state to ensure a predictable configuration
    ufw --force reset >/dev/null
    log "UFW has been reset to its default state."

    # Set default policies: deny all incoming, allow all outgoing
    ufw default deny incoming
    ufw default allow outgoing
    log "UFW default policies set to 'deny incoming' and 'allow outgoing'."

    # 1. Allow SSH access
    ufw allow "${SSH_PORT}/tcp" comment "SSH Access"
    log "Firewall rule added for SSH on port ${SSH_PORT}/tcp."

    # 2. Allow Libvirt TLS if enabled
    if [ "${ALLOW_LIBVIRT_TLS}" == "true" ]; then
        ufw allow 16514/tcp comment "Libvirt TLS Management"
        log "Firewall rule added for Libvirt TLS on port 16514/tcp."
    fi

    # 3. Allow all ports defined in the configuration
    # Convert comma-separated string to an array
    IFS=',' read -r -a ports_array <<< "$ALLOWED_PORTS"
    if [ ${#ports_array[@]} -gt 0 ]; then
        print_message "Allowing ports for VM services: ${ALLOWED_PORTS}"
        for port_rule in "${ports_array[@]}"; do
            # Trim whitespace
            port_rule=$(echo "$port_rule" | tr -d '[:space:]')
            if [[ -n "$port_rule" ]]; then
                ufw allow "$port_rule" comment "VM Service Port"
                log "Firewall rule added for VM service on ${port_rule}."
            fi
        done
    else
        print_warning "No ports defined in ALLOWED_PORTS. Only SSH will be accessible."
        log "Warning: ALLOWED_PORTS is empty in settings.conf."
    fi
}

# Configures kernel parameters for secure network bridging.
configure_bridge_filtering() {
    print_message "Configuring bridge network filtering for KVM..."
    local sysctl_conf="/etc/sysctl.d/90-kvm-bridge-filtering.conf"
    
    # These settings prevent host firewall rules from interfering with VM-to-VM traffic
    # on the same bridge, which is a common source of networking issues.
    cat > "${sysctl_conf}" <<-EOF
	# KVM/libvirt bridge filtering settings
	# Prevents iptables from processing bridged traffic, allowing VMs to communicate freely.
	# Host firewall rules will still apply to traffic entering/leaving the host itself.
	net.bridge.bridge-nf-call-ip6tables = 0
	net.bridge.bridge-nf-call-iptables = 0
	net.bridge.bridge-nf-call-arptables = 0
	EOF

    # Apply the settings immediately
    sysctl -p "${sysctl_conf}" >/dev/null
    log "Applied bridge filtering sysctl settings."
}

# Enables UFW non-interactively.
enable_ufw() {
    print_message "Enabling UFW firewall..."
    # The --force flag skips the interactive prompt.
    ufw --force enable
    log "UFW has been enabled."
    print_message "Firewall is now active."
    # Display the final ruleset
    ufw status verbose
}
