#!/bin/bash
# =================================================================
# Virtual machine resource controls
# =================================================================

run_vm_resources() {
    print_header "Virtual Machine Resource Controls"
    log "Starting VM resource controls configuration"
    
    setup_vm_resources
    
    log "VM resource controls configuration completed"
}

setup_vm_resources() {
    # Check if cgroups tools are installed
    if ! command_exists cgcreate; then
        print_message "Installing cgroups tools..."
        log "Installing cgroups tools"
        apt-get install -y cgroup-tools
    fi
    
    # Create a systemd slice for VM resource control if it doesn't exist
    if [ ! -f /etc/systemd/system/machine.slice.d/resources.conf ]; then
        print_message "Creating VM resource control settings..."
        log "Creating VM resource control settings"
        
        mkdir -p /etc/systemd/system/machine.slice.d/
        cat > /etc/systemd/system/machine.slice.d/resources.conf <<EOF
[Slice]
# Memory resource controls
MemoryAccounting=true
MemoryLow=${VM_MEMORY_MIN:-512M}

# CPU resource controls
CPUAccounting=true
CPUQuota=${VM_CPU_QUOTA:-90%}

# IO resource controls
IOAccounting=true
IOWeight=100
EOF
        log "Created VM resource control settings in /etc/systemd/system/machine.slice.d/resources.conf"
        
        systemctl daemon-reload
        log "Reloaded systemd daemon"
    else
        log "VM resource control settings already exist"
    fi
    
    # NOTE: Removed OOMScoreAdjust for libvirtd as it causes startup failures
    # The OOM killer protection was causing systemd to fail starting libvirtd
    # Default systemd settings provide adequate protection without custom OOMScoreAdjust
    
    print_message "VM resource controls configured."
    log "VM resource controls configured successfully"
}
