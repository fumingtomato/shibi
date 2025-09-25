#!/bin/bash
# =================================================================
# VM storage security
# =================================================================

run_storage_security() {
    print_header "VM Storage Security"
    log "Starting VM storage security configuration"
    
    secure_vm_storage
    
    log "VM storage security configuration completed"
}

secure_vm_storage() {
    # Find the VM storage directory
    VM_STORAGE_DIR=$(virsh pool-dumpxml default 2>/dev/null | grep -o '<path>.*</path>' | sed 's/<path>//g' | sed 's/<\/path>//g')
    
    if [ -z "$VM_STORAGE_DIR" ]; then
        print_warning "Default VM storage pool not found."
        log "Default VM storage pool not found"
        print_message "Checking for common VM storage locations..."
        
        for dir in "/var/lib/libvirt/images" "/srv/vm" "/srv/vms"; do
            if [ -d "$dir" ]; then
                VM_STORAGE_DIR="$dir"
                print_message "Found VM storage directory: $VM_STORAGE_DIR"
                log "Found VM storage directory: $VM_STORAGE_DIR"
                break
            fi
        done
        
        if [ -z "$VM_STORAGE_DIR" ]; then
            read -p "Enter your VM storage directory: " VM_STORAGE_DIR
            if [ ! -d "$VM_STORAGE_DIR" ]; then
                print_error "Directory $VM_STORAGE_DIR does not exist. Cannot secure VM storage."
                log "ERROR: Directory $VM_STORAGE_DIR does not exist"
                return
            fi
        fi
    else
        print_message "VM storage directory: $VM_STORAGE_DIR"
        log "VM storage directory: $VM_STORAGE_DIR"
    fi
    
    # Secure permissions on VM storage
    print_message "Securing VM storage permissions..."
    log "Securing VM storage permissions"
    
    # Check if directory is owned by proper user
    if [ "$(stat -c '%U' "$VM_STORAGE_DIR")" != "root" ] || [ "$(stat -c '%G' "$VM_STORAGE_DIR")" != "root" ]; then
        chown root:root "$VM_STORAGE_DIR"
        print_message "Changed ownership of $VM_STORAGE_DIR to root:root"
        log "Changed ownership of $VM_STORAGE_DIR to root:root"
    fi
    
    # Ensure proper permissions
    chmod 750 "$VM_STORAGE_DIR"
    log "Set permissions 750 on $VM_STORAGE_DIR"
    
    # Check for individual VM disk files and secure them
    print_message "Securing VM disk files..."
    log "Securing VM disk files"
    find "$VM_STORAGE_DIR" -type f \( -name "*.qcow2" -o -name "*.img" \) | while read disk_file; do
        chmod 640 "$disk_file"
        print_message "Secured permissions for $(basename "$disk_file")"
        log "Set permissions 640 on $disk_file"
    done
    
    # Skip encryption setup - removed the prompt and encryption template creation
    print_message "VM storage permissions secured."
    print_message "Note: Disk encryption setup has been skipped for performance reasons."
    log "VM storage security configuration completed (encryption skipped)"
}
