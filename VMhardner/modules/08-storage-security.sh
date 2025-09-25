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
    
    # Get the libvirt user and group
    LIBVIRT_USER=$(ps -ef | grep libvirtd | grep -v grep | head -n 1 | awk '{print $1}')
    LIBVIRT_GROUP="libvirt"
    QEMU_GROUP="libvirt-qemu"
    
    print_message "Detected libvirt user: $LIBVIRT_USER"
    log "Detected libvirt user: $LIBVIRT_USER"
    
    # Make sure the VM storage directory has appropriate permissions
    if [ -d "$VM_STORAGE_DIR" ]; then
        # Set base directory ownership to root:root but allow libvirt group read access
        chown root:root "$VM_STORAGE_DIR"
        chmod 755 "$VM_STORAGE_DIR"
        print_message "Set base directory permissions: $VM_STORAGE_DIR (755 root:root)"
        log "Set permissions 755 on $VM_STORAGE_DIR"
        
        # Process subdirectories
        find "$VM_STORAGE_DIR" -type d | while read dir; do
            # Skip the top-level directory as we already set it
            if [ "$dir" != "$VM_STORAGE_DIR" ]; then
                # For subdirectories, ensure libvirt has access
                chown root:$QEMU_GROUP "$dir"
                chmod 750 "$dir"
                print_message "Secured directory: $dir (750 root:$QEMU_GROUP)"
                log "Set permissions 750 on $dir (root:$QEMU_GROUP)"
            fi
        done
        
        # Check for individual VM disk files and secure them recursively
        print_message "Securing VM disk files..."
        log "Securing VM disk files"
        
        # Find all VM disk files (including in subdirectories)
        find "$VM_STORAGE_DIR" -type f \( -name "*.qcow2" -o -name "*.img" -o -name "*.raw" \) | while read disk_file; do
            # Ensure libvirt-qemu can read/write disk files
            chown root:$QEMU_GROUP "$disk_file"
            chmod 660 "$disk_file"
            print_message "Secured VM disk: $(basename "$disk_file") (660 root:$QEMU_GROUP)"
            log "Set permissions 660 on $disk_file (root:$QEMU_GROUP)"
        done
        
        # Fix specific problem cases - look for files with no access
        find "$VM_STORAGE_DIR" -type f -not -perm /004 | while read no_access_file; do
            if [[ "$no_access_file" == *".qcow2" || "$no_access_file" == *".img" || "$no_access_file" == *".raw" ]]; then
                print_warning "Found VM disk with restricted permissions: $no_access_file"
                chown root:$QEMU_GROUP "$no_access_file"
                chmod 660 "$no_access_file"
                print_message "Fixed permissions: $(basename "$no_access_file") (660 root:$QEMU_GROUP)"
                log "Fixed permissions on $no_access_file (660 root:$QEMU_GROUP)"
            fi
        done
        
        # Add specific fix for nextclouD directory if it exists (case from error message)
        if [ -d "$VM_STORAGE_DIR/nextclouD" ]; then
            print_message "Found nextclouD directory - applying special permission fixes"
            chown -R root:$QEMU_GROUP "$VM_STORAGE_DIR/nextclouD"
            chmod -R 750 "$VM_STORAGE_DIR/nextclouD"
            find "$VM_STORAGE_DIR/nextclouD" -type f \( -name "*.qcow2" -o -name "*.img" -o -name "*.raw" \) -exec chmod 660 {} \;
            print_message "Fixed permissions on nextclouD directory and contents"
            log "Fixed permissions on $VM_STORAGE_DIR/nextclouD directory and contents"
        fi
    else
        print_error "VM storage directory $VM_STORAGE_DIR no longer exists!"
        log "ERROR: VM storage directory $VM_STORAGE_DIR does not exist"
        return 1
    fi
    
    # Skip encryption setup
    print_message "VM storage permissions secured."
    print_message "Note: Disk encryption setup has been skipped for performance reasons."
    log "VM storage security configuration completed (encryption skipped)"
}
