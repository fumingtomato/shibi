#!/bin/bash
# =================================================================
# VM Host Hardener v2.0 - Module 07: Storage Security
#
# Description: This module secures the VM storage pool by setting
# strict permissions on disk images and directories to prevent
# unauthorized access.
# =================================================================

run_storage_security() {
    print_header "Module 07: Securing VM Storage"
    log "Starting VM storage security configuration."

    secure_vm_storage_permissions

    log "VM storage security configuration completed."
}

# Sets secure permissions on the libvirt default storage pool.
secure_vm_storage_permissions() {
    print_message "Securing VM storage permissions..."

    # Attempt to find the default storage pool path from libvirt
    local storage_path
    storage_path=$(virsh pool-dumpxml default 2>/dev/null | \
                   grep -o '<path>.*</path>' | \
                   sed -e 's/<path>//' -e 's/<\/path>//')

    # Fallback if the default pool isn't found or named 'default'
    if [ -z "$storage_path" ] && [ -d "/var/lib/libvirt/images" ]; then
        storage_path="/var/lib/libvirt/images"
        log "Default pool not found, using standard path: ${storage_path}"
    fi

    if [ -z "$storage_path" ] || [ ! -d "$storage_path" ]; then
        print_warning "Could not determine VM storage directory. Skipping permission changes."
        log "Warning: VM storage path not found. Permissions not secured."
        return
    fi
    
    log "Found VM storage directory: ${storage_path}"
    print_message "Securing storage directory: ${storage_path}"

    # Set ownership and permissions for the main storage directory
    # Owner: root, Group: root, Permissions: 755 (rwxr-xr-x)
    # This allows libvirt to navigate into the directory.
    chown root:root "${storage_path}"
    chmod 755 "${storage_path}"
    log "Set permissions on ${storage_path} to 755 (root:root)."

    # Set ownership and permissions for VM disk images
    # Owner: root, Group: libvirt-qemu, Permissions: 660 (rw-rw----)
    # This allows the QEMU process to read/write its disk, but no one else.
    # The -type f ensures we only target files.
    find "${storage_path}" -type f \( -name "*.qcow2" -o -name "*.img" -o -name "*.raw" \) \
        -exec chown root:libvirt-qemu {} \; \
        -exec chmod 660 {} \;

    log "Set permissions on all VM disk images to 660 (root:libvirt-qemu)."
    print_message "Permissions on VM disk images have been secured."
    print_warning "Note: For higher security, consider manual setup of disk encryption (LUKS)."
    log "Disk encryption is recommended as a manual, advanced step."
}
