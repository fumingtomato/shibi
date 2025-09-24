#!/bin/bash
# VM Host Hardening - VM Backup Configuration Module

configure_backups() {
    print_header "VM Backup Configuration"
    
    # Get list of VMs
    VM_LIST=$(virsh list --all --name)
    
    # Check if we have VMs to back up
    if [ -z "$VM_LIST" ]; then
        print_warning "No VMs detected to back up."
        return
    fi
    
    print_message "Setting up automated VM backups..."
    
    # Ask for backup directory
    read -p "Enter path for VM backups [/var/backup/vms]: " BACKUP_DIR
    BACKUP_DIR=${BACKUP_DIR:-/var/backup/vms}
    
    # Create backup directory if it doesn't exist
    if [ ! -d "$BACKUP_DIR" ]; then
        mkdir -p "$BACKUP_DIR"
        chmod 750 "$BACKUP_DIR"
    fi
    
    # Create backup script if it doesn't exist or is outdated
    if [ ! -f /usr/local/bin/backup-vms.sh ] || [ "$(grep -c "VM Backup Script" /usr/local/bin/backup-vms.sh)" -eq 0 ]; then
        print_message "Creating VM backup script..."
        
        cat > /usr/local/bin/backup-vms.sh <<EOF
#!/bin/bash
# Automated VM Backup Script

BACKUP_DIR="$BACKUP_DIR"
DATE=\$(date +"%Y%m%d-%H%M%S")
LOG_FILE="/var/log/vm-backup.log"

# Initialize log
echo "======== VM Backup: \$(date) ========" >> \$LOG_FILE

# Make sure backup directory exists
mkdir -p "\$BACKUP_DIR"

# Get list of running VMs
RUNNING_VMS=\$(virsh list --name)

# Process each VM
for VM in \$(virsh list --all --name); do
    echo "Backing up VM: \$VM" >> \$LOG_FILE
    
    # Create VM-specific directory
    VM_BACKUP_DIR="\$BACKUP_DIR/\$VM/\$DATE"
    mkdir -p "\$VM_BACKUP_DIR"
    
    # Check if VM is running
    if echo "\$RUNNING_VMS" | grep -q "\$VM"; then
        echo "\$VM is running - creating snapshot first" >> \$LOG_FILE
        
        # Find the VM disk
        DISK=\$(virsh domblklist \$VM | grep -o '/.*\.qcow2\|/.*\.img' | head -1)
        
        if [ -n "\$DISK" ]; then
            # Create snapshot
            virsh snapshot-create-as --domain \$VM backup_snap "Backup snapshot" --disk-only --atomic >> \$LOG_FILE 2>&1
            
            if [ \$? -eq 0 ]; then
                # Export VM configuration
                virsh dumpxml \$VM > "\$VM_BACKUP_DIR/\$VM.xml"
                
                # Copy snapshot
                cp "\$DISK" "\$VM_BACKUP_DIR/"
                
                # Remove snapshot
                virsh blockcommit \$VM vda --active --pivot >> \$LOG_FILE 2>&1
                virsh snapshot-delete \$VM backup_snap --metadata >> \$LOG_FILE 2>&1
            else
                echo "Failed to create snapshot for \$VM" >> \$LOG_FILE
            fi
        else
            echo "Could not find disk for \$VM" >> \$LOG_FILE
        fi
    else
        echo "\$VM is not running - backing up directly" >> \$LOG_FILE
        
        # Export VM configuration
        virsh dumpxml \$VM > "\$VM_BACKUP_DIR/\$VM.xml"
        
        # Find and copy VM disk
        DISK=\$(virsh domblklist \$VM | grep -o '/.*\.qcow2\|/.*\.img' | head -1)
        
        if [ -n "\$DISK" ]; then
            cp "\$DISK" "\$VM_BACKUP_DIR/"
        else
            echo "Could not find disk for \$VM" >> \$LOG_FILE
        fi
    fi
    
    echo "Backup of \$VM completed" >> \$LOG_FILE
done

# Cleanup old backups (keep last 3)
for VM in \$(virsh list --all --name); do
    if [ -d "\$BACKUP_DIR/\$VM/" ]; then
        VM_BACKUP_COUNT=\$(ls -1 "\$BACKUP_DIR/\$VM/" 2>/dev/null | wc -l)
        if [ \$VM_BACKUP_COUNT -gt 3 ]; then
            # Delete oldest backups
            OLDEST_BACKUPS=\$(ls -1 "\$BACKUP_DIR/\$VM/" | sort | head -n \$((\$VM_BACKUP_COUNT - 3)))
            for OLD_BACKUP in \$OLDEST_BACKUPS; do
                echo "Removing old backup: \$VM/\$OLD_BACKUP" >> \$LOG_FILE
                rm -rf "\$BACKUP_DIR/\$VM/\$OLD_BACKUP"
            done
        fi
    fi
done

echo "======== VM Backup Completed: \$(date) ========" >> \$LOG_FILE
EOF
        
        chmod +x /usr/local/bin/backup-vms.sh
    fi
    
    # Create a weekly cron job for backups if it doesn't exist
    if [ ! -f /etc/cron.d/vm-backups ]; then
        print_message "Setting up weekly backup cron job..."
        cat > /etc/cron.d/vm-backups <<EOF
# Run VM backups every Sunday at 1:00 AM
0 1 * * 0 root /usr/local/bin/backup-vms.sh
EOF
    fi
    
    # Setup log rotation for backup logs if it doesn't exist
    if [ ! -f /etc/logrotate.d/vm-backup ]; then
        cat > /etc/logrotate.d/vm-backup <<EOF
/var/log/vm-backup.log {
    weekly
    rotate 12
    compress
    missingok
    notifempty
}
EOF
    fi
    
    print_message "VM backup configuration complete. Backups will run weekly."
    print_message "Backup location: $BACKUP_DIR"
}
