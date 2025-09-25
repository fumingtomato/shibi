#!/bin/bash
# Module: 10-backups.sh - VM Backup Configuration
# Part of VM Host Hardening Script

# Check if we're being run standalone or as part of the main script
if [ -z "$LOG_FILE" ]; then
    # Running standalone, need to source common
    SCRIPT_DIR="$(dirname "$0")"
    if [ -f "${SCRIPT_DIR}/00-common.sh" ]; then
        source "${SCRIPT_DIR}/00-common.sh"
    else
        echo "Error: Could not find common functions file"
        exit 1
    fi
fi

configure_backups() {
    print_header "VM Backup Configuration"
    
    # Get the list of VMs if not already defined
    if [ -z "$VM_LIST" ]; then
        VM_LIST=$(virsh list --all --name)
        if [ -z "$VM_LIST" ]; then
            print_warning "No VMs detected to back up"
            return
        fi
    fi
    
    print_message "Setting up automated VM backups..."
    
    # Use BACKUP_DIRECTORY from settings or ask for it
    if [ -z "$BACKUP_DIRECTORY" ]; then
        read -p "Enter path for VM backups [/var/backup/vms]: " BACKUP_DIRECTORY
        BACKUP_DIRECTORY=${BACKUP_DIRECTORY:-/var/backup/vms}
    fi
    
    # Create backup directory if it doesn't exist
    if [ ! -d "$BACKUP_DIRECTORY" ]; then
        mkdir -p "$BACKUP_DIRECTORY"
        chmod 750 "$BACKUP_DIRECTORY"
        print_message "Created backup directory: $BACKUP_DIRECTORY"
    else
        print_message "Using existing backup directory: $BACKUP_DIRECTORY"
    fi
    
    # Create backup script if it doesn't exist
    if [ ! -f /usr/local/bin/backup-vms.sh ]; then
        print_message "Creating VM backup script..."
        
        cat > /usr/local/bin/backup-vms.sh <<EOFSCRIPT
#!/bin/bash
# Automated VM Backup Script

BACKUP_DIR="$BACKUP_DIRECTORY"
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
    if [ -d "\$BACKUP_DIR/\$VM" ]; then
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
EOFSCRIPT
        
        chmod +x /usr/local/bin/backup-vms.sh
        print_message "VM backup script created"
    else
        print_message "VM backup script already exists"
    fi
    
    # Create a weekly cron job for backups if it doesn't exist
    if ! crontab -l 2>/dev/null | grep -q "backup-vms.sh"; then
        print_message "Setting up weekly backup cron job..."
        (crontab -l 2>/dev/null; echo "0 1 * * 0 /usr/local/bin/backup-vms.sh") | crontab -
    else
        print_message "VM backup cron job already exists"
    fi
    
    # Setup log rotation for backup logs
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
        print_message "Log rotation configured for VM backups"
    else
        print_message "VM backup log rotation already configured"
    fi
    
    print_message "VM backup configuration complete. Backups will run weekly."
    print_message "Backup location: $BACKUP_DIRECTORY"
}

# Execute function if script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    configure_backups
fi
