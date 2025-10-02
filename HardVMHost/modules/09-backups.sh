#!/bin/bash
# =================================================================
# VM Host Hardener v2.0 - Module 09: Automated Backups
#
# Description: This module creates and configures a script for
# automated backups of all virtual machines, including live snapshots,
# XML configuration, and log rotation.
# =================================================================

run_backups() {
    if [ "${ENABLE_BACKUPS}" != "true" ]; then
        print_message "Skipping backup configuration as per settings."
        log "Backup configuration skipped (ENABLE_BACKUPS is not 'true')."
        return
    fi

    print_header "Module 09: Configuring Automated VM Backups"
    log "Starting backup configuration."

    create_backup_script
    setup_backup_cronjob
    setup_backup_logrotate

    print_message "Backup system configured successfully."
    log "Backup configuration completed."
}

# Creates the main backup script.
create_backup_script() {
    local script_path="/usr/local/bin/backup-vms.sh"
    print_message "Creating backup script at ${script_path}..."

    # Create the backup directory if it doesn't exist
    mkdir -p "${BACKUP_DIRECTORY}"
    chown root:root "${BACKUP_DIRECTORY}"
    chmod 750 "${BACKUP_DIRECTORY}"
    log "Ensured backup directory exists: ${BACKUP_DIRECTORY}"

    # Create the script using a heredoc
    cat > "${script_path}" <<-EOFSCRIPT
#!/bin/bash
# Automated VM Backup Script (v2.0)
set -u

# --- Configuration ---
readonly BACKUP_DIR="${BACKUP_DIRECTORY}"
readonly RETENTION_COUNT="${BACKUP_RETENTION_COUNT}"
readonly LOG_FILE="/var/log/vm-backup.log"
readonly DATE=\$(date +"%Y-%m-%d_%H-%M-%S")

# --- Logging ---
log() {
    echo "\$(date '+%Y-%m-%d %H:%M:%S') - \$1" >> "\${LOG_FILE}"
}

# --- Main Logic ---
log "===== Starting VM Backup Run ====="

# Get all VMs (running and shut off)
ALL_VMS=\$(virsh list --all --name | grep -v '^$')

if [ -z "\$ALL_VMS" ]; then
    log "No virtual machines found. Exiting backup."
    exit 0
fi

for vm in \$ALL_VMS; do
    log "Processing backup for VM: \$vm"
    
    local vm_backup_dir="\$BACKUP_DIR/\$vm"
    local current_backup_path="\$vm_backup_dir/\$DATE"
    mkdir -p "\$current_backup_path"

    # 1. Backup VM XML configuration
    virsh dumpxml "\$vm" > "\$current_backup_path/\${vm}.xml"
    log "Backed up XML configuration for \$vm."

    # 2. Backup VM Disks
    # Find all disk target devices (e.g., vda, vdb)
    local disks
    disks=\$(virsh domblklist "\$vm" --details | grep 'disk' | awk '{print \$3}')

    for disk_target in \$disks; do
        local disk_path
        disk_path=\$(virsh domblklist "\$vm" --details | grep "\$disk_target" | awk '{print \$4}')
        
        if [ -z "\$disk_path" ]; then
            log "Warning: Could not find disk path for target \$disk_target on VM \$vm. Skipping disk."
            continue
        fi
        
        local disk_filename
        disk_filename=\$(basename "\$disk_path")
        local backup_disk_path="\$current_backup_path/\$disk_filename"

        # Check if VM is running for live snapshot
        if virsh list --name | grep -q "^\$vm\$"; then
            # Live backup using a temporary snapshot
            log "Performing live backup for disk \$disk_target (\$disk_path)..."
            virsh snapshot-create-as --domain "\$vm" --name "backup-\$disk_target" --disk-only --atomic --quiesce
            
            # Copy the disk file while the VM writes to the snapshot
            cp "\$disk_path" "\$backup_disk_path"
            
            # Merge the snapshot back into the base image
            virsh blockcommit "\$vm" "\$disk_target" --active --pivot
            # The snapshot is now merged, but we need to remove the metadata
            virsh snapshot-delete "\$vm" "backup-\$disk_target" --metadata
            log "Live backup of \$disk_target completed."
        else
            # Offline backup - simple copy
            log "Performing offline backup for disk \$disk_target (\$disk_path)..."
            cp "\$disk_path" "\$backup_disk_path"
            log "Offline backup of \$disk_target completed."
        fi
    done

    # 3. Rotate old backups
    if [ -d "\$vm_backup_dir" ]; then
        # List directories by name (which is the date) and remove the oldest
        local backups_to_remove
        backups_to_remove=\$(ls -1r "\$vm_backup_dir" | tail -n +\$((\$RETENTION_COUNT + 1)))
        for old_backup in \$backups_to_remove; do
            log "Removing old backup: \$vm/\$old_backup"
            rm -rf "\$vm_backup_dir/\$old_backup"
        done
    fi
    log "Backup for VM: \$vm completed."
done

log "===== VM Backup Run Finished ====="
EOFSCRIPT

    chmod +x "${script_path}"
    log "Backup script created at ${script_path}."
}

# Sets up the cron job for the backup script.
setup_backup_cronjob() {
    local script_path="/usr/local/bin/backup-vms.sh"
    local cron_job="${BACKUP_CRON_SCHEDULE} ${script_path}"

    if ! crontab -l 2>/dev/null | grep -q "${script_path}"; then
        (crontab -l 2>/dev/null; echo "${cron_job} # Added by VM Host Hardener") | crontab -
        log "Cron job created for backups."
        print_message "Backup cron job scheduled to run at: ${BACKUP_CRON_SCHEDULE}"
    else
        log "Cron job for backups already exists."
    fi
}

# Sets up log rotation for the backup log file.
setup_backup_logrotate() {
    local logrotate_conf="/etc/logrotate.d/vm-backup"

    cat > "${logrotate_conf}" <<EOF
/var/log/vm-backup.log {
    weekly
    rotate 4
    compress
    delaycompress
    missingok
    notifempty
}
EOF
    log "Log rotation configured for vm-backup.log."
}
