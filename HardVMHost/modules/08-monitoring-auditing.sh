#!/bin/bash
# =================================================================
# VM Host Hardener v2.0 - Module 08: Monitoring and Auditing
#
# Description: This module configures system auditing with auditd
# and sets up a resource monitoring script with cron and log rotation.
# =================================================================

run_monitoring_auditing() {
    print_header "Module 08: Configuring Monitoring and Auditing"
    log "Starting monitoring and auditing configuration."

    if [ "${ENABLE_AUDITD}" == "true" ]; then
        setup_auditing
    else
        log "auditd configuration skipped as per settings."
    fi

    if [ "${ENABLE_MONITORING_CRON}" == "true" ]; then
        setup_monitoring
    else
        log "Resource monitoring setup skipped as per settings."
    fi

    log "Monitoring and auditing configuration completed."
}

# Configures auditd to monitor for security-relevant events.
setup_auditing() {
    print_message "Configuring system auditing with auditd..."
    local rules_file="/etc/audit/rules.d/99-vm-host-hardening.rules"

    # Create a rules file to monitor libvirt/VM activity.
    cat > "${rules_file}" <<-EOF
	# Audit rules for VM Host (Applied by Hardener Script)

	# Monitor for changes to libvirt configuration files
	-w /etc/libvirt/ -p wa -k libvirt_config_changes

	# Monitor for changes to VM disk images
	-w /var/lib/libvirt/images/ -p wa -k vm_disk_changes

	# Monitor execution of virtualization management commands
	-a always,exit -F path=/usr/bin/virsh -F perm=x -k virsh_command
	-a always,exit -F path=/usr/bin/qemu-system-x86_64 -F perm=x -k vm_execution
	EOF

    # Restart auditd to apply the new rules. The '|| true' prevents script exit
    # if the service is masked or already restarting. A proper check follows.
    systemctl restart auditd || true
    sleep 1 # Give the service a moment
    if ! systemctl is-active --quiet auditd; then
        print_warning "auditd service is not active. Auditing may not function correctly."
        log "Warning: auditd service failed to start or is not active."
    else
        log "auditd rules applied and service is active."
        print_message "auditd configured to monitor VM-related activity."
    fi
}

# Creates a monitoring script, cron job, and log rotation config.
setup_monitoring() {
    print_message "Setting up resource monitoring script..."
    local script_path="/usr/local/bin/vm-monitor.sh"
    local logrotate_conf="/etc/logrotate.d/vm-monitor"

    # Create the monitoring script
    cat > "${script_path}" <<'EOFSCRIPT'
#!/bin/bash
# VM Resource Monitoring Script (v2.0)

LOG_FILE="/var/log/vm-monitor.log"

# --- Main Logging Function ---
log_section() {
    echo -e "\n--- $1 ---" >> "${LOG_FILE}"
}

# --- Script Execution ---
echo "--- VM Monitor Report: $(date) ---" >> "${LOG_FILE}"

log_section "Host Resource Usage"
(
    echo "CPU Usage:"
    top -bn1 | grep "Cpu(s)"
    echo -e "\nMemory Usage:"
    free -h
    echo -e "\nDisk Usage:"
    df -h /
) >> "${LOG_FILE}"

log_section "Libvirt Service Status"
systemctl is-active --quiet libvirtd && echo "libvirtd: active" >> "${LOG_FILE}" || echo "libvirtd: inactive" >> "${LOG_FILE}"

log_section "Running VMs"
virsh list --name >> "${LOG_FILE}"

log_section "Recent Libvirt Errors (last 10)"
grep -i "error\|warning" /var/log/libvirt/libvirtd.log 2>/dev/null | tail -10 >> "${LOG_FILE}" || echo "No errors/warnings found." >> "${LOG_FILE}"

echo -e "\n--- End of Report ---\n" >> "${LOG_FILE}"
EOFSCRIPT

    chmod +x "${script_path}"
    log "Created monitoring script at ${script_path}."

    # Create cron job
    local cron_job="${MONITORING_CRON_SCHEDULE} ${script_path}"
    # Use a unique identifier to avoid adding duplicate cron jobs
    if ! crontab -l 2>/dev/null | grep -q "${script_path}"; then
        (crontab -l 2>/dev/null; echo "${cron_job} # Added by VM Host Hardener") | crontab -
        log "Cron job created for resource monitoring."
        print_message "Cron job scheduled to run at: ${MONITORING_CRON_SCHEDULE}"
    else
        log "Cron job for monitoring already exists."
    fi

    # Create log rotation configuration
    cat > "${logrotate_conf}" <<EOF
/var/log/vm-monitor.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
}
EOF
    log "Log rotation configured for vm-monitor.log."
    print_message "Monitoring script, cron job, and log rotation are configured."
}
