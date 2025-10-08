#!/bin/bash
# =================================================================
# VM Host Hardener v2.0 - Module 10: Security Report
#
# Description: This module generates a comprehensive report detailing
# the system's final hardened state and provides recommendations.
# =================================================================

run_security_report() {
    print_header "Module 10: Generating Final Security Report"
    log "Starting security report generation."

    # Initialize the report file
    init_report

    # Append each section to the report
    report_system_info
    report_vm_status
    report_security_status
    report_hardening_summary
    report_final_recommendations

    # Finalize the report
    echo "===== End of Report =====" >> "${REPORT_FILE}"
    log "Security report generation completed."

    # Display a summary to the console
    display_console_summary
}

# --- Report Generation Functions ---

# Creates a fresh report file with a header.
init_report() {
    cat > "${REPORT_FILE}" <<-EOF
	# =================================================================
	# VM Host Security Report (v${VERSION})
	# Generated: $(date)
	# =================================================================
	EOF
}

# Appends system and OS information.
report_system_info() {
    cat >> "${REPORT_FILE}" <<-EOF

	### System Information ###
	Hostname: $(hostname)
	OS Version: $(lsb_release -ds)
	Kernel: $(uname -r)
	Uptime: $(uptime -p)
	EOF
}

# Appends the status of virtual machines.
report_vm_status() {
    cat >> "${REPORT_FILE}" <<-EOF

	### Virtual Machine Status ###
	$(virsh list --all)
	EOF
}

# Appends the status of key security services and configurations.
report_security_status() {
    cat >> "${REPORT_FILE}" <<-EOF

	### Core Security Status ###
	Firewall (UFW) Status: $(ufw status | head -n 1)
	SSH Port: ${SSH_PORT}
	SSH Root Login: ${PERMIT_ROOT_LOGIN}
	SSH Password Auth: ${PASSWORD_AUTHENTICATION}

	--- Key Service Status ---
	libvirtd: $(systemctl is-active libvirtd)
	sshd: $(systemctl is-active ssh)
	ufw: $(systemctl is-active ufw)
	auditd: $(systemctl is-active auditd)
	fail2ban: $(systemctl is-active fail2ban)
	unattended-upgrades: $(systemctl is-active unattended-upgrades)
	chronyd: $(systemctl is-active chrony)
	EOF
}

# Appends a summary of the hardening components configured by this script.
report_hardening_summary() {
    cat >> "${REPORT_FILE}" <<-EOF

	### Hardening Components Summary ###
	Kernel Hardening Config: $([ -f /etc/sysctl.d/95-vm-host-hardening.conf ] && echo "Applied" || echo "Not Found")
	Resource Limits Config: $([ -f /etc/security/limits.d/95-vm-host-hardening.conf ] && echo "Applied" || echo "Not Found")
	Backup Script: $([ -f /usr/local/bin/backup-vms.sh ] && echo "Installed" || echo "Not Installed")
	Backup Cron Job: $(crontab -l 2>/dev/null | grep -q "backup-vms.sh" && echo "Configured" || echo "Not Configured")
	Monitoring Script: $([ -f /usr/local/bin/vm-monitor.sh ] && echo "Installed" || echo "Not Installed")
	Monitoring Cron Job: $(crontab -l 2>/dev/null | grep -q "vm-monitor.sh" && echo "Configured" || echo "Not Configured")
	EOF
}

# Appends final recommendations and next steps.
report_final_recommendations() {
    cat >> "${REPORT_FILE}" <<-EOF

	### Final Recommendations ###
	1.  [CRITICAL] Reboot the system to ensure all kernel parameters and service changes are fully applied.
	    Command: sudo reboot

	2.  [HIGH] Verify you can log in as the new admin user ('${ADMIN_USER:-<not_created>}') using the configured SSH key.
	    Command: ssh ${ADMIN_USER:-<user>}@<host_ip>

	3.  [MEDIUM] Review the full log file for any warnings or unexpected messages.
	    Log File: ${LOG_FILE}

	4.  [INFO] Check the status of your virtual machines to ensure they are running correctly after the changes.
	    Command: sudo virsh list --all
	EOF
}

# Displays a brief summary to the console.
display_console_summary() {
    print_message "--- Final Summary ---"
    
    local ufw_status
    ufw_status=$(ufw status | head -n 1)
    print_message "Firewall Status: ${ufw_status}"

    if [ "${CREATE_ADMIN_USER}" == "true" ]; then
        print_message "Admin User '${ADMIN_USER}' is configured for key-based SSH."
    fi

    if [ "${ENABLE_BACKUPS}" == "true" ]; then
        print_message "Automated backups are configured to run on schedule: ${BACKUP_CRON_SCHEDULE}"
    fi
    
    print_warning "A system reboot is highly recommended to apply all hardening changes."
}
