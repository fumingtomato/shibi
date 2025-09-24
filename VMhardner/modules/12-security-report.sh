#!/bin/bash
# =================================================================
# Security report generation
# =================================================================

run_security_report() {
    print_header "Generating Security Report"
    log "Starting security report generation"
    
    generate_security_report
    
    log "Security report generation completed"
}

generate_security_report() {
    print_message "Generating comprehensive security report..."
    log "Generating comprehensive security report"
    
    # Initialize report
    echo "=========================================" > "$REPORT_FILE"
    echo "VM Host Security Report" >> "$REPORT_FILE"
    echo "Generated: $(date)" >> "$REPORT_FILE"
    echo "Hostname: $(hostname)" >> "$REPORT_FILE"
    echo "=========================================" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    
    # System Information
    echo "=== SYSTEM INFORMATION ===" >> "$REPORT_FILE"
    echo "OS: $(lsb_release -ds 2>/dev/null || cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"')" >> "$REPORT_FILE"
    echo "Kernel: $(uname -r)" >> "$REPORT_FILE"
    echo "Architecture: $(uname -m)" >> "$REPORT_FILE"
    echo "Uptime: $(uptime -p)" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    
    # VM Information
    echo "=== VIRTUAL MACHINES ===" >> "$REPORT_FILE"
    echo "Total VMs: $(virsh list --all | grep -c '^ [0-9]')" >> "$REPORT_FILE"
    echo "Running VMs: $(virsh list | grep -c running)" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "VM List:" >> "$REPORT_FILE"
    virsh list --all >> "$REPORT_FILE" 2>&1
    echo "" >> "$REPORT_FILE"
    
    # Network Configuration
    echo "=== NETWORK CONFIGURATION ===" >> "$REPORT_FILE"
    echo "Public Interfaces: ${PUBLIC_INTERFACES[*]}" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "Firewall Status:" >> "$REPORT_FILE"
    ufw status verbose >> "$REPORT_FILE" 2>&1
    echo "" >> "$REPORT_FILE"
    
    # SSH Configuration
    echo "=== SSH CONFIGURATION ===" >> "$REPORT_FILE"
    echo "SSH Port: $(grep '^Port' /etc/ssh/sshd_config 2>/dev/null || echo 'Port 22 (default)')" >> "$REPORT_FILE"
    echo "PermitRootLogin: $(grep '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null || echo 'Not explicitly set')" >> "$REPORT_FILE"
    echo "PasswordAuthentication: $(grep '^PasswordAuthentication' /etc/ssh/sshd_config 2>/dev/null || echo 'Not explicitly set')" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    
    # Security Updates
    echo "=== SECURITY UPDATES ===" >> "$REPORT_FILE"
    echo "Checking for available security updates..." >> "$REPORT_FILE"
    apt-get -s upgrade | grep -i security | wc -l | xargs -I {} echo "{} security updates available" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    
    # Running Services
    echo "=== KEY SERVICES STATUS ===" >> "$REPORT_FILE"
    for service in ssh ufw libvirtd apparmor auditd fail2ban; do
        if systemctl is-active --quiet $service; then
            echo "$service: Active" >> "$REPORT_FILE"
        else
            echo "$service: Inactive or Not Installed" >> "$REPORT_FILE"
        fi
    done
    echo "" >> "$REPORT_FILE"
    
    # Kernel Parameters
    echo "=== KERNEL SECURITY PARAMETERS ===" >> "$REPORT_FILE"
    echo "IP Forwarding: $(sysctl net.ipv4.ip_forward | cut -d= -f2)" >> "$REPORT_FILE"
    echo "SYN Cookies: $(sysctl net.ipv4.tcp_syncookies | cut -d= -f2)" >> "$REPORT_FILE"
    echo "ICMP Redirects: $(sysctl net.ipv4.conf.all.accept_redirects | cut -d= -f2)" >> "$REPORT_FILE"
    echo "Source Routing: $(sysctl net.ipv4.conf.all.accept_source_route | cut -d= -f2)" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    
    # Storage Security
    echo "=== STORAGE SECURITY ===" >> "$REPORT_FILE"
    if [ -n "$VM_STORAGE_DIR" ]; then
        echo "VM Storage Directory: $VM_STORAGE_DIR" >> "$REPORT_FILE"
        echo "Directory Permissions: $(stat -c %a "$VM_STORAGE_DIR")" >> "$REPORT_FILE"
        echo "Directory Owner: $(stat -c '%U:%G' "$VM_STORAGE_DIR")" >> "$REPORT_FILE"
    else
        echo "VM Storage Directory: Not configured" >> "$REPORT_FILE"
    fi
    echo "" >> "$REPORT_FILE"
    
    # Backup Configuration
    echo "=== BACKUP CONFIGURATION ===" >> "$REPORT_FILE"
    if [ -f /usr/local/bin/backup-vms.sh ]; then
        echo "Backup Script: Installed" >> "$REPORT_FILE"
        if crontab -l 2>/dev/null | grep -q "backup-vms.sh"; then
            echo "Backup Schedule: Configured in cron" >> "$REPORT_FILE"
            crontab -l 2>/dev/null | grep "backup-vms.sh" >> "$REPORT_FILE"
        else
            echo "Backup Schedule: Not configured" >> "$REPORT_FILE"
        fi
    else
        echo "Backup Script: Not installed" >> "$REPORT_FILE"
    fi
    echo "" >> "$REPORT_FILE"
    
    # Monitoring Configuration
    echo "=== MONITORING CONFIGURATION ===" >> "$REPORT_FILE"
    if [ -f /usr/local/bin/vm-monitor.sh ]; then
        echo "VM Monitor Script: Installed" >> "$REPORT_FILE"
        if crontab -l 2>/dev/null | grep -q "vm-monitor.sh"; then
            echo "Monitoring Schedule: Configured in cron" >> "$REPORT_FILE"
            crontab -l 2>/dev/null | grep "vm-monitor.sh" >> "$REPORT_FILE"
        else
            echo "Monitoring Schedule: Not configured" >> "$REPORT_FILE"
        fi
    else
        echo "VM Monitor Script: Not installed" >> "$REPORT_FILE"
    fi
    echo "" >> "$REPORT_FILE"
    
    # Recent Security Events
    echo "=== RECENT SECURITY EVENTS ===" >> "$REPORT_FILE"
    echo "Last 10 SSH authentication failures:" >> "$REPORT_FILE"
    grep "authentication failure" /var/log/auth.log 2>/dev/null | tail -10 >> "$REPORT_FILE" || echo "No recent failures found" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    
    if command_exists fail2ban-client; then
        echo "Fail2ban Status:" >> "$REPORT_FILE"
        fail2ban-client status 2>/dev/null | grep "Jail list" >> "$REPORT_FILE" || echo "Fail2ban not running" >> "$REPORT_FILE"
    fi
    echo "" >> "$REPORT_FILE"
    
    # Security Recommendations
    echo "=== SECURITY RECOMMENDATIONS ===" >> "$REPORT_FILE"
    
    # Check for security issues and provide recommendations
    RECOMMENDATIONS=()
    
    # Check if root can SSH with password
    if grep -q "^PermitRootLogin yes" /etc/ssh/sshd_config 2>/dev/null; then
        RECOMMENDATIONS+=("- Consider setting 'PermitRootLogin prohibit-password' or 'no' in SSH configuration")
    fi
    
    # Check if password authentication is enabled
    if ! grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config 2>/dev/null; then
        RECOMMENDATIONS+=("- Consider disabling password authentication and using SSH keys only")
    fi
    
    # Check if firewall is enabled
    if ! ufw status | grep -q "Status: active"; then
        RECOMMENDATIONS+=("- UFW firewall is not active. Enable it for better security")
    fi
    
    # Check for security updates
    UPDATE_COUNT=$(apt-get -s upgrade | grep -i security | wc -l)
    if [ "$UPDATE_COUNT" -gt 0 ]; then
        RECOMMENDATIONS+=("- There are $UPDATE_COUNT security updates available. Apply them soon")
    fi
    
    # Check if SELinux/AppArmor is enabled
    if ! command_exists aa-status || ! aa-status --enabled 2>/dev/null; then
        if ! command_exists getenforce || [ "$(getenforce 2>/dev/null)" != "Enforcing" ]; then
            RECOMMENDATIONS+=("- Consider enabling AppArmor or SELinux for mandatory access control")
        fi
    fi
    
    # Check if audit is running
    if ! systemctl is-active --quiet auditd; then
        RECOMMENDATIONS+=("- Auditd is not running. Enable it for better security auditing")
    fi
    
    # Check VM isolation
    if [ "$ENABLE_VM_ISOLATION" != "true" ]; then
        RECOMMENDATIONS+=("- VM isolation is not enabled. Consider enabling it in settings")
    fi
    
    # Check backup configuration
    if [ ! -f /usr/local/bin/backup-vms.sh ]; then
        RECOMMENDATIONS+=("- VM backup script is not installed. Regular backups are important")
    fi
    
    if [ ${#RECOMMENDATIONS[@]} -eq 0 ]; then
        echo "No critical security issues found. System appears well-hardened." >> "$REPORT_FILE"
    else
        echo "The following recommendations should be considered:" >> "$REPORT_FILE"
        for rec in "${RECOMMENDATIONS[@]}"; do
            echo "$rec" >> "$REPORT_FILE"
        done
    fi
    echo "" >> "$REPORT_FILE"
    
    # Summary
    echo "=== SUMMARY ===" >> "$REPORT_FILE"
    echo "Security hardening script version: $VERSION" >> "$REPORT_FILE"
    echo "Report generated on: $(date)" >> "$REPORT_FILE"
    echo "Log file: $LOG_FILE" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "For detailed logs, check: $LOG_FILE" >> "$REPORT_FILE"
    echo "=========================================" >> "$REPORT_FILE"
    
    print_message "Security report saved to: $REPORT_FILE"
    log "Security report saved to: $REPORT_FILE"
    
    # Display report summary to console
    echo ""
    print_header "Security Report Summary"
    
    # Count and display key metrics
    TOTAL_VMS=$(virsh list --all | grep -c '^ [0-9]' || echo "0")
    RUNNING_VMS=$(virsh list | grep -c running || echo "0")
    SECURITY_UPDATES=$(apt-get -s upgrade | grep -i security | wc -l)
    
    print_message "Total VMs: $TOTAL_VMS (Running: $RUNNING_VMS)"
    
    if [ "$SECURITY_UPDATES" -gt 0 ]; then
        print_warning "Security Updates Available: $SECURITY_UPDATES"
    else
        print_message "System is up to date with security patches"
    fi
    
    if ufw status | grep -q "Status: active"; then
        print_message "Firewall: Active"
    else
        print_warning "Firewall: Inactive"
    fi
    
    if [ ${#RECOMMENDATIONS[@]} -gt 0 ]; then
        print_warning "Security recommendations: ${#RECOMMENDATIONS[@]} items need attention"
    else
        print_message "No critical security issues found"
    fi
    
    echo ""
    print_message "Full report available at: $REPORT_FILE"
}
