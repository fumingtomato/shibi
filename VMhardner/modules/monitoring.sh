#!/bin/bash

# =================================================================
# SECTION 8: SYSTEM AUDITING AND MONITORING
# =================================================================

setup_monitoring() {
    print_header "System Auditing and Monitoring"
    
    # Configure auditd if installed
    if command -v auditd &> /dev/null; then
        print_message "Configuring system auditing with auditd..."
        
        # Backup existing config if needed
        backup_config_file /etc/audit/auditd.conf
        
        # Configure audit settings
        sed -i 's/^log_file.*/log_file = \/var\/log\/audit\/audit.log/' /etc/audit/auditd.conf
        sed -i 's/^max_log_file =.*/max_log_file = 50/' /etc/audit/auditd.conf
        sed -i 's/^max_log_file_action.*/max_log_file_action = rotate/' /etc/audit/auditd.conf
        sed -i 's/^space_left =.*/space_left = 75/' /etc/audit/auditd.conf
        sed -i 's/^space_left_action.*/space_left_action = email/' /etc/audit/auditd.conf
        sed -i 's/^admin_space_left =.*/admin_space_left = 50/' /etc/audit/auditd.conf
        sed -i 's/^admin_space_left_action.*/admin_space_left_action = halt/' /etc/audit/auditd.conf
        
        # Add VM-specific audit rules
        if [ ! -f /etc/audit/rules.d/90-vm-monitoring.rules ]; then
            print_message "Adding VM-specific audit rules..."
            
            cat > /etc/audit/rules.d/90-vm-monitoring.rules <<EOF
# Monitor libvirt configuration changes
-w /etc/libvirt/ -p wa -k libvirt_config
-w /var/lib/libvirt/ -p wa -k libvirt_storage

# Monitor VM creation and management
-a always,exit -F path=/usr/bin/virsh -F perm=x -F key=virsh_commands
-a always,exit -F path=/usr/bin/qemu-system-x86_64 -F perm=x -F key=vm_start

# Monitor VM disk access
-a always,exit -F arch=b64 -S open -F dir=/var/lib/libvirt/images -F key=vm_disk_access
EOF
            
            # Restart auditd to apply changes
            service auditd restart
        fi
    fi
    
    # Install and configure logwatch for daily reports if not already done
    if ! command -v logwatch &> /dev/null; then
        print_message "Installing logwatch for daily security reports..."
        apt-get install -y logwatch
        
        # Configure logwatch
        mkdir -p /etc/logwatch/conf/
        cat > /etc/logwatch/conf/logwatch.conf <<EOF
# Logwatch configuration
Output = mail
Format = html
MailTo = root
Detail = High
Service = All
# Add additional services
Service = libvirt
Service = sshd
Service = pam
EOF
    fi
    
    # Setup VM monitoring script
    print_message "Creating VM monitoring script..."
    
    cat > /usr/local/bin/vm-monitor.sh <<EOF
#!/bin/bash
# VM Resource Monitoring Script

DATE=\$(date +"%Y-%m-%d %H:%M:%S")
REPORT_FILE="/var/log/vm-monitor-\$(date +%Y%m%d).log"

echo "======== VM Monitor Report: \$DATE ========" >> \$REPORT_FILE

# Check libvirt status
echo "== Libvirt Service Status ==" >> \$REPORT_FILE
systemctl status libvirtd --no-pager | grep "Active:" >> \$REPORT_FILE

# List running VMs
echo -e "\n== Running VMs ==" >> \$REPORT_FILE
virsh list --all >> \$REPORT_FILE

# Check VM resource usage
echo -e "\n== VM Resource Usage ==" >> \$REPORT_FILE
for vm in \$(virsh list --name); do
    echo "\$vm:" >> \$REPORT_FILE
    virsh domstats \$vm --balloon --vcpu --interface --block >> \$REPORT_FILE
done

# Check host resource usage
echo -e "\n== Host Resource Usage ==" >> \$REPORT_FILE
echo "CPU usage:" >> \$REPORT_FILE
top -bn1 | grep "Cpu(s)" >> \$REPORT_FILE
echo "Memory usage:" >> \$REPORT_FILE
free -h >> \$REPORT_FILE
echo "Disk usage:" >> \$REPORT_FILE
df -h >> \$REPORT_FILE

# Check for any issues in logs
echo -e "\n== Recent Libvirt Errors ==" >> \$REPORT_FILE
grep -i error /var/log/libvirt/libvirtd.log | tail -20 >> \$REPORT_FILE

echo "======== End of Report ========" >> \$REPORT_FILE
echo "" >> \$REPORT_FILE

# Email the report if over threshold
CPU_USAGE=\$(top -bn1 | grep "Cpu(s)" | awk '{print \$2 + \$4}' | cut -d. -f1)
MEMORY_USAGE=\$(free | grep Mem | awk '{print int(\$3/\$2 * 100)}')

if [ "\$CPU_USAGE" -gt 80 ] || [ "\$MEMORY_USAGE" -gt 80 ]; then
    cat \$REPORT_FILE | mail -s "WARNING: High resource usage on VM host" root
fi
EOF
    
    chmod +x /usr/local/bin/vm-monitor.sh
    
    # Setup cron job for monitoring
    if ! crontab -l | grep -q "vm-monitor.sh"; then
        print_message "Setting up cron job for VM monitoring..."
        (crontab -l 2>/dev/null; echo "*/15 * * * * /usr/local/bin/vm-monitor.sh") | crontab -
    fi
    
    # Setup log rotation for monitoring logs
    cat > /etc/logrotate.d/vm-monitor <<EOF
/var/log/vm-monitor-*.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
}
EOF
    
    print_message "Monitoring configuration complete."
}
