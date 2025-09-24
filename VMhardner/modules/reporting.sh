#!/bin/bash

# =================================================================
# SECTION 11: SECURITY REPORTING
# =================================================================

generate_security_report() {
    print_header "Security Status Report"
    
    # Create a temporary file for the report
    REPORT_FILE=$(mktemp)
    
    print_message "Generating security report..."
    
    # Report header
    cat > $REPORT_FILE <<EOF
===================================
VM HOST SECURITY REPORT
===================================
Date: $(date)
Hostname: $(hostname)
Kernel: $(uname -r)

===================================
SYSTEM INFORMATION
===================================
EOF
    
    # System information
    echo "OS Version:" >> $REPORT_FILE
    lsb_release -d 2>/dev/null | tee -a $REPORT_FILE || cat /etc/os-release | grep PRETTY_NAME | tee -a $REPORT_FILE
    
    echo -e "\nCPU Information:" >> $REPORT_FILE
    grep "model name" /proc/cpuinfo | head -1 | tee -a $REPORT_FILE
    
    echo -e "\nVirtualization Support:" >> $REPORT_FILE
    if grep -E 'svm|vmx' /proc/cpuinfo &> /dev/null; then
        echo "CPU supports hardware virtualization." | tee -a $REPORT_FILE
    else
        echo "WARNING: CPU might not support hardware virtualization!" | tee -a $REPORT_FILE
    fi
    
    echo -e "\nKernel Parameters:" >> $REPORT_FILE
    sysctl -a 2>/dev/null | grep -E 'kernel.randomize_va_space|kernel.kptr_restrict|net.ipv4.tcp_syncookies' | tee -a $REPORT_FILE
    
    # VM information
    cat >> $REPORT_FILE <<EOF

===================================
VIRTUALIZATION STATUS
===================================
EOF
    
    echo "Libvirt Service:" >> $REPORT_FILE
    systemctl status libvirtd --no-pager | grep "Active:" | tee -a $REPORT_FILE
    
    echo -e "\nVirtual Machines:" >> $REPORT_FILE
    virsh list --all | tee -a $REPORT_FILE
    
    echo -e "\nVirtual Networks:" >> $REPORT_FILE
    virsh net-list --all | tee -a $REPORT_FILE
    
    # Security settings
    cat >> $REPORT_FILE <<EOF

===================================
SECURITY CONFIGURATION
===================================
EOF
    
    echo "Firewall Status:" >> $REPORT_FILE
    if command -v ufw &> /dev/null; then
        ufw status | tee -a $REPORT_FILE
    elif command -v firewall-cmd &> /dev/null; then
        firewall-cmd --state | tee -a $REPORT_FILE
    else
        echo "No firewall detected." | tee -a $REPORT_FILE
    fi
    
    echo -e "\nSSH Configuration:" >> $REPORT_FILE
    grep -E "^PermitRootLogin|^PasswordAuthentication|^X11Forwarding|^Protocol" /etc/ssh/sshd_config | tee -a $REPORT_FILE
    
    echo -e "\nFail2ban Status:" >> $REPORT_FILE
    if command -v fail2ban-client &> /dev/null; then
        fail2ban-client status | tee -a $REPORT_FILE
    else
        echo "Fail2ban not installed." | tee -a $REPORT_FILE
    fi
    
    echo -e "\nAppArmor Status:" >> $REPORT_FILE
    if command -v aa-status &> /dev/null; then
        aa-status | tee -a $REPORT_FILE
    else
        echo "AppArmor not installed." | tee -a $REPORT_FILE
    fi
    
    # Vulnerabilities
    cat >> $REPORT_FILE <<EOF

===================================
SECURITY VULNERABILITIES
===================================
EOF
    
    echo "Checking for common vulnerabilities..." >> $REPORT_FILE
    
    # Check for root SSH login
    if grep -q "^PermitRootLogin yes" /etc/ssh/sshd_config; then
        echo "WARNING: Root SSH login is allowed!" | tee -a $REPORT_FILE
    else
        echo "Root SSH login properly restricted." | tee -a $REPORT_FILE
    fi
    
    # Check for password authentication
    if grep -q "^PasswordAuthentication yes" /etc/ssh/sshd_config; then
        echo "WARNING: SSH password authentication is enabled." | tee -a $REPORT_FILE
    else
        echo "SSH password authentication disabled." | tee -a $REPORT_FILE
    fi
    
    # Check for firewall
    if command -v ufw &> /dev/null && ! ufw status | grep -q "Status: active"; then
        echo "WARNING: Firewall is not enabled!" | tee -a $REPORT_FILE
    elif ! command -v ufw &> /dev/null && ! command -v firewall-cmd &> /dev/null; then
        echo "WARNING: No firewall detected!" | tee -a $REPORT_FILE
    else
        echo "Firewall is active." | tee -a $REPORT_FILE
    fi
    
    # Check libvirt security
    if grep -q "security_driver = \"none\"" /etc/libvirt/qemu.conf; then
        echo "WARNING: Libvirt security driver is disabled!" | tee -a $REPORT_FILE
    else
        echo "Libvirt security driver is properly configured." | tee -a $REPORT_FILE
    fi
    
    # Run a brief Lynis scan if available
    if command -v lynis &> /dev/null; then
        echo -e "\nRunning Lynis security audit (brief)..." | tee -a $REPORT_FILE
        lynis audit system --quick 2>/dev/null | grep -E "^Hardening|^Security|^Warning" | tee -a $REPORT_FILE
    fi
    
    # Summary and recommendations
    cat >> $REPORT_FILE <<EOF

===================================
SECURITY RECOMMENDATIONS
===================================
1. Regularly update the system with: apt update && apt upgrade
2. Monitor VM logs at /var/log/libvirt/
3. Run periodic security scans with: lynis audit system
4. Check firewall rules with: ufw status verbose
5. Monitor authentication failures with: grep "Failed password" /var/log/auth.log

For detailed VM monitoring, use the provided script:
  /usr/local/bin/vm-monitor.sh
  
For VM backups, use:
  /usr/local/bin/backup-vms.sh
EOF
    
    # Display the report and save a copy
    cat $REPORT_FILE
    cp $REPORT_FILE /root/vm-host-security-report.txt
    
    print_message "Security report saved to /root/vm-host-security-report.txt"
    
    # Clean up temp file
    rm $REPORT_FILE
}
