#!/bin/bash

# =================================================================
# SECTION 2: SYSTEM UPDATES AND PACKAGE MANAGEMENT
# =================================================================

run_system_updates() {
    print_header "System Updates and Package Management"
    update_system
}

update_system() {
    # Check if system was updated in the last 24 hours
    if [ -f /var/lib/apt/periodic/update-success-stamp ]; then
        last_update=$(stat -c %Y /var/lib/apt/periodic/update-success-stamp)
        now=$(date +%s)
        hours_since_update=$(( (now - last_update) / 3600 ))
        
        if [ $hours_since_update -lt 24 ]; then
            print_message "System was updated less than 24 hours ago. Skipping update."
            return
        fi
    fi
    
    print_message "Updating package lists..."
    apt-get update
    
    print_message "Installing security updates..."
    apt-get -y --only-upgrade install $(apt-get --just-print upgrade | grep -i security | awk '{print $2}')
    
    print_message "Installing essential security packages..."
    # Check for each package before installing
    PACKAGES="fail2ban ufw unattended-upgrades apt-listchanges lynis aide rkhunter auditd chrony apparmor apparmor-utils"
    
    for pkg in $PACKAGES; do
        if ! is_package_installed $pkg; then
            print_message "Installing $pkg..."
            apt-get install -y $pkg
        else
            print_message "$pkg is already installed."
        fi
    done
    
    # Configure unattended upgrades if not already configured
    if [ ! -f /etc/apt/apt.conf.d/50unattended-upgrades.bak ]; then
        print_message "Configuring unattended security upgrades..."
        backup_config_file /etc/apt/apt.conf.d/50unattended-upgrades
        
        cat > /etc/apt/apt.conf.d/50unattended-upgrades <<EOF
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}";
    "\${distro_id}:\${distro_codename}-security";
    "\${distro_id}ESMApps:\${distro_codename}-apps-security";
    "\${distro_id}ESM:\${distro_codename}-infra-security";
};
Unattended-Upgrade::Package-Blacklist {
};
Unattended-Upgrade::DevRelease "false";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF
        
        cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
    else
        print_message "Unattended upgrades are already configured."
    fi
}
