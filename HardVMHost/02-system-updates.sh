#!/bin/bash
# =================================================================
# VM Host Hardener v2.0 - Module 02: System Updates
#
# Description: This module ensures the system is up-to-date with the
# latest security patches and configures unattended-upgrades for
# ongoing protection.
# =================================================================

run_system_updates() {
    print_header "Module 02: Applying System Updates"
    log "Starting system updates and package management."

    update_package_lists
    install_security_packages
    configure_unattended_upgrades
    apply_pending_security_updates

    log "System updates and package management completed."
    print_message "System is up-to-date and configured for automatic security updates."
}

# Updates the local package cache.
update_package_lists() {
    print_message "Updating package lists from repositories..."
    log "Running apt-get update."
    apt-get update -y
}

# Installs essential security-related packages.
install_security_packages() {
    print_message "Installing additional security packages (fail2ban)..."
    local packages_to_install=()
    # fail2ban is a key tool for preventing brute-force attacks.
    local security_packages=("fail2ban" "apt-listchanges")

    for pkg in "${security_packages[@]}"; do
        if ! package_installed "$pkg"; then
            packages_to_install+=("$pkg")
        fi
    done

    if [ ${#packages_to_install[@]} -gt 0 ]; then
        log "Installing missing security packages: ${packages_to_install[*]}."
        apt-get install -y "${packages_to_install[@]}"
        log "Security packages installed."
    else
        log "All security packages are already present."
    fi
}

# Configures unattended-upgrades to automatically install security updates.
configure_unattended_upgrades() {
    print_message "Configuring unattended security upgrades..."
    log "Writing configuration for unattended-upgrades."

    # This file configures WHAT to upgrade.
    # We are allowing security updates from the main repositories.
    cat > /etc/apt/apt.conf.d/50unattended-upgrades <<-EOF
	Unattended-Upgrade::Allowed-Origins {
	    "\${distro_id}:\${distro_codename}-security";
	};
	Unattended-Upgrade::Package-Blacklist {
	};
	Unattended-Upgrade::DevRelease "false";
	Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
	Unattended-Upgrade::Remove-Unused-Dependencies "true";
	Unattended-Upgrade::Automatic-Reboot "false";
	EOF

    # This file configures WHEN to run upgrades.
    # We are enabling daily checks and package list updates.
    cat > /etc/apt/apt.conf.d/20auto-upgrades <<-EOF
	APT::Periodic::Update-Package-Lists "1";
	APT::Periodic::Unattended-Upgrade "1";
	APT::Periodic::AutocleanInterval "7";
	EOF

    log "Unattended upgrades configured."
    print_message "Unattended upgrades have been configured to run daily."
}

# Applies any pending security updates immediately.
apply_pending_security_updates() {
    print_message "Checking for and applying any pending security updates now..."
    log "Running unattended-upgrade to apply initial security patches."

    # The -d flag provides detailed output which is useful for logging.
    # This command uses the configuration we just wrote to apply only security updates.
    unattended-upgrade -d
    
    log "Pending security updates applied."
    print_message "All pending security updates have been installed."
}
