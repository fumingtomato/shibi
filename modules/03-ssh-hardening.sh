#!/bin/bash
# =================================================================
# VM Host Hardener v2.0 - Module 03: SSH Hardening
#
# Description: This module secures the SSH service by applying best
# practices and optionally creates a dedicated, key-based admin user
# for VM management.
# =================================================================

run_ssh_hardening() {
    print_header "Module 03: Hardening SSH Service"
    log "Starting SSH hardening."

    harden_sshd_config
    setup_admin_user

    # Check if the configuration has changed before restarting
    local sshd_config_file="/etc/ssh/sshd_config"
    if ! diff -q "${sshd_config_file}" "${sshd_config_file}.bak" &>/dev/null; then
        restart_service "ssh"
    else
        print_message "SSH configuration is already hardened. No restart needed."
        log "SSH configuration unchanged."
    fi

    log "SSH hardening completed."
}

# Applies security settings to /etc/ssh/sshd_config
harden_sshd_config() {
    local sshd_config_file="/etc/ssh/sshd_config"
    print_message "Hardening SSH configuration (${sshd_config_file})..."

    # Apply settings from settings.conf
    configure_setting "Port" "${SSH_PORT}" "${sshd_config_file}"
    configure_setting "PermitRootLogin" "${PERMIT_ROOT_LOGIN}" "${sshd_config_file}"
    configure_setting "PasswordAuthentication" "${PASSWORD_AUTHENTICATION}" "${sshd_config_file}"
    
    # Standard security best practices
    configure_setting "Protocol" "2" "${sshd_config_file}"
    configure_setting "X11Forwarding" "no" "${sshd_config_file}"
    configure_setting "MaxAuthTries" "3" "${sshd_config_file}"
    configure_setting "ClientAliveInterval" "300" "${sshd_config_file}"
    configure_setting "ClientAliveCountMax" "2" "${sshd_config_file}"
    configure_setting "PermitEmptyPasswords" "no" "${sshd_config_file}"
    
    # Apply strong crypto settings from config
    configure_setting "Ciphers" "${SSH_CIPHERS}" "${sshd_config_file}"
    configure_setting "MACs" "${SSH_MACS}" "${sshd_config_file}"
    configure_setting "KexAlgorithms" "${SSH_KEX_ALGORITHMS}" "${sshd_config_file}"

    log "Finished applying sshd_config settings."
}

# Creates and configures a dedicated admin user if enabled in settings.conf
setup_admin_user() {
    if [ "${CREATE_ADMIN_USER}" != "true" ]; then
        print_message "Skipping admin user creation as per configuration."
        log "Admin user creation skipped."
        return
    fi

    print_message "Setting up dedicated VM administrator: ${ADMIN_USER}"
    log "Starting setup for admin user '${ADMIN_USER}'."

    # Create user if it doesn't exist
    if id "${ADMIN_USER}" &>/dev/null; then
        log "User ${ADMIN_USER} already exists."
    else
        useradd -m -s /bin/bash -c "VM Administrator" "${ADMIN_USER}"
        # Lock the password, forcing key-only login
        passwd -l "${ADMIN_USER}" >/dev/null
        log "Created user ${ADMIN_USER} and locked password."
    fi

    # Add user to required groups for VM management
    local vm_groups=("libvirt" "kvm")
    for group in "${vm_groups[@]}"; do
        if getent group "$group" > /dev/null; then
            if ! id -nG "${ADMIN_USER}" | grep -qw "$group"; then
                usermod -aG "$group" "${ADMIN_USER}"
                log "Added ${ADMIN_USER} to group ${group}."
            fi
        fi
    done

    # Set up SSH key authentication
    local ssh_dir="/home/${ADMIN_USER}/.ssh"
    local auth_keys_file="${ssh_dir}/authorized_keys"
    
    mkdir -p "${ssh_dir}"
    # Write the key from settings.conf to the authorized_keys file
    echo "${ADMIN_USER_SSH_KEY}" > "${auth_keys_file}"

    # Set secure permissions
    chmod 700 "${ssh_dir}"
    chmod 600 "${auth_keys_file}"
    chown -R "${ADMIN_USER}:${ADMIN_USER}" "${ssh_dir}"
    log "SSH public key installed and permissions set for ${ADMIN_USER}."

    # Create sudo rule for VM management commands
    local sudoers_file="/etc/sudoers.d/99-vm-admin"
    print_message "Creating sudo rules for ${ADMIN_USER}..."
    cat > "${sudoers_file}" <<-EOF
	# Sudo privileges for the VM administrator (${ADMIN_USER})
	# Allows management of VMs and firewall without a password.
	# This is a security trade-off for convenience. For higher security,
	# remove NOPASSWD and require password entry for sudo commands.
	${ADMIN_USER} ALL=(ALL) NOPASSWD: /usr/bin/virsh, /usr/bin/virt-*, /usr/sbin/ufw
	EOF
    chmod 440 "${sudoers_file}"
    log "Sudo rules created at ${sudoers_file}."

    print_message "Admin user ${ADMIN_USER} configured successfully for key-based login."
}
