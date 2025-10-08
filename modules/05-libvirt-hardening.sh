#!/bin/bash
# =================================================================
# VM Host Hardener v2.0 - Module 05: Libvirt/QEMU Hardening
#
# Description: This module applies security best practices to the
# libvirt daemon and QEMU configuration files to enhance VM isolation
# and protect the host.
# =================================================================

run_libvirt_hardening() {
    print_header "Module 05: Hardening Libvirt and QEMU"
    log "Starting libvirt/QEMU hardening."

    harden_libvirtd_conf
    harden_qemu_conf

    # Check if either configuration file has changed before restarting
    local libvirtd_conf="/etc/libvirt/libvirtd.conf"
    local qemu_conf="/etc/libvirt/qemu.conf"
    
    if ! diff -q "${libvirtd_conf}" "${libvirtd_conf}.bak" &>/dev/null || \
       ! diff -q "${qemu_conf}" "${qemu_conf}.bak" &>/dev/null; then
        restart_service "libvirtd"
    else
        print_message "Libvirt/QEMU configuration is already hardened. No restart needed."
        log "Libvirt/QEMU configuration unchanged."
    fi

    log "Libvirt/QEMU hardening completed."
}

# Secures the main libvirt daemon configuration file.
harden_libvirtd_conf() {
    local conf_file="/etc/libvirt/libvirtd.conf"
    print_message "Hardening libvirt daemon config (${conf_file})..."

    # Use polkit for read-write access, disable insecure read-only socket
    configure_setting "auth_unix_ro" '"none"' "${conf_file}" " = "
    configure_setting "auth_unix_rw" '"polkit"' "${conf_file}" " = "

    # Set secure permissions for libvirt sockets
    configure_setting "unix_sock_group" '"libvirt"' "${conf_file}" " = "
    configure_setting "unix_sock_ro_perms" '"0770"' "${conf_file}" " = "
    configure_setting "unix_sock_rw_perms" '"0770"' "${conf_file}" " = "
    configure_setting "unix_sock_admin_perms" '"0700"' "${conf_file}" " = "
    
    log "Applied settings to ${conf_file}."
}

# Secures the QEMU driver configuration file.
harden_qemu_conf() {
    local conf_file="/etc/libvirt/qemu.conf"
    print_message "Hardening QEMU driver config (${conf_file})..."

    # Use AppArmor for mandatory access control
    configure_setting "security_driver" "\"${QEMU_SECURITY_DRIVER}\"" "${conf_file}" " = "

    # Run VMs as a dedicated, non-privileged user (qemu)
    configure_setting "user" '"libvirt-qemu"' "${conf_file}" " = "
    configure_setting "group" '"libvirt-qemu"' "${conf_file}" " = "
    
    # Enable dynamic ownership for better permissions management
    configure_setting "dynamic_ownership" "1" "${conf_file}" " = "

    # Enable seccomp sandboxing to restrict syscalls available to the VM process
    configure_setting "seccomp_sandbox" "1" "${conf_file}" " = "

    # Drop capabilities to limit the VM process's privileges
    configure_setting "clear_emulator_capabilities" "1" "${conf_file}" " = "

    log "Applied settings to ${conf_file}."
}
