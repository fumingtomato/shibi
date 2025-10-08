#!/bin/bash
# =================================================================
# VM Host Hardener v2.0 - Module 06: Kernel Hardening
#
# Description: This module applies security-focused kernel parameters
# via sysctl to enhance the host's resilience against various attacks.
# =================================================================

run_kernel_hardening() {
    if [ "${ENABLE_KERNEL_HARDENING}" != "true" ]; then
        print_message "Skipping kernel hardening as per settings."
        log "Kernel hardening skipped (ENABLE_KERNEL_HARDENING is not 'true')."
        return
    fi

    print_header "Module 06: Applying Kernel Hardening"
    log "Starting kernel hardening."

    apply_sysctl_settings
    set_resource_limits

    log "Kernel hardening completed."
}

# Creates a dedicated sysctl config file with security parameters.
apply_sysctl_settings() {
    local conf_file="/etc/sysctl.d/95-vm-host-hardening.conf"
    print_message "Applying kernel security settings via sysctl..."

    cat > "${conf_file}" <<-EOF
	# =================================================================
	# Kernel Security Settings for VM Host (Applied by Hardener Script)
	# =================================================================

	# --- Network Security ---
	# Protect against IP spoofing
	net.ipv4.conf.all.rp_filter = 1
	net.ipv4.conf.default.rp_filter = 1

	# Ignore ICMP redirects (potential man-in-the-middle)
	net.ipv4.conf.all.accept_redirects = 0
	net.ipv4.conf.default.accept_redirects = 0
	net.ipv6.conf.all.accept_redirects = 0
	net.ipv6.conf.default.accept_redirects = 0

	# Ignore source-routed packets (potential man-in-the-middle)
	net.ipv4.conf.all.accept_source_route = 0
	net.ipv4.conf.default.accept_source_route = 0
	net.ipv6.conf.all.accept_source_route = 0
	net.ipv6.conf.default.accept_source_route = 0

	# Enable TCP SYN cookies to help prevent SYN flood attacks
	net.ipv4.tcp_syncookies = 1
	net.ipv4.tcp_max_syn_backlog = 2048
	net.ipv4.tcp_synack_retries = 2
	net.ipv4.tcp_syn_retries = 5

	# Do not act as a router
	net.ipv4.ip_forward = 0
	net.ipv6.conf.all.forwarding = 0

	# --- Memory and Process Security ---
	# Randomize memory space layout (ASLR)
	kernel.randomize_va_space = 2

	# Restrict access to kernel pointers in /proc
	kernel.kptr_restrict = 2

	# Disable the magic SysRq key
	kernel.sysrq = 0

	# Restrict access to dmesg (kernel log buffer)
	kernel.dmesg_restrict = 1

	# Control ptrace scope to prevent unauthorized process inspection
	kernel.yama.ptrace_scope = 1

	# Prevent users from creating suid-dumpable processes
	fs.suid_dumpable = 0

	# Set a minimum address for mmap to prevent null-pointer dereference attacks
	vm.mmap_min_addr = 65536
	EOF

    # Apply the settings immediately
    sysctl -p "${conf_file}" >/dev/null
    log "Applied kernel parameters from ${conf_file}."
    print_message "Kernel parameters have been applied."
}

# Sets secure default resource limits for users.
set_resource_limits() {
    local conf_file="/etc/security/limits.d/95-vm-host-hardening.conf"
    print_message "Setting secure resource limits..."

    cat > "${conf_file}" <<-EOF
	# Default resource limits for system security (Applied by Hardener Script)
	# Prevent resource exhaustion attacks like fork bombs.
	*    hard   core    0
	*    hard   nproc   10000
	*    soft   nproc   10000
	*    hard   nofile  65536
	*    soft   nofile  4096
	EOF
    
    log "Configured resource limits in ${conf_file}."
    print_message "System resource limits have been configured."
}
