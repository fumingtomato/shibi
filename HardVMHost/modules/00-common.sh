#!/bin/bash
# =================================================================
# VM Host Hardener v2.0 - Common Functions
#
# This module is sourced by the main script and provides common
# utility functions for logging, configuration management, and
# service control to all other modules.
# =================================================================

# --- Configuration Loading ---

# Loads settings from the config file. Exits if critical settings are missing.
load_config() {
    local config_file="${CONFIG_DIR}/settings.conf"
    if [ ! -f "$config_file" ]; then
        print_error "FATAL: Configuration file not found at ${config_file}."
        exit 1
    fi

    # Source the config file, ignoring comments and empty lines.
    # shellcheck source=/dev/null
    source <(grep -v -e '^#' -e '^[[:space:]]*$' "$config_file")

    # Validate critical settings
    if [ "${CREATE_ADMIN_USER}" == "true" ] && [ "${ADMIN_USER_SSH_KEY}" == "<PASTE YOUR PUBLIC SSH KEY HERE>" ]; then
        print_error "FATAL: CREATE_ADMIN_USER is true, but ADMIN_USER_SSH_KEY is not set in settings.conf."
        exit 1
    fi
    log "Configuration loaded successfully."
}

# --- Logging ---

# Initializes the log file with a header.
init_log() {
    # Ensure the log directory exists
    mkdir -p "$(dirname "${LOG_FILE}")"
    # Create or truncate the log file and add a header
    cat > "$LOG_FILE" <<-EOF
	# =================================================================
	# VM Host Hardener v${VERSION} - Log File
	# Started at: $(date)
	# Hostname: $(hostname)
	# OS: $(lsb_release -ds 2>/dev/null || cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '"')
	# Kernel: $(uname -r)
	# =================================================================
	EOF
}

# Appends a timestamped message to the log file.
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

# --- System Utilities ---

# Checks if a command is available in the system's PATH.
command_exists() {
    command -v "$1" &>/dev/null
}

# Checks if a Debian package is installed.
package_installed() {
    dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "install ok installed"
}

# Restarts a systemd service and verifies it became active.
restart_service() {
    local service_name="$1"
    print_message "Restarting ${service_name} service..."
    log "Attempting to restart ${service_name}."
    systemctl restart "$service_name"
    # Wait a moment for the service to initialize
    sleep 2
    if systemctl is-active --quiet "$service_name"; then
        log "${service_name} restarted and is active."
        print_message "${service_name} restarted successfully."
    else
        print_error "FATAL: Failed to restart ${service_name}. Check journalctl -u ${service_name} for details."
        log "FATAL: ${service_name} failed to restart."
        exit 1
    fi
}

# --- Configuration File Management ---

# A robust function to modify settings in key-value configuration files.
# Handles commented-out lines, existing values, and adds new lines if needed.
# Usage: configure_setting "key" "value" "filepath"
configure_setting() {
    local key="$1"
    local value="$2"
    local file="$3"
    local separator="${4:- }" # Default separator is a space

    # Create a backup if one doesn't already exist.
    if [ ! -f "${file}.bak" ]; then
        cp "$file" "${file}.bak"
        log "Created backup of ${file} at ${file}.bak"
    fi

    # Escape special characters for sed
    local sed_value
    sed_value=$(printf '%s\n' "$value" | sed -e 's/[\/&]/\\&/g')

    local line="${key}${separator}${value}"

    # If the exact line already exists, do nothing.
    if grep -q "^${line}$" "$file"; then
        log "OK: '${key}' is already set to '${value}' in ${file}."
        return
    fi

    # If the key exists (commented or not), replace the line.
    if grep -q -E "^#?[[:space:]]*${key}" "$file"; then
        sed -i -E "s/^[#[:space:]]*${key}.*/${line}/" "$file"
        log "MODIFIED: Set '${key}' to '${value}' in ${file}."
    else
        # If the key doesn't exist, add it to the end of the file.
        echo "${line}" >> "$file"
        log "ADDED: '${key}${separator}${value}' to ${file}."
    fi
}
