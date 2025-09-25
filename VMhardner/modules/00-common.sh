#!/bin/bash
# =================================================================
# Common functions and variables for VM Host Hardening
# =================================================================

# Make sure the script is idempotent
SCRIPT_IDEMPOTENT=true

# Global variables
TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
LOG_FILE="/var/log/vm-host-hardening.log"
REPORT_FILE="/root/vm-host-security-report.txt"

# Virtual machine info
VM_LIST=""
VM_STORAGE_DIR=""
PUBLIC_INTERFACES=()
LIBVIRT_NETWORKS=""

# Source the settings file if it exists
if [ -f "${CONFIG_DIR}/settings.conf" ]; then
    source "${CONFIG_DIR}/settings.conf"
else
    print_warning "Settings file not found. Using defaults."
fi

# Initialize log file
init_log() {
    mkdir -p $(dirname "$LOG_FILE")
    echo "===== VM Host Hardening Script v$VERSION - Started at $(date) =====" > "$LOG_FILE"
    echo "Hostname: $(hostname)" >> "$LOG_FILE"
    echo "OS: $(lsb_release -ds 2>/dev/null || cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"')" >> "$LOG_FILE"
    echo "Kernel: $(uname -r)" >> "$LOG_FILE"
    echo "===================================================" >> "$LOG_FILE"
}

# Log a message
log() {
    echo "$(date +"%Y-%m-%d %H:%M:%S"): $1" >> "$LOG_FILE"
}

# Function to check if a command exists
command_exists() {
    command -v "$1" &> /dev/null
}

# Function to check if a package is installed
package_installed() {
    dpkg -l "$1" &> /dev/null
}

# Function to modify a config setting if it doesn't match
configure_setting() {
    local file="$1"
    local parameter="$2"
    local value="$3"
    local comment="${4:-}"
    
    # Make a backup if it doesn't exist
    if [ ! -f "${file}.bak" ] && [ -f "$file" ]; then
        cp "$file" "${file}.bak"
        log "Created backup of $file"
    fi
    
    # Create file if it doesn't exist
    if [ ! -f "$file" ]; then
        touch "$file"
    fi
    
    # If the parameter doesn't exist or is commented, add/uncomment it
    if ! grep -q "^${parameter}" "$file" 2>/dev/null; then
        if grep -q "^#[[:space:]]*${parameter}" "$file" 2>/dev/null; then
            # Uncomment the parameter - use | as delimiter to avoid conflicts with quotes
            sed -i "\|^#[[:space:]]*${parameter}|s|.*|${parameter} ${value}|" "$file"
            log "Uncommented and set $parameter to $value in $file"
        else
            # Add the parameter
            if [ -n "$comment" ]; then
                echo -e "\n# $comment" >> "$file"
            fi
            echo "${parameter} ${value}" >> "$file"
            log "Added $parameter with value $value to $file"
        fi
    else
        # If the parameter exists but has a different value, update it
        current_value=$(grep "^${parameter}" "$file" | sed "s|^${parameter}[[:space:]]*||")
        if [ "$current_value" != "$value" ]; then
            # Use | as delimiter to avoid conflicts with quotes in values
            sed -i "\|^${parameter}|s|.*|${parameter} ${value}|" "$file"
            log "Updated $parameter to $value in $file (was $current_value)"
        else
            log "Parameter $parameter already set to $value in $file"
        fi
    fi
}

# Initialize the log
init_log
