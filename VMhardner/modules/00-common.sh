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

# Function to modify a config setting for libvirt (uses = syntax)
configure_libvirt_setting() {
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
    
    # For libvirt configs, format the line properly with equals sign
    local formatted_line="${parameter} = ${value}"
    
    # Check if parameter exists (commented or not)
    if grep -q "^${parameter}\|^#.*${parameter}" "$file" 2>/dev/null; then
        # Parameter exists, update it
        sed -i "s/^#*${parameter}.*/${formatted_line}/" "$file"
        log "Updated ${parameter} in $file"
    else
        # Parameter doesn't exist, add it
        if [ -n "$comment" ]; then
            echo -e "\n# $comment" >> "$file"
        fi
        echo "${formatted_line}" >> "$file"
        log "Added ${parameter} to $file"
    fi
}

# Original function for other config files (SSH, etc)
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
    
    # Escape special characters in the value for sed
    local escaped_value=$(printf '%s\n' "$value" | sed 's/[[\.*^$()+?{|]/\\&/g')
    
    # Check if parameter exists (commented or not)
    if grep -q "^${parameter}\|^#.*${parameter}" "$file" 2>/dev/null; then
        # Parameter exists (maybe commented), update or uncomment it
        if grep -q "^${parameter}" "$file" 2>/dev/null; then
            # Parameter is active, check if value needs updating
            current_line=$(grep "^${parameter}" "$file" | head -1)
            if [ "$current_line" != "${parameter} ${value}" ]; then
                # Use a temporary file for safer editing
                grep -v "^${parameter}" "$file" > "${file}.tmp"
                echo "${parameter} ${value}" >> "${file}.tmp"
                mv "${file}.tmp" "$file"
                log "Updated $parameter to $value in $file"
            else
                log "Parameter $parameter already set to $value in $file"
            fi
        else
            # Parameter is commented, uncomment and set it
            grep -v "^#.*${parameter}" "$file" > "${file}.tmp"
            echo "${parameter} ${value}" >> "${file}.tmp"
            mv "${file}.tmp" "$file"
            log "Uncommented and set $parameter to $value in $file"
        fi
    else
        # Parameter doesn't exist, add it
        if [ -n "$comment" ]; then
            echo -e "\n# $comment" >> "$file"
        fi
        echo "${parameter} ${value}" >> "$file"
        log "Added $parameter with value $value to $file"
    fi
}

# Alternative function for auditd settings
sed_if_not_exists() {
    local param="$1"
    local value="$2"
    local file="$3"
    
    if grep -q "^${param}" "$file" 2>/dev/null; then
        # Parameter exists, update it
        grep -v "^${param}" "$file" > "${file}.tmp"
        echo "$value" >> "${file}.tmp"
        mv "${file}.tmp" "$file"
    else
        # Parameter doesn't exist, add it
        echo "$value" >> "$file"
    fi
}

# Initialize the log
init_log
