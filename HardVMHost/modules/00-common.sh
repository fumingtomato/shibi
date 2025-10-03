#!/bin/bash
# =================================================================
# VM Host Hardener v2.0.1 - Common Functions (Corrected)
# =================================================================

# --- Version Info ---
readonly VERSION="2.0.1"

# --- Color Codes ---
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly RED='\033[0;31m'
readonly NC='\033[0m'

# --- Output & Logging ---
# These functions were missing and are required by the main script.
print_header() {
    echo -e "${YELLOW}==================================================${NC}"
    echo -e "${YELLOW} $1 ${NC}"
    echo -e "${YELLOW}==================================================${NC}"
}
print_message() { echo -e "${GREEN}$1${NC}"; }
print_warning() { echo -e "${YELLOW}$1${NC}"; }
print_error() { echo -e "${RED}$1${NC}"; }

log() {
    # This function already existed.
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

init_log() {
    mkdir -p "$(dirname "${LOG_FILE}")"
    cat > "$LOG_FILE" <<-EOF
	# VM Host Hardener v${VERSION} - Log File
	# Started at: $(date)
	# =================================================================
	EOF
}

# --- Module Execution ---
# This function was missing. It's needed to run modules 01-10.
run_module() {
    local module_file="${INSTALL_DIR}/modules/$1"
    if [ -f "$module_file" ]; then
        source "$module_file"
        # Assumes each module has a run_ function (e.g., run_prerequisites)
        local run_function_name="run_$(basename "$1" .sh | sed 's/^[0-9]*-//')"
        if command -v "$run_function_name" &>/dev/null; then
            "$run_function_name"
        else
            print_error "FATAL: Run function '${run_function_name}' not found in module '$1'."
            exit 1
        fi
    else
        print_error "FATAL: Module file '$1' not found at '${module_file}'."
        exit 1
    fi
}


# --- Configuration Loading ---
load_config() {
    local config_file="${INSTALL_DIR}/config/settings.conf"
    if [ ! -f "$config_file" ]; then
        print_error "FATAL: Configuration file not found at ${config_file}."
        exit 1
    fi
    source <(grep -v -e '^#' -e '^[[:space:]]*$' "$config_file")
    if [ "${CREATE_ADMIN_USER}" == "true" ] && [ "${ADMIN_USER_SSH_KEY}" == "<PASTE YOUR PUBLIC SSH KEY HERE>" ]; then
        print_error "FATAL: CREATE_ADMIN_USER is true, but ADMIN_USER_SSH_KEY is not set in settings.conf."
        exit 1
    fi
    log "Configuration loaded successfully."
}

# --- System Utilities ---
command_exists() { command -v "$1" &>/dev/null; }
package_installed() { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "install ok installed"; }

restart_service() {
    local service_name="$1"
    print_message "Restarting ${service_name} service..."
    log "Attempting to restart ${service_name}."
    systemctl restart "$service_name"
    sleep 2
    if systemctl is-active --quiet "$service_name"; then
        log "${service_name} restarted and is active."
    else
        print_error "FATAL: Failed to restart ${service_name}."
        log "FATAL: ${service_name} failed to restart."
        exit 1
    fi
}

# --- Configuration File Management ---
configure_setting() {
    local key="$1"; local value="$2"; local file="$3"; local separator="${4:- }"
    if [ ! -f "${file}.bak" ]; then cp "$file" "${file}.bak"; fi
    local sed_value; sed_value=$(printf '%s\n' "$value" | sed -e 's/[\/&]/\\&/g')
    local line="${key}${separator}${value}"
    if grep -q "^${line}$" "$file"; then return; fi
    if grep -q -E "^#?[[:space:]]*${key}" "$file"; then
        sed -i -E "s/^[#[:space:]]*${key}.*/${line}/" "$file"
    else
        echo "${line}" >> "$file"
    fi
    log "Set '${key}' to '${value}' in ${file}."
}
