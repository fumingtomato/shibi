#!/bin/bash

# =================================================================
# MULTI-IP BULK MAIL SERVER INSTALLER - MAIN SCRIPT - FIXED VERSION
# Enhanced module loading, error recovery, and debugging capabilities
# Version: 16.0.1
# Fixed: Module name mappings, error handling, and dependency checking
# =================================================================

set -o pipefail  # Exit on pipe failure
set -E           # ERR trap is inherited by shell functions

# Configuration
REPO_URL="https://raw.githubusercontent.com/fumingtomato/shibi/main/MultiIPMail"
MODULES_DIR="./modules"
LOG_FILE="/var/log/mail-installer-$(date +%Y%m%d-%H%M%S).log"
DEBUG=${DEBUG:-false}
MAX_DOWNLOAD_RETRIES=3
MODULE_LOAD_TIMEOUT=30

# Color codes
GREEN='\033[38;5;208m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[1;33m'
NC='\033[0m'

# Initialize log file
mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"
chmod 640 "$LOG_FILE"

# Basic output functions (before module loading)
print_message() {
    echo -e "${GREEN}$1${NC}"
    log_message "[INFO] $1"
}

print_error() {
    echo -e "${RED}$1${NC}" >&2
    log_message "[ERROR] $1"
}

print_warning() {
    echo -e "${YELLOW}$1${NC}"
    log_message "[WARNING] $1"
}

print_header() {
    echo -e "${BLUE}==================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}==================================================${NC}"
    log_message "[HEADER] $1"
}

print_debug() {
    if [ "$DEBUG" = true ]; then
        echo -e "[DEBUG] $1"
    fi
    log_message "[DEBUG] $1"
}

log_message() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

# Enhanced error handling
handle_error() {
    local line_no=$1
    local bash_lineno=$2
    local last_command=$3
    local error_code=$4
    
    print_error "Error occurred in script!"
    print_error "  Line: $line_no"
    print_error "  Command: $last_command"
    print_error "  Exit Code: $error_code"
    log_message "FATAL ERROR at line $line_no: $last_command (exit code: $error_code)"
    
    # Save error state for recovery
    cat > /tmp/installer_error_state <<EOF
ERROR_LINE=$line_no
ERROR_COMMAND=$last_command
ERROR_CODE=$error_code
ERROR_TIME=$(date -u '+%Y-%m-%d %H:%M:%S')
ERROR_MODULE=${CURRENT_MODULE:-unknown}
EOF
    
    print_error ""
    print_error "Installation failed! Error details saved to /tmp/installer_error_state"
    print_error "Check log file: $LOG_FILE"
    print_error ""
    print_error "You can try:"
    print_error "  1. Fix the issue and run the installer again"
    print_error "  2. Run with DEBUG=true for more details"
    print_error "  3. Check GitHub issues at: https://github.com/fumingtomato/shibi/issues"
    
    cleanup_on_exit
    exit 1
}

# Set error trap
trap 'handle_error ${LINENO} ${BASH_LINENO} "$BASH_COMMAND" $?' ERR

# Download module with retry logic and validation
download_module() {
    local module_name=$1
    local github_name=${2:-$module_name}
    local attempt=1
    
    CURRENT_MODULE="$module_name"
    
    while [ $attempt -le $MAX_DOWNLOAD_RETRIES ]; do
        print_debug "Downloading $module_name (attempt $attempt/$MAX_DOWNLOAD_RETRIES)..."
        
        local temp_file=$(mktemp)
        local url="${REPO_URL}/modules/${github_name}.sh"
        
        # Download with timeout and proper error handling
        if curl -fsSL --connect-timeout 10 --max-time 30 \
                -o "$temp_file" "$url" 2>/dev/null; then
            
            # Validate downloaded file
            if [ -s "$temp_file" ]; then
                # Check if it's actually a shell script
                if head -1 "$temp_file" | grep -q '^#!/bin/bash'; then
                    mv "$temp_file" "${MODULES_DIR}/${module_name}.sh"
                    chmod +x "${MODULES_DIR}/${module_name}.sh"
                    print_debug "✓ Successfully downloaded $module_name"
                    return 0
                else
                    print_warning "Downloaded file is not a valid shell script: $module_name"
                    rm -f "$temp_file"
                fi
            else
                print_warning "Downloaded empty file for $module_name"
                rm -f "$temp_file"
            fi
        else
            print_debug "Failed to download $module_name (attempt $attempt)"
            rm -f "$temp_file"
        fi
        
        attempt=$((attempt + 1))
        if [ $attempt -le $MAX_DOWNLOAD_RETRIES ]; then
            sleep 2
        fi
    done
    
    print_error "Failed to download $module_name after $MAX_DOWNLOAD_RETRIES attempts"
    return 1
}

# Safe source with validation and timeout
safe_source() {
    local module_file=$1
    local module_name=$(basename "$module_file" .sh)
    
    CURRENT_MODULE="$module_name"
    
    if [ ! -f "$module_file" ]; then
        print_error "Module file not found: $module_file"
        return 1
    fi
    
    # Validate syntax before sourcing
    if ! bash -n "$module_file" 2>/dev/null; then
        print_error "Syntax error in module: $module_file"
        return 1
    fi
    
    print_debug "Loading module: $module_name"
    
    # Source the module
    source "$module_file"
    
    if [ $? -eq 0 ]; then
        print_debug "✓ Successfully loaded $module_name"
        return 0
    else
        print_error "Failed to load module: $module_name"
        return 1
    fi
}

# Check for required commands
check_requirements() {
    local missing_commands=()
    local required_commands=("curl" "wget" "unzip" "systemctl" "git" "bash" "sed" "awk" "grep")
    
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            missing_commands+=("$cmd")
        fi
    done
    
    if [ ${#missing_commands[@]} -gt 0 ]; then
        print_error "Missing required commands: ${missing_commands[*]}"
        print_message "Installing missing dependencies..."
        apt-get update || true
        apt-get install -y curl wget unzip systemd git sed gawk grep || true
    fi
}

# Create module directory
create_module_directory() {
    if [ ! -d "$MODULES_DIR" ]; then
        mkdir -p "$MODULES_DIR"
        print_debug "Created modules directory: $MODULES_DIR"
    fi
}

# Download all modules with progress indication
download_all_modules() {
    print_header "Downloading Installation Modules"
    
    # Define all modules with their GitHub names (FIXED mappings)
    declare -A modules=(
        ["core_functions"]="core-functions"
        ["packages_system"]="packages-system"
        ["mysql_dovecot"]="mysql-dovecot"
        ["postfix_setup"]="postfix-setup"
        ["multiip_config"]="multiip-config"
        ["dkim_spf"]="dkim-spf"
        ["dns_ssl"]="dns-ssl"
        ["sticky_ip"]="sticky-ip"
        ["monitoring_scripts"]="monitoring-scripts"
        ["security_hardening"]="security-hardening"
        ["utility_scripts"]="utility-scripts"
        ["mailwizz_integration"]="mailwizz-integration"
        ["main_installer_part2"]="main-installer-part2"
        ["main_installer"]="main-installer"
    )
    
    local total_modules=${#modules[@]}
    local current=0
    local failed_modules=()
    
    for module_name in "${!modules[@]}"; do
        current=$((current + 1))
        github_name="${modules[$module_name]}"
        
        echo -n "[$current/$total_modules] Downloading $module_name... "
        
        if download_module "$module_name" "$github_name"; then
            echo "✓"
        else
            echo "✗"
            failed_modules+=("$module_name")
        fi
    done
    
    if [ ${#failed_modules[@]} -gt 0 ]; then
        print_error "Failed to download modules: ${failed_modules[*]}"
        print_message "Attempting alternative download method..."
        
        # Try alternative download from GitHub archive
        for module in "${failed_modules[@]}"; do
            github_name="${modules[$module]}"
            if download_module_alternative "$module" "$github_name"; then
                # Remove from failed list if successful
                failed_modules=("${failed_modules[@]/$module}")
            fi
        done
        
        # Check if any modules still failed
        failed_modules=($(echo "${failed_modules[@]}" | tr ' ' '\n' | grep -v '^$' | tr '\n' ' '))
        if [ ${#failed_modules[@]} -gt 0 ]; then
            print_error "Could not download required modules: ${failed_modules[*]}"
            return 1
        fi
    fi
    
    print_message "All modules downloaded successfully"
    return 0
}

# Alternative download method using GitHub archive
download_module_alternative() {
    local module_name=$1
    local github_name=$2
    
    print_debug "Trying alternative download for $module_name..."
    
    local temp_dir=$(mktemp -d)
    cd "$temp_dir"
    
    # Download entire repository as archive
    if wget -q "https://github.com/fumingtomato/shibi/archive/refs/heads/main.zip" -O repo.zip; then
        unzip -q repo.zip
        
        # Find and copy the module
        local module_file="shibi-main/New_PfMIP/modules/${github_name}.sh"
        if [ -f "$module_file" ]; then
            cp "$module_file" "${MODULES_DIR}/${module_name}.sh"
            chmod +x "${MODULES_DIR}/${module_name}.sh"
            cd - > /dev/null
            rm -rf "$temp_dir"
            print_debug "✓ Successfully downloaded $module_name via alternative method"
            return 0
        fi
    fi
    
    cd - > /dev/null
    rm -rf "$temp_dir"
    return 1
}

# Load all modules with dependency order
load_all_modules() {
    print_header "Loading Installation Modules"
    
    # Define loading order (dependencies first) - FIXED ORDER
    local load_order=(
        "core_functions"
        "packages_system"
        "mysql_dovecot"
        "multiip_config"
        "postfix_setup"
        "dkim_spf"
        "dns_ssl"
        "sticky_ip"
        "monitoring_scripts"
        "security_hardening"
        "utility_scripts"
        "mailwizz_integration"
        "main_installer_part2"  # Load part2 BEFORE main_installer
        "main_installer"
    )
    
    local failed_modules=()
    
    for module in "${load_order[@]}"; do
        local module_file="${MODULES_DIR}/${module}.sh"
        
        if [ -f "$module_file" ]; then
            echo -n "Loading $module... "
            if safe_source "$module_file"; then
                echo "✓"
            else
                echo "✗"
                failed_modules+=("$module")
            fi
        else
            print_error "Module file not found: $module_file"
            failed_modules+=("$module")
        fi
    done
    
    if [ ${#failed_modules[@]} -gt 0 ]; then
        print_error "Failed to load modules: ${failed_modules[*]}"
        return 1
    fi
    
    # Verify critical functions are available
    local critical_functions=(
        "check_root"
        "setup_mysql"
        "setup_postfix_multi_ip"
        "first_time_installation_multi_ip"
        "main_menu"
        "fix_mysql_config"
        "create_add_ip_script"
    )
    
    print_debug "Verifying critical functions..."
    local missing_functions=()
    for func in "${critical_functions[@]}"; do
        if ! type "$func" &>/dev/null 2>&1; then
            print_warning "Function not loaded: $func"
            missing_functions+=("$func")
        fi
    done
    
    if [ ${#missing_functions[@]} -gt 0 ]; then
        print_error "Critical functions not loaded: ${missing_functions[*]}"
        return 1
    fi
    
    print_message "All modules loaded successfully"
    return 0
}

# Cleanup function
cleanup_on_exit() {
    print_debug "Performing cleanup..."
    
    # Save installation state if needed
    if [ -f /root/.installer_progress ]; then
        cp /root/.installer_progress /root/.installer_progress.backup 2>/dev/null || true
    fi
    
    # Clear temporary files
    rm -f /tmp/installer_*.tmp 2>/dev/null || true
    
    print_debug "Cleanup completed"
}

# Set cleanup trap
trap cleanup_on_exit EXIT

# Self-update check
check_for_updates() {
    print_debug "Checking for installer updates..."
    
    local current_version="16.0.1"
    local latest_version_url="${REPO_URL}/version.txt"
    local latest_version=$(curl -fsSL "$latest_version_url" 2>/dev/null || echo "$current_version")
    
    if [ "$latest_version" != "$current_version" ]; then
        print_warning "New version available: $latest_version (current: $current_version)"
        read -p "Update installer before continuing? (y/n): " update_choice
        if [[ "$update_choice" == "y" || "$update_choice" == "Y" ]]; then
            update_installer
            exec "$0" "$@"  # Restart with new version
        fi
    else
        print_debug "Installer is up to date (version: $current_version)"
    fi
}

# Main execution
main() {
    print_header "Multi-IP Bulk Mail Server Installer"
    print_message "Version: 16.0.1"
    print_message "Repository: https://github.com/fumingtomato/shibi"
    print_message ""
    
    # Check if running as root
    if [ "$(id -u)" != "0" ]; then
        print_error "This script must be run as root or with sudo privileges"
        echo "Please run: sudo $0"
        exit 1
    fi
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --debug)
                DEBUG=true
                print_message "Debug mode enabled"
                ;;
            --help|-h)
                echo "Usage: $0 [OPTIONS]"
                echo "Options:"
                echo "  --debug    Enable debug output"
                echo "  --help     Show this help message"
                exit 0
                ;;
            *)
                print_warning "Unknown option: $1"
                ;;
        esac
        shift
    done
    
    # Check system requirements
    check_requirements
    
    # Create module directory
    create_module_directory
    
    # Download all required modules
    if ! download_all_modules; then
        print_error "Failed to download required modules"
        print_error "Please check your internet connection and try again"
        exit 1
    fi
    
    # Load all modules
    if ! load_all_modules; then
        print_error "Failed to load required modules"
        print_error "Installation cannot continue"
        exit 1
    fi
    
    # Verify we're ready to proceed
    if type main_menu &>/dev/null 2>&1; then
        print_message "All modules loaded successfully"
        print_message "Starting installation menu..."
        echo ""
        
        # Initialize MySQL configuration early to prevent warnings
        if type init_mysql_postfix_config &>/dev/null 2>&1; then
            init_mysql_postfix_config
        fi
        
        # Call the main menu
        main_menu
    else
        print_error "Main menu function not found"
        print_error "Module loading may have failed"
        exit 1
    fi
}

# Check if script is being sourced or executed
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    # Script is being executed
    main "$@"
else
    # Script is being sourced
    print_debug "Script sourced - modules loaded but not executing main menu"
fi
