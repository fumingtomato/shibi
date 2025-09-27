#!/bin/bash

# =================================================================
# Multi-IP Bulk Mail Server Master Installer - FIXED VERSION
# Version: 16.1.0
# Repository: https://github.com/fumingtomato/shibi
# Fixed: Module loading, naming consistency, error handling
# =================================================================

set -e

INSTALLER_NAME="Multi-IP Bulk Mail Server Installer"
INSTALLER_VERSION="16.1.0"
GITHUB_USER="fumingtomato"
GITHUB_REPO="shibi"
GITHUB_BRANCH="main"
BASE_URL="https://raw.githubusercontent.com/$GITHUB_USER/$GITHUB_REPO/$GITHUB_BRANCH/New_PfMIP"
INSTALLER_DIR="/tmp/multiip-installer-$$"

# Export version for use in modules
export INSTALLER_VERSION
export INSTALLER_NAME

# Colors
RED='\033[0;31m'
GREEN='\033[38;5;208m'
YELLOW='\033[1;33m'
BLUE='\033[1;33m'
NC='\033[0m'

# Simple print functions for bootstrap
print_message() {
    echo -e "${GREEN}$1${NC}"
}

print_error() {
    echo -e "${RED}$1${NC}"
}

print_warning() {
    echo -e "${YELLOW}$1${NC}"
}

print_header() {
    echo -e "${BLUE}==================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}==================================================${NC}"
}

print_debug() {
    if [ "$DEBUG" = true ]; then
        echo -e "[DEBUG] $1"
    fi
}

# Export print functions immediately
export -f print_message print_error print_warning print_header print_debug

# Function to handle errors
handle_error() {
    local line_no=$1
    local bash_lineno=$2
    local last_command=$3
    
    print_error "An error occurred:"
    print_error "  Line: $line_no"
    print_error "  Command: $last_command"
    print_error "Installation failed. Cleaning up..."
    
    # Cleanup
    cd /
    rm -rf "$INSTALLER_DIR"
    
    print_error "Please check the logs and try again."
    print_error "If this persists, report issue at: https://github.com/$GITHUB_USER/$GITHUB_REPO/issues"
    exit 1
}

# Set error trap
trap 'handle_error $LINENO $BASH_LINENO "$BASH_COMMAND"' ERR

# Check if running as root
if [ "$(id -u)" != "0" ]; then
    print_error "This script must be run as root or with sudo"
    exit 1
fi

print_header "$INSTALLER_NAME v$INSTALLER_VERSION"
print_message "Initializing installation process..."
print_message "Repository: https://github.com/$GITHUB_USER/$GITHUB_REPO"
print_message ""

# Check internet connectivity
print_message "Checking internet connectivity..."
if ! ping -c 1 google.com &>/dev/null && ! ping -c 1 8.8.8.8 &>/dev/null; then
    print_error "No internet connection detected. Please check your network."
    exit 1
fi

# Install required tools if missing
print_message "Checking required tools..."
if ! command -v wget &> /dev/null; then
    print_message "Installing wget..."
    apt-get update && apt-get install -y wget
fi

if ! command -v curl &> /dev/null; then
    print_message "Installing curl..."
    apt-get update && apt-get install -y curl
fi

# Create temporary directory
print_message "Creating temporary installation directory..."
mkdir -p "$INSTALLER_DIR"
cd "$INSTALLER_DIR"

# Function to download a module with better validation
download_module() {
    local module_name=$1
    local file_name=$2
    local max_attempts=3
    local attempt=1
    
    # Use the provided file name or default to module name
    local target_file="${file_name:-$module_name}"
    
    while [ $attempt -le $max_attempts ]; do
        print_message "Downloading $module_name (attempt $attempt/$max_attempts)..."
        
        # Try wget first
        if wget --user-agent="Mozilla/5.0" -q -O "$target_file" "$BASE_URL/modules/$module_name" 2>/dev/null; then
            if [ -s "$target_file" ]; then
                # Check if it's a valid shell script or has expected content
                if head -n 1 "$target_file" | grep -q "^#!/bin/bash\|^#!.*sh" || grep -q "function\|export" "$target_file"; then
                    chmod +x "$target_file"
                    print_message "✓ Successfully downloaded $module_name"
                    return 0
                else
                    print_warning "Downloaded file doesn't appear to be valid. Retrying..."
                    rm -f "$target_file"
                fi
            else
                print_warning "Downloaded file is empty"
                rm -f "$target_file"
            fi
        fi
        
        # Try curl as fallback
        if curl -L -s -o "$target_file" "$BASE_URL/modules/$module_name" 2>/dev/null; then
            if [ -s "$target_file" ] && grep -q "function\|export\|#!/bin/bash" "$target_file"; then
                chmod +x "$target_file"
                print_message "✓ Successfully downloaded $module_name with curl"
                return 0
            else
                rm -f "$target_file"
            fi
        fi
        
        attempt=$((attempt + 1))
        if [ $attempt -le $max_attempts ]; then
            sleep 2
        fi
    done
    
    print_error "Failed to download $module_name after $max_attempts attempts"
    return 1
}

# FIXED: Consistent module naming - using underscores throughout
print_message "Downloading installer modules..."

# Define modules with their actual GitHub names and local names
declare -A modules=(
    ["core-functions.sh"]="core_functions.sh"
    ["packages_system.sh"]="packages_system.sh"
    ["multiip_config.sh"]="multiip_config.sh"
    ["mysql_dovecot.sh"]="mysql_dovecot.sh"
    ["postfix_setup.sh"]="postfix_setup.sh"
    ["dkim_spf.sh"]="dkim_spf.sh"
    ["dns_ssl.sh"]="dns_ssl.sh"
    ["monitoring_scripts.sh"]="monitoring_scripts.sh"
    ["security_hardening.sh"]="security_hardening.sh"
    ["mailwizz_integration.sh"]="mailwizz_integration.sh"
    ["utility_scripts.sh"]="utility_scripts.sh"
    ["sticky_ip.sh"]="sticky_ip.sh"
    ["main_installer_part2.sh"]="main_installer_part2.sh"
    ["main_installer.sh"]="main_installer.sh"
)

# Module loading order (local names)
module_order=(
    "core_functions.sh"
    "packages_system.sh"
    "multiip_config.sh"
    "mysql_dovecot.sh"
    "postfix_setup.sh"
    "dkim_spf.sh"
    "dns_ssl.sh"
    "monitoring_scripts.sh"
    "security_hardening.sh"
    "mailwizz_integration.sh"
    "utility_scripts.sh"
    "sticky_ip.sh"
    "main_installer_part2.sh"
    "main_installer.sh"
)

# Check if modules are accessible
print_message "Checking module availability..."
test_url="${BASE_URL}/modules/core-functions.sh"
if ! curl -L -s --head "$test_url" | head -n 1 | grep "200\|301\|302" > /dev/null; then
    print_error "Cannot access modules at $BASE_URL/modules/"
    print_error "Please check that the repository and path are correct."
    cd /
    rm -rf "$INSTALLER_DIR"
    exit 1
fi

# Download each module with proper naming
failed_modules=()
for github_name in "${!modules[@]}"; do
    local_name="${modules[$github_name]}"
    if ! download_module "$github_name" "$local_name"; then
        failed_modules+=("$github_name")
    fi
done

# Check if any modules failed to download
if [ ${#failed_modules[@]} -gt 0 ]; then
    print_error "Failed to download the following modules:"
    for module in "${failed_modules[@]}"; do
        echo "  - $module"
    done
    print_error "Installation cannot continue."
    cd /
    rm -rf "$INSTALLER_DIR"
    exit 1
fi

print_message "All modules downloaded successfully"

# Verify all files exist with their local names
print_message "Verifying module integrity..."
for local_name in "${module_order[@]}"; do
    if [ ! -r "$local_name" ]; then
        print_error "Module $local_name is not readable"
        ls -la "$INSTALLER_DIR"
        cd /
        rm -rf "$INSTALLER_DIR"
        exit 1
    fi
done

# FIXED: Proper module loading with error recovery
print_message "Loading modules..."

# Create a wrapper function for safe sourcing
safe_source() {
    local module=$1
    local temp_err=$(mktemp)
    
    # Try to source the module and capture any errors
    if bash -c "source '$module'" 2>"$temp_err"; then
        # If test succeeds, source it in current shell
        source "$module"
        rm -f "$temp_err"
        return 0
    else
        print_warning "Module $module has issues: $(cat $temp_err)"
        rm -f "$temp_err"
        return 1
    fi
}

# Source modules in correct order
for module in "${module_order[@]}"; do
    print_message "Loading module: $module"
    
    if [ -f "$module" ]; then
        # Source the module
        set +e  # Temporarily disable exit on error
        source "./$module" 2>/dev/null || {
            print_warning "Warning loading $module, attempting recovery..."
            # Try to load it anyway
            . "./$module" 2>/dev/null || true
        }
        set -e  # Re-enable exit on error
    else
        print_error "Module $module not found!"
        ls -la "$INSTALLER_DIR"
        exit 1
    fi
done

# FIXED: Create log file function if not loaded from modules
if ! type log_message &>/dev/null 2>&1; then
    log_message() {
        local log_file="${LOG_FILE:-/var/log/mail-installer-$(date +%Y%m%d-%H%M%S).log}"
        echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" >> "$log_file"
    }
    export -f log_message
fi

print_message "Verifying critical functions..."

# Define critical functions to verify
critical_functions=(
    "check_root"
    "get_public_ip"
    "validate_domain"
    "validate_email"
    "check_system_requirements"
    "install_required_packages"
    "setup_mysql"
    "setup_dovecot"
    "setup_postfix_multi_ip"
    "setup_opendkim"
    "get_all_server_ips"
    "configure_hostname"
    "create_multi_ip_dns_records"
    "get_ssl_certificates"
    "setup_website"
    "harden_server"
    "create_utility_scripts"
    "create_ip_warmup_scripts"
    "create_monitoring_scripts"
    "create_mailwizz_multi_ip_guide"
    "first_time_installation_multi_ip"
    "main_menu"
)

# Check and export all critical functions
missing_functions=()
for func in "${critical_functions[@]}"; do
    if type "$func" &>/dev/null 2>&1; then
        export -f "$func" 2>/dev/null || true
    else
        missing_functions+=("$func")
    fi
done

# Report missing functions if any
if [ ${#missing_functions[@]} -gt 0 ]; then
    print_warning "Some functions are not available:"
    for func in "${missing_functions[@]}"; do
        echo "  - $func"
    done
    
    # Check if we have the minimum required functions
    if ! type "main_menu" &>/dev/null 2>&1 || ! type "first_time_installation_multi_ip" &>/dev/null 2>&1; then
        print_error "Critical functions missing. Installation cannot continue."
        print_error "This may be due to incomplete module downloads."
        cd /
        rm -rf "$INSTALLER_DIR"
        exit 1
    fi
    
    print_warning "Non-critical functions missing. Installation may continue with limited features."
fi

# FIXED: Ensure main_menu exists with all features
if ! type main_menu &>/dev/null 2>&1; then
    print_error "main_menu function not found after module loading!"
    print_message "Creating emergency main_menu..."
    
    main_menu() {
        print_header "$INSTALLER_NAME v$INSTALLER_VERSION"
        print_message "Emergency menu - limited functionality"
        echo
        echo "1) Install Multi-IP Bulk Mail Server"
        echo "2) Exit"
        echo
        read -p "Enter your choice [1-2]: " choice
        
        case $choice in
            1)
                if type first_time_installation_multi_ip &>/dev/null 2>&1; then
                    first_time_installation_multi_ip
                else
                    print_error "Installation function not available!"
                    exit 1
                fi
                ;;
            2)
                print_message "Exiting..."
                exit 0
                ;;
            *)
                print_error "Invalid option"
                exit 1
                ;;
        esac
    }
    
    export -f main_menu
fi

# Create log directory
mkdir -p /var/log
LOG_FILE="/var/log/mail-installer-$(date +%Y%m%d-%H%M%S).log"
export LOG_FILE

print_message "Installation log will be saved to: $LOG_FILE"

# Initialize the log file
echo "========================================" > "$LOG_FILE"
echo "Mail Server Installation Log" >> "$LOG_FILE"
echo "Started: $(date)" >> "$LOG_FILE"
echo "Version: $INSTALLER_VERSION" >> "$LOG_FILE"
echo "========================================" >> "$LOG_FILE"

# Display system information
print_message ""
print_message "System Information:"
print_message "  OS: $(lsb_release -ds 2>/dev/null || cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'"' -f2 || echo 'Unknown')"
print_message "  Kernel: $(uname -r)"
print_message "  Architecture: $(uname -m)"
print_message "  Hostname: $(hostname -f 2>/dev/null || hostname)"
print_message "  Memory: $(free -h | awk '/^Mem:/{print $2}') total"
print_message "  Disk: $(df -h / | awk 'NR==2{print $4}') available on root"
print_message ""

# Final verification before running
print_message "Pre-installation checks:"
if type check_root &>/dev/null 2>&1; then
    check_root && print_message "✓ Root access verified" || true
else
    # Fallback root check
    [ "$(id -u)" = "0" ] && print_message "✓ Root access verified" || {
        print_error "Not running as root!"
        exit 1
    }
fi

# Check for minimum required functions
required_for_start=(
    "main_menu"
    "first_time_installation_multi_ip"
)

all_ready=true
for func in "${required_for_start[@]}"; do
    if type "$func" &>/dev/null 2>&1; then
        print_message "✓ Function $func is available"
    else
        print_error "✗ Function $func is missing"
        all_ready=false
    fi
done

if [ "$all_ready" = false ]; then
    print_error "Cannot start installation - required functions missing"
    cd /
    rm -rf "$INSTALLER_DIR"
    exit 1
fi

print_message ""
print_message "All pre-installation checks passed!"
print_message ""

# Run the main menu
print_message "Starting installer interface..."

# Add cleanup trap for normal exit
cleanup_on_exit() {
    if [ -d "$INSTALLER_DIR" ]; then
        print_message "Cleaning up temporary files..."
        cd /
        rm -rf "$INSTALLER_DIR"
    fi
}

trap cleanup_on_exit EXIT

# Run main menu with error handling
set +e  # Allow main_menu to handle its own errors

if type main_menu &>/dev/null 2>&1; then
    # Run main menu and capture exit code
    main_menu
    exit_code=$?
    
    if [ $exit_code -eq 0 ]; then
        print_message ""
        print_message "Installation process completed successfully!"
        print_message "Log file saved at: $LOG_FILE"
        print_message ""
        print_message "Next steps:"
        print_message "1. Check the documentation at /root/mail-server-multiip-info.txt"
        print_message "2. Configure PTR records with your hosting provider"
        print_message "3. Test your mail server with: send-test-email your@email.com"
        print_message ""
        print_message "For support, visit: https://github.com/$GITHUB_USER/$GITHUB_REPO/issues"
    else
        print_error "Installation exited with code: $exit_code"
        print_error "Check the log file for details: $LOG_FILE"
    fi
else
    print_error "main_menu function not available even after all attempts!"
    exit 1
fi

set -e

# The cleanup trap will handle removing temporary files
exit $exit_code
