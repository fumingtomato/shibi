#!/bin/bash

# =================================================================
# Multi-IP Bulk Mail Server Master Installer
# Version: 16.0.2
# Repository: https://github.com/fumingtomato/shibi
# =================================================================

set -e

INSTALLER_NAME="Multi-IP Bulk Mail Server Installer"
INSTALLER_VERSION="16.0.2"
GITHUB_USER="fumingtomato"
GITHUB_REPO="shibi"
GITHUB_BRANCH="main"
BASE_URL="https://raw.githubusercontent.com/$GITHUB_USER/$GITHUB_REPO/$GITHUB_BRANCH/New_PfMIP"
INSTALLER_DIR="/tmp/multiip-installer-$$"

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

# Function to handle errors
handle_error() {
    local line_no=$1
    local bash_lineno=$2
    local last_command=$3
    
    print_error "An error occurred:"
    print_error "  Line: $line_no"
    print_error "  Command: $last_command"
    print_error "Installation failed. Cleaning up..."
    
    # Show what was downloaded for debugging
    print_error "Downloaded files:"
    ls -la "$INSTALLER_DIR" 2>/dev/null || true
    
    # Show first few lines of problematic file if it exists
    if [ -f "$INSTALLER_DIR/core-functions.sh" ]; then
        print_error "First lines of core-functions.sh:"
        head -n 5 "$INSTALLER_DIR/core-functions.sh"
    fi
    
    # Cleanup
    cd /
    rm -rf "$INSTALLER_DIR"
    
    print_error "Please check the logs and try again."
    exit 1
}

# Set error trap with more detail
trap 'handle_error $LINENO $BASH_LINENO "$BASH_COMMAND"' ERR

# Check if running as root
if [ "$(id -u)" != "0" ]; then
    print_error "This script must be run as root or with sudo"
    exit 1
fi

print_header "$INSTALLER_NAME v$INSTALLER_VERSION"
print_message "Initializing installation process..."
print_message ""

# Check internet connectivity
print_message "Checking internet connectivity..."
if ! ping -c 1 google.com &>/dev/null && ! ping -c 1 8.8.8.8 &>/dev/null; then
    print_error "No internet connection detected. Please check your network."
    exit 1
fi

# Create temporary directory
print_message "Creating temporary installation directory..."
mkdir -p "$INSTALLER_DIR"
cd "$INSTALLER_DIR"

# Function to download a module with retry and validation
download_module() {
    local module=$1
    local max_attempts=3
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        print_message "Downloading $module (attempt $attempt/$max_attempts)..."
        
        # Try wget first with proper user agent
        if wget --user-agent="Mozilla/5.0" -q -O "$module" "$BASE_URL/modules/$module" 2>/dev/null; then
            # Validate that we got a shell script, not HTML
            if [ -s "$module" ]; then
                if head -n 1 "$module" | grep -q "^#!/bin/bash\|^#!.*sh"; then
                    chmod +x "$module"
                    print_message "✓ Successfully downloaded $module"
                    return 0
                else
                    print_warning "Downloaded file doesn't appear to be a shell script. First line:"
                    head -n 1 "$module"
                    rm -f "$module"
                fi
            else
                print_warning "Downloaded file is empty"
                rm -f "$module"
            fi
        fi
        
        # Try curl as fallback
        print_warning "wget failed or invalid content, trying curl..."
        if curl -L -s -o "$module" "$BASE_URL/modules/$module" 2>/dev/null; then
            if [ -s "$module" ]; then
                if head -n 1 "$module" | grep -q "^#!/bin/bash\|^#!.*sh"; then
                    chmod +x "$module"
                    print_message "✓ Successfully downloaded $module with curl"
                    return 0
                else
                    print_warning "Downloaded file doesn't appear to be a shell script"
                    rm -f "$module"
                fi
            else
                print_warning "Downloaded file is empty"
                rm -f "$module"
            fi
        fi
        
        attempt=$((attempt + 1))
        if [ $attempt -le $max_attempts ]; then
            print_warning "Retrying in 2 seconds..."
            sleep 2
        fi
    done
    
    print_error "Failed to download $module after $max_attempts attempts"
    return 1
}

# Download all modules in the correct order
print_message "Downloading installer modules..."

# CRITICAL: Use correct filenames with hyphens, not underscores!
modules=(
    "core-functions.sh"          # Note: hyphen not underscore
    "packages_system.sh"         # System packages and functions
    "multiip_config.sh"          # IP configuration
    "mysql_dovecot.sh"           # MySQL and Dovecot setup
    "postfix_setup.sh"           # Postfix configuration
    "dkim_spf.sh"                # DKIM/SPF setup
    "dns_ssl.sh"                 # DNS and SSL configuration
    "monitoring_scripts.sh"       # Monitoring utilities
    "security_hardening.sh"      # Security configuration
    "mailwizz_integration.sh"    # MailWizz integration
    "utility_scripts.sh"         # Utility scripts
    "sticky_ip.sh"               # Sticky IP feature
    "main_installer_part2.sh"    # Additional installer functions
    "main_installer.sh"          # Main installation logic
)

# Check if modules are accessible
print_message "Checking module availability..."
test_url="${BASE_URL}/modules/core-functions.sh"
if ! curl -L -s --head "$test_url" | head -n 1 | grep "200\|301\|302" > /dev/null; then
    print_error "Cannot access modules at $BASE_URL/modules/"
    print_error "Please check that the repository and path are correct."
    print_error "Test URL: $test_url"
    cd /
    rm -rf "$INSTALLER_DIR"
    exit 1
fi

# Download each module
failed_modules=()
for module in "${modules[@]}"; do
    if ! download_module "$module"; then
        failed_modules+=("$module")
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

# Verify all files exist and are readable
print_message "Verifying module integrity..."
for module in "${modules[@]}"; do
    if [ ! -r "$module" ]; then
        print_error "Module $module is not readable"
        cd /
        rm -rf "$INSTALLER_DIR"
        exit 1
    fi
    
    # Check for basic shell script syntax
    if ! bash -n "$module" 2>/dev/null; then
        print_warning "Module $module may have syntax issues"
    fi
done

# Rename downloaded files to match what the scripts expect internally
# This fixes the hyphen vs underscore issue
print_message "Preparing modules..."
if [ -f "core-functions.sh" ]; then
    cp "core-functions.sh" "core_functions.sh"
fi

# Source all modules with error handling - FIXED VERSION
print_message "Loading modules..."

# First, source all modules without checking to ensure all functions are available
for module in "${modules[@]}"; do
    # Convert hyphen to underscore for sourcing
    source_name=$(echo "$module" | sed 's/-/_/g')
    
    # If file with underscore doesn't exist, use original
    if [ ! -f "$source_name" ]; then
        source_name="$module"
    fi
    
    print_message "Loading module: $source_name"
    
    # Source the module in the main shell - force it
    set +e  # Temporarily disable exit on error
    source "./$source_name" 2>/dev/null || source "./$module" 2>/dev/null || true
    set -e  # Re-enable exit on error
done

# Now explicitly export critical functions
print_message "Exporting critical functions..."

# List of functions to explicitly export
functions_to_export=(
    "main_menu"
    "check_root"
    "print_message"
    "print_error"
    "print_warning"
    "print_header"
    "print_debug"
    "log_message"
    "first_time_installation_multi_ip"
    "install_required_packages"
    "setup_mysql"
    "setup_postfix_multi_ip"
    "configure_hostname"
    "save_configuration"
    "create_final_documentation"
    "get_all_server_ips"
    "setup_dovecot"
    "setup_opendkim"
    "create_multi_ip_dns_records"
    "get_ssl_certificates"
    "setup_website"
    "harden_server"
    "init_mysql_postfix_config"
    "fix_mysql_config"
    "setup_email_aliases"
    "restart_services_ordered"
    "run_post_installation_checks"
)

# Export each function if it exists
for func in "${functions_to_export[@]}"; do
    if type "$func" &>/dev/null 2>&1; then
        export -f "$func" 2>/dev/null || true
    fi
done

print_message "All modules loaded successfully"

# Create a fallback main_menu function if it still doesn't exist
if ! type main_menu &>/dev/null 2>&1; then
    print_message "Creating fallback main_menu function..."
    
    main_menu() {
        print_header "$INSTALLER_NAME v$INSTALLER_VERSION"
        print_message "Optimized for commercial bulk mailing with multiple IP addresses"
        print_message "Current Date and Time (UTC): $(date -u '+%Y-%m-%d %H:%M:%S')"
        print_message "Current User: $(whoami)"
        echo
        
        # Initialize MySQL config early to prevent warnings (if function exists)
        if type init_mysql_postfix_config &>/dev/null 2>&1; then
            init_mysql_postfix_config
        fi
        
        echo "Please select an option:"
        echo "1) Install Multi-IP Bulk Mail Server with MailWizz optimization"
        echo "2) Add additional IP to existing installation"
        echo "3) View current IP configuration"
        echo "4) Run diagnostics"
        echo "5) Update installer"
        echo "6) Exit"
        echo
        
        read -p "Enter your choice [1-6]: " choice
        
        case $choice in
            1)
                if type first_time_installation_multi_ip &>/dev/null 2>&1; then
                    first_time_installation_multi_ip
                else
                    print_error "Installation function not found. Please check module loading."
                    exit 1
                fi
                ;;
            2)
                print_message "Add additional IP feature not implemented yet."
                ;;
            3)
                print_message "View IP configuration feature not implemented yet."
                ;;
            4)
                print_message "Diagnostics feature not implemented yet."
                ;;
            5)
                print_message "Update installer feature not implemented yet."
                ;;
            6)
                print_message "Exiting installer. No changes were made."
                exit 0
                ;;
            *)
                print_error "Invalid option. Exiting."
                exit 1
                ;;
        esac
    }
    
    export -f main_menu
fi

# Verify critical functions are available
print_message "Verifying critical functions..."
critical_functions=(
    "main_menu"
    "check_root"
    "install_required_packages"
    "configure_hostname"
    "setup_mysql"
    "setup_postfix_multi_ip"
    "save_configuration"
    "create_final_documentation"
)

missing_functions=()
for func in "${critical_functions[@]}"; do
    if ! type "$func" &>/dev/null 2>&1; then
        missing_functions+=("$func")
    fi
done

if [ ${#missing_functions[@]} -gt 0 ]; then
    print_error "Critical functions are missing:"
    for func in "${missing_functions[@]}"; do
        echo "  - $func"
    done
    
    # Try one more time to source main_installer_part2.sh directly
    print_message "Attempting emergency load of main_installer_part2.sh..."
    if [ -f "main_installer_part2.sh" ]; then
        . ./main_installer_part2.sh
        
        # Check again for main_menu
        if type main_menu &>/dev/null 2>&1; then
            print_message "Emergency load successful - main_menu is now available"
        else
            print_error "Emergency load failed - Installation cannot continue."
            cd /
            rm -rf "$INSTALLER_DIR"
            exit 1
        fi
    else
        print_error "Installation cannot continue."
        cd /
        rm -rf "$INSTALLER_DIR"
        exit 1
    fi
else
    print_message "All critical functions verified"
fi

# Create log directory
mkdir -p /var/log
LOG_FILE="/var/log/mail-installer-$(date +%Y%m%d-%H%M%S).log"
print_message "Installation log will be saved to: $LOG_FILE"

# Export log file location for use by modules
export LOG_FILE

# Display system information
print_message ""
print_message "System Information:"
print_message "  OS: $(lsb_release -ds 2>/dev/null || cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)"
print_message "  Kernel: $(uname -r)"
print_message "  Architecture: $(uname -m)"
print_message "  Hostname: $(hostname -f)"
print_message ""

# Run the main menu
print_message "Starting installer interface..."
if type main_menu &>/dev/null 2>&1; then
    # Redirect output to both terminal and log file
    main_menu 2>&1 | tee -a "$LOG_FILE"
else
    print_error "main_menu function not available. Installation failed."
    cd /
    rm -rf "$INSTALLER_DIR"
    exit 1
fi

# Cleanup temporary files
print_message "Cleaning up temporary files..."
cd /
rm -rf "$INSTALLER_DIR"

print_message ""
print_message "Installation process completed!"
print_message "Log file saved at: $LOG_FILE"
print_message ""
print_message "If you encountered any issues, please check the log file."
print_message "For support, visit: https://github.com/$GITHUB_USER/$GITHUB_REPO/issues"
