#!/bin/bash
# =================================================================
# VM Host Hardener - Installation and Execution Script
# Downloads and immediately runs the VM Host Hardener
# For Ubuntu 24.04 LTS hosting mail, web, and NextCloud VMs
# =================================================================

set -e

# GitHub repository information
GITHUB_USER="fumingtomato"
GITHUB_REPO="shibi"
GITHUB_BRANCH="main"
BASE_URL="https://raw.githubusercontent.com/${GITHUB_USER}/${GITHUB_REPO}/${GITHUB_BRANCH}/VMhardner"

# Color codes for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to display messages
print_message() {
    echo -e "${GREEN}$1${NC}"
}

print_warning() {
    echo -e "${YELLOW}$1${NC}"
}

print_error() {
    echo -e "${RED}$1${NC}"
}

print_header() {
    echo -e "${BLUE}==================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}==================================================${NC}"
}

# Check if script is run as root
if [ "$(id -u)" != "0" ]; then
    print_error "This script must be run as root or with sudo privileges"
    exit 1
fi

print_header "VM Host Hardener - Installation & Execution"
print_message "This script will install and immediately run the VM host hardening process"
print_message "Optimized for hosts running mail, web, and NextCloud VMs"
echo ""

# Create installation directory
INSTALL_DIR="/opt/vm-host-hardener"
print_message "Creating installation directory: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

# Create subdirectories
mkdir -p config modules

# Function to download a file
download_file() {
    local url="$1"
    local dest="$2"
    local filename=$(basename "$dest")
    
    print_message "Downloading $filename..."
    
    if wget -q -O "$dest" "$url"; then
        print_message "✓ Downloaded $filename"
        return 0
    else
        print_error "✗ Failed to download $filename from $url"
        return 1
    fi
}

# Download main script
print_header "Downloading Core Files"
download_file "${BASE_URL}/harden-vm-host.sh" "harden-vm-host.sh" || exit 1
chmod +x harden-vm-host.sh

# Download README
download_file "${BASE_URL}/README.md" "README.md" || true

# Download configuration file
print_header "Downloading Configuration"
download_file "${BASE_URL}/config/settings.conf" "config/settings.conf" || exit 1

# Download all module files
print_header "Downloading Modules"

MODULE_FILES=(
    "00-common.sh"
    "01-system-checks.sh"
    "02-system-updates.sh"
    "03-ssh-hardening.sh"
    "04-firewall.sh"
    "05-libvirt-hardening.sh"
    "06-vm-resources.sh"
    "07-network-security.sh"
    "08-storage-security.sh"
    "09-monitoring.sh"
    "10-backups.sh"
    "11-kernel-hardening.sh"
    "12-security-report.sh"
)

# Track download success
failed_downloads=0

for module in "${MODULE_FILES[@]}"; do
    if ! download_file "${BASE_URL}/modules/${module}" "modules/${module}"; then
        ((failed_downloads++))
    else
        chmod +x "modules/${module}"
    fi
done

# Check if all downloads succeeded
if [ $failed_downloads -gt 0 ]; then
    print_error ""
    print_error "Failed to download $failed_downloads module(s)"
    print_error "Installation incomplete. Please check your internet connection and try again."
    exit 1
fi

# Create symlink for easy access
print_message "Creating command symlink..."
ln -sf "$INSTALL_DIR/harden-vm-host.sh" /usr/local/bin/vm-hardener

# Verify installation
print_header "Verifying Installation"

# Check that all files exist
all_files_present=true
for module in "${MODULE_FILES[@]}"; do
    if [ ! -f "modules/${module}" ]; then
        print_error "Missing: modules/${module}"
        all_files_present=false
    fi
done

if [ ! -f "config/settings.conf" ]; then
    print_error "Missing: config/settings.conf"
    all_files_present=false
fi

if [ ! -f "harden-vm-host.sh" ]; then
    print_error "Missing: harden-vm-host.sh"
    all_files_present=false
fi

if [ "$all_files_present" = true ]; then
    print_message "✓ All files downloaded successfully"
    
    print_header "Starting VM Host Hardening Process"
    print_message ""
    print_message "The hardening process will now begin automatically."
    print_message "This script is optimized for hosts running:"
    print_message "  • Mail server VMs (SMTP/IMAP)"
    print_message "  • Web server VMs (HTTP/HTTPS)"
    print_message "  • NextCloud VMs"
    print_message ""
    print_warning "The following ports will be automatically configured:"
    print_message "  • SSH (22 or custom if configured)"
    print_message "  • HTTP (80) - For web and NextCloud VMs"
    print_message "  • HTTPS (443) - For web and NextCloud VMs"
    print_message "  • SMTP (25) - For mail server VMs"
    print_message "  • SMTPS/Submission (465/587) - For mail server VMs"
    print_message "  • IMAP (143) - For mail server VMs"
    print_message "  • IMAPS (993) - For mail server VMs"
    print_message ""
    
    read -p "Press Enter to continue with the hardening process..."
    
    # Run the hardening script directly
    print_header "Executing VM Host Hardening"
    exec "$INSTALL_DIR/harden-vm-host.sh"
    
else
    print_error ""
    print_error "Installation verification failed!"
    print_error "Some files are missing. Please run the installer again."
    exit 1
fi
