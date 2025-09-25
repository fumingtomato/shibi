#!/bin/bash
# =================================================================
# VM Host Hardener - Local Installation Script
# For Ubuntu 24.04 LTS
# =================================================================

set -e

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

print_header "VM Host Hardener - Local Installation"

# Get the directory where this script is located
INSTALLER_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Check if we're in the right directory structure
if [ ! -f "$INSTALLER_DIR/harden-vm-host.sh" ]; then
    print_error "Cannot find harden-vm-host.sh in current directory"
    print_error "Please run this script from the vm-host-hardener directory"
    exit 1
fi

# Create installation directory
INSTALL_DIR="/opt/vm-host-hardener"
print_message "Creating installation directory: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"

# Copy all files to installation directory
print_message "Copying files to installation directory..."
cp -r "$INSTALLER_DIR"/* "$INSTALL_DIR/" 2>/dev/null || true

# Make scripts executable
print_message "Setting executable permissions..."
chmod +x "$INSTALL_DIR/harden-vm-host.sh"
chmod +x "$INSTALL_DIR"/modules/*.sh 2>/dev/null || true

# Create symlink for easy access
print_message "Creating command symlink..."
ln -sf "$INSTALL_DIR/harden-vm-host.sh" /usr/local/bin/vm-hardener

print_header "Installation Complete"
print_message "VM Host Hardener has been installed successfully!"
print_message ""
print_message "You can now run the hardening script using:"
print_message "  sudo vm-hardener"
print_message "Or directly:"
print_message "  sudo $INSTALL_DIR/harden-vm-host.sh"
print_message ""
print_message "To start the hardening process, run:"
print_message "  sudo vm-hardener"
