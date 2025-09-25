#!/bin/bash

# =================================================================
# VM Host Hardener - Installation Script
# =================================================================

# Check if running as root
if [ "$(id -u)" != "0" ]; then
    echo "This script must be run as root or with sudo"
    exit 1
fi

# Set installation directory
INSTALL_DIR="/opt/vm-host-hardener"

echo "=================================================="
echo "VM Host Hardener - Installation & Execution"
echo "=================================================="
echo "This script will install and immediately run the VM host hardening process"
echo "Optimized for hosts running mail, web, and NextCloud VMs"
echo ""

# Create installation directory
echo "Creating installation directory: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/modules"
mkdir -p "$INSTALL_DIR/config"

# Base URL for raw files
BASE_URL="https://raw.githubusercontent.com/fumingtomato/shibi/main/VMhardner"

# Function to download a file
download_file() {
    local url="$1"
    local dest="$2"
    local filename=$(basename "$dest")
    
    echo "Downloading $filename..."
    if wget -q "$url" -O "$dest"; then
        echo "✓ Downloaded $filename"
        return 0
    else
        echo "✗ Failed to download $filename"
        return 1
    fi
}

# Download main script
echo "=================================================="
echo "Downloading Core Files"
echo "=================================================="
download_file "$BASE_URL/harden-vm-host.sh" "$INSTALL_DIR/harden-vm-host.sh"
chmod +x "$INSTALL_DIR/harden-vm-host.sh"

# Download README
download_file "$BASE_URL/README.md" "$INSTALL_DIR/README.md"

# Download configuration
echo "=================================================="
echo "Downloading Configuration"
echo "=================================================="
download_file "$BASE_URL/config/settings.conf" "$INSTALL_DIR/config/settings.conf"

# Download all modules
echo "=================================================="
echo "Downloading Modules"
echo "=================================================="

MODULES=(
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

for module in "${MODULES[@]}"; do
    download_file "$BASE_URL/modules/$module" "$INSTALL_DIR/modules/$module"
    chmod +x "$INSTALL_DIR/modules/$module"
done

# Create symlink for easy execution
echo "Creating command symlink..."
ln -sf "$INSTALL_DIR/harden-vm-host.sh" /usr/local/bin/vm-hardener

# Verify installation
echo "=================================================="
echo "Verifying Installation"
echo "=================================================="

if [ -f "$INSTALL_DIR/harden-vm-host.sh" ] && [ -d "$INSTALL_DIR/modules" ] && [ -f "$INSTALL_DIR/config/settings.conf" ]; then
    echo "✓ All files downloaded successfully"
else
    echo "✗ Installation incomplete. Some files may be missing."
    exit 1
fi

echo "=================================================="
echo "Starting VM Host Hardening Process"
echo "=================================================="
echo ""
echo "The hardening process will now begin automatically."
echo "This script is optimized for hosts running:"
echo "  • Mail server VMs (SMTP/IMAP)"
echo "  • Web server VMs (HTTP/HTTPS)"
echo "  • NextCloud VMs"
echo ""
echo "The following ports will be automatically configured:"
echo "  • SSH (22 or custom if configured)"
echo "  • HTTP (80) - For web and NextCloud VMs"
echo "  • HTTPS (443) - For web and NextCloud VMs"
echo "  • SMTP (25) - For mail server VMs"
echo "  • SMTPS/Submission (465/587) - For mail server VMs"
echo "  • IMAP (143) - For mail server VMs"
echo "  • IMAPS (993) - For mail server VMs"
echo ""

# NO PAUSE - REMOVED THE READ COMMAND

echo "=================================================="
echo "Executing VM Host Hardening"
echo "=================================================="

# Execute the hardening script
cd "$INSTALL_DIR"
./harden-vm-host.sh

echo ""
echo "=================================================="
echo "Installation Complete"
echo "=================================================="
echo "VM Host Hardener has been installed to: $INSTALL_DIR"
echo "You can run it again anytime with: sudo vm-hardener"
echo ""
echo "To uninstall, run:"
echo "  sudo rm -rf $INSTALL_DIR"
echo "  sudo rm -f /usr/local/bin/vm-hardener"
echo ""

exit 0
