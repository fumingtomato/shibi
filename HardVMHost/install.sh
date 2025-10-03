#!/bin/bash
# =================================================================
# VM Host Hardener v2.0 - Installation Script
#
# This script downloads and installs the VM Host Hardener to your
# system. It will not run the hardener automatically.
# =================================================================

set -e

# --- Configuration ---
# Installation directory for all hardening scripts.
readonly INSTALL_DIR="/opt/vm-host-hardener"
# The base URL to the raw GitHub files.
# This must point to the correct repository and branch where the files are hosted.
readonly BASE_URL="https://raw.githubusercontent.com/fumingtomato/shibi/dude/HardVMHost"

# Color codes for output
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly RED='\033[0;31m'

# --- Helper Functions ---
print_message() { echo -e "${GREEN}$1\033[0m"; }
print_warning() { echo -e "${YELLOW}$1\033[0m"; }
print_error() { echo -e "${RED}$1\033[0m"; }

# Function to download a file using wget or curl.
download_file() {
    local url="$1"
    local dest="$2"
    local filename=$(basename "$dest")

    echo "Downloading $filename..."
    if command -v wget &>/dev/null; then
        if ! wget -q -O "$dest" "$url"; then
            print_error "✗ ERROR: wget failed to download $filename from $url"
            return 1
        fi
    elif command -v curl &>/dev/null; then
        if ! curl -s -L -o "$dest" "$url"; then
            print_error "✗ ERROR: curl failed to download $filename from $url"
            return 1
        fi
    else
        print_error "✗ ERROR: Neither wget nor curl is available. Please install one and try again."
        exit 1
    fi
    print_message "✓ Downloaded $filename"
}

# --- Main Installation Logic ---
main() {
    # 1. Check for root privileges
    if [ "$(id -u)" -ne 0 ]; then
        print_error "This script must be run as root or with sudo privileges."
        exit 1
    fi

    echo "=================================================="
    echo "VM Host Hardener v2.0 - Installation"
    echo "=================================================="
    print_message "Installing to: ${INSTALL_DIR}"

    # 2. Create directory structure
    mkdir -p "${INSTALL_DIR}/config"
    mkdir -p "${INSTALL_DIR}/modules"

    # 3. Download all the files
    # Main script
    download_file "${BASE_URL}/harden-vm-host.sh" "${INSTALL_DIR}/harden-vm-host.sh"

    # Config file
    download_file "${BASE_URL}/config/settings.conf" "${INSTALL_DIR}/config/settings.conf"

    # Module files
    local modules=(
        "00-common.sh"
        "01-prerequisites.sh"
        "02-system-updates.sh"
        "03-ssh-hardening.sh"
        "04-firewall.sh"
        "05-libvirt-hardening.sh"
        "06-kernel-hardening.sh"
        "07-storage-security.sh"
        "08-monitoring-auditing.sh"
        "09-backups.sh"
        "10-security-report.sh"
    )

    for module in "${modules[@]}"; do
        download_file "${BASE_URL}/modules/${module}" "${INSTALL_DIR}/modules/${module}"
    done

    # 4. Set executable permissions
    print_message "Setting executable permissions..."
    chmod +x "${INSTALL_DIR}/harden-vm-host.sh"
    chmod +x "${INSTALL_DIR}"/modules/*.sh

    # 5. Create a symlink for easy execution
    ln -sf "${INSTALL_DIR}/harden-vm-host.sh" /usr/local/bin/vm-hardener
    print_message "Symlink created. You can now use the 'vm-hardener' command."

    # 6. Print final instructions
    echo "=================================================="
    print_message "✓ Installation Complete!"
    echo "=================================================="
    echo ""
    print_warning "--> ACTION REQUIRED: CONFIGURE SSH KEY <--"
    echo ""
    print_message "The hardener is configured to use secure SSH keys instead of passwords."
    print_message "You need to add your PUBLIC SSH key to the configuration file."
    echo ""
    cat <<-EOF
	---------------------------------------------------------------------
	   How to Find or Create Your SSH Public Key
	---------------------------------------------------------------------
	Run these commands on your **LOCAL COMPUTER**, not on this server.

	1. Check for an existing key:
	   Open a terminal on your local machine (Mac, Linux, or WSL on Windows)
	   and run:
	   
	   cat ~/.ssh/id_ed25519.pub

	   - If it prints a line starting with 'ssh-ed25519...', you have a key!
	     Copy the ENTIRE line. This is your public key.
	   - If you get an error like "No such file or directory", proceed to step 2.

	2. If you don't have a key, create one:
	   Run the following command on your local machine. Ed25519 is modern and secure.

	   ssh-keygen -t ed25519 -C "fumingtomato@example.com"

	   - It will ask where to save the key. Just press ENTER to accept the default.
	   - It will ask for a passphrase. This is an optional password to protect
	     your key file. For simplicity, you can leave it empty by pressing ENTER twice.
	     (For higher security, enter a strong passphrase).

	3. Display and copy your new public key:
	   After creating the key, run the 'cat' command from step 1 again:

	   cat ~/.ssh/id_ed25519.pub

	   Now it will show your new public key. Copy the entire output.
	---------------------------------------------------------------------

	Once you have copied your public key:

	1. Open the configuration file on THIS SERVER:
	   sudo nano ${INSTALL_DIR}/config/settings.conf

	2. Find the line that says:
	   ADMIN_USER_SSH_KEY="<PASTE YOUR PUBLIC SSH KEY HERE>"

	3. Replace "<PASTE YOUR PUBLIC SSH KEY HERE>" with the key you just copied.
	   Save the file (Ctrl+O, Enter) and exit (Ctrl+X).

	4. Finally, run the hardener:
	   sudo vm-hardener
	EOF
}

# --- Entry Point ---
main
