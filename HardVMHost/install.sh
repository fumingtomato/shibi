#!/bin/bash
# =================================================================
# VM Host Hardener v2.0 - Self-Patching Installation Script
#
# This script downloads the VM Host Hardener and automatically
# patches a known bug in the main script during installation.
# The result is a fully functional hardener with no manual
# fixes required.
# =================================================================

set -e

# --- Configuration ---
readonly INSTALL_DIR="/opt/vm-host-hardener"
readonly BASE_URL="https://raw.githubusercontent.com/fumingtomato/shibi/dude/VMhardner"
readonly MAIN_SCRIPT_NAME="harden-vm-host.sh"
readonly MAIN_SCRIPT_PATH="${INSTALL_DIR}/${MAIN_SCRIPT_NAME}"

# --- Color Codes ---
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly RED='\033[0;31m'
readonly NC='\033[0m' # No Color

# --- Helper Functions ---
print_message() { echo -e "${GREEN}$1${NC}"; }
print_warning() { echo -e "${YELLOW}$1${NC}"; }
print_error() { echo -e "${RED}$1${NC}"; }

download_file() {
    local url="$1"
    local dest="$2"
    local filename=$(basename "$dest")

    echo "Downloading ${filename}..."
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
}

# --- Main Installation Logic ---
main() {
    if [ "$(id -u)" -ne 0 ]; then
        print_error "This script must be run as root or with sudo privileges."
        exit 1
    fi

    echo "=================================================="
    echo "VM Host Hardener v2.0 - Installer"
    echo "=================================================="
    print_message "Installing to: ${INSTALL_DIR}"

    # 1. Create directory structure
    mkdir -p "${INSTALL_DIR}/config"
    mkdir -p "${INSTALL_DIR}/modules"

    # 2. Download all files
    print_message "--- Downloading script components ---"
    download_file "${BASE_URL}/${MAIN_SCRIPT_NAME}" "${MAIN_SCRIPT_PATH}"
    download_file "${BASE_URL}/config/settings.conf" "${INSTALL_DIR}/config/settings.conf"

    local modules=(
        "00-common.sh" "01-prerequisites.sh" "02-system-updates.sh"
        "03-ssh-hardening.sh" "04-firewall.sh" "05-libvirt-hardening.sh"
        "06-kernel-hardening.sh" "07-storage-security.sh" "08-monitoring-auditing.sh"
        "09-backups.sh" "10-security-report.sh"
    )
    for module in "${modules[@]}"; do
        download_file "${BASE_URL}/modules/${module}" "${INSTALL_DIR}/modules/${module}"
    done
    print_message "✓ All components downloaded."

    # 3. *** AUTOMATED PATCHING STEP ***
    # This fixes the directory location bug in the downloaded harden-vm-host.sh
    print_message "--- Applying automated patch to fix script error ---"
    
    # This is the code that correctly finds the script's directory.
    local patch_code
    patch_code='SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" \&> \/dev\/null \&\& pwd)\nreadonly SCRIPT_DIR'
    
    # This is the new, corrected 'source' line.
    local new_source_line
    new_source_line='if [ -f "${SCRIPT_DIR}\/modules\/00-common.sh" ]; then\n    source "${SCRIPT_DIR}\/modules\/00-common.sh"\nelse\n    echo "FATAL: Module 00-common.sh not found at ${SCRIPT_DIR}\/modules\/00-common.sh."\n    exit 1\nfi'

    # Use sed to find the old 'source' line, insert the patch before it, and replace the old line.
    if sed -i.bak "s|source \"modules/00-common.sh\"|${patch_code}\n\n${new_source_line}|" "${MAIN_SCRIPT_PATH}"; then
        rm -f "${MAIN_SCRIPT_PATH}.bak" # Clean up backup file on success
        print_message "✓ Automated patch applied successfully."
    else
        print_error "✗ ERROR: Automated patching failed. The script may not run correctly."
        exit 1
    fi

    # 4. Set permissions and create symlink
    print_message "--- Finalizing installation ---"
    chmod +x "${MAIN_SCRIPT_PATH}"
    chmod +x "${INSTALL_DIR}"/modules/*.sh
    ln -sf "${MAIN_SCRIPT_PATH}" /usr/local/bin/vm-hardener
    print_message "✓ Permissions set and 'vm-hardener' command created."

    # 5. Print final instructions
    echo "=================================================="
    print_message "✓ Installation and patching complete!"
    echo "=================================================="
    echo ""
    print_warning "--> ACTION REQUIRED: CONFIGURE SSH KEY <--"
    print_message "Please edit the configuration file and add your public SSH key."
    echo ""
    echo "  1. Find/Create your key (on your local computer, not the server):"
    echo "     cat ~/.ssh/id_ed25519.pub"
    echo ""
    echo "  2. Open the configuration file on THIS SERVER:"
    echo "     sudo nano ${INSTALL_DIR}/config/settings.conf"
    echo ""
    echo "  3. Paste your key, save the file, and then run the hardener:"
    echo "     sudo vm-hardener"
    echo ""
}

main
