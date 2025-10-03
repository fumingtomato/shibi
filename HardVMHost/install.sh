#!/bin/bash
# =================================================================
# VM Host Hardener v2.0 - Definitive Installation Script
#
# This script downloads all components and builds the main executable
# with the correct, robust logic to find its own directory,
# permanently fixing the "module not found" error.
# =================================================================

set -e

# --- Configuration ---
readonly INSTALL_DIR="/opt/vm-host-hardener"
readonly BASE_URL="https://raw.githubusercontent.com/fumingtomato/shibi/dude/HardVMHost"
readonly MAIN_SCRIPT_NAME="harden-vm-host.sh"
readonly MAIN_SCRIPT_PATH="${INSTALL_DIR}/${MAIN_SCRIPT_NAME}"

# --- Color Codes ---
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly RED='\033[0;31m'
readonly NC='\033[0m'

# --- Helper Functions ---
print_message() { echo -e "${GREEN}$1${NC}"; }
print_warning() { echo -e "${YELLOW}$1${NC}"; }
print_error() { echo -e "${RED}$1${NC}"; }

download_file() {
    local url="$1"
    local dest="$2"
    local filename=$(basename "$dest")
    echo "Downloading ${filename}..."
    if command -v curl &>/dev/null; then
        if ! curl -s -f -L -o "$dest" "$url"; then
            print_error "✗ ERROR: curl failed to download $filename from $url"
            return 1
        fi
    elif command -v wget &>/dev/null; then
        if ! wget -q -O "$dest" "$url"; then
            print_error "✗ ERROR: wget failed to download $filename from $url"
            return 1
        fi
    else
        print_error "✗ ERROR: Neither curl nor wget is available. Please install one."
        exit 1
    fi
}

# --- Main Installation Logic ---
main() {
    if [ "$(id -u)" -ne 0 ]; then
        print_error "This script must be run as root or with sudo privileges."
        exit 1
    fi

    # Clean up previous failed installations
    if [ -d "${INSTALL_DIR}" ]; then
        print_warning "Removing previous failed installation to ensure a clean state."
        rm -rf "${INSTALL_DIR}"
    fi

    echo "=================================================="
    echo "VM Host Hardener v2.0 - Definitive Installer"
    echo "=================================================="
    print_message "Installing to: ${INSTALL_DIR}"

    # 1. Create directory structure
    mkdir -p "${INSTALL_DIR}/config"
    mkdir -p "${INSTALL_DIR}/modules"

    # 2. Download all module and configuration files
    print_message "--- Downloading script components ---"
    download_file "${BASE_URL}/config/settings.conf" "${INSTALL_DIR}/config/settings.conf"
    local modules=("00-common.sh" "01-prerequisites.sh" "02-system-updates.sh" "03-ssh-hardening.sh" "04-firewall.sh" "05-libvirt-hardening.sh" "06-kernel-hardening.sh" "07-storage-security.sh" "08-monitoring-auditing.sh" "09-backups.sh" "10-security-report.sh")
    for module in "${modules[@]}"; do
        download_file "${BASE_URL}/modules/${module}" "${INSTALL_DIR}/modules/${module}"
    done
    print_message "✓ All components downloaded successfully."

    # 3. *** THE DEFINITIVE FIX ***
    # This creates the main script with the correct logic to resolve symlinks.
    print_message "--- Creating main executable with correct directory logic ---"
    tee "${MAIN_SCRIPT_PATH}" > /dev/null <<'EOF'
#!/bin/bash
set -e

# This is the correct and robust way to find the script's true directory,
# even when called through a symlink.
SCRIPT_PATH=$(readlink -f "${BASH_SOURCE[0]}")
SCRIPT_DIR=$(dirname "${SCRIPT_PATH}")
readonly SCRIPT_DIR

# Source the common module using the now-correct SCRIPT_DIR
if [ -f "${SCRIPT_DIR}/modules/00-common.sh" ]; then
    source "${SCRIPT_DIR}/modules/00-common.sh"
else
    echo "FATAL: Critical module 00-common.sh not found at ${SCRIPT_DIR}/modules/00-common.sh." >&2
    exit 1
fi

main() {
    print_header "VM Host Hardener v${VERSION}"
    if [ "$(id -u)" -ne 0 ]; then
        print_error "This script must be run as root or with sudo privileges."; log "ERROR: Script not run as root."; exit 1;
    fi
    load_config; init_log
    log "===== VM Host Hardener v${VERSION} Started ====="
    run_module "01-prerequisites.sh"
    run_module "02-system-updates.sh"
    run_module "03-ssh-hardening.sh"
    run_module "04-firewall.sh"
    run_module "05-libvirt-hardening.sh"
    run_module "06-kernel-hardening.sh"
    run_module "07-storage-security.sh"
    run_module "08-monitoring-auditing.sh"
    run_module "09-backups.sh"
    run_module "10-security-report.sh"
    print_header "Hardening process completed successfully!"
    log "===== VM Host Hardener Finished ====="
}
main
EOF
    print_message "✓ Main executable created correctly."

    # 4. Set permissions and create symlink
    print_message "--- Finalizing installation ---"
    chmod +x "${MAIN_SCRIPT_PATH}"
    chmod +x "${INSTALL_DIR}"/modules/*.sh
    ln -sf "${MAIN_SCRIPT_PATH}" /usr/local/bin/vm-hardener
    print_message "✓ Permissions set and 'vm-hardener' command created."

    # 5. Print final instructions
    echo "=================================================="
    print_message "✓ Installation complete. The script is now ready."
    echo "=================================================="
    echo ""
    print_warning "--> ACTION REQUIRED: CONFIGURE YOUR USER AND SSH KEY <--"
    echo ""
    echo "  1. Open the configuration file:"
    echo "     sudo nano ${INSTALL_DIR}/config/settings.conf"
    echo ""
    echo "  2. Change ADMIN_USER to \"auggie\" and paste your SSH public key."
    echo ""
    echo "  3. Save the file, then run the hardener:"
    echo "     sudo vm-hardener"
    echo ""
}

main
