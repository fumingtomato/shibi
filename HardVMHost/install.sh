#!/bin/bash
# =================================================================
# VM Host Hardener v2.0.1 - Final Corrected Installer
#
# This installer downloads the modules and creates a main script
# with a hardcoded, absolute path to guarantee it finds its files.
# This permanently fixes the "module not found" error.
# =================================================================

set -e

# --- Configuration ---
readonly INSTALL_DIR="/opt/vm-host-hardener"
readonly BASE_URL="https://raw.githubusercontent.com/fumingtomato/shibi/dude/HardVMHost"
readonly MAIN_SCRIPT_PATH="${INSTALL_DIR}/harden-vm-host.sh"

# --- Color Codes ---
readonly GREEN='\033[0;32m'; readonly YELLOW='\033[1;33m'; readonly RED='\033[0;31m'; readonly NC='\033[0m'

# --- Helper Functions ---
print_message() { echo -e "${GREEN}$1${NC}"; }
print_warning() { echo -e "${YELLOW}$1${NC}"; }
print_error() { echo -e "${RED}$1${NC}"; }

download_file() {
    local url="$1"; local dest="$2"; local filename; filename=$(basename "$dest")
    echo "Downloading ${filename}..."
    if ! curl -s -f -L -o "$dest" "$url"; then
        print_error "✗ ERROR: curl failed to download $filename from $url. Please check the URL and your connection."
        exit 1
    fi
}

# --- Main Installation Logic ---
main() {
    if [ "$(id -u)" -ne 0 ]; then print_error "This script must be run as root."; exit 1; fi

    print_warning "Removing previous failed installations to ensure a clean state..."
    rm -rf "${INSTALL_DIR}"
    rm -f /usr/local/bin/vm-hardener

    echo "=================================================="
    echo "VM Host Hardener v2.0.1 - Final Installer"
    echo "=================================================="
    print_message "Installing to: ${INSTALL_DIR}"

    # 1. Create directory structure
    mkdir -p "${INSTALL_DIR}/config" "${INSTALL_DIR}/modules"

    # 2. Download all modules and config
    print_message "--- Downloading script components ---"
    download_file "${BASE_URL}/config/settings.conf" "${INSTALL_DIR}/config/settings.conf"
    local modules=("00-common.sh" "01-prerequisites.sh" "02-system-updates.sh" "03-ssh-hardening.sh" "04-firewall.sh" "05-libvirt-hardening.sh" "06-kernel-hardening.sh" "07-storage-security.sh" "08-monitoring-auditing.sh" "09-backups.sh" "10-security-report.sh")
    for module in "${modules[@]}"; do download_file "${BASE_URL}/modules/${module}" "${INSTALL_DIR}/modules/${module}"; done
    print_message "✓ All components downloaded successfully."

    # 3. Create the simplified and corrected main script
    print_message "--- Creating main executable with a permanent fix ---"
    tee "${MAIN_SCRIPT_PATH}" > /dev/null <<'EOF'
#!/bin/bash
set -e
readonly INSTALL_DIR="/opt/vm-host-hardener"
source "${INSTALL_DIR}/modules/00-common.sh"
main() {
    print_header "VM Host Hardener v${VERSION}"
    if [ "$(id -u)" -ne 0 ]; then print_error "Must be root."; exit 1; fi
    load_config; init_log
    log "===== VM Host Hardener v${VERSION} Started ====="
    run_module "01-prerequisites.sh"; run_module "02-system-updates.sh"
    run_module "03-ssh-hardening.sh"; run_module "04-firewall.sh"
    run_module "05-libvirt-hardening.sh"; run_module "06-kernel-hardening.sh"
    run_module "07-storage-security.sh"; run_module "08-monitoring-auditing.sh"
    run_module "09-backups.sh"; run_module "10-security-report.sh"
    print_header "Hardening process completed successfully!"
    log "===== VM Host Hardener Finished ====="
}
main
EOF
    print_message "✓ Main executable created correctly."

    # 4. Set permissions and create the symlink
    print_message "--- Finalizing installation ---"
    chmod +x "${MAIN_SCRIPT_PATH}"
    chmod +x "${INSTALL_DIR}"/modules/*.sh
    ln -sf "${MAIN_SCRIPT_PATH}" /usr/local/bin/vm-hardener
    print_message "✓ Permissions set and 'vm-hardener' command created."

    echo "=================================================="
    print_message "✓ Installation complete. This will now work."
    echo "=================================================="
    echo ""
    print_warning "--> ACTION REQUIRED: CONFIGURE YOUR USER AND SSH KEY <--"
    echo "  1. sudo nano ${INSTALL_DIR}/config/settings.conf"
    echo "  2. Change ADMIN_USER and paste your SSH public key."
    echo "  3. sudo vm-hardener"
    echo ""
}

main
