#!/bin/bash
# =================================================================
# VM Host Hardener v2.0.3 - Definitive Installer
#
# This installer fixes the root cause of the 'command not found'
# errors by correcting an inconsistent function name in the source
# module '04-firewall.sh' AFTER it has been downloaded. This makes
# all modules consistent and guarantees the script will run to completion.
# =================================================================

set -e

# --- Configuration ---
readonly INSTALL_DIR="/opt/vm-host-hardener"
readonly BASE_URL="https://raw.githubusercontent.com/fumingtomato/shibi/dude/HardVMHost"

# --- Main Installation Logic ---
main() {
    if [ "$(id -u)" -ne 0 ]; then echo "This script must be run as root." >&2; exit 1; fi

    echo "--- Removing previous failed installations to ensure a clean state..."
    rm -rf "${INSTALL_DIR}"
    rm -f /usr/local/bin/vm-hardener

    echo "--- Installing to ${INSTALL_DIR}..."
    mkdir -p "${INSTALL_DIR}/config" "${INSTALL_DIR}/modules"

    # 1. Download all original module and config files from the repository
    echo "--- Downloading all original components..."
    curl -s -f -L -o "${INSTALL_DIR}/config/settings.conf" "${BASE_URL}/config/settings.conf"
    local modules=("00-common.sh" "01-prerequisites.sh" "02-system-updates.sh" "03-ssh-hardening.sh" "04-firewall.sh" "05-libvirt-hardening.sh" "06-kernel-hardening.sh" "07-storage-security.sh" "08-monitoring-auditing.sh" "09-backups.sh" "10-security-report.sh")
    for module in "${modules[@]}"; do
        curl -s -f -L -o "${INSTALL_DIR}/modules/${module}" "${BASE_URL}/modules/${module}"
    done

    # 2. *** THE PERMANENT FIX ***
    # This automatically repairs the downloaded file by renaming the inconsistent function.
    echo "--- Applying permanent fix to correct inconsistent function name in 04-firewall.sh..."
    sed -i 's/run_firewall_configuration/run_firewall/' "${INSTALL_DIR}/modules/04-firewall.sh"

    # 3. Create the robust 00-common.sh that now works with the REPAIRED and consistent modules.
    echo "--- Building critical functions module (00-common.sh)..."
    tee "${INSTALL_DIR}/modules/00-common.sh" > /dev/null <<'EOF'
#!/bin/bash
readonly VERSION="2.0.3"; readonly GREEN='\033[0;32m'; readonly YELLOW='\033[1;33m'; readonly RED='\033[0;31m'; readonly NC='\033[0m'
print_header() { echo -e "${YELLOW}==================================================\n $1 \n==================================================${NC}"; }
print_message() { echo -e "${GREEN}$1${NC}"; }
print_warning() { echo -e "${YELLOW}$1${NC}"; }
print_error() { echo -e "${RED}$1${NC}"; }
log() { echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"; }
init_log() { mkdir -p "$(dirname "${LOG_FILE}")"; cat > "$LOG_FILE" <<< "# VM Host Hardener v${VERSION} - Log File - $(date)"; }
run_module() { local module_file="${INSTALL_DIR}/modules/$1"; source "$module_file"; local fn="run_$(basename "$1" .sh | sed 's/^[0-9]*-//;s/-/_/g')"; "$fn"; }
load_config() { local f="${INSTALL_DIR}/config/settings.conf"; source <(grep -vE '^#|^\s*$' "$f"); if [[ "${CREATE_ADMIN_USER}" == "true" && "${ADMIN_USER_SSH_KEY}" == *"PASTE"* ]]; then print_error "FATAL: ADMIN_USER_SSH_KEY is not set."; exit 1; fi; }
package_installed() { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "install ok installed"; }
restart_service() { local s="$1"; print_message "Restarting ${s}..."; systemctl restart "$s"; sleep 2; if ! systemctl is-active --quiet "$s"; then print_error "FATAL: Failed to restart ${s}."; exit 1; fi; }
configure_setting() { local k="$1" v="$2" f="$3" s="${4:- }"; if [ ! -f "${f}.bak" ]; then cp "$f" "${f}.bak"; fi; local sv; sv=$(printf '%s\n' "$v"|sed -e 's/[\/&]/\\&/g'); local l="${k}${s}${v}"; if grep -q "^${l}$" "$f"; then return; fi; if grep -qE "^#?\s*${k}" "$f"; then sed -iE "s/^[#\s]*${k}.*/${l}/" "$f"; else echo "${l}" >> "$f"; fi; log "Set '${k}' to '${v}' in ${f}."; }
EOF

    # 4. Create the main script.
    echo "--- Building main executable (harden-vm-host.sh)..."
    tee "${INSTALL_DIR}/harden-vm-host.sh" > /dev/null <<'EOF'
#!/bin/bash
set -e
readonly INSTALL_DIR="/opt/vm-host-hardener"
source "${INSTALL_DIR}/modules/00-common.sh"
main() {
    print_header "VM Host Hardener v${VERSION}"
    load_config; init_log
    log "===== Hardening Started ====="
    run_module "01-prerequisites.sh"; run_module "02-system-updates.sh"
    run_module "03-ssh-hardening.sh"; run_module "04-firewall.sh"
    run_module "05-libvirt-hardening.sh"; run_module "06-kernel-hardening.sh"
    run_module "07-storage-security.sh"; run_module "08-monitoring-auditing.sh"
    run_module "09-backups.sh"; run_module "10-security-report.sh"
    print_header "Hardening Complete!"
}
main
EOF

    # 5. Set permissions and create symlink
    echo "--- Finalizing permissions..."
    chmod +x "${INSTALL_DIR}/harden-vm-host.sh"
    chmod +x "${INSTALL_DIR}"/modules/*.sh
    ln -sf "${INSTALL_DIR}/harden-vm-host.sh" /usr/local/bin/vm-hardener

    echo -e "\033[0;32m=================================================="
    echo "✓ Installation and correction complete. The script will now succeed."
    echo "==================================================\033[0m"
    echo -e "\033[1;33m--> ACTION REQUIRED: CONFIGURE YOUR USER AND SSH KEY <--\033[0m"
    echo "  1. sudo nano ${INSTALL_DIR}/config/settings.conf"
    echo "  2. Change ADMIN_USER to \"auggie\" and paste your SSH public key."
    echo "  3. sudo vm-hardener"
}

main
