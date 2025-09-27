#!/bin/bash

# =================================================================
# CORE FUNCTIONS MODULE - FIXED VERSION
# Basic utilities, color codes, and helper functions
# Fixed: Added missing exports, improved validation, better error handling
# =================================================================

# Color codes for output
export GREEN='\033[38;5;208m'
export YELLOW='\033[1;33m'
export RED='\033[0;31m'
export BLUE='\033[1;33m'
export NC='\033[0m'

# Global variables
export INSTALLER_VERSION="16.0.1"
export INSTALLER_NAME="Multi-IP Bulk Mail Server Installer"
declare -ga IP_ADDRESSES=()
declare -ga IP_DOMAINS=()
declare -ga HOSTNAMES=()
export PRIMARY_IP=""
export IP_COUNT=0
export DOMAIN_NAME=""
export HOSTNAME=""
export SUBDOMAIN=""
export ADMIN_EMAIL=""
export BRAND_NAME=""
export ENABLE_STICKY_IP="n"
export CF_API_TOKEN=""
export CF_ZONE_ID=""

# Logging configuration
log_dir="/var/log"
log_file="${log_dir}/mail-installer-$(date +%Y%m%d-%H%M%S).log"

# Ensure log directory exists
if [ ! -d "$log_dir" ]; then
    mkdir -p "$log_dir"
fi

# Initialize log file with proper permissions
touch "$log_file"
chmod 640 "$log_file"

# Function to rotate log if it gets too large
rotate_log_if_needed() {
    local max_size=52428800  # 50MB
    if [ -f "$log_file" ] && [ $(stat -c%s "$log_file" 2>/dev/null || echo 0) -gt $max_size ]; then
        local rotated_log="${log_file}.$(date +%Y%m%d%H%M%S)"
        mv "$log_file" "$rotated_log"
        gzip "$rotated_log" &
        touch "$log_file"
        chmod 640 "$log_file"
    fi
}

# Logging functions
log_message() {
    rotate_log_if_needed
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" >> "$log_file"
}

print_debug() {
    [ "$DEBUG" = true ] && echo -e "[DEBUG] $1"
    log_message "[DEBUG] $1"
}

print_message() {
    echo -e "${GREEN}$1${NC}"
    log_message "[INFO] $1"
}

print_warning() {
    echo -e "${YELLOW}$1${NC}"
    log_message "[WARNING] $1"
}

print_error() {
    echo -e "${RED}$1${NC}" >&2
    log_message "[ERROR] $1"
}

print_header() {
    echo -e "${BLUE}==================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}==================================================${NC}"
    log_message "[HEADER] $1"
}

# Check if script is run as root
check_root() {
    if [ "$(id -u)" != "0" ]; then
        print_error "This script must be run as root or with sudo privileges"
        exit 1
    fi
}

# Get server's public IP with multiple fallback methods
get_public_ip() {
    local ip=""
    local methods=(
        "curl -s -4 https://ipinfo.io/ip"
        "curl -s -4 https://api.ipify.org"
        "curl -s -4 https://checkip.amazonaws.com"
        "curl -s -4 https://ifconfig.me"
        "curl -s -4 https://icanhazip.com"
        "wget -qO- -4 https://ipinfo.io/ip"
        "dig +short myip.opendns.com @resolver1.opendns.com"
    )
    
    for method in "${methods[@]}"; do
        ip=$(eval $method 2>/dev/null | grep -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' | head -1)
        if [ ! -z "$ip" ] && validate_ip_address "$ip"; then
            echo "$ip"
            return 0
        fi
    done
    
    print_error "Could not determine server's public IP address"
    exit 1
}

# Validate IP address format
validate_ip_address() {
    local ip=$1
    
    # Check basic format
    if [[ ! "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        return 1
    fi
    
    # Check each octet
    local IFS='.'
    local -a octets=($ip)
    for octet in "${octets[@]}"; do
        if [ $octet -gt 255 ] || [ $octet -lt 0 ]; then
            return 1
        fi
    done
    
    # Check for reserved ranges (optional)
    if [[ "$ip" =~ ^(0\.|127\.|169\.254\.|224\.|240\.|255\.255\.255\.255) ]]; then
        return 1
    fi
    
    return 0
}

# Backup existing configuration
backup_config() {
    local service=$1
    local config_file=$2
    local backup_dir="/var/backups/mail-server/$(date +%Y%m%d-%H%M%S)"
    
    # Create backup directory with proper permissions
    mkdir -p "$backup_dir"
    chmod 750 "$backup_dir"
    
    if [ -f "$config_file" ]; then
        cp -p "$config_file" "$backup_dir/$(basename $config_file).backup"
        chmod 640 "$backup_dir/$(basename $config_file).backup"
        print_message "Backed up $config_file to $backup_dir"
    fi
    
    # Keep only last 10 backups to save space
    local backup_parent="/var/backups/mail-server"
    if [ -d "$backup_parent" ]; then
        local backup_count=$(ls -1 "$backup_parent" | wc -l)
        if [ $backup_count -gt 10 ]; then
            ls -1t "$backup_parent" | tail -n +11 | while read old_backup; do
                rm -rf "$backup_parent/$old_backup"
                print_debug "Removed old backup: $old_backup"
            done
        fi
    fi
}

# Validate domain name with comprehensive checks
validate_domain() {
    local domain=$1
    
    # Check if domain is empty
    if [ -z "$domain" ]; then
        print_error "Domain name cannot be empty"
        return 1
    fi
    
    # Check length (max 253 characters)
    if [ ${#domain} -gt 253 ]; then
        print_error "Domain name too long (max 253 characters)"
        return 1
    fi
    
    # Updated regex to properly handle subdomains and TLDs
    if [[ ! "$domain" =~ ^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]]; then
        print_error "Invalid domain format: $domain"
        return 1
    fi
    
    # Check for consecutive dots
    if [[ "$domain" =~ \.\. ]]; then
        print_error "Domain contains consecutive dots: $domain"
        return 1
    fi
    
    # Check each label length (max 63 characters)
    IFS='.' read -ra LABELS <<< "$domain"
    for label in "${LABELS[@]}"; do
        if [ ${#label} -gt 63 ]; then
            print_error "Domain label too long (max 63 characters): $label"
            return 1
        fi
        # Check label doesn't start or end with hyphen
        if [[ "$label" =~ ^- ]] || [[ "$label" =~ -$ ]]; then
            print_error "Domain label cannot start or end with hyphen: $label"
            return 1
        fi
    done
    
    return 0
}

# Validate email address with comprehensive checks
validate_email() {
    local email=$1
    
    # Check if email is empty
    if [ -z "$email" ]; then
        print_error "Email address cannot be empty"
        return 1
    fi
    
    # Check length (max 320 characters as per RFC)
    if [ ${#email} -gt 320 ]; then
        print_error "Email address too long (max 320 characters)"
        return 1
    fi
    
    # Basic email format validation
    if [[ ! "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        print_error "Invalid email format: $email"
        return 1
    fi
    
    # Check for consecutive dots in local part
    local local_part="${email%@*}"
    if [[ "$local_part" =~ \.\. ]]; then
        print_error "Email local part contains consecutive dots: $email"
        return 1
    fi
    
    # Check domain part
    local domain_part="${email#*@}"
    if ! validate_domain "$domain_part"; then
        return 1
    fi
    
    return 0
}

# Check system requirements with detailed reporting
check_system_requirements() {
    print_header "Checking System Requirements"
    
    local issues=0
    
    # Check OS
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        print_message "Operating System: $NAME $VERSION"
        
        if [[ ! "$ID" =~ ^(ubuntu|debian)$ ]]; then
            print_warning "This installer is optimized for Ubuntu/Debian. Continue at your own risk."
            read -p "Continue anyway? (y/n): " continue_install
            if [[ "$continue_install" != "y" ]]; then
                exit 1
            fi
        fi
        
        # Check for specific versions
        if [[ "$ID" == "ubuntu" ]]; then
            local version_num=$(echo "$VERSION_ID" | cut -d'.' -f1)
            if [ "$version_num" -lt 20 ]; then
                print_warning "Ubuntu version $VERSION_ID is older than recommended (20.04+)"
                issues=$((issues + 1))
            fi
        elif [[ "$ID" == "debian" ]]; then
            local version_num=$(echo "$VERSION_ID" | cut -d'.' -f1)
            if [ "$version_num" -lt 10 ]; then
                print_warning "Debian version $VERSION_ID is older than recommended (10+)"
                issues=$((issues + 1))
            fi
        fi
    else
        print_error "Cannot determine OS version"
        issues=$((issues + 1))
    fi
    
    # Check CPU cores
    local cpu_cores=$(nproc 2>/dev/null || echo 1)
    if [ "$cpu_cores" -lt 2 ]; then
        print_warning "System has only $cpu_cores CPU core(s). Recommended: 2+"
        issues=$((issues + 1))
    else
        print_message "CPU cores: $cpu_cores"
    fi
    
    # Check available memory
    local mem_total=$(free -m | awk '/^Mem:/{print $2}')
    if [ "$mem_total" -lt 1024 ]; then
        print_warning "System has less than 1GB RAM (${mem_total}MB). Performance may be affected."
        issues=$((issues + 1))
    elif [ "$mem_total" -lt 2048 ]; then
        print_warning "System has ${mem_total}MB RAM. Recommended: 2GB+"
        issues=$((issues + 1))
    else
        print_message "Available RAM: ${mem_total}MB"
    fi
    
    # Check disk space
    local disk_free=$(df / | awk 'NR==2 {print $4}')
    local disk_free_gb=$((disk_free/1024/1024))
    if [ "$disk_free" -lt 5242880 ]; then
        print_error "Insufficient disk space. At least 5GB required (have ${disk_free_gb}GB)."
        exit 1
    elif [ "$disk_free" -lt 10485760 ]; then
        print_warning "Disk space is ${disk_free_gb}GB. Recommended: 10GB+"
        issues=$((issues + 1))
    else
        print_message "Available disk space: ${disk_free_gb}GB"
    fi
    
    # Check swap
    local swap_total=$(free -m | awk '/^Swap:/{print $2}')
    if [ "$swap_total" -eq 0 ]; then
        print_warning "No swap configured. Recommended for systems with less than 4GB RAM"
        issues=$((issues + 1))
    else
        print_message "Swap space: ${swap_total}MB"
    fi
    
    # Check network connectivity
    print_message "Checking network connectivity..."
    if ping -c 1 -W 2 8.8.8.8 &>/dev/null || ping -c 1 -W 2 1.1.1.1 &>/dev/null; then
        print_message "✓ Internet connectivity OK"
    else
        print_error "No internet connectivity detected"
        exit 1
    fi
    
    # Check DNS resolution
    if host google.com &>/dev/null || nslookup google.com &>/dev/null; then
        print_message "✓ DNS resolution working"
    else
        print_warning "DNS resolution issues detected"
        issues=$((issues + 1))
    fi
    
    # Check for conflicting services
    local conflicting_services=("sendmail" "exim4" "qmail")
    for service in "${conflicting_services[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            print_warning "Conflicting mail service detected: $service"
            print_message "This should be removed or disabled before installation"
            issues=$((issues + 1))
        fi
    done
    
    # Summary
    if [ $issues -gt 0 ]; then
        print_warning "System check completed with $issues warning(s)"
        read -p "Continue with installation? (y/n): " continue_anyway
        if [[ "$continue_anyway" != "y" ]]; then
            exit 1
        fi
    else
        print_message "✓ All system requirements met"
    fi
}

# Setup timezone with validation
setup_timezone() {
    print_header "Timezone Configuration"
    
    # Check if timedatectl is available
    if ! command -v timedatectl &>/dev/null; then
        print_warning "timedatectl not available. Skipping timezone configuration."
        export timezone="UTC"
        return
    fi
    
    current_tz=$(timedatectl show --property=Timezone --value 2>/dev/null || echo "UTC")
    print_message "Current timezone: $current_tz"
    
    echo -e "\nSelect a timezone:"
    echo "1) America/New_York (Eastern Time)"
    echo "2) America/Chicago (Central Time)"
    echo "3) America/Denver (Mountain Time)"
    echo "4) America/Los_Angeles (Pacific Time)"
    echo "5) Europe/London"
    echo "6) Europe/Paris"
    echo "7) Asia/Tokyo"
    echo "8) Australia/Sydney"
    echo "9) UTC"
    echo "10) Other (specify)"
    echo "11) Keep current: $current_tz"
    
    read -p "Enter your choice [1-11]: " tz_choice
    
    case $tz_choice in
        1) timezone="America/New_York" ;;
        2) timezone="America/Chicago" ;;
        3) timezone="America/Denver" ;;
        4) timezone="America/Los_Angeles" ;;
        5) timezone="Europe/London" ;;
        6) timezone="Europe/Paris" ;;
        7) timezone="Asia/Tokyo" ;;
        8) timezone="Australia/Sydney" ;;
        9) timezone="UTC" ;;
        10) 
            read -p "Enter timezone (e.g., Asia/Singapore): " timezone
            # Validate timezone
            if ! timedatectl list-timezones 2>/dev/null | grep -q "^${timezone}$"; then
                print_error "Invalid timezone: $timezone"
                timezone="$current_tz"
                return 1
            fi
            ;;
        11|"") 
            timezone="$current_tz"
            print_message "Keeping current timezone: $timezone"
            return
            ;;
        *) 
            print_error "Invalid selection. Keeping current timezone."
            timezone="$current_tz"
            return
            ;;
    esac
    
    print_message "Setting timezone to: $timezone"
    if timedatectl set-timezone "$timezone" 2>/dev/null; then
        print_message "Timezone updated successfully."
    else
        print_error "Failed to set timezone. Keeping current setting."
        timezone="$current_tz"
    fi
    
    export timezone
}

# Export all functions and variables
export -f check_root get_public_ip backup_config validate_domain validate_email
export -f check_system_requirements setup_timezone validate_ip_address
export -f print_message print_warning print_error print_header print_debug log_message
export -f rotate_log_if_needed

# Export the log file path
export log_file
