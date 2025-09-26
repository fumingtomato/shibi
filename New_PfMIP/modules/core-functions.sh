#!/bin/bash

# =================================================================
# CORE FUNCTIONS MODULE
# Basic utilities, color codes, and helper functions
# =================================================================

# Color codes for output
export GREEN='\033[38;5;208m'
export YELLOW='\033[1;33m'
export RED='\033[0;31m'
export BLUE='\033[1;33m'
export NC='\033[0m'

# Global variables
export INSTALLER_VERSION="16.0.0"
export INSTALLER_NAME="Multi-IP Bulk Mail Server Installer"
declare -ga IP_ADDRESSES=()
declare -ga IP_DOMAINS=()
export PRIMARY_IP=""
export IP_COUNT=0

# Logging functions
log_file="/var/log/mail-installer-$(date +%Y%m%d-%H%M%S).log"

log_message() {
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
    echo -e "${RED}$1${NC}"
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

# Get server's public IP
get_public_ip() {
    local ip=$(curl -s https://ipinfo.io/ip)
    if [ -z "$ip" ]; then
        ip=$(curl -s https://api.ipify.org)
    fi
    if [ -z "$ip" ]; then
        print_error "Could not determine server's public IP address"
        exit 1
    fi
    echo "$ip"
}

# Backup existing configuration
backup_config() {
    local service=$1
    local config_file=$2
    local backup_dir="/var/backups/mail-server/$(date +%Y%m%d-%H%M%S)"
    
    mkdir -p "$backup_dir"
    
    if [ -f "$config_file" ]; then
        cp "$config_file" "$backup_dir/$(basename $config_file).backup"
        print_message "Backed up $config_file to $backup_dir"
    fi
}

# Validate domain name
validate_domain() {
    local domain=$1
    # Updated regex to properly handle subdomains like mta1.fuelmonkies.com
    if [[ ! "$domain" =~ ^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]]; then
        print_error "Invalid domain format: $domain"
        return 1
    fi
    return 0
}

# Validate email address
validate_email() {
    local email=$1
    if [[ ! "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        print_error "Invalid email format: $email"
        return 1
    fi
    return 0
}

# Check system requirements
check_system_requirements() {
    print_header "Checking System Requirements"
    
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
    fi
    
    # Check available memory
    local mem_total=$(free -m | awk '/^Mem:/{print $2}')
    if [ "$mem_total" -lt 1024 ]; then
        print_warning "System has less than 1GB RAM. Performance may be affected."
    else
        print_message "Available RAM: ${mem_total}MB"
    fi
    
    # Check disk space
    local disk_free=$(df / | awk 'NR==2 {print $4}')
    if [ "$disk_free" -lt 5242880 ]; then
        print_error "Insufficient disk space. At least 5GB required."
        exit 1
    else
        print_message "Available disk space: $((disk_free/1024/1024))GB"
    fi
}

# Setup timezone
setup_timezone() {
    print_header "Timezone Configuration"
    
    current_tz=$(timedatectl | grep "Time zone" | awk '{print $3}')
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
    timedatectl set-timezone "$timezone"
    print_message "Timezone updated successfully."
}

export -f check_root get_public_ip backup_config validate_domain validate_email
export -f check_system_requirements setup_timezone
export -f print_message print_warning print_error print_header print_debug log_message
