#!/bin/bash

# =================================================================
# PACKAGES AND SYSTEM MODULE - FIXED VERSION
# System updates, package installation, and dependency management
# Fixed: Better package conflict resolution, retry logic, and error handling
# =================================================================

# Package lists
declare -a REQUIRED_PACKAGES=(
    "curl" "wget" "git" "unzip" "software-properties-common"
    "apt-transport-https" "ca-certificates" "gnupg" "lsb-release"
    "net-tools" "dnsutils" "whois" "sudo" "cron" "rsyslog"
    "ufw" "fail2ban" "iptables" "ipset"
)

declare -a MAIL_PACKAGES=(
    "postfix" "postfix-mysql" "postfix-pcre"
    "dovecot-core" "dovecot-imapd" "dovecot-pop3d" "dovecot-lmtpd"
    "dovecot-mysql" "dovecot-sieve" "dovecot-managesieved"
    "opendkim" "opendkim-tools" "opendmarc"
    "spamassassin" "spamc" "postgrey" "amavisd-new"
    "clamav" "clamav-daemon" "libclamunrar9"
)

declare -a WEB_PACKAGES=(
    "nginx" "apache2" "libapache2-mod-php"
    "php" "php-fpm" "php-mysql" "php-cli" "php-common"
    "php-mbstring" "php-xml" "php-curl" "php-zip"
    "php-gd" "php-imagick" "php-intl" "php-bcmath"
    "php-json" "php-opcache" "php-readline"
)

declare -a DATABASE_PACKAGES=(
    "mysql-server" "mysql-client"
    "redis-server" "memcached"
)

declare -a MONITORING_PACKAGES=(
    "htop" "iotop" "nethogs" "iftop" "vnstat"
    "sysstat" "monit" "prometheus-node-exporter"
    "mailgraph" "pflogsumm"
)

declare -a SSL_PACKAGES=(
    "certbot" "python3-certbot-nginx" "python3-certbot-apache"
)

# APT configuration for non-interactive installation
export DEBIAN_FRONTEND=noninteractive
export APT_LISTCHANGES_FRONTEND=none

# Configure APT for automated installation
configure_apt() {
    print_message "Configuring APT for automated installation..."
    
    # Create APT configuration for non-interactive mode
    cat > /etc/apt/apt.conf.d/99automated <<EOF
APT::Get::Assume-Yes "true";
APT::Get::force-yes "true";
Dpkg::Options {
   "--force-confdef";
   "--force-confold";
}
DPkg::Pre-Install-Pkgs {"/usr/sbin/dpkg-preconfigure --apt || true";};
EOF
    
    # Disable needrestart if present (Ubuntu 22.04+)
    if [ -f /etc/needrestart/needrestart.conf ]; then
        sed -i "s/^#\$nrconf{restart}.*/\$nrconf{restart} = 'a';/" /etc/needrestart/needrestart.conf
        sed -i "s/^#\$nrconf{kernelhints}.*/\$nrconf{kernelhints} = -1;/" /etc/needrestart/needrestart.conf
    fi
    
    # Configure debconf for non-interactive mode
    echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections
}

# Fix any broken packages
fix_broken_packages() {
    print_message "Checking for broken packages..."
    
    # Try to fix broken dependencies
    apt-get install -f -y &>/dev/null || true
    
    # Reconfigure any packages that need it
    dpkg --configure -a &>/dev/null || true
    
    # Clean package cache
    apt-get clean
    apt-get autoclean -y
    apt-get autoremove -y
    
    # Update package database
    apt-get update || {
        print_error "Failed to update package database"
        # Try to fix sources.list
        fix_apt_sources
        apt-get update
    }
}

# Fix APT sources if corrupted
fix_apt_sources() {
    print_message "Fixing APT sources..."
    
    # Backup current sources
    cp /etc/apt/sources.list /etc/apt/sources.list.backup.$(date +%s)
    
    # Detect OS and version
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        
        if [[ "$ID" == "ubuntu" ]]; then
            # Generate fresh Ubuntu sources
            cat > /etc/apt/sources.list <<EOF
deb http://archive.ubuntu.com/ubuntu/ $VERSION_CODENAME main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu/ $VERSION_CODENAME-updates main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu/ $VERSION_CODENAME-security main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu/ $VERSION_CODENAME-backports main restricted universe multiverse
EOF
        elif [[ "$ID" == "debian" ]]; then
            # Generate fresh Debian sources
            cat > /etc/apt/sources.list <<EOF
deb http://deb.debian.org/debian/ $VERSION_CODENAME main contrib non-free
deb http://security.debian.org/debian-security $VERSION_CODENAME-security main contrib non-free
deb http://deb.debian.org/debian/ $VERSION_CODENAME-updates main contrib non-free
EOF
        fi
    fi
}

# Update system packages with retry logic
update_system_packages() {
    print_header "Updating System Packages"
    
    configure_apt
    
    local max_retries=3
    local retry_count=0
    
    while [ $retry_count -lt $max_retries ]; do
        print_message "Updating package database (attempt $((retry_count+1))/$max_retries)..."
        
        if apt-get update 2>&1 | tee -a "$log_file"; then
            print_message "✓ Package database updated successfully"
            break
        else
            retry_count=$((retry_count+1))
            if [ $retry_count -lt $max_retries ]; then
                print_warning "Update failed, retrying in 5 seconds..."
                sleep 5
                fix_broken_packages
            else
                print_error "Failed to update package database after $max_retries attempts"
                return 1
            fi
        fi
    done
    
    # Upgrade existing packages
    print_message "Upgrading installed packages..."
    apt-get upgrade -y 2>&1 | tee -a "$log_file" || {
        print_warning "Some packages failed to upgrade"
        fix_broken_packages
    }
    
    # Perform distribution upgrade if needed
    if [ "$PERFORM_DIST_UPGRADE" == "yes" ]; then
        print_message "Performing distribution upgrade..."
        apt-get dist-upgrade -y 2>&1 | tee -a "$log_file" || {
            print_warning "Distribution upgrade had issues"
        }
    fi
    
    print_message "✓ System packages updated"
}

# Install a list of packages with error handling
install_packages() {
    local package_list=("$@")
    local failed_packages=()
    
    for package in "${package_list[@]}"; do
        if ! dpkg -l | grep -q "^ii.*$package"; then
            print_message "Installing $package..."
            
            if apt-get install -y "$package" 2>&1 | tee -a "$log_file"; then
                print_message "✓ $package installed successfully"
            else
                print_warning "Failed to install $package"
                failed_packages+=("$package")
            fi
        else
            print_debug "$package is already installed"
        fi
    done
    
    # Retry failed packages once
    if [ ${#failed_packages[@]} -gt 0 ]; then
        print_message "Retrying failed packages..."
        fix_broken_packages
        
        for package in "${failed_packages[@]}"; do
            print_message "Retry installing $package..."
            apt-get install -y "$package" 2>&1 | tee -a "$log_file" || {
                print_error "Could not install $package"
            }
        done
    fi
}

# Install required system packages
install_required_packages() {
    print_header "Installing Required System Packages"
    
    # Enable universe repository for Ubuntu
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        if [[ "$ID" == "ubuntu" ]]; then
            add-apt-repository universe -y 2>/dev/null || true
            apt-get update
        fi
    fi
    
    install_packages "${REQUIRED_PACKAGES[@]}"
    
    print_message "✓ Required packages installed"
}

# Install mail server packages with conflict resolution
install_mail_packages() {
    print_header "Installing Mail Server Packages"
    
    # Remove conflicting mail servers
    local conflicting_services=("sendmail" "exim4" "qmail" "nullmailer")
    for service in "${conflicting_services[@]}"; do
        if dpkg -l | grep -q "^ii.*$service"; then
            print_message "Removing conflicting package: $service"
            systemctl stop "$service" 2>/dev/null || true
            apt-get remove -y "$service*" 2>/dev/null || true
            apt-get purge -y "$service*" 2>/dev/null || true
        fi
    done
    
    # Pre-configure Postfix to avoid interactive prompts
    debconf-set-selections <<< "postfix postfix/mailname string $HOSTNAME"
    debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Internet Site'"
    debconf-set-selections <<< "postfix postfix/destinations string $HOSTNAME, localhost"
    
    # Install mail packages
    install_packages "${MAIL_PACKAGES[@]}"
    
    # Ensure mail services are stopped during configuration
    systemctl stop postfix 2>/dev/null || true
    systemctl stop dovecot 2>/dev/null || true
    systemctl stop opendkim 2>/dev/null || true
    systemctl stop opendmarc 2>/dev/null || true
    systemctl stop spamassassin 2>/dev/null || true
    systemctl stop clamav-daemon 2>/dev/null || true
    
    print_message "✓ Mail server packages installed"
}

# Install web server packages with PHP version selection
install_web_packages() {
    print_header "Installing Web Server Packages"
    
    # Detect available PHP version
    local php_version=""
    if apt-cache show php8.2 &>/dev/null; then
        php_version="8.2"
    elif apt-cache show php8.1 &>/dev/null; then
        php_version="8.1"
    elif apt-cache show php8.0 &>/dev/null; then
        php_version="8.0"
    elif apt-cache show php7.4 &>/dev/null; then
        php_version="7.4"
    fi
    
    if [ ! -z "$php_version" ]; then
        print_message "Installing PHP $php_version"
        
        # Update package list with specific PHP version
        local php_packages=()
        for pkg in "${WEB_PACKAGES[@]}"; do
            if [[ "$pkg" == php* ]] && [[ "$pkg" != "php" ]]; then
                # Replace php- with php{version}-
                php_packages+=("php${php_version}${pkg#php}")
            else
                php_packages+=("$pkg")
            fi
        done
        
        install_packages "${php_packages[@]}"
    else
        install_packages "${WEB_PACKAGES[@]}"
    fi
    
    # Stop web services during configuration
    systemctl stop nginx 2>/dev/null || true
    systemctl stop apache2 2>/dev/null || true
    
    print_message "✓ Web server packages installed"
}

# Install database packages with security configuration
install_database_packages() {
    print_header "Installing Database Packages"
    
    # Pre-configure MySQL to avoid prompts
    local mysql_root_pass=$(openssl rand -base64 32)
    debconf-set-selections <<< "mysql-server mysql-server/root_password password $mysql_root_pass"
    debconf-set-selections <<< "mysql-server mysql-server/root_password_again password $mysql_root_pass"
    
    # Install database packages
    install_packages "${DATABASE_PACKAGES[@]}"
    
    # Save MySQL root password
    echo "[client]" > /root/.my.cnf
    echo "user=root" >> /root/.my.cnf
    echo "password=$mysql_root_pass" >> /root/.my.cnf
    chmod 600 /root/.my.cnf
    
    # Stop database services during configuration
    systemctl stop mysql 2>/dev/null || true
    systemctl stop redis-server 2>/dev/null || true
    systemctl stop memcached 2>/dev/null || true
    
    print_message "✓ Database packages installed"
    print_message "MySQL root password saved in /root/.my.cnf"
}

# Install monitoring packages
install_monitoring_packages() {
    print_header "Installing Monitoring Packages"
    
    install_packages "${MONITORING_PACKAGES[@]}"
    
    # Configure vnstat for network monitoring
    if command -v vnstat &>/dev/null; then
        vnstat -u -i eth0 2>/dev/null || vnstat -u -i ens3 2>/dev/null || true
        systemctl enable vnstat 2>/dev/null || true
        systemctl start vnstat 2>/dev/null || true
    fi
    
    print_message "✓ Monitoring packages installed"
}

# Install SSL/TLS packages
install_ssl_packages() {
    print_header "Installing SSL/TLS Packages"
    
    # Add Certbot PPA for Ubuntu
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        if [[ "$ID" == "ubuntu" ]]; then
            add-apt-repository ppa:certbot/certbot -y 2>/dev/null || true
            apt-get update
        fi
    fi
    
    install_packages "${SSL_PACKAGES[@]}"
    
    print_message "✓ SSL/TLS packages installed"
}

# Clean up after installation
cleanup_packages() {
    print_message "Cleaning up package cache..."
    
    apt-get autoremove -y
    apt-get autoclean -y
    apt-get clean
    
    # Remove old kernels (keep current + 1 previous)
    if command -v purge-old-kernels &>/dev/null; then
        purge-old-kernels --keep 2 -y 2>/dev/null || true
    fi
    
    # Clear systemd journal if too large
    journalctl --vacuum-size=100M 2>/dev/null || true
    
    print_message "✓ Package cleanup completed"
}

# Main package installation function
install_all_packages() {
    print_header "Package Installation"
    
    # Configure APT first
    configure_apt
    
    # Fix any existing issues
    fix_broken_packages
    
    # Update system
    update_system_packages
    
    # Install packages in order
    install_required_packages
    install_mail_packages
    install_database_packages
    install_web_packages
    install_monitoring_packages
    install_ssl_packages
    
    # Cleanup
    cleanup_packages
    
    print_message "✓ All packages installed successfully"
}

# Check if specific package is installed
is_package_installed() {
    local package=$1
    dpkg -l | grep -q "^ii.*$package" && return 0 || return 1
}

# Get package version
get_package_version() {
    local package=$1
    dpkg -l | grep "^ii.*$package" | awk '{print $3}'
}

# Export functions
export -f configure_apt fix_broken_packages fix_apt_sources
export -f update_system_packages install_packages
export -f install_required_packages install_mail_packages
export -f install_web_packages install_database_packages
export -f install_monitoring_packages install_ssl_packages
export -f cleanup_packages install_all_packages
export -f is_package_installed get_package_version
