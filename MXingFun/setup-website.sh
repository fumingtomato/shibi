#!/bin/bash

# =================================================================
# WEBSITE SETUP FOR BULK EMAIL COMPLIANCE - AUTOMATIC, NO QUESTIONS
# Version: 17.0.6 - FIXED DATABASE ACCESS FOR WEB SERVER
# Creates compliance website automatically with all required pages
# FIXED: SSL certificates include ALL subdomains properly
# FIXED: Database password accessible to web server
# ADDED: Backend integration for user password changes and global colors
# =================================================================

# Colors
GREEN='\033[38;5;208m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[1;33m'
NC='\033[0m'

print_message() {
    echo -e "${GREEN}$1${NC}"
}

print_error() {
    echo -e "${RED}$1${NC}" >&2
}

print_warning() {
    echo -e "${YELLOW}$1${NC}"
}

print_header() {
    echo -e "${BLUE}==================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}==================================================${NC}"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    print_error "This script must be run as root"
    exit 1
fi

print_header "Website Setup for Bulk Email Compliance"
echo ""

# Load configuration from installer
if [ -f "$(pwd)/install.conf" ]; then
    source "$(pwd)/install.conf"
elif [ -f "/root/mail-installer/install.conf" ]; then
    source "/root/mail-installer/install.conf"
fi

# Get domain from system if not in config
if [ -z "$DOMAIN_NAME" ]; then
    if [ -f /etc/postfix/main.cf ]; then
        DOMAIN_NAME=$(postconf -h mydomain 2>/dev/null)
    fi
    
    if [ -z "$DOMAIN_NAME" ]; then
        DOMAIN_NAME=$(hostname -d)
    fi
fi

# Get hostname with subdomain
if [ ! -z "$MAIL_SUBDOMAIN" ]; then
    HOSTNAME="$MAIL_SUBDOMAIN.$DOMAIN_NAME"
    MAIL_PREFIX="$MAIL_SUBDOMAIN"
else
    HOSTNAME=${HOSTNAME:-"mail.$DOMAIN_NAME"}
    MAIL_PREFIX="mail"
fi

# Get primary IP if not in config
if [ -z "$PRIMARY_IP" ]; then
    PRIMARY_IP=$(curl -s https://ipinfo.io/ip 2>/dev/null || hostname -I | awk '{print $1}')
fi

# Get admin email
if [ -z "$ADMIN_EMAIL" ]; then
    ADMIN_EMAIL="${FIRST_EMAIL:-admin@$DOMAIN_NAME}"
fi

# Get database password
if [ -f /root/.mail_db_password ]; then
    DB_PASS=$(cat /root/.mail_db_password)
fi

# Get current date
CURRENT_DATE=$(date +'%B %d, %Y')
CURRENT_YEAR=$(date +%Y)

echo "Domain: $DOMAIN_NAME"
echo "Mail Server: $HOSTNAME"
echo "Mail Prefix: $MAIL_PREFIX"
echo "Primary IP: $PRIMARY_IP"
echo "Admin Email: $ADMIN_EMAIL"
echo ""

# Build list of ALL subdomains for SSL
SSL_DOMAINS="$DOMAIN_NAME www.$DOMAIN_NAME $HOSTNAME"

# Add numbered subdomains if multiple IPs
if [ ${#IP_ADDRESSES[@]} -gt 1 ]; then
    for i in $(seq 1 $((${#IP_ADDRESSES[@]} - 1))); do
        SSL_DOMAINS="$SSL_DOMAINS ${MAIL_PREFIX}${i}.$DOMAIN_NAME"
    done
fi

echo "SSL will be configured for: $SSL_DOMAINS"
echo ""

# ===================================================================
# CRITICAL FIX: CREATE WEB-ACCESSIBLE DATABASE CONFIGURATION
# ===================================================================

print_header "Setting Up Database Access for Web Server"

# Create a secure directory for web configuration
WEB_CONFIG_DIR="/etc/mail-web-config"
mkdir -p "$WEB_CONFIG_DIR"

# Copy database password to web-accessible location with proper permissions
if [ ! -z "$DB_PASS" ]; then
    echo "$DB_PASS" > "$WEB_CONFIG_DIR/db_password"
    
    # Set permissions so web server can read it
    chmod 644 "$WEB_CONFIG_DIR/db_password"
    
    # Also create a PHP config file for easier access
    cat > "$WEB_CONFIG_DIR/db_config.php" <<EOF
<?php
// Database configuration for mail server web interface
define('DB_HOST', 'localhost');
define('DB_USER', 'mailuser');
define('DB_PASS', '$DB_PASS');
define('DB_NAME', 'mailserver');

// Alternative host if localhost fails
define('DB_HOST_ALT', '127.0.0.1');
?>
EOF
    
    chmod 644 "$WEB_CONFIG_DIR/db_config.php"
    
    print_message "✓ Database configuration created for web access"
else
    print_warning "⚠ Database password not found - web interface may not work"
fi

# ===================================================================
# 1. INSTALL NGINX AND PHP
# ===================================================================

print_header "Installing Web Server and PHP"

# Install Nginx
if ! command -v nginx &> /dev/null; then
    echo "Installing Nginx..."
    apt-get update > /dev/null 2>&1
    DEBIAN_FRONTEND=noninteractive apt-get install -y nginx > /dev/null 2>&1
    
    if [ $? -eq 0 ]; then
        print_message "✓ Nginx installed"
    else
        print_error "✗ Failed to install Nginx"
        exit 1
    fi
else
    print_message "✓ Nginx already installed"
fi

# Install PHP for backend processing
echo "Installing PHP and required extensions..."
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    php-fpm php-mysql php-json php-mbstring \
    php-xml php-curl > /dev/null 2>&1

# Get PHP version
PHP_VERSION=$(php -v 2>/dev/null | head -n1 | cut -d' ' -f2 | cut -d'.' -f1,2)

if [ -z "$PHP_VERSION" ]; then
    # Try to detect PHP-FPM version
    PHP_FPM_SERVICE=$(systemctl list-units --all | grep php.*fpm | head -1 | awk '{print $1}')
    if [ ! -z "$PHP_FPM_SERVICE" ]; then
        PHP_VERSION=$(echo $PHP_FPM_SERVICE | grep -oP 'php\K[0-9.]+')
    fi
fi

if [ -z "$PHP_VERSION" ]; then
    PHP_VERSION="7.4"  # Default fallback
fi

print_message "✓ PHP $PHP_VERSION installed"

# Stop Apache if running (conflicts with nginx)
if systemctl is-active --quiet apache2; then
    echo "Stopping Apache2 (conflicts with Nginx)..."
    systemctl stop apache2
    systemctl disable apache2 2>/dev/null
fi

# ===================================================================
# 2. CREATE WEBSITE DIRECTORY
# ===================================================================

print_header "Creating Website Files"

WEB_ROOT="/var/www/$DOMAIN_NAME"

# Create directory structure
echo "Creating website directory: $WEB_ROOT"
mkdir -p "$WEB_ROOT"

# Check if directory was created
if [ ! -d "$WEB_ROOT" ]; then
    print_error "Failed to create website directory"
    exit 1
fi

# Create additional directories
mkdir -p "$WEB_ROOT/css"
mkdir -p "$WEB_ROOT/js"
mkdir -p "$WEB_ROOT/images"
mkdir -p "$WEB_ROOT/api"
mkdir -p "$WEB_ROOT/data"

# Create colors configuration file
echo '{"primary":"#667eea","secondary":"#764ba2"}' > "$WEB_ROOT/data/colors.json"
chmod 666 "$WEB_ROOT/data/colors.json"

# ===================================================================
# 3. CREATE WEBSITE CONTENT WITH BACKEND API (FIXED)
# ===================================================================

echo "Creating website pages and backend API..."

# Create PHP API endpoints for backend functionality with FIXED database access
cat > "$WEB_ROOT/api/auth.php" <<'APIAUTH'
<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

$input = json_decode(file_get_contents('php://input'), true);
$email = $input['email'] ?? '';
$password = $input['password'] ?? '';

if (empty($email) || empty($password)) {
    http_response_code(400);
    echo json_encode(['error' => 'Email and password required']);
    exit;
}

// FIXED: Load database configuration from web-accessible location
$db_config_file = '/etc/mail-web-config/db_config.php';
if (file_exists($db_config_file)) {
    require_once($db_config_file);
} else {
    // Fallback: try to read password file directly
    $db_pass_file = '/etc/mail-web-config/db_password';
    if (file_exists($db_pass_file) && is_readable($db_pass_file)) {
        $db_pass = trim(file_get_contents($db_pass_file));
        define('DB_HOST', 'localhost');
        define('DB_USER', 'mailuser');
        define('DB_PASS', $db_pass);
        define('DB_NAME', 'mailserver');
        define('DB_HOST_ALT', '127.0.0.1');
    } else {
        http_response_code(500);
        echo json_encode(['error' => 'Database configuration missing']);
        exit;
    }
}

// Try connecting to database
$mysqli = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);

// If localhost fails, try 127.0.0.1
if ($mysqli->connect_error) {
    $mysqli = new mysqli(DB_HOST_ALT, DB_USER, DB_PASS, DB_NAME);
    
    if ($mysqli->connect_error) {
        http_response_code(500);
        echo json_encode(['error' => 'Database connection failed']);
        exit;
    }
}

// Query user
$stmt = $mysqli->prepare("SELECT email, password FROM virtual_users WHERE email = ? AND active = 1");
$stmt->bind_param("s", $email);
$stmt->execute();
$result = $stmt->get_result();

if ($row = $result->fetch_assoc()) {
    // Verify password using Dovecot's method
    $stored_pass = $row['password'];
    
    // Check if it's a plain password (for testing) or hashed
    if (strpos($stored_pass, '{') === 0) {
        // It's hashed, we need to verify properly
        // Try multiple verification methods
        
        // Method 1: Use doveadm if available
        $cmd = "doveadm pw -t " . escapeshellarg($stored_pass) . " -p " . escapeshellarg($password) . " 2>&1";
        exec($cmd, $output, $return_code);
        
        $verified = false;
        
        // Check for success in different ways
        if ($return_code === 0) {
            // Check output for verification message
            $output_str = implode(' ', $output);
            if (strpos($output_str, 'verified') !== false || empty($output_str)) {
                $verified = true;
            }
        }
        
        // Method 2: If doveadm fails, try password_verify for CRYPT passwords
        if (!$verified && strpos($stored_pass, '{SHA512-CRYPT}') === 0) {
            $hash = substr($stored_pass, 14); // Remove {SHA512-CRYPT} prefix
            if (function_exists('password_verify')) {
                $verified = password_verify($password, $hash);
            }
        }
        
        // Method 3: For PLAIN passwords stored with {PLAIN} prefix
        if (!$verified && strpos($stored_pass, '{PLAIN}') === 0) {
            $plain_pass = substr($stored_pass, 7); // Remove {PLAIN} prefix
            $verified = ($plain_pass === $password);
        }
        
        if ($verified) {
            // Success
            session_start();
            $_SESSION['user'] = $email;
            echo json_encode(['success' => true, 'user' => $email]);
        } else {
            // Debug info (remove in production)
            error_log("Auth failed - Return code: $return_code, Output: " . implode(' ', $output));
            http_response_code(401);
            echo json_encode(['error' => 'Invalid credentials']);
        }
    } else {
        // Plain password comparison (not recommended for production)
        if ($stored_pass === $password) {
            session_start();
            $_SESSION['user'] = $email;
            echo json_encode(['success' => true, 'user' => $email]);
        } else {
            http_response_code(401);
            echo json_encode(['error' => 'Invalid credentials']);
        }
    }
} else {
    http_response_code(401);
    echo json_encode(['error' => 'Invalid credentials']);
}

$stmt->close();
$mysqli->close();
APIAUTH

# Create password change API with FIXED database access
cat > "$WEB_ROOT/api/change-password.php" <<'APIPASS'
<?php
session_start();
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

if (!isset($_SESSION['user'])) {
    http_response_code(401);
    echo json_encode(['error' => 'Not authenticated']);
    exit;
}

$input = json_decode(file_get_contents('php://input'), true);
$current_password = $input['currentPassword'] ?? '';
$new_password = $input['newPassword'] ?? '';
$user_email = $_SESSION['user'];

if (empty($current_password) || empty($new_password)) {
    http_response_code(400);
    echo json_encode(['error' => 'Current and new passwords required']);
    exit;
}

if (strlen($new_password) < 8) {
    http_response_code(400);
    echo json_encode(['error' => 'New password must be at least 8 characters']);
    exit;
}

// FIXED: Load database configuration from web-accessible location
$db_config_file = '/etc/mail-web-config/db_config.php';
if (file_exists($db_config_file)) {
    require_once($db_config_file);
} else {
    $db_pass_file = '/etc/mail-web-config/db_password';
    if (file_exists($db_pass_file) && is_readable($db_pass_file)) {
        $db_pass = trim(file_get_contents($db_pass_file));
        define('DB_HOST', 'localhost');
        define('DB_USER', 'mailuser');
        define('DB_PASS', $db_pass);
        define('DB_NAME', 'mailserver');
        define('DB_HOST_ALT', '127.0.0.1');
    } else {
        http_response_code(500);
        echo json_encode(['error' => 'Database configuration missing']);
        exit;
    }
}

// Database connection
$mysqli = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);

if ($mysqli->connect_error) {
    $mysqli = new mysqli(DB_HOST_ALT, DB_USER, DB_PASS, DB_NAME);
    
    if ($mysqli->connect_error) {
        http_response_code(500);
        echo json_encode(['error' => 'Database connection failed']);
        exit;
    }
}

// Verify current password first
$stmt = $mysqli->prepare("SELECT password FROM virtual_users WHERE email = ?");
$stmt->bind_param("s", $user_email);
$stmt->execute();
$result = $stmt->get_result();

if ($row = $result->fetch_assoc()) {
    $stored_pass = $row['password'];
    
    // Verify current password
    $valid = false;
    if (strpos($stored_pass, '{') === 0) {
        // Hashed password
        $cmd = "doveadm pw -t '$stored_pass' -p " . escapeshellarg($current_password) . " 2>&1";
        exec($cmd, $output, $return_code);
        if ($return_code === 0 && strpos(implode('', $output), 'verified') !== false) {
            $valid = true;
        }
    } else {
        // Plain password
        $valid = ($stored_pass === $current_password);
    }
    
    if (!$valid) {
        http_response_code(401);
        echo json_encode(['error' => 'Current password is incorrect']);
        $stmt->close();
        $mysqli->close();
        exit;
    }
    
    // Hash new password using doveadm
    $cmd = "doveadm pw -s SHA512-CRYPT -p " . escapeshellarg($new_password) . " 2>/dev/null";
    $new_hash = trim(shell_exec($cmd));
    
    if (empty($new_hash)) {
        // Fallback to SSHA512 if SHA512-CRYPT fails
        $cmd = "doveadm pw -s SSHA512 -p " . escapeshellarg($new_password) . " 2>/dev/null";
        $new_hash = trim(shell_exec($cmd));
    }
    
    if (empty($new_hash)) {
        // Last resort - store plain (not recommended)
        $new_hash = "{PLAIN}$new_password";
    }
    
    // Update password
    $update_stmt = $mysqli->prepare("UPDATE virtual_users SET password = ? WHERE email = ?");
    $update_stmt->bind_param("ss", $new_hash, $user_email);
    
    if ($update_stmt->execute()) {
        echo json_encode(['success' => true, 'message' => 'Password changed successfully']);
    } else {
        http_response_code(500);
        echo json_encode(['error' => 'Failed to update password']);
    }
    
    $update_stmt->close();
} else {
    http_response_code(404);
    echo json_encode(['error' => 'User not found']);
}

$stmt->close();
$mysqli->close();
APIPASS

# Create colors API (global for all visitors)
cat > "$WEB_ROOT/api/colors.php" <<'APICOLORS'
<?php
session_start();
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST');
header('Access-Control-Allow-Headers: Content-Type');

$colors_file = dirname(__DIR__) . '/data/colors.json';

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    // Get current colors
    if (file_exists($colors_file)) {
        $colors = json_decode(file_get_contents($colors_file), true);
        echo json_encode($colors);
    } else {
        // Default colors
        echo json_encode(['primary' => '#667eea', 'secondary' => '#764ba2']);
    }
} elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Check if user is logged in
    if (!isset($_SESSION['user'])) {
        http_response_code(401);
        echo json_encode(['error' => 'Authentication required to change colors']);
        exit;
    }
    
    // Update colors (only logged in users can change)
    $input = json_decode(file_get_contents('php://input'), true);
    $primary = $input['primary'] ?? '#667eea';
    $secondary = $input['secondary'] ?? '#764ba2';
    
    // Validate hex colors
    if (!preg_match('/^#[0-9A-Fa-f]{6}$/', $primary) || !preg_match('/^#[0-9A-Fa-f]{6}$/', $secondary)) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid color format']);
        exit;
    }
    
    $colors = ['primary' => $primary, 'secondary' => $secondary];
    
    if (file_put_contents($colors_file, json_encode($colors))) {
        echo json_encode(['success' => true, 'colors' => $colors]);
    } else {
        http_response_code(500);
        echo json_encode(['error' => 'Failed to save colors']);
    }
} else {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
}
APICOLORS

# Create session check API
cat > "$WEB_ROOT/api/session.php" <<'APISESSION'
<?php
session_start();
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

if (isset($_SESSION['user'])) {
    echo json_encode(['authenticated' => true, 'user' => $_SESSION['user']]);
} else {
    echo json_encode(['authenticated' => false]);
}
APISESSION

# Create logout API
cat > "$WEB_ROOT/api/logout.php" <<'APILOGOUT'
<?php
session_start();
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

session_destroy();
echo json_encode(['success' => true, 'message' => 'Logged out successfully']);
APILOGOUT

# Create database test API for debugging
cat > "$WEB_ROOT/api/test-db.php" <<'APITEST'
<?php
// Test database connection (remove in production)
header('Content-Type: application/json');

$db_config_file = '/etc/mail-web-config/db_config.php';
$db_pass_file = '/etc/mail-web-config/db_password';

$status = [];

// Check if config files exist
$status['config_file_exists'] = file_exists($db_config_file);
$status['pass_file_exists'] = file_exists($db_pass_file);
$status['config_file_readable'] = is_readable($db_config_file);
$status['pass_file_readable'] = is_readable($db_pass_file);

// Try to load configuration
if (file_exists($db_config_file)) {
    require_once($db_config_file);
    $status['db_config_loaded'] = true;
    $status['db_host'] = DB_HOST ?? 'not set';
    $status['db_user'] = DB_USER ?? 'not set';
    $status['db_name'] = DB_NAME ?? 'not set';
    $status['db_pass_set'] = !empty(DB_PASS);
    
    // Try to connect
    $mysqli = @new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    if ($mysqli->connect_error) {
        // Try alternative host
        $mysqli = @new mysqli(DB_HOST_ALT, DB_USER, DB_PASS, DB_NAME);
        if ($mysqli->connect_error) {
            $status['db_connection'] = false;
            $status['error'] = 'Connection failed to both hosts';
        } else {
            $status['db_connection'] = true;
            $status['connected_to'] = DB_HOST_ALT;
            $mysqli->close();
        }
    } else {
        $status['db_connection'] = true;
        $status['connected_to'] = DB_HOST;
        $mysqli->close();
    }
} else {
    $status['db_config_loaded'] = false;
    $status['error'] = 'Configuration file not found';
}

echo json_encode($status, JSON_PRETTY_PRINT);
APITEST

# Set permissions for API files
chown -R www-data:www-data "$WEB_ROOT/api" 2>/dev/null || chown -R nginx:nginx "$WEB_ROOT/api" 2>/dev/null
chmod 755 "$WEB_ROOT/api"
chmod 644 "$WEB_ROOT/api/"*.php

# Create modern CSS file with dynamic colors support
cat > "$WEB_ROOT/css/style.css" <<'EOF'
/* Modern Email Service Website Styles with Dynamic Colors */
:root {
    --primary-color: #667eea;
    --secondary-color: #764ba2;
    --text-color: #333;
    --text-light: #6c757d;
    --bg-light: #f8f9fa;
    --white: #ffffff;
    --border-color: #e9ecef;
}

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
    line-height: 1.6;
    color: var(--text-color);
    background: var(--bg-light);
}

.container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 0 20px;
}

/* Header Styles */
header {
    background: linear-gradient(135deg, var(--primary-color) 0%, var(--secondary-color) 100%);
    color: var(--white);
    padding: 80px 0;
    text-align: center;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
}

header h1 {
    font-size: 3em;
    margin-bottom: 10px;
    font-weight: 700;
}

header p {
    font-size: 1.2em;
    opacity: 0.95;
}

/* Navigation */
nav {
    background: var(--white);
    box-shadow: 0 2px 5px rgba(0,0,0,0.1);
    padding: 20px 0;
    position: sticky;
    top: 0;
    z-index: 100;
}

nav ul {
    list-style: none;
    display: flex;
    justify-content: center;
    gap: 40px;
    flex-wrap: wrap;
}

nav a {
    color: var(--text-color);
    text-decoration: none;
    font-weight: 500;
    transition: color 0.3s;
    font-size: 1.1em;
}

nav a:hover {
    color: var(--primary-color);
}

/* Content Area */
.content {
    padding: 80px 0;
    background: var(--white);
    margin: 40px 0;
    border-radius: 10px;
    box-shadow: 0 2px 20px rgba(0,0,0,0.05);
}

.section {
    margin-bottom: 60px;
}

h2 {
    color: var(--primary-color);
    margin-bottom: 25px;
    font-size: 2.5em;
    font-weight: 600;
}

.card {
    background: var(--bg-light);
    padding: 40px;
    border-radius: 10px;
    margin-bottom: 30px;
    border: 1px solid var(--border-color);
}

.card h3 {
    color: #495057;
    margin-bottom: 15px;
    font-size: 1.5em;
}

/* Features Grid */
.features {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 30px;
    margin-top: 30px;
}

.feature {
    text-align: center;
    padding: 30px;
    background: var(--bg-light);
    border-radius: 10px;
    transition: transform 0.3s, box-shadow 0.3s;
}

.feature:hover {
    transform: translateY(-5px);
    box-shadow: 0 5px 20px rgba(102,126,234,0.1);
}

.feature-icon {
    font-size: 3em;
    margin-bottom: 15px;
}

/* Buttons */
.btn {
    display: inline-block;
    padding: 15px 40px;
    background: var(--primary-color);
    color: var(--white);
    text-decoration: none;
    border-radius: 50px;
    font-weight: 600;
    transition: background 0.3s, transform 0.3s;
    margin-top: 20px;
    border: none;
    cursor: pointer;
}

.btn:hover {
    background: var(--secondary-color);
    transform: translateY(-2px);
}

/* Footer */
footer {
    background: #2c3e50;
    color: var(--white);
    text-align: center;
    padding: 50px 0;
    margin-top: 80px;
}

footer a {
    color: var(--primary-color);
    text-decoration: none;
}

footer a:hover {
    text-decoration: underline;
}

/* Notices and Alerts */
.notice {
    background: #fff3cd;
    border: 1px solid #ffc107;
    color: #856404;
    padding: 20px;
    border-radius: 5px;
    margin: 20px 0;
}

/* Compliance Badges */
.compliance-badges {
    display: flex;
    justify-content: center;
    gap: 20px;
    margin: 40px 0;
    flex-wrap: wrap;
}

.badge {
    padding: 10px 20px;
    background: var(--white);
    border: 2px solid var(--primary-color);
    border-radius: 5px;
    font-weight: 600;
    color: var(--primary-color);
}

/* Login Form Styles */
.login-form {
    max-width: 500px;
    margin: 0 auto;
    padding: 40px;
    background: var(--white);
    border-radius: 10px;
    box-shadow: 0 2px 20px rgba(0,0,0,0.1);
}

.form-group {
    margin-bottom: 25px;
}

.form-group label {
    display: block;
    margin-bottom: 8px;
    font-weight: 600;
    color: var(--text-color);
}

.form-group input {
    width: 100%;
    padding: 12px;
    border: 1px solid var(--border-color);
    border-radius: 5px;
    font-size: 16px;
}

.form-group input:focus {
    outline: none;
    border-color: var(--primary-color);
}

.color-picker-group {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 20px;
    margin: 30px 0;
}

.color-input {
    display: flex;
    align-items: center;
    gap: 10px;
}

.color-input input[type="color"] {
    width: 50px;
    height: 50px;
    border: none;
    border-radius: 5px;
    cursor: pointer;
}

.user-info {
    background: var(--bg-light);
    padding: 15px;
    border-radius: 5px;
    margin-bottom: 20px;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.logout-btn {
    background: #dc3545;
    color: white;
    border: none;
    padding: 8px 20px;
    border-radius: 5px;
    cursor: pointer;
    font-weight: 600;
}

.logout-btn:hover {
    background: #c82333;
}

/* Responsive Design */
@media (max-width: 768px) {
    header h1 {
        font-size: 2em;
    }
    
    nav ul {
        flex-direction: column;
        gap: 10px;
        text-align: center;
    }
    
    h2 {
        font-size: 1.8em;
    }
    
    .features {
        grid-template-columns: 1fr;
    }
    
    .color-picker-group {
        grid-template-columns: 1fr;
    }
}
EOF

# Create JavaScript file for loading global colors on all pages
cat > "$WEB_ROOT/js/colors.js" <<'JSCOLORS'
// Load and apply global colors for all visitors
(function() {
    // Function to load colors from API
    function loadGlobalColors() {
        fetch('/api/colors.php')
            .then(response => response.json())
            .then(data => {
                if (data.primary) {
                    document.documentElement.style.setProperty('--primary-color', data.primary);
                }
                if (data.secondary) {
                    document.documentElement.style.setProperty('--secondary-color', data.secondary);
                }
            })
            .catch(error => {
                console.error('Failed to load colors:', error);
            });
    }
    
    // Load colors when page loads
    loadGlobalColors();
    
    // Reload colors every 30 seconds to catch updates
    setInterval(loadGlobalColors, 30000);
})();
JSCOLORS

print_message "✓ Backend API and dynamic color system created"

# Create Privacy Policy page
cat > "$WEB_ROOT/privacy.html" <<'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Privacy Policy - $DOMAIN_NAME</title>
    <link rel="stylesheet" href="/css/style.css">
    <script src="/js/colors.js"></script>
    <style>
        .privacy-content {
            line-height: 1.8;
        }
        .privacy-content h2 {
            margin-top: 40px;
            margin-bottom: 20px;
            color: var(--primary-color);
        }
        .privacy-content h3 {
            margin-top: 30px;
            margin-bottom: 15px;
            color: #495057;
        }
        .privacy-content p {
            margin-bottom: 15px;
        }
        .privacy-content ul {
            margin-left: 30px;
            margin-bottom: 20px;
        }
        .privacy-content li {
            margin-bottom: 10px;
        }
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>Privacy Policy</h1>
            <p>$DOMAIN_NAME</p>
        </div>
    </header>
    
    <nav>
        <ul>
            <li><a href="/">Home</a></li>
            <li><a href="/privacy.html">Privacy Policy</a></li>
            <li><a href="/terms.html">Terms of Service</a></li>
            <li><a href="/user-settings.html">User Settings</a></li>
        </ul>
    </nav>
    
    <div class="content">
        <div class="container privacy-content">
            <p><em>Last Updated: $CURRENT_DATE</em></p>
            
            <p>This Privacy Policy explains the data collection and use practices of this Publisher and all its related Websites owned or registered to Publisher. It also explains what this Publisher does with personally identifiable data that you may provide or transmit to this Publisher. For purposes of the General Data Protection Regulation (known as the "GDPR"), this Publisher is the controller of any personal data collected on its Websites.</p>

            <p>This Privacy Policy applies to this Website, its Web Pages and any other Websites, Web Pages or Domains related to, owned by or registered to this Publisher. It does not apply to any third-party websites, applications, products or services that may be promoted by this Publisher for which the Publisher does not control.</p>

            <p>By accessing this Website, you are consenting to the information collection and use practices described in this policy as well as the Acceptable Use Policy.</p>

            <p><strong>YOU MUST BE 18 YEARS OF AGE OR OLDER TO USE THIS WEBSITE. IF YOU DO NOT AGREE WITH THE TERMS OF THIS PRIVACY POLICY, OR THE TERMS OF USE PROVIDED ON THIS WEBSITE, PLEASE DO NOT USE THIS WEBSITE IN ANY WAY.</strong></p>

            <h2>Before using this Website, you should know:</h2>
            <ul>
                <li>Any personal information you provide to this Publisher through its Websites includes your consent to email you information, advertisements or promotions that appear to interest you.</li>
                <li>This Publisher sends email notifications, email newsletters and/or first-party and third-party promotions to its subscribers.</li>
                <li>If you no longer consent to receiving email from this Publisher, you can easily unsubscribe from this Publisher's email list by clicking the "unsubscribe" link at the bottom of Publisher's email.</li>
                <li>If you unsubscribe or opt-out of this Publisher's email list, they will no longer contact you, nor will this Publisher keep your personal information on file for any other reason than the maintenance of a "Do-Not-Contact" list to further ensure your privacy and compliance with the law.</li>
                <li>If you do not unsubscribe or opt-out, this Publisher may process, analyze, segment, sell, rent or transfer your data for any legally permissible purpose.</li>
            </ul>

            <h2>Changes to Privacy Policy:</h2>
            <p>This Privacy Policy changes from time to time and changes are effective upon posting. It is your sole responsibility to periodically review this policy for updates and you are solely responsible to be aware of any changes to this and all posted policies on this website.</p>

            <h2>Information Collection, Use, and Dissemination Practices:</h2>
            <p>This policy applies to Publisher's collection, use, storage and disclosure of information by Publisher (a) on its websites, including all its divisions, subsidiaries and related companies (collectively, the "Websites"), (b) on various third-party websites, and (c) to Publisher's other information collection, including the purchase of customer lists from third parties, or the use of customer lists from third-parties. The Publisher is not responsible for the information collection or privacy practices of third party-websites or applications.</p>

            <h2>1. Collection of Information</h2>
            
            <h3>1.1. User Direct Information:</h3>
            <p>Each time you provide information to Publisher on any Website page owned, operated or controlled by the Publisher, request information on any site, or submit any other form of inquiry, send us an email, subscribe to a newsletter, redeem an offer or otherwise transmit information via the site in any way, Publisher may obtain and collect personally identifiable information provided by you, including, but not limited to, your name, email address, mailing address, social security number, credit card information, telephone number, or any other form of data that you submit, including your user agent information, a cookie, IP address, a time-date stamp and potentially more information may be collected and recorded to a backup file for our records indefinitely.</p>

            <p>You may also provide us with information that, when combined with personally identifiable information, provides the Publisher with a better idea of who you are, including but not limited to your gender, birthday, marital status, and education level (collectively referred to as "personal information"). If you choose to access our Site, use our Services or purchase our products, we may require you to provide personal information as indicated on the forms throughout the Site.</p>

            <h3>1.2. Survey Information:</h3>
            <p>Publisher collects information from you when you voluntarily complete a survey, order form, or a registration page either online by using the internet, or offline by providing this information through the mail, in person or using a telephone. This information may also be collected by surveys, order forms, or registration pages operated by third-parties. This method of collection is collectively known as a survey ("Survey"). In such Surveys, the Publisher or a third-party may ask you to provide personal identifiable information Including your name, email address, street address, zip code, telephone numbers (Including cell phone numbers and carriers), birth date, gender, salary range, education and marital status, occupation, social security number, employment information, personal and online interests, and such other information as may be requested from time to time. The Publisher may also collect such information concerning you from another source and use that information in combination with information provided from this website. Completing the Surveys is completely voluntary, and you are under no obligation to provide Survey Information to Publisher or any third-party.</p>

            <h3>1.3. Third-Party List Information:</h3>
            <p>Publisher may collect information from you or about you when you provide information to a third-party and Publisher subsequently purchases, licenses, or otherwise acquires the information from the third-party. Such purchased information may include, but is not limited to, your name, email address, street address, zip code, telephone numbers (Including cell phone numbers and carriers), birth date, gender, salary range, education and marital status, occupation, industry of employment, personal and online interests, and such other information as the individual may have provided to the third-party. When acquiring this information, Publisher seeks assurances from the third-party that it has a right to transfer the information to Publisher and that the third-party has a right to provide offers from advertisers to you included on the third-party list.</p>

            <h3>1.4. Cookies, Web Beacons, and Other Info Collected Using Technology:</h3>
            <p>Publisher currently uses cookie and web beacon technology to associate certain Internet-related information about you with information about you in its database. Additionally, Publisher may use other new and evolving sources of information in the future.</p>

            <p><strong>(a) Cookies:</strong> Cookies are a feature of your browser software. If enabled, we may write cookies that may store small amounts of data on your computer about your visit to any of the pages of this Site. Cookies assist us in tracking which of our features appeal the most to you and what content you may have viewed on past visits. When you visit this site again, cookies can enable us to customize our content according to your preferences. We may use cookies to: keep track of the number of return visits to this site; accumulate and report aggregate, statistical information on website usage; deliver specific content to you based on your interests or past viewing history; save your password for ease of access to our Site. You can disable cookies, although the website may not function properly for you. Your browser preferences can be modified to accept or reject all cookies, or request a notification when a cookie is set. You may read more about cookies at http://cookiecentral.com. In order to use all of the features and functionality of Publisher's websites, you need to accept cookies.</p>

            <p>Third party vendors, including Google, use cookies to serve ads based on a user's prior visits to your website or other websites. Google's use of advertising cookies enables it and its partners to serve ads to your users based on their visit to your sites and/or other sites on the Internet. Users may opt out of personalized advertising by visiting Ads Settings.</p>

            <p><strong>(b) Web Beacons:</strong> A web beacon is a programming code that can be used to display an image on a web page, but can also be used to transfer your unique user identification to a database and associate you with previously acquired information about an individual in a database. This allows Publisher to track certain websites you visit. Web beacons are used to track online behavioral habits for marketing purposes to determine products or services you may be interested in. In addition to using web beacons on web pages, Publisher also uses web beacons in email messages sent to individuals listed in Publisher's database.</p>

            <p><strong>(c) IP Addresses:</strong> Publisher automatically tracks certain information based upon your behavior on the Site. We may use this information to do internal research on our users' demographics, interests, and behavior to better understand, protect and serve you and our community. This information may include the URL that you just came from (whether this URL is on the Site or not), which URL you next go to (whether this URL is on the Site or not), your computer browser information, and your IP address. Your Internet Protocol ("IP") is a unique Internet "address" which is assigned to you by your Internet Service Provider ("ISP"). For local area network ("LAN"), DSL, or cable modem users, an IP address may be permanently assigned to a particular computer. IP addresses are automatically logged by web servers, collecting information about a user's traffic patterns. While the IP address does not identify an individual by name, it may, with the cooperation of the ISP, be used to locate and identify an individual using the web. Your IP address can, however, reveal what geographic area you are connecting from, or which ISP you are using. Finally, other websites you visit have IP addresses, and we may collect the IP addresses of those websites and their pages.</p>

            <p><strong>(d) Computer Profiles:</strong> Publisher may also collect and accumulate other anonymous data which will help us understand and analyze the internet experience of our visitors. For instance, Publisher may accumulate visitor data relating to referring domain names, the type of browsers used, operating system software, screen resolutions, color capabilities, browser plug-ins, language settings, cookie preferences, search engine keywords and JavaScript enablement. When you provide us with personal identification information, we are able to use such visitor data to identify you.</p>

            <p><strong>(e) Data Analysis:</strong> Data analysis technology may be employed from time to time if used by a client of Publisher.</p>

            <p><strong>(f) New Technology:</strong> The use of technology on the internet, Including cookies and web beacons, is rapidly developing. As a result, Publisher strongly encourages individuals to revisit this policy for any updates regarding its use of new technology.</p>

            <h3>1.5. No Information Collected from Children:</h3>
            <p>Publisher will never knowingly collect any personal information about children under the age of 18. If Publisher obtains actual knowledge that it has collected personal information about a child under the age of 18, that information will be immediately deleted from its database. Because it does not collect such information, Publisher has no such information to knowingly use or to disclose to third-parties. Publisher has designed this policy in order to comply with the Children's Online Privacy Protection Act ("COPPA").</p>

            <h3>1.6. Credit Card Information:</h3>
            <p>Publisher may, in certain instances, collect credit card numbers and related information when an individual places an order from Publisher. When the credit card information is submitted to Publisher, such information is encrypted and is protected with SSL encryption software. Publisher will use the credit card information for purposes of processing and completing the purchase transaction, and the credit card information will be disclosed to third-parties only as necessary to complete the purchase transaction.</p>

            <h2>2. Use of Individual Information</h2>
            <p>The following section describes how Publisher uses personal information. The uses described in these sections may change at any time. Publisher may also broaden its use of your personal information. Publisher may also use your personal information to provide commercial promotional offers to individuals or entities through, among other things, email advertising, telephone marketing, direct mail marketing, banner advertising, SMS mobile and text messaging.</p>

            <h3>2.1. Discretion to Use Information:</h3>
            <p>The personal information collected on this Site and by third-parties will be used to operate the Site and to provide the Services or Products or carry out the transactions you have requested or authorized. Publisher may change or broaden its use of your personal information at any time. Publisher may use your personal information to provide promotional offers to individuals by means of email advertising, telephone marketing, direct mail marketing, online banner advertising, and package stuffers, and other possible uses. PUBLISHER MAY USE, SELL OR TRANSFER INDIVIDUAL INFORMATION TO THIRD-PARTIES FOR ANY LEGALLY PERMISSIBLE PURPOSE AT ITS SOLE DISCRETION.</p>

            <h3>2.2. Email:</h3>
            <p>Publisher may use your personal information to provide first and third-party advertisements and offers by email to you. Publisher may maintain separate email lists for different purposes. If you wish to end your email subscription from a particular list, you only need to press the unsubscribe link on the bottom or footer of any email message sent by this Publisher. Because Publisher only sends emails when you have agreed to receive emails from Publisher or you have agreed to receive emails from third-parties, statutes requiring certain formatting for unsolicited email are not applicable to email messages sent by Publisher. Publisher is not responsible for any email sent by a third-party to whom it has sold, transferred or otherwise licensed email contact information. Publisher is indemnified by all third-parties who mail or email data collected by Publisher as licensing would include procedures to lawfully transfer your email information to them for CAN-SPAM compliant uses. If a third-party that is licensed to use your data for any legal reason is not in compliance, such activity is directly the responsibility of the entity mailing to your email address and should be addressed with the company or individual that owns the email address from which you received mail from.</p>

            <h3>2.3. Profiling and Target Advertising:</h3>
            <p>Publisher uses your information to make and improve profiles of you and to track your online browsing habits and determine which areas of Publisher's websites are most frequently visited. This information helps Publisher to better understand your interests so that it can target advertising and promotions to you. Publisher may, at its discretion, target advertising by using email, direct mail, telephones, cell phones, and other means of communication to provide promotional offers.</p>

            <h3>2.4. Storage of Personal Information:</h3>
            <p>Publisher stores your information in a database on Publisher's servers. Our servers have security measures (such as a firewall) in place to protect against the loss, misuse, and alteration of the information under Publisher's control. Notwithstanding such measures, Publisher cannot guarantee that its security measures will prevent Publisher computers from being illegally accessed, and your information from being stolen or altered, and Publisher expressly disclaims responsibility or liability in the event of any damage resulting from such illegal activity by others.</p>

            <h2>3. Use of Personal Information</h2>
            
            <h3>3.1. Sale or Transfer to Third-Parties:</h3>
            <p>PUBLISHER MAY USE, SELL OR TRANSFER INDIVIDUAL INFORMATION TO THIRD-PARTIES FOR ANY LEGALLY PERMISSIBLE PURPOSE AT ITS SOLE DISCRETION. Publisher uses your personal information in the following (3) ways: Customer Service; Marketing; and Complying with the law.</p>

            <h3>3.2. Customer Service:</h3>
            <p>Publisher will use your personal information to respond to you, to process, validate and verify requests and/or purchase orders, to fulfill any of your requests and to tailor your experience on our Websites.</p>

            <h3>3.3. Marketing:</h3>
            <p>Publisher will use your personal information for any marketing and survey purpose on behalf of Publisher and its affiliates and subsidiaries to send information to you about additional goods or services that may be of interest to you. In addition, Publisher will disclose your personal information to third-party agents and independent contractors to help us conduct our marketing and survey efforts and to share with other companies in connection with marketing efforts, including but not limited to, direct marketing. You may have no relationship with these other companies.</p>

            <h3>3.4. Complying with Legal Processes:</h3>
            <p>Publisher will use or disclose your personal information in response to subpoenas, court orders, warrants, or legal process, or to otherwise establish or exercise our legal rights or defend against legal claims, or in the event you violate or breach an agreement with Publisher. Publisher will use and disclose your personal information if we believe you will harm the property or rights of Publisher, its owners, or those of Publisher's other customers. Finally, we will use or disclose your personal information if we believe it is necessary to share information in order to investigate, prevent, or take action regarding illegal activities, suspected fraud, situations involving potential threats to the physical safety of any person, violations of Publisher's acceptable use policy, or as otherwise required by law when responding to subpoenas, court orders and other legal processes.</p>

            <h3>3.5. Order Fulfillment:</h3>
            <p>Publisher will transfer your personal information to third-parties when necessary to provide a Product or Service that you order from such third-party while using Publisher's Websites or when responding to offers provided by Publisher.</p>

            <h3>3.6. Data Summary:</h3>
            <p>Publisher may sell or transfer non-individualized information, such as summary or aggregated anonymous information about all persons or sub-groups of persons.</p>

            <h2>4. Privacy Practices of Third-Parties</h2>
            
            <h3>4.1. Advertiser cookies and web beacons:</h3>
            <p>Advertising agencies, advertising networks, and other companies who place advertisements on the Websites and on the internet generally may use their own cookies, web beacons, and other technology to collect information about individuals. Publisher does not control the use of such technology and Publisher has no responsibility for the use of such technology to gather information about you.</p>

            <h3>4.2. Links:</h3>
            <p>The Websites and email messages sometimes contain hypertext links to the websites of third-parties. Publisher is not responsible for the privacy practices or the content of such other websites. Linked Websites may contain links to websites maintained by third-parties. Such links are provided for your convenience and reference only. Publisher does not operate or control in any respect any information, software, products or services available on such third party websites. The inclusion of a link to a website or to an article or blog on a website does not imply any endorsement of the services or the site, its contents, or its sponsoring organization.</p>

            <h2>5. SMS, Wireless and Other Mobile Offerings:</h2>
            <p>Some of the services that we provide may result in sending an SMS, wireless or other mobile offering to your cell phone. These should be obvious in the context of the offering at the time you sign up. By signing up, you are agreeing to receive these mobile offerings. You understand that your wireless carrier's standard rates apply to these messages. To unsubscribe or discontinue SMS messages, send "STOP", "END", "QUIT" to the SMS text message you have received. This process impacts only the future delivery of the particular SMS message offering, so you must send that message for each offering. This will not affect offerings sent on behalf of third-parties.</p>

            <h2>6. User Consumer Rights</h2>
            <p>For more information about protecting your privacy, you may wish to visit: <a href="http://www.ftc.gov" target="_blank">http://www.ftc.gov</a></p>

            <h2>SERVICE SUBSCRIPTION & EXPRESS CONSENT TO RECEIVE PHONE CALLS OR MESSAGES</h2>
            <p>Your use of this Website (and any associated offers, advertisements, newsletters, or other programs), and providing your email address and/or telephone number, constitutes a subscription and acceptance of the Terms of Use and Privacy Policy of the Website. Subscribers may receive recorded telephone messages regarding various special product offers and purchase incentives, and could be automatically entered into various related campaigns.</p>

            <p>By subscribing, such act constitutes your express written consent to be contacted by us or our partner companies via prerecorded telephone message for purposes of the Amended Telemarketing Sales Rule (16 CFR §310 et seq.), and the Electronic Signatures in Global and National Commerce Act (15 USC §96), as amended from time to time. The calls you are agreeing to receive may describe goods and services which may be offered by third-parties and any goods or services described in the call are not sold by or through Publisher.</p>

            <p>You are subscribing to receive calls only from Publisher and their partner third-party companies, and only at the specific number(s) you have provided to us if you did provide a number. Your consent will be effective if the number you have provided is a home, business, or mobile phone line, or if the number is registered on any state or federal Do-Not-Call (DNC) list as of the date of this consent. Publisher reserves the right to refrain from calling any number registered on a DNC list in connection with any promotions. This consent shall remain in effect until you revoke your consent and cancel your subscription.</p>

            <p>If you have additional questions about this policy, please contact Publisher from the "Contact Us" page of the Publisher's website.</p>
        </div>
    </div>
    
    <footer>
        <div class="container">
            <p>&copy; $CURRENT_YEAR $DOMAIN_NAME - All Rights Reserved</p>
            <p style="margin-top: 15px;">
                <a href="/privacy.html">Privacy Policy</a> | 
                <a href="/terms.html">Terms of Service</a>
            </p>
        </div>
    </footer>
</body>
</html>
EOF

# Note: The variables $DOMAIN_NAME, $CURRENT_DATE, and $CURRENT_YEAR will be replaced by their actual values when the script runs
sed -i "s/\$DOMAIN_NAME/$DOMAIN_NAME/g" "$WEB_ROOT/privacy.html"
sed -i "s/\$CURRENT_DATE/$CURRENT_DATE/g" "$WEB_ROOT/privacy.html"
sed -i "s/\$CURRENT_YEAR/$CURRENT_YEAR/g" "$WEB_ROOT/privacy.html"

# Create Terms of Service page
cat > "$WEB_ROOT/terms.html" <<'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Terms of Service - $DOMAIN_NAME</title>
    <link rel="stylesheet" href="/css/style.css">
    <script src="/js/colors.js"></script>
    <style>
        .terms-content {
            line-height: 1.8;
        }
        .terms-content h2 {
            margin-top: 40px;
            margin-bottom: 20px;
            color: var(--primary-color);
        }
        .terms-content h3 {
            margin-top: 30px;
            margin-bottom: 15px;
            color: #495057;
        }
        .terms-content p {
            margin-bottom: 15px;
        }
        .terms-content ul {
            margin-left: 30px;
            margin-bottom: 20px;
        }
        .terms-content li {
            margin-bottom: 10px;
        }
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>Terms of Service</h1>
            <p>$DOMAIN_NAME</p>
        </div>
    </header>
    
    <nav>
        <ul>
            <li><a href="/">Home</a></li>
            <li><a href="/privacy.html">Privacy Policy</a></li>
            <li><a href="/terms.html">Terms of Service</a></li>
            <li><a href="/user-settings.html">User Settings</a></li>
        </ul>
    </nav>
    
    <div class="content">
        <div class="container terms-content">
            <p><em>Last Updated: $CURRENT_DATE</em></p>
            
            <p>Welcome to our website. This site is maintained as a service to our customers. By using this site, you agree to comply with and be bound by the following terms and conditions of use. Please review these terms and conditions carefully. If you do not agree to these terms and conditions, you should not use this site.</p>
            
            <h2>Agreement</h2>
            <p>This Agreement (the "Agreement") specifies the Terms and Conditions for access to and use of $DOMAIN_NAME (the "Site") and describe the terms and conditions applicable to your access of and use of the Site. This Agreement may be modified at any time by Site upon posting of the modified agreement. Any such modifications shall be effective immediately. You can view the most recent version of these terms at any time at Site. Each use by you shall constitute and be deemed your unconditional acceptance of this Agreement.</p>

            <h2>Intellectual Property Ownership</h2>

            <h3>(a) Our Content</h3>
            <p>All content included on this site is and shall continue to be the property of Site or its content suppliers and is protected under applicable copyright, patent, trademark, and other proprietary rights. Any copying, redistribution, use or publication by you of any such content or any part of the Site is prohibited without express permission by Site. Under no circumstances will you acquire any ownership rights or other interest in any content by or through your use of this site. Site is the trademark or registered trademark of Site. Other product and company names mentioned on this Site may be trademarks of their respective owners.</p>

            <h3>(b) User Supplied Content</h3>
            <p>By accessing our forum, bulletin board, chat room, or any other user interactive area of our site, and placing any information in any of those areas, you hereby grant us a perpetual, irrevocable, royalty free license in and to such materials, including but not limited to the right to post, publish, transmit, distribute, create derivative works based upon, create translations of, modify, amend, enhance, change, display and publicly perform such materials in any form or media, whether now known or later discovered. You also grant to others who access the forum, bulletin board, chat room or any other user interactive area of our site a perpetual, non-revocable, royalty free license to view, download, store and reproduce your postings but such license is limited to the personal use and enjoyment of such other party.</p>

            <h3>(c) Personal Use</h3>
            <p>Site grants you a limited, revocable, nonexclusive license to use this site solely for your own personal use and not for republication, distribution, assignment, sublicense, sale, preparation of derivative works, or other use. You agree not to copy materials on the site, reverse engineer or break into the site, or use materials, products or services in violation of any law. The use of this website is at the discretion of Site and Site may terminate your use of this website at any time.</p>

            <h3>(d) Other Uses</h3>
            <p>All other use of Content from the Site, including, but not limited to uploading, downloading, modification, publication, transmission, participation in the transfer or sale of, copying, reproduction, republishing, creation of derivative works from, distribution, performance, display, incorporation into another web site, reproducing the Site (whether by linking, framing or any other method), or in any other way exploiting any of the Content, in whole or in part, is strictly prohibited without Site prior express written consent.</p>

            <h2>Disclaimers</h2>
            
            <h3>(a) DISCLAIMER OF WARRANTIES</h3>
            <p>THE INFORMATION ON THIS SITE IS PROVIDED ON AN "AS IS," "AS AVAILABLE" BASIS. YOU AGREE THAT USE OF THIS SITE IS AT YOUR SOLE RISK. Site DISCLAIMS ALL WARRANTIES OF ANY KIND, INCLUDING BUT NOT LIMITED TO ANY EXPRESS WARRANTIES, STATUTORY WARRANTIES, AND ANY IMPLIED WARRANTIES OF: MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT. YOUR SOLE AND EXCLUSIVE REMEDY RELATING TO YOUR USE OF THE SITE SHALL BE TO DISCONTINUE USING THE SITE.</p>

            <p>FURTHERMORE, Site DOES NOT WARRANT THAT USE OF THE SITE WILL BE UNINTERRUPTED, AVAILABLE AT ANY TIME OR FROM ANY LOCATION, SECURE OR ERROR-FREE, THAT DEFECTS WILL BE CORRECTED, OR THAT THE SERVICE IS FREE OF VIRUSES OR OTHER HARMFUL COMPONENTS. Site, ITS SUBSIDIARIES, VENDORS AND AFFILIATES DISCLAIM ANY RESPONSIBILITY FOR THE DELETION, FAILURE TO STORE, OR UNTIMELY DELIVERY OF ANY INFORMATION OR MATERIALS, AND ANY MATERIAL DOWNLOADED OR OTHERWISE OBTAINED THROUGH THE SITE. USE OF THE SITE'S SERVICES IS DONE AT YOUR OWN DISCRETION AND RISK, AND YOU WILL BE SOLELY RESPONSIBLE FOR ANY DAMAGES TO YOU COMPUTER SYSTEMS OR LOSS OF DATA THAT MAY RESULT FROM THE DOWNLOAD OF SUCH INFORMATION OR MATERIAL.</p>

            <h3>(b) LIMITATION OF LIABILITY</h3>
            <p>Site SHALL NOT BE RESPONSIBLE OR LIABLE TO PROVIDERS OR ANY THIRD PARTIES UNDER ANY CIRCUMSTANCES FOR ANY INDIRECT, CONSEQUENTIAL, SPECIAL, PUNITIVE OR EXEMPLARY DAMAGES OR LOSSES, INCLUDING BUT NOT LIMITED TO, DAMAGES FOR LOSS OF PROFITS, GOODWILL, USE, DATA OR OTHER INTANGIBLE LOSSES WHICH MAY BE INCURRED IN CONNECTION WITH Site OR THE SITE, OR USE THEREOF, OR ANY OF THE DATA OR OTHER MATERIALS TRANSMITTED THROUGH OR RESIDING ON THE SITE OR ANY SERVICES, OR INFORMATION PURCHASED, RECEIVED OR SOLD BY WAY OF THE SITE, REGARDLESS OF THE TYPE OF CLAIM OR THE NATURE OF THE CAUSE OF ACTION, EVEN IF Site HAS BEEN ADVISED OF THE POSSIBILITY OF DAMAGE OR LOSS.</p>

            <h3>(c) EARNINGS DISCLAIMERS</h3>
            <p>The information presented in this Website is intended to be for your educational and entertainment purposes only.</p>

            <p>We are not presenting you with a business opportunity.</p>

            <p>We are not presenting you with a distributorship.</p>

            <p>We are not making any claims as to income you may earn.</p>

            <p>We are not presenting you with an opportunity to get rich.</p>

            <p>Before embarking on any endeavor, please use caution and seek the advice your own personal professional advisors, such as your attorney and your accountant.</p>

            <p>Where income figures are mentioned (if any), those income figures are anecdotal information passed on to us concerning the results achieved by the individual sharing the information. We have performed no independent verification of the statements made by those individuals. Please do not assume that you will make those same income figures.</p>

            <p>Please do not construe any statement in this website as a claim or representation of average earnings. There are NO average earnings. Testimonials and statements of individuals are not to be construed as claims or representations of average earnings. We cannot, do not, and will not make any claims as to earnings, average, or otherwise.</p>

            <p>Success in any endeavor is based on many factors individual to you. We do not know your educational background, your skills, your prior experience, or the time you can and will devote to the endeavor.</p>

            <p>Please perform your own due diligence before embarking on any course of action. Follow the advice of your personal qualified advisors.</p>

            <p>There are risks in any endeavor that are not suitable for everyone. If you use capital, only "risk" capital should be used.</p>

            <p>There is no guarantee that you will earn any money using any of the ideas presented in our in materials. Examples in our materials are not to be interpreted as a promise or guarantee of earnings. Many factors will be important in determining your actual results and no guarantees are made that you will achieve results similar to ours or anybody else's. No guarantee is made that you will achieve any result at all from the ideas in our material.</p>

            <p>You agree that we will not share in your success, nor will we be responsible for your failure or for your actions in any endeavor you may undertake.</p>

            <p>Please understand that past performance cannot be an indication of possible future results.</p>

            <p>Materials in our product and our website may contain information that includes or is based upon forward-looking statements within the meaning of the securities litigation reform act of 1995. Forward-looking statements give our expectations or forecasts of future events. You can identify these statements by the fact that they do not relate strictly to historical or current facts. They use words such as "anticipate," "estimate," "expect," "project," "intend," "plan," "believe," and other words and terms of similar meaning in connection with a description of potential earnings or financial performance. Any and all forward looking statements in our materials are intended to express our opinion of earnings potential. They are opinions only and should not be relied upon as fact.</p>

            <h3>(g) Applicable Law</h3>
            <p>You agree that the laws of the state of Florida, without regard to conflicts of laws provisions will govern these Terms and Condition of Use and any dispute that may arise between you and Site or its affiliates. Venue shall be in United States.</p>

            <h3>(h) Arbitration</h3>
            <p>As part of the consideration that Site requires for viewing, using or interacting with this website, you agree to the use of binding arbitration for any claim, dispute, or controversy of any kind (whether in contract, tort or otherwise) arising out of or relating to this website. Arbitration shall be conducted pursuant to the rules of the American Arbitration Association which are in effect on the date a dispute is submitted to the American Arbitration Association. Information about the American Arbitration Association, its rules, and its forms are available from the American Arbitration Association, 335 Madison Avenue, Floor 10, New York, New York, 10017-4605. Hearing will take place in the city or county of Site. In no case shall you have the right to go to court or have a jury trial. You will not have the right to engage in pre-trial discovery except as provided in the rules; you will not have the right to participate as a representative or member of any class of claimants pertaining to any claim subject to arbitration; the arbitrator's decision will be final and binding with limited rights of appeal. The prevailing party shall be reimbursed by the other party for any and all costs associated with the dispute arbitration, including attorney fees, collection fees, investigation fees, and travel expenses.</p>

            <h3>(i) Severability</h3>
            <p>If any provision of this Agreement shall be adjudged by any court of competent jurisdiction to be unenforceable or invalid, that provision shall be limited or eliminated to the minimum extent necessary so that this Agreement will otherwise remain in full force and effect.</p>

            <h3>(j) Termination</h3>
            <p>Site may terminate this Agreement at any time, with or without notice, for any reason.</p>

            <h3>(k) Applicable Law</h3>
            <p>You agree that the laws of the state of Florida, without regard to conflicts of laws provisions will govern these Terms and Condition of Use and any dispute that may arise between you and Site or its affiliates. Venue shall be in Florida High Court.</p>

            <h3>(l) Arbitration</h3>
            <p>As part of the consideration that Site requires for viewing, using or interacting with this website, you agree to the use of binding arbitration for any claim, dispute, or controversy of any kind (whether in contract, tort or otherwise) arising out of or relating to this website. Arbitration shall be conducted pursuant to the rules of the American Arbitration Association which are in effect on the date a dispute is submitted to the American Arbitration Association. Information about the American Arbitration Association, its rules, and its forms are available from the American Arbitration Association, 335 Madison Avenue, Floor 10, New York, New York, 10017-4605. Hearing will take place in the city or county of Site. In no case shall you have the right to go to court or have a jury trial. You will not have the right to engage in pre-trial discovery except as provided in the rules; you will not have the right to participate as a representative or member of any class of claimants pertaining to any claim subject to arbitration; the arbitrator's decision will be final and binding with limited rights of appeal. The prevailing party shall be reimbursed by the other party for any and all costs associated with the dispute arbitration, including attorney fees, collection fees, investigation fees, and travel expenses.</p>

            <h3>(m) Severability</h3>
            <p>If any provision of this Agreement shall be adjudged by any court of competent jurisdiction to be unenforceable or invalid, that provision shall be limited or eliminated to the minimum extent necessary so that this Agreement will otherwise remain in full force and effect.</p>

            <h3>(n) Termination</h3>
            <p>Site may terminate this Agreement at any time, with or without notice, for any reason.</p>

            <h3>(o) Contact Information</h3>
            <p><strong>HOW TO CONTACT US:</strong><br>
            $FIRST_EMAIL</p>
        </div>
    </div>
    
    <footer>
        <div class="container">
            <p>&copy; $CURRENT_YEAR $DOMAIN_NAME - All Rights Reserved</p>
            <p style="margin-top: 15px;">
                <a href="/privacy.html">Privacy Policy</a> | 
                <a href="/terms.html">Terms of Service</a>
            </p>
        </div>
    </footer>
</body>
</html>
EOF

# Note: The variables $DOMAIN_NAME, $FIRST_EMAIL, $CURRENT_DATE, and $CURRENT_YEAR will be replaced by their actual values when the script runs
sed -i "s/\$DOMAIN_NAME/$DOMAIN_NAME/g" "$WEB_ROOT/terms.html"
sed -i "s/\$FIRST_EMAIL/$ADMIN_EMAIL/g" "$WEB_ROOT/terms.html"
sed -i "s/\$CURRENT_DATE/$CURRENT_DATE/g" "$WEB_ROOT/terms.html"
sed -i "s/\$CURRENT_YEAR/$CURRENT_YEAR/g" "$WEB_ROOT/terms.html"

# Create robots.txt
cat > "$WEB_ROOT/robots.txt" <<EOF
User-agent: *
Allow: /
Sitemap: https://$DOMAIN_NAME/sitemap.xml

# Privacy and compliance pages
Allow: /privacy.html
Allow: /terms.html
Allow: /user-settings.html

# Block API endpoints from crawling
Disallow: /api/
Disallow: /data/

# Allow CSS and JS
Allow: /css/
Allow: /js/

# Crawl-delay for respectful crawling
Crawl-delay: 1

# Major search engine bots
User-agent: Googlebot
Allow: /

User-agent: Bingbot
Allow: /

User-agent: Slurp
Allow: /

User-agent: DuckDuckBot
Allow: /

# Block bad bots
User-agent: AhrefsBot
Disallow: /

User-agent: SemrushBot
Disallow: /

User-agent: MJ12bot
Disallow: /

User-agent: DotBot
Disallow: /
EOF

# Create sitemap.xml
cat > "$WEB_ROOT/sitemap.xml" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
    <url>
        <loc>https://$DOMAIN_NAME/</loc>
        <lastmod>$(date +%Y-%m-%d)</lastmod>
        <changefreq>monthly</changefreq>
        <priority>1.0</priority>
    </url>
    <url>
        <loc>https://$DOMAIN_NAME/privacy.html</loc>
        <lastmod>$(date +%Y-%m-%d)</lastmod>
        <changefreq>monthly</changefreq>
        <priority>0.8</priority>
    </url>
    <url>
        <loc>https://$DOMAIN_NAME/terms.html</loc>
        <lastmod>$(date +%Y-%m-%d)</lastmod>
        <changefreq>monthly</changefreq>
        <priority>0.8</priority>
    </url>
    <url>
        <loc>https://$DOMAIN_NAME/user-settings.html</loc>
        <lastmod>$(date +%Y-%m-%d)</lastmod>
        <changefreq>weekly</changefreq>
        <priority>0.7</priority>
    </url>
</urlset>
EOF

# Create a simple contact page (optional but useful for compliance)
cat > "$WEB_ROOT/contact.html" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Contact Us - $DOMAIN_NAME</title>
    <link rel="stylesheet" href="/css/style.css">
    <script src="/js/colors.js"></script>
</head>
<body>
    <header>
        <div class="container">
            <h1>Contact Us</h1>
            <p>$DOMAIN_NAME</p>
        </div>
    </header>
    
    <nav>
        <ul>
            <li><a href="/">Home</a></li>
            <li><a href="/privacy.html">Privacy Policy</a></li>
            <li><a href="/terms.html">Terms of Service</a></li>
            <li><a href="/user-settings.html">User Settings</a></li>
        </ul>
    </nav>
    
    <div class="content">
        <div class="container">
            <div class="section">
                <h2>Get in Touch</h2>
                <div class="card">
                    <h3>Contact Information</h3>
                    <p>If you have any questions, concerns, or feedback, please don't hesitate to reach out to us.</p>
                    
                    <div style="margin-top: 30px;">
                        <p><strong>Email:</strong></p>
                        <p><a href="mailto:$ADMIN_EMAIL">$ADMIN_EMAIL</a></p>
                    </div>
                    
                    <div style="margin-top: 30px;">
                        <p><strong>For Privacy Concerns:</strong></p>
                        <p>Please review our <a href="/privacy.html">Privacy Policy</a> or contact us at the email above.</p>
                    </div>
                    
                    <div style="margin-top: 30px;">
                        <p><strong>To Unsubscribe:</strong></p>
                        <p>Please use the unsubscribe link in any email you've received from us. If you're having trouble, contact us at the email above with your request.</p>
                    </div>
                </div>
            </div>
            
            <div class="section">
                <h2>Legal Information</h2>
                <div class="card">
                    <p>This website is operated by $DOMAIN_NAME</p>
                    <p>Please review our <a href="/terms.html">Terms of Service</a> and <a href="/privacy.html">Privacy Policy</a> for more information about how we handle your data and our legal obligations.</p>
                </div>
            </div>
        </div>
    </div>
    
    <footer>
        <div class="container">
            <p>&copy; $CURRENT_YEAR $DOMAIN_NAME - All Rights Reserved</p>
            <p style="margin-top: 15px;">
                <a href="/privacy.html">Privacy Policy</a> | 
                <a href="/terms.html">Terms of Service</a>
            </p>
        </div>
    </footer>
</body>
</html>
EOF

# Update sitemap to include contact page
cat > "$WEB_ROOT/sitemap.xml" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
    <url>
        <loc>https://$DOMAIN_NAME/</loc>
        <lastmod>$(date +%Y-%m-%d)</lastmod>
        <changefreq>monthly</changefreq>
        <priority>1.0</priority>
    </url>
    <url>
        <loc>https://$DOMAIN_NAME/privacy.html</loc>
        <lastmod>$(date +%Y-%m-%d)</lastmod>
        <changefreq>monthly</changefreq>
        <priority>0.8</priority>
    </url>
    <url>
        <loc>https://$DOMAIN_NAME/terms.html</loc>
        <lastmod>$(date +%Y-%m-%d)</lastmod>
        <changefreq>monthly</changefreq>
        <priority>0.8</priority>
    </url>
    <url>
        <loc>https://$DOMAIN_NAME/user-settings.html</loc>
        <lastmod>$(date +%Y-%m-%d)</lastmod>
        <changefreq>weekly</changefreq>
        <priority>0.7</priority>
    </url>
    <url>
        <loc>https://$DOMAIN_NAME/contact.html</loc>
        <lastmod>$(date +%Y-%m-%d)</lastmod>
        <changefreq>monthly</changefreq>
        <priority>0.6</priority>
    </url>
</urlset>
EOF

# Set proper permissions for all created files
chmod 644 "$WEB_ROOT/robots.txt"
chmod 644 "$WEB_ROOT/sitemap.xml"
chmod 644 "$WEB_ROOT/contact.html"
chmod 644 "$WEB_ROOT/privacy.html"
chmod 644 "$WEB_ROOT/terms.html"

print_message "✓ All compliance pages, robots.txt, and sitemap.xml created successfully"

echo "Creating HTML pages with backend integration..."

# Homepage with only Manage Your Preferences section
cat > "$WEB_ROOT/index.html" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="Email services by $DOMAIN_NAME">
    <title>$DOMAIN_NAME</title>
    <link rel="stylesheet" href="/css/style.css">
    <script src="/js/colors.js"></script>
</head>
<body>
    <header>
        <div class="container">
            <h1>$DOMAIN_NAME</h1>
        </div>
    </header>
    
    <nav>
        <ul>
            <li><a href="/">Home</a></li>
            <li><a href="/privacy.html">Privacy Policy</a></li>
            <li><a href="/terms.html">Terms of Service</a></li>
            <li><a href="/user-settings.html">User Settings</a></li>
        </ul>
    </nav>
    
    <div class="content">
        <div class="container">
            <div class="section">
                <h2>Manage Your Preferences</h2>
                <div class="card">
                    <h3>Email Preferences</h3>
                    <p>You have complete control over the emails you receive from us. Every email includes an unsubscribe link that allows you to:</p>
                    <ul style="margin-left: 20px; margin-top: 15px; line-height: 2;">
                        <li>• Unsubscribe from all communications</li>
                        <li>• Update your email preferences</li>
                        <li>• Choose specific types of emails to receive</li>
                        <li>• Manage frequency settings</li>
                    </ul>
                    <div class="notice">
                        <strong>Important:</strong> To unsubscribe or manage your email preferences, please use the unsubscribe link provided in any email you've received from us.
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <footer>
        <div class="container">
            <p>&copy; $CURRENT_YEAR $DOMAIN_NAME - All Rights Reserved</p>
            <p style="margin-top: 15px;">
                <a href="/privacy.html">Privacy Policy</a> | 
                <a href="/terms.html">Terms of Service</a> | 
                <a href="/api/test-db.php" style="opacity: 0.3;">DB</a>
            </p>
        </div>
    </footer>
</body>
</html>
EOF

# Create User Settings page
cat > "$WEB_ROOT/user-settings.html" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Settings - $DOMAIN_NAME</title>
    <link rel="stylesheet" href="/css/style.css">
    <script src="/js/colors.js"></script>
    <style>
        .settings-container {
            max-width: 600px;
            margin: 50px auto;
            padding: 40px;
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 20px rgba(0,0,0,0.1);
        }
        .tab-buttons {
            display: flex;
            gap: 10px;
            margin-bottom: 30px;
        }
        .tab-button {
            flex: 1;
            padding: 12px;
            background: #f8f9fa;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.3s;
        }
        .tab-button.active {
            background: var(--primary-color);
            color: white;
        }
        .tab-button:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        .tab-content {
            display: none;
        }
        .tab-content.active {
            display: block;
        }
        .success-message, .error-message {
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            display: none;
        }
        .success-message {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        .error-message {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        .loading {
            display: none;
            text-align: center;
            padding: 20px;
        }
        .loading.show {
            display: block;
        }
        .debug-info {
            background: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            font-size: 12px;
            margin-top: 20px;
            display: none;
        }
    </style>
</head>
<body>
    <nav>
        <ul>
            <li><a href="/">Home</a></li>
            <li><a href="/privacy.html">Privacy Policy</a></li>
            <li><a href="/terms.html">Terms of Service</a></li>
            <li><a href="/user-settings.html">User Settings</a></li>
        </ul>
    </nav>
    
    <div class="settings-container">
        <h1 style="color: var(--primary-color); margin-bottom: 30px;">User Settings</h1>
        
        <div class="success-message" id="successMessage"></div>
        <div class="error-message" id="errorMessage"></div>
        
        <div class="user-info" id="userInfo" style="display: none;">
            <span>Logged in as: <strong id="userEmail"></strong></span>
            <button class="logout-btn" onclick="logout()">Logout</button>
        </div>
        
        <div class="tab-buttons">
            <button class="tab-button active" onclick="showTab('login')" id="loginTabBtn">Login</button>
            <button class="tab-button" onclick="showTab('colors')" id="colorsTabBtn" disabled>Theme Colors</button>
            <button class="tab-button" onclick="showTab('password')" id="passwordTabBtn" disabled>Change Password</button>
        </div>
        
        <!-- Login Tab -->
        <div class="tab-content active" id="loginTab">
            <h2>Login to Your Account</h2>
            <p style="margin-bottom: 20px; color: #666;">Use your email account credentials to login.</p>
            <form id="loginForm">
                <div class="form-group">
                    <label for="loginEmail">Email Address:</label>
                    <input type="email" id="loginEmail" name="email" required placeholder="user@$DOMAIN_NAME">
                </div>
                <div class="form-group">
                    <label for="loginPassword">Password:</label>
                    <input type="password" id="loginPassword" name="password" required>
                </div>
                <button type="submit" class="btn">Login</button>
                <button type="button" class="btn" style="background: #6c757d; margin-left: 10px;" onclick="testDatabase()">Test DB Connection</button>
            </form>
            <div class="loading" id="loginLoading">Authenticating...</div>
            <div class="debug-info" id="debugInfo"></div>
        </div>
        
        <!-- Colors Tab -->
        <div class="tab-content" id="colorsTab">
            <h2>Customize Theme Colors</h2>
            <p style="margin-bottom: 20px; color: #666;">Changes will be visible to all website visitors.</p>
            <form id="colorForm">
                <div class="color-picker-group">
                    <div class="form-group">
                        <label>Primary Color:</label>
                        <div class="color-input">
                            <input type="color" id="primaryColor" value="#667eea">
                            <input type="text" value="#667eea" id="primaryHex" pattern="^#[0-9A-Fa-f]{6}$">
                        </div>
                    </div>
                    <div class="form-group">
                        <label>Secondary Color:</label>
                        <div class="color-input">
                            <input type="color" id="secondaryColor" value="#764ba2">
                            <input type="text" value="#764ba2" id="secondaryHex" pattern="^#[0-9A-Fa-f]{6}$">
                        </div>
                    </div>
                </div>
                <button type="submit" class="btn">Save Colors (Global)</button>
                <button type="button" class="btn" style="background: #6c757d; margin-left: 10px;" onclick="resetColors()">Reset to Default</button>
            </form>
            <div class="loading" id="colorLoading">Saving colors...</div>
        </div>
        
        <!-- Password Tab -->
        <div class="tab-content" id="passwordTab">
            <h2>Change Password</h2>
            <p style="margin-bottom: 20px; color: #666;">Change your email account password.</p>
            <form id="passwordForm">
                <div class="form-group">
                    <label for="currentPassword">Current Password:</label>
                    <input type="password" id="currentPassword" name="currentPassword" required>
                </div>
                <div class="form-group">
                    <label for="newPassword">New Password:</label>
                    <input type="password" id="newPassword" name="newPassword" required minlength="8">
                </div>
                <div class="form-group">
                    <label for="confirmPassword">Confirm New Password:</label>
                    <input type="password" id="confirmPassword" name="confirmPassword" required minlength="8">
                </div>
                <button type="submit" class="btn">Change Password</button>
            </form>
            <div class="loading" id="passwordLoading">Changing password...</div>
        </div>
    </div>
    
    <script>
        let currentUser = null;
        
        // Check session on page load
        window.addEventListener('DOMContentLoaded', function() {
            checkSession();
            loadCurrentColors();
        });
        
        // Test database connection
        function testDatabase() {
            fetch('/api/test-db.php')
                .then(response => response.json())
                .then(data => {
                    const debugDiv = document.getElementById('debugInfo');
                    debugDiv.style.display = 'block';
                    debugDiv.innerHTML = '<strong>Database Test:</strong><pre>' + JSON.stringify(data, null, 2) + '</pre>';
                    
                    if (data.db_connection) {
                        showSuccess('Database connection successful!');
                    } else {
                        showError('Database connection failed: ' + (data.error || 'Unknown error'));
                    }
                })
                .catch(error => {
                    showError('Failed to test database: ' + error);
                });
        }
        
        // Check if user is already logged in
        function checkSession() {
            fetch('/api/session.php')
                .then(response => response.json())
                .then(data => {
                    if (data.authenticated) {
                        currentUser = data.user;
                        showLoggedInState();
                    }
                })
                .catch(error => console.error('Session check failed:', error));
        }
        
        // Show logged in state
        function showLoggedInState() {
            document.getElementById('userInfo').style.display = 'flex';
            document.getElementById('userEmail').textContent = currentUser;
            document.getElementById('colorsTabBtn').disabled = false;
            document.getElementById('passwordTabBtn').disabled = false;
            document.getElementById('loginTabBtn').textContent = 'Account';
            
            // Clear login form
            document.getElementById('loginForm').reset();
        }
        
        // Tab switching
        function showTab(tabName) {
            if (tabName !== 'login' && !currentUser) {
                showError('Please login first');
                return;
            }
            
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
            });
            document.querySelectorAll('.tab-button').forEach(btn => {
                btn.classList.remove('active');
            });
            
            document.getElementById(tabName + 'Tab').classList.add('active');
            document.getElementById(tabName + 'TabBtn').classList.add('active');
        }
        
        // Login form
        document.getElementById('loginForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const email = document.getElementById('loginEmail').value;
            const password = document.getElementById('loginPassword').value;
            
            document.getElementById('loginLoading').classList.add('show');
            hideMessages();
            
            try {
                const response = await fetch('/api/auth.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ email, password })
                });
                
                const data = await response.json();
                document.getElementById('loginLoading').classList.remove('show');
                
                if (response.ok && data.success) {
                    currentUser = data.user;
                    showLoggedInState();
                    showSuccess('Login successful! You can now change settings.');
                    
                    // Switch to colors tab
                    setTimeout(() => showTab('colors'), 1000);
                } else {
                    showError(data.error || 'Login failed. Please check your credentials.');
                }
            } catch (error) {
                document.getElementById('loginLoading').classList.remove('show');
                showError('Connection error. Please try again.');
                console.error('Login error:', error);
            }
        });
        
        // Load current colors
        function loadCurrentColors() {
            fetch('/api/colors.php')
                .then(response => response.json())
                .then(data => {
                    if (data.primary) {
                        document.getElementById('primaryColor').value = data.primary;
                        document.getElementById('primaryHex').value = data.primary;
                    }
                    if (data.secondary) {
                        document.getElementById('secondaryColor').value = data.secondary;
                        document.getElementById('secondaryHex').value = data.secondary;
                    }
                })
                .catch(error => console.error('Failed to load colors:', error));
        }
        
        // Color form
        document.getElementById('colorForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const primary = document.getElementById('primaryColor').value;
            const secondary = document.getElementById('secondaryColor').value;
            
            document.getElementById('colorLoading').classList.add('show');
            hideMessages();
            
            try {
                const response = await fetch('/api/colors.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ primary, secondary })
                });
                
                const data = await response.json();
                document.getElementById('colorLoading').classList.remove('show');
                
                if (response.ok && data.success) {
                    // Apply colors immediately
                    document.documentElement.style.setProperty('--primary-color', primary);
                    document.documentElement.style.setProperty('--secondary-color', secondary);
                    
                    showSuccess('Colors saved successfully! All visitors will see the new theme.');
                } else {
                    showError(data.error || 'Failed to save colors.');
                }
            } catch (error) {
                document.getElementById('colorLoading').classList.remove('show');
                showError('Failed to save colors. Please try again.');
                console.error('Color save error:', error);
            }
        });
        
        // Password form
        document.getElementById('passwordForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const currentPassword = document.getElementById('currentPassword').value;
            const newPassword = document.getElementById('newPassword').value;
            const confirmPassword = document.getElementById('confirmPassword').value;
            
            if (newPassword !== confirmPassword) {
                showError('New passwords do not match!');
                return;
            }
            
            document.getElementById('passwordLoading').classList.add('show');
            hideMessages();
            
            try {
                const response = await fetch('/api/change-password.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ currentPassword, newPassword })
                });
                
                const data = await response.json();
                document.getElementById('passwordLoading').classList.remove('show');
                
                if (response.ok && data.success) {
                    showSuccess('Password changed successfully!');
                    document.getElementById('passwordForm').reset();
                } else {
                    showError(data.error || 'Failed to change password.');
                }
            } catch (error) {
                document.getElementById('passwordLoading').classList.remove('show');
                showError('Failed to change password. Please try again.');
                console.error('Password change error:', error);
            }
        });
        
        // Logout function
        function logout() {
            fetch('/api/logout.php')
                .then(response => response.json())
                .then(data => {
                    currentUser = null;
                    document.getElementById('userInfo').style.display = 'none';
                    document.getElementById('colorsTabBtn').disabled = true;
                    document.getElementById('passwordTabBtn').disabled = true;
                    document.getElementById('loginTabBtn').textContent = 'Login';
                    showTab('login');
                    showSuccess('Logged out successfully.');
                })
                .catch(error => console.error('Logout error:', error));
        }
        
        // Color picker sync
        document.getElementById('primaryColor').addEventListener('input', function(e) {
            document.getElementById('primaryHex').value = e.target.value;
        });
        
        document.getElementById('secondaryColor').addEventListener('input', function(e) {
            document.getElementById('secondaryHex').value = e.target.value;
        });
        
        document.getElementById('primaryHex').addEventListener('input', function(e) {
            if (e.target.validity.valid) {
                document.getElementById('primaryColor').value = e.target.value;
            }
        });
        
        document.getElementById('secondaryHex').addEventListener('input', function(e) {
            if (e.target.validity.valid) {
                document.getElementById('secondaryColor').value = e.target.value;
            }
        });
        
        // Reset colors
        function resetColors() {
            if (!currentUser) {
                showError('Please login first');
                return;
            }
            
            document.getElementById('primaryColor').value = '#667eea';
            document.getElementById('primaryHex').value = '#667eea';
            document.getElementById('secondaryColor').value = '#764ba2';
            document.getElementById('secondaryHex').value = '#764ba2';
            
            // Save default colors to server
            fetch('/api/colors.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ primary: '#667eea', secondary: '#764ba2' })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    document.documentElement.style.setProperty('--primary-color', '#667eea');
                    document.documentElement.style.setProperty('--secondary-color', '#764ba2');
                    showSuccess('Colors reset to default!');
                }
            })
            .catch(error => {
                console.error('Reset colors error:', error);
                showError('Failed to reset colors.');
            });
        }
        
        // Message functions
        function showSuccess(message) {
            const elem = document.getElementById('successMessage');
            elem.textContent = message;
            elem.style.display = 'block';
            document.getElementById('errorMessage').style.display = 'none';
            setTimeout(() => elem.style.display = 'none', 5000);
        }
        
        function showError(message) {
            const elem = document.getElementById('errorMessage');
            elem.textContent = message;
            elem.style.display = 'block';
            document.getElementById('successMessage').style.display = 'none';
            setTimeout(() => elem.style.display = 'none', 5000);
        }
        
        function hideMessages() {
            document.getElementById('successMessage').style.display = 'none';
            document.getElementById('errorMessage').style.display = 'none';
        }
    </script>
</body>
</html>
EOF

# Set final permissions
chown -R www-data:www-data "$WEB_ROOT" 2>/dev/null || chown -R nginx:nginx "$WEB_ROOT" 2>/dev/null
chmod -R 755 "$WEB_ROOT"
chmod 666 "$WEB_ROOT/data/colors.json"

print_message "✓ Website files created with fixed database access"

# ===================================================================
# 4. CONFIGURE NGINX (CRITICAL - THIS FIXES THE DEFAULT PAGE ISSUE)
# ===================================================================

print_header "Configuring Nginx"

# Remove default nginx site to avoid conflicts
echo "Removing default nginx configuration..."
rm -f /etc/nginx/sites-enabled/default
rm -f /etc/nginx/sites-available/default

# Create nginx configuration for the domain
echo "Creating Nginx configuration for $DOMAIN_NAME..."

cat > "/etc/nginx/sites-available/$DOMAIN_NAME" <<NGINX_CONFIG
# Mail Server Website Configuration
# Generated: $(date)

server {
    listen 80 default_server;
    listen [::]:80 default_server;
    
    server_name $DOMAIN_NAME www.$DOMAIN_NAME $HOSTNAME _;
    
    root $WEB_ROOT;
    index index.html index.php;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    # Main location
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    # PHP handling for API
    location ~ \.php\$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php$PHP_VERSION-fpm.sock;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
    }
    
    # API directory specific handling
    location /api/ {
        try_files \$uri \$uri/ =404;
        
        # Ensure PHP files in API directory are processed
        location ~ \.php\$ {
            include snippets/fastcgi-php.conf;
            fastcgi_pass unix:/var/run/php/php$PHP_VERSION-fpm.sock;
            fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
            include fastcgi_params;
        }
    }
    
    # Deny access to hidden files
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }
    
    # Static file caching
    location ~* \.(jpg|jpeg|png|gif|ico|css|js|svg|woff|woff2|ttf|eot)$ {
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
    
    # Let's Encrypt challenge
    location /.well-known/acme-challenge/ {
        root $WEB_ROOT;
        allow all;
    }
    
    # Log files
    access_log /var/log/nginx/${DOMAIN_NAME}_access.log;
    error_log /var/log/nginx/${DOMAIN_NAME}_error.log;
}
NGINX_CONFIG

# Enable the site
echo "Enabling website configuration..."
ln -sf "/etc/nginx/sites-available/$DOMAIN_NAME" "/etc/nginx/sites-enabled/$DOMAIN_NAME"

# Remove any other enabled sites that might conflict
for site in /etc/nginx/sites-enabled/*; do
    if [ -f "$site" ] && [ "$(basename $site)" != "$DOMAIN_NAME" ]; then
        echo "Removing conflicting site: $(basename $site)"
        rm -f "$site"
    fi
done

# Test nginx configuration
echo "Testing Nginx configuration..."
nginx -t 2>/dev/null

if [ $? -eq 0 ]; then
    print_message "✓ Nginx configuration is valid"
else
    print_error "✗ Nginx configuration has errors"
    echo "Attempting to fix common issues..."
    
    # Check if PHP-FPM socket exists
    if [ ! -S "/var/run/php/php$PHP_VERSION-fpm.sock" ]; then
        # Try to find the correct PHP-FPM socket
        PHP_SOCKET=$(find /var/run/php/ -name "*.sock" 2>/dev/null | head -1)
        if [ ! -z "$PHP_SOCKET" ]; then
            echo "Found PHP socket: $PHP_SOCKET"
            sed -i "s|/var/run/php/php.*-fpm.sock|$PHP_SOCKET|g" "/etc/nginx/sites-available/$DOMAIN_NAME"
        fi
    fi
    
    # Test again
    nginx -t 2>/dev/null
fi

# Start/restart services
echo "Starting services..."

# Ensure PHP-FPM is running
systemctl start php$PHP_VERSION-fpm 2>/dev/null || systemctl start php-fpm 2>/dev/null
systemctl enable php$PHP_VERSION-fpm 2>/dev/null || systemctl enable php-fpm 2>/dev/null

# Restart Nginx to apply all changes
systemctl stop nginx
sleep 2
systemctl start nginx
systemctl enable nginx

# Verify services are running
echo ""
echo "Checking service status..."
if systemctl is-active --quiet nginx; then
    print_message "✓ Nginx is running"
else
    print_error "✗ Nginx is not running"
    systemctl status nginx --no-pager | head -10
fi

if systemctl is-active --quiet php$PHP_VERSION-fpm 2>/dev/null || systemctl is-active --quiet php-fpm 2>/dev/null; then
    print_message "✓ PHP-FPM is running"
else
    print_warning "⚠ PHP-FPM may not be running"
fi

# ===================================================================
# COMPLETION
# ===================================================================

print_header "Website Setup Complete!"

echo ""
echo "✅ Website created at: $WEB_ROOT"
echo "✅ Database configuration accessible to web server"
echo "✅ Nginx configured with PHP support"
echo "✅ Backend API integrated with mail database"
echo "✅ User authentication system active"
echo ""

echo "FIXED FEATURES:"
echo "  ✓ Database password accessible at: /etc/mail-web-config/db_password"
echo "  ✓ PHP config file at: /etc/mail-web-config/db_config.php"
echo "  ✓ Web server can now connect to database"
echo "  ✓ User Settings page will work properly"
echo ""

echo "TEST DATABASE CONNECTION:"
echo "  Visit: http://$PRIMARY_IP/api/test-db.php"
echo "  This will show if the database connection is working"
echo ""

print_message "✓ Website setup completed with FIXED database access!"
