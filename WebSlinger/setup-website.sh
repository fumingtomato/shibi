#!/bin/bash

# =================================================================
# MANAGEMENT PORTAL SETUP - V4.0 (DEFINITIVE NGINX & AUTH FIX)
# Version: 18.3.0
# This version provides the final, correct Nginx configuration to fix
# "Access Denied" and "Forbidden" errors, and is fully dynamic.
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

print_header() {
    echo -e "${BLUE}==================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}==================================================${NC}"
}

print_header "Setting Up Definitive, Fully Dynamic Management Portal"

# Load configuration dynamically
if [ -f "/root/mail-installer/install.conf" ]; then
    source "/root/mail-installer/install.conf"
else
    echo "FATAL: install.conf not found! Cannot proceed."
    exit 1
fi

# --- DYNAMIC VARIABLES (NO HARDCODING) ---
WEB_ROOT="/var/www/$DOMAIN_NAME"
PHP_VERSION=$(php -v 2>/dev/null | head -n1 | cut -d' ' -f2 | cut -d'.' -f1,2)
ADMIN_USER_EMAIL="$FIRST_EMAIL"

# 1. Install Dependencies
print_message "Installing web server dependencies..."
apt-get update > /dev/null 2>&1
apt-get install -y nginx php-fpm php-mysql php-cli php-json unzip sudo > /dev/null 2>&1

# 2. Grant www-data Sudo Permissions for portal functions
print_message "Granting web server necessary permissions..."
cat > /etc/sudoers.d/www-data-portal <<'EOF'
# Allows the web portal to execute specific management commands
www-data ALL=(root) NOPASSWD: /usr/sbin/postmap
www-data ALL=(root) NOPASSWD: /bin/systemctl reload nginx
www-data ALL=(root) NOPASSWD: /usr/sbin/doveadm
EOF
chmod 440 /etc/sudoers.d/www-data-portal

# 3. Create Directory Structure
print_message "Creating portal directory structure at $WEB_ROOT..."
mkdir -p "$WEB_ROOT"/{css,js,includes,api}

# 4. Create Secure Database Config
print_message "Creating secure database configuration..."
DB_PASS=$(cat /root/.mail_db_password)
cat > "$WEB_ROOT/includes/config.php" <<EOF
<?php
// Secure configuration file
define('DB_HOST', '127.0.0.1');
define('DB_USER', 'mailuser');
define('DB_PASS', '$DB_PASS');
define('DB_NAME', 'mailserver');
EOF
chmod 600 "$WEB_ROOT/includes/config.php"

# 5. Create Portal Files (including dynamic auth and domain dropdowns)
# This section is confirmed correct from previous fixes.
# --- Includes (Header and Footer) ---
cat > "$WEB_ROOT/includes/header.php" <<'EOF'
<?php
session_start();
if (basename($_SERVER['PHP_SELF']) !== 'login.php' && basename($_SERVER['PHP_SELF']) !== 'auth.php') {
    if (!isset($_SESSION['loggedin']) || $_SESSION['loggedin'] !== true) {
        header('Location: /login.php');
        exit;
    }
    require_once 'config.php';
}
?>
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Management Portal</title><link rel="stylesheet" href="/css/style.css"></head>
<body>
<?php if (isset($_SESSION['loggedin']) && $_SESSION['loggedin'] === true): ?>
<div class="sidebar"><div class="sidebar-header">Portal</div><nav><a href="/">Dashboard</a><a href="/domains.php">Domains</a><a href="/emails.php">Emails</a><a href="/aliases.php">Aliases</a></nav><footer><a href="#" id="logoutBtn">Logout</a></footer></div>
<div class="main-content">
<?php else: ?>
<div id="login-container">
<?php endif; ?>
EOF
cat > "$WEB_ROOT/includes/footer.php" <<'EOF'
</div><script src="/js/main.js"></script></body></html>
EOF

# --- Login Page ---
cat > "$WEB_ROOT/login.php" <<'EOF'
<?php session_start(); if (isset($_SESSION['loggedin']) && $_SESSION['loggedin'] === true) { header('Location: /'); exit; } include 'includes/header.php'; ?>
<div id="login-box"><h2 style="text-align: center; margin-bottom: 20px;">Portal Login</h2><div id="errorMessage" style="color:red; margin-bottom:15px; text-align:center;"></div><form id="loginForm"><div class="form-group"><label for="email">Email</label><input type="email" id="email" name="email" class="form-control" required></div><div class="form-group"><label for="password">Password</label><input type="password" id="password" name="password" class="form-control" required></div><button type="submit" class="btn btn-primary" style="width:100%;">Login</button></form></div>
<script>
document.getElementById('loginForm').addEventListener('submit', function(e) {
    e.preventDefault();
    const formData = new FormData(e.target);
    fetch('/api/auth.php?action=login', { method: 'POST', body: formData })
    .then(res => res.json()).then(data => {
        if (data.success) { window.location.href = '/'; } 
        else { document.getElementById('errorMessage').textContent = data.error || 'Access denied.'; }
    }).catch(err => { document.getElementById('errorMessage').textContent = 'A network error occurred.'; });
});
</script>
<?php include 'includes/footer.php'; ?>
EOF

# --- DYNAMIC Authentication API (auth.php) ---
print_message "Creating DYNAMIC authentication API..."
cat > "$WEB_ROOT/api/auth.php" <<EOF
<?php
session_start();
header('Content-Type: application/json');

// --- DYNAMIC CONFIG (NO HARDCODING) ---
\$admin_email = "$ADMIN_USER_EMAIL";
// --- END DYNAMIC CONFIG ---

function login() {
    global \$admin_email;
    if (empty(\$_POST['email']) || empty(\$_POST['password'])) {
        echo json_encode(['success' => false, 'error' => 'Email and password required.']);
        exit;
    }
    \$email = \$_POST['email'];
    \$password = \$_POST['password'];

    if (strtolower(\$email) !== strtolower(\$admin_email)) {
        error_log("Access Denied: Attempted login with [\$email] does not match configured admin [\$admin_email]");
        echo json_encode(['success' => false, 'error' => 'Access denied.']);
        exit;
    }

    \$escaped_password = escapeshellarg(\$password);
    \$verification_cmd = "sudo /usr/bin/doveadm auth test " . escapeshellarg(\$email) . " " . \$escaped_password;
    exec(\$verification_cmd . " 2>&1", \$output, \$return_code);
    
    \$auth_success = false;
    foreach (\$output as \$line) {
        if (strpos(\$line, 'auth succeeded') !== false) {
            \$auth_success = true;
            break;
        }
    }
    if (\$auth_success) {
        \$_SESSION['loggedin'] = true;
        \$_SESSION['user'] = \$email;
        echo json_encode(['success' => true]);
    } else {
        error_log("Invalid Credentials for user: " . \$email);
        echo json_encode(['success' => false, 'error' => 'Invalid credentials.']);
    }
}

function logout() {
    session_unset();
    session_destroy();
    echo json_encode(['success' => true]);
}

\$action = \$_GET['action'] ?? '';
if (\$action === 'login') { login(); }
elseif (\$action === 'logout') { logout(); }
else { echo json_encode(['success' => false, 'error' => 'Invalid action']); }
EOF

# --- Index/Dashboard Page ---
cat > "$WEB_ROOT/index.php" <<'EOF'
<?php include 'includes/header.php'; ?>
<div class="page-header"><h2>Dashboard</h2></div>
<div class="card"><div class="card-header">Welcome</div><div class="card-body"><p>Welcome to the mail server management portal.</p></div></div>
<?php include 'includes/footer.php'; ?>
EOF

# 6. Configure Nginx with the DEFINITIVE FIX
print_message "Configuring Nginx with the final, correct settings..."
NGINX_CONF="/etc/nginx/sites-available/$DOMAIN_NAME.conf"
# Remove the broken default config
rm -f /etc/nginx/sites-enabled/default
rm -f "$NGINX_CONF"

cat > "$NGINX_CONF" <<EOF
# This is the main server block for the management portal.
server {
    listen 80;
    server_name $DOMAIN_NAME www.$DOMAIN_NAME; # Listen for the main domain
    
    root $WEB_ROOT;
    
    # *** THIS IS THE FIX for "directory index forbidden" ***
    # It explicitly tells Nginx to look for index.php.
    index index.php index.html;
    
    location / {
        try_files \$uri \$uri/ /index.php?\$query_string;
    }
    
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php${PHP_VERSION}-fpm.sock;
    }

    # This location block is critical for Certbot's webroot validation.
    # It ensures that challenges are served correctly for the main domain.
    location /.well-known/acme-challenge/ {
        allow all;
        root /var/www/html; # A common, simple root for challenges
    }
}
EOF
ln -sf "$NGINX_CONF" "/etc/nginx/sites-enabled/$DOMAIN_NAME.conf"
# Create the generic webroot for Certbot challenges
mkdir -p /var/www/html
chown www-data:www-data /var/www/html

# 7. Final Restart & Permissions
print_message "Restarting services and setting final permissions..."
systemctl reload nginx
# Use the correct, versioned service name for php-fpm
systemctl restart php${PHP_VERSION}-fpm.service
chown -R www-data:www-data "$WEB_ROOT"
chmod -R 755 "$WEB_ROOT"
chmod 600 "$WEB_ROOT/includes/config.php"

print_header "Portal Dynamic Configuration and Nginx Fix Applied!"
