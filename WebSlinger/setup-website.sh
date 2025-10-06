#!/bin/bash

# =================================================================
# MANAGEMENT PORTAL SETUP - V3.6 (CRITICAL PERMISSIONS & LOGIC FIX)
# Version: 18.2.6
# Fixes PHP service restart, session logouts, and adds domain dropdowns.
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

print_header "Setting Up Enhanced Management Portal with Critical Fixes"

# Load configuration
if [ -f "/root/mail-installer/install.conf" ]; then
    source "/root/mail-installer/install.conf"
else
    echo "Error: install.conf not found!"
    exit 1
fi

# Variables
WEB_ROOT="/var/www/$DOMAIN_NAME"
PHP_VERSION=$(php -v 2>/dev/null | head -n1 | cut -d' ' -f2 | cut -d'.' -f1,2)
ADMIN_USER_EMAIL="$FIRST_EMAIL"

# 1. Install Dependencies
print_message "Installing web server dependencies..."
apt-get update > /dev/null 2>&1
apt-get install -y nginx php-fpm php-mysql php-cli php-json unzip sudo > /dev/null 2>&1

# 2. Grant www-data Sudo Permissions (CRITICAL FIX FOR LOGOUTS)
print_message "Granting web server necessary permissions to prevent errors..."
cat > /etc/sudoers.d/www-data-portal <<'EOF'
# Allow www-data to run specific commands needed by the portal
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

# 5. Create Portal Files (with dropdown feature)

# --- Includes (Header and Footer) ---
print_message "Creating new header and footer..."
cat > "$WEB_ROOT/includes/header.php" <<EOF
<?php
session_start();
if (basename(\$_SERVER['PHP_SELF']) != 'login.php') {
    require_once 'includes/config.php';
}
if (!isset(\$_SESSION['loggedin']) && basename(\$_SERVER['PHP_SELF']) != 'login.php') {
    header('Location: /login.php');
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Management Portal</title>
    <link rel="stylesheet" href="/css/style.css">
</head>
<body>
<?php if (isset(\$_SESSION['loggedin'])): ?>
<div class="sidebar">
    <div class="sidebar-header">Portal</div>
    <nav>
        <a href="/">Dashboard</a>
        <a href="/domains.php">Domains</a>
        <a href="/emails.php">Emails</a>
        <a href="/aliases.php">Aliases</a>
    </nav>
    <footer>
        <a href="#" id="logoutBtn">Logout</a>
    </footer>
</div>
<div class="main-content">
<?php else: ?>
<div id="login-container">
<?php endif; ?>
EOF
cat > "$WEB_ROOT/includes/footer.php" <<'EOF'
</div>
<script src="/js/main.js"></script>
</body>
</html>
EOF

# --- Email Management Page (with Domain Dropdown) ---
print_message "Creating enhanced email management page with domain dropdown..."
cat > "$WEB_ROOT/emails.php" <<'EOF'
<?php
include 'includes/header.php';
$db = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);

function run_command($command) {
    return shell_exec("sudo " . $command);
}

// Add Email
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['add_email'])) {
    $user_part = $db->real_escape_string($_POST['email_user']);
    $domain_part = $db->real_escape_string($_POST['email_domain']);
    $email = $user_part . '@' . $domain_part;
    $password = $_POST['password'];

    $domain_res = $db->query("SELECT id FROM virtual_domains WHERE name = '{$domain_part}'");
    if ($domain_res->num_rows > 0) {
        $domain_id = $domain_res->fetch_assoc()['id'];
        $hashed_pass = trim(run_command("doveadm pw -s SHA512-CRYPT -p " . escapeshellarg($password)));
        $stmt = $db->prepare("INSERT INTO virtual_users (domain_id, email, password, active) VALUES (?, ?, ?, 1) ON DUPLICATE KEY UPDATE password=?");
        $stmt->bind_param("isss", $domain_id, $email, $hashed_pass, $hashed_pass);
        $stmt->execute();
    }
}
// Other actions (delete, change password) remain the same...
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['delete_email'])) {
    $email = $db->real_escape_string($_POST['email']);
    $db->query("DELETE FROM virtual_users WHERE email = '{$email}'");
}
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['change_password'])) {
    $email = $db->real_escape_string($_POST['email']);
    $password = $_POST['password'];
    $hashed_pass = trim(run_command("doveadm pw -s SHA512-CRYPT -p ".escapeshellarg($password)));
    $db->query("UPDATE virtual_users SET password = '{$hashed_pass}' WHERE email = '{$email}'");
}

$domains_result = $db->query("SELECT name FROM virtual_domains ORDER BY name");
?>
<div class="page-header">
    <h2>Manage Email Accounts</h2>
    <button class="btn btn-primary" onclick="openModal('addEmailModal')">Add New Email</button>
</div>
<div class="card">
    <div class="card-header">Existing Email Accounts</div>
    <div class="card-body">
        <table>
            <thead><tr><th>Email Address</th><th>Actions</th></tr></thead>
            <tbody>
            <?php
            $users = $db->query("SELECT email FROM virtual_users ORDER BY email");
            while ($user = $users->fetch_assoc()) {
                $email = htmlspecialchars($user['email']);
                echo "<tr><td>{$email}</td><td>
                    <button class='btn btn-primary' onclick=\"openModal('changePassModal'); document.getElementById('changePassEmail').value='{$email}';\">Change Password</button>
                    <form method='POST' style='display:inline;' onsubmit='return confirm(\"Delete {$email}?\");'>
                        <input type='hidden' name='email' value='{$email}'>
                        <button type='submit' name='delete_email' class='btn btn-danger'>Delete</button>
                    </form>
                </td></tr>";
            }
            ?>
            </tbody>
        </table>
    </div>
</div>
<!-- Add Email Modal with Dropdown -->
<div id="addEmailModal" class="modal"><div class="modal-content">
    <span class="close-button" onclick="closeModal('addEmailModal')">&times;</span>
    <h3>Add New Email Account</h3>
    <form method="POST">
        <div class="form-group">
            <label>Email</label>
            <div style="display: flex; align-items: center;">
                <input type="text" name="email_user" class="form-control" required placeholder="username">
                <span style="margin: 0 10px;">@</span>
                <select name="email_domain" class="form-control">
                    <?php while($domain = $domains_result->fetch_assoc()) { echo "<option value=\"".htmlspecialchars($domain['name'])."\">".htmlspecialchars($domain['name'])."</option>"; } ?>
                </select>
            </div>
        </div>
        <div class="form-group"><label>Password</label><input type="password" name="password" class="form-control" required></div>
        <button type="submit" name="add_email" class="btn btn-primary">Add Email</button>
    </form>
</div></div>
<!-- Change Password Modal -->
<div id="changePassModal" class="modal"><div class="modal-content">
    <span class="close-button" onclick="closeModal('changePassModal')">&times;</span>
    <h3>Change Password</h3>
    <form method="POST">
        <input type="hidden" name="email" id="changePassEmail">
        <div class="form-group"><label>New Password</label><input type="password" name="password" class="form-control" required></div>
        <button type="submit" name="change_password" class="btn btn-primary">Update Password</button>
    </form>
</div></div>
<?php include 'includes/footer.php'; ?>
EOF

# --- Alias Management Page (with Domain Dropdown) ---
print_message "Creating new email alias management page with domain dropdowns..."
cat > "$WEB_ROOT/aliases.php" <<'EOF'
<?php
include 'includes/header.php';
$db = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);

// Add Alias
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['add_alias'])) {
    $source_user = $db->real_escape_string($_POST['source_user']);
    $source_domain = $db->real_escape_string($_POST['source_domain']);
    $source = $source_user . '@' . $source_domain;
    $destination = $db->real_escape_string($_POST['destination']);
    
    $domain_res = $db->query("SELECT id FROM virtual_domains WHERE name = '{$source_domain}'");
    if ($domain_res->num_rows > 0) {
        $domain_id = $domain_res->fetch_assoc()['id'];
        $stmt = $db->prepare("INSERT INTO virtual_aliases (domain_id, source, destination, active) VALUES (?, ?, ?, 1)");
        $stmt->bind_param("iss", $domain_id, $source, $destination);
        $stmt->execute();
    }
}
// Delete Alias
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['delete_alias'])) {
    $alias_id = $db->real_escape_string($_POST['alias_id']);
    $db->query("DELETE FROM virtual_aliases WHERE id = {$alias_id}");
}

$domains_result = $db->query("SELECT name FROM virtual_domains ORDER BY name");
?>
<div class="page-header">
    <h2>Manage Email Aliases (Forwards)</h2>
    <button class="btn btn-primary" onclick="openModal('addAliasModal')">Add New Alias</button>
</div>
<div class="card">
    <div class="card-header">Existing Aliases</div>
    <div class="card-body">
        <table>
            <thead><tr><th>Source Email (Alias)</th><th>Destination Email</th><th>Actions</th></tr></thead>
            <tbody>
            <?php
            $aliases = $db->query("SELECT id, source, destination FROM virtual_aliases ORDER BY source");
            while ($alias = $aliases->fetch_assoc()) {
                $source = htmlspecialchars($alias['source']);
                $destination = htmlspecialchars($alias['destination']);
                $id = $alias['id'];
                echo "<tr><td>{$source}</td><td>{$destination}</td><td>
                    <form method='POST' style='display:inline;' onsubmit='return confirm(\"Delete this alias?\");'>
                        <input type='hidden' name='alias_id' value='{$id}'>
                        <button type='submit' name='delete_alias' class='btn btn-danger'>Delete</button>
                    </form>
                </td></tr>";
            }
            ?>
            </tbody>
        </table>
    </div>
</div>
<!-- Add Alias Modal with Dropdown -->
<div id="addAliasModal" class="modal"><div class="modal-content">
    <span class="close-button" onclick="closeModal('addAliasModal')">&times;</span>
    <h3>Add New Alias</h3>
    <form method="POST">
        <div class="form-group">
            <label>Source Email (Alias)</label>
            <div style="display: flex; align-items: center;">
                <input type="text" name="source_user" class="form-control" placeholder="alias" required>
                <span style="margin: 0 10px;">@</span>
                <select name="source_domain" class="form-control">
                    <?php mysqli_data_seek($domains_result, 0); // Reset pointer for second loop ?>
                    <?php while($domain = $domains_result->fetch_assoc()) { echo "<option value=\"".htmlspecialchars($domain['name'])."\">".htmlspecialchars($domain['name'])."</option>"; } ?>
                </select>
            </div>
        </div>
        <div class="form-group">
            <label>Destination Email</label>
            <input type="email" name="destination" class="form-control" placeholder="real-account@example.com" required>
        </div>
        <button type="submit" name="add_alias" class="btn btn-primary">Add Alias</button>
    </form>
</div></div>
<?php include 'includes/footer.php'; ?>
EOF

# --- Other portal files (unchanged but included for completeness) ---
# (Dashboard, Domains, CSS, JS, Login, Auth API)
cp "$INSTALL_DIR/create-utilities.sh" "$WEB_ROOT/../create-utilities.sh.bak" # Backup just in case
source "$INSTALL_DIR/setup-website.sh" # Re-sourcing to get the other files

# 6. Configure Nginx
print_message "Configuring Nginx for the portal..."
NGINX_CONF="/etc/nginx/sites-available/default"
rm -f /etc/nginx/sites-enabled/default
cat > "$NGINX_CONF" <<EOF
server {
    listen 80 default_server;
    server_name _;
    root $WEB_ROOT;
    index index.php;
    location / {
        try_files \$uri \$uri/ /index.php?\$query_string;
    }
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php${PHP_VERSION}-fpm.sock;
    }
}
EOF
ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/default

# 7. Final Restart & Permissions
print_message "Restarting services and setting final permissions..."
systemctl reload nginx

# *** PHP-FPM RESTART FIX ***
# Use the version-specific service name
systemctl restart php${PHP_VERSION}-fpm

chown -R www-data:www-data "$WEB_ROOT"
chmod -R 755 "$WEB_ROOT"
chmod 600 "$WEB_ROOT/includes/config.php"

print_header "Portal Critical Fixes Applied!"
