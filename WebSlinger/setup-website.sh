#!/bin/bash

# =================================================================
# MANAGEMENT PORTAL SETUP - V3.3 (CLEANUP)
# Version: 18.2.3
# Removes incorrect permission fix, which is now handled by setup-permissions.sh
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

print_header "Setting Up Enhanced Management Portal with Alias Management"

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
ADMIN_USER_EMAIL="$FIRST_EMAIL" # The first email is the admin

# 1. Install Dependencies
print_message "Installing web server dependencies..."
apt-get update > /dev/null 2>&1
apt-get install -y nginx php-fpm php-mysql php-cli php-json unzip > /dev/null 2>&1

# 2. Create Directory Structure
print_message "Creating portal directory structure at $WEB_ROOT..."
mkdir -p "$WEB_ROOT"/{css,js,includes,api}

# 3. Create Portal Files

# --- CSS (Refined UI) ---
print_message "Creating refined CSS file..."
cat > "$WEB_ROOT/css/style.css" <<'EOF'
:root {
    --primary-color: #0d6efd;
    --secondary-color: #6c757d;
    --bg-light: #f8f9fa;
    --bg-white: #ffffff;
    --border-color: #dee2e6;
    --text-dark: #212529;
    --text-light: #6c757d;
}
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; background-color: var(--bg-light); color: var(--text-dark); margin: 0; display: flex; min-height: 100vh; }
.sidebar { width: 250px; background: #343a40; color: white; display: flex; flex-direction: column; position: fixed; height: 100%; }
.sidebar-header { padding: 20px; font-size: 1.5em; text-align: center; background: rgba(0,0,0,0.2); }
.sidebar nav { flex-grow: 1; }
.sidebar nav a { display: block; color: #adb5bd; text-decoration: none; padding: 15px 20px; }
.sidebar nav a:hover, .sidebar nav a.active { background: var(--primary-color); color: white; }
.sidebar footer { padding: 20px; font-size: 0.8em; text-align: center; }
.main-content { margin-left: 250px; width: calc(100% - 250px); padding: 20px; }
.page-header { border-bottom: 1px solid var(--border-color); padding-bottom: 15px; margin-bottom: 30px; display: flex; justify-content: space-between; align-items: center; }
.card { background: var(--bg-white); border: 1px solid var(--border-color); border-radius: 0.375rem; margin-bottom: 20px; }
.card-header { padding: 1rem 1rem; background-color: rgba(0,0,0,.03); border-bottom: 1px solid var(--border-color); font-size: 1.2em; font-weight: 500; }
.card-body { padding: 1rem 1rem; }
.form-group { margin-bottom: 1rem; }
.form-group label { display: block; margin-bottom: .5rem; font-weight: 500; }
.form-control { width: 100%; padding: .5rem .75rem; font-size: 1rem; border: 1px solid var(--border-color); border-radius: .25rem; box-sizing: border-box; }
.btn { display: inline-block; font-weight: 400; text-align: center; vertical-align: middle; cursor: pointer; border: 1px solid transparent; padding: .5rem 1rem; font-size: 1rem; border-radius: .25rem; text-decoration: none; }
.btn-primary { color: #fff; background-color: var(--primary-color); border-color: var(--primary-color); }
.btn-danger { color: #fff; background-color: #dc3545; border-color: #dc3545; }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 12px; border-bottom: 1px solid var(--border-color); }
th { background-color: var(--bg-light); }
.modal { display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.5); }
.modal-content { background-color: #fff; margin: 15% auto; padding: 20px; border-radius: 5px; width: 80%; max-width: 500px; }
.close-button { color: #aaa; float: right; font-size: 28px; font-weight: bold; cursor: pointer; }
#login-container { width: 100%; height: 100vh; display: flex; justify-content: center; align-items: center; }
#login-box { width: 350px; padding: 40px; background: white; box-shadow: 0 0 20px rgba(0,0,0,0.1); border-radius: 10px; }
EOF

# --- JavaScript (for Modals and AJAX) ---
print_message "Creating enhanced JavaScript file..."
cat > "$WEB_ROOT/js/main.js" <<'EOF'
document.addEventListener('DOMContentLoaded', () => {
    // Set active nav link
    const path = window.location.pathname;
    document.querySelectorAll('.sidebar nav a').forEach(link => {
        if (link.getAttribute('href') === path) {
            link.classList.add('active');
        }
    });

    // Handle logout
    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', e => {
            e.preventDefault();
            fetch('/api/auth.php?action=logout', { method: 'POST' })
                .then(() => window.location.href = '/login.php');
        });
    }

    // Modal handling
    window.openModal = (id) => document.getElementById(id).style.display = 'block';
    window.closeModal = (id) => document.getElementById(id).style.display = 'none';

    document.querySelectorAll('.modal .close-button').forEach(btn => {
        btn.onclick = () => btn.closest('.modal').style.display = 'none';
    });
    window.onclick = (event) => {
        if (event.target.classList.contains('modal')) {
            event.target.style.display = 'none';
        }
    };
});
EOF

# --- Includes (Header and Footer with new UI) ---
print_message "Creating new header and footer with Aliases link..."
cat > "$WEB_ROOT/includes/header.php" <<EOF
<?php
session_start();
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

# --- Login Page (Secure) ---
print_message "Creating secure login page..."
cat > "$WEB_ROOT/login.php" <<EOF
<?php
include 'includes/header.php';
// Redirect if already logged in
if (isset(\$_SESSION['loggedin'])) {
    header('Location: /');
    exit;
}
?>
<div id="login-box">
    <h2 style="text-align: center; margin-bottom: 20px;">Portal Login</h2>
    <div id="errorMessage" style="color:red; margin-bottom:15px; text-align:center;"></div>
    <form id="loginForm" method="POST" action="/api/auth.php?action=login">
        <div class="form-group">
            <label for="email">Email</label>
            <input type="email" id="email" name="email" class="form-control" required>
        </div>
        <div class="form-group">
            <label for="password">Password</label>
            <input type="password" id="password" name="password" class="form-control" required>
        </div>
        <button type="submit" class="btn btn-primary" style="width:100%;">Login</button>
    </form>
</div>
<script>
document.getElementById('loginForm').addEventListener('submit', function(e) {
    e.preventDefault();
    const form = e.target;
    const formData = new FormData(form);
    const errorDiv = document.getElementById('errorMessage');
    
    fetch(form.action, {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            window.location.href = '/';
        } else {
            errorDiv.textContent = data.error || 'An unknown error occurred.';
        }
    })
    .catch(err => {
        errorDiv.textContent = 'A network error occurred. Please try again.';
    });
});
</script>
<?php include 'includes/footer.php'; ?>
EOF

# --- Secure Authentication API (auth.php) with DIAGNOSTIC LOGGING ---
print_message "Creating secure authentication API with diagnostic logging..."
cat > "$WEB_ROOT/api/auth.php" <<EOF
<?php
session_start();
header('Content-Type: application/json');

// --- CONFIG ---
\$admin_email = "$ADMIN_USER_EMAIL";
// --- END CONFIG ---

function login() {
    global \$admin_email;
    if (empty(\$_POST['email']) || empty(\$_POST['password'])) {
        echo json_encode(['success' => false, 'error' => 'Email and password are required.']);
        exit;
    }

    \$email = \$_POST['email'];
    \$password = \$_POST['password'];

    if (\$email !== \$admin_email) {
        echo json_encode(['success' => false, 'error' => 'Access denied.']);
        exit;
    }

    \$escaped_password = escapeshellarg(\$password);
    // Use full path for doveadm to avoid PATH issues
    \$verification_cmd = "/usr/bin/doveadm auth test " . escapeshellarg(\$email) . " " . \$escaped_password;
    
    exec(\$verification_cmd . " 2>&1", \$output, \$return_code);

    \$auth_success = false;
    foreach (\$output as \$line) {
        if (strpos(\$line, 'passdb lookup succeeded') !== false) {
            \$auth_success = true;
            break;
        }
    }

    if (\$auth_success) {
        \$_SESSION['loggedin'] = true;
        \$_SESSION['user'] = \$email;
        echo json_encode(['success' => true]);
    } else {
        // DETAILED LOGGING FOR DIAGNOSIS
        \$log_message = "Failed login for user: " . \$email . "\\n";
        \$log_message .= "doveadm command: " . \$verification_cmd . "\\n";
        \$log_message .= "Return code: " . \$return_code . "\\n";
        \$log_message .= "Output: " . implode("\\n", \$output);
        error_log(\$log_message);
        
        echo json_encode(['success' => false, 'error' => 'Invalid credentials.']);
    }
}

function logout() {
    session_unset();
    session_destroy();
    echo json_encode(['success' => true, 'message' => 'Logged out']);
}

\$action = \$_GET['action'] ?? '';
switch (\$action) {
    case 'login':
        login();
        break;
    case 'logout':
        logout();
        break;
    default:
        echo json_encode(['success' => false, 'error' => 'Invalid action']);
        break;
}
EOF

# --- Dashboard (index.php) ---
print_message "Creating new dashboard..."
cat > "$WEB_ROOT/index.php" <<'EOF'
<?php include 'includes/header.php'; ?>
<div class="page-header">
    <h2>Dashboard</h2>
</div>
<div class="card">
    <div class="card-header">Server Status</div>
    <div class="card-body">
        <p>Welcome to the mail server management portal.</p>
        <p><strong>PHP Version:</strong> <?php echo phpversion(); ?></p>
        <p><strong>Nginx Version:</strong> <?php echo shell_exec('nginx -v 2>&1'); ?></p>
    </div>
</div>
<div class="card">
    <div class="card-header">Quick Stats</div>
    <div class="card-body">
        <?php
            $db_pass = trim(file_get_contents('/root/.mail_db_password'));
            $conn = new mysqli('127.0.0.1', 'mailuser', $db_pass, 'mailserver');
            $domains_count = shell_exec("ls -l /etc/nginx/sites-available | grep -v 'default' | grep -v 'total' | wc -l");
            $users_count = "DB Error";
            $aliases_count = "DB Error";
            if (!$conn->connect_error) {
                $users_res = $conn->query("SELECT COUNT(*) as count FROM virtual_users");
                $users_count = $users_res->fetch_assoc()['count'];
                $aliases_res = $conn->query("SELECT COUNT(*) as count FROM virtual_aliases");
                $aliases_count = $aliases_res->fetch_assoc()['count'];
            }
        ?>
        <p><strong>Managed Domains:</strong> <?php echo $domains_count; ?></p>
        <p><strong>Email Accounts:</strong> <?php echo $users_count; ?></p>
        <p><strong>Email Aliases:</strong> <?php echo $aliases_count; ?></p>
    </div>
</div>
<?php include 'includes/footer.php'; ?>
EOF

# --- Domain Management Page (with Delete) ---
print_message "Creating enhanced domain management page..."
cat > "$WEB_ROOT/domains.php" <<'EOF'
<?php
include 'includes/header.php';

function run_command($command) {
    shell_exec($command . " > /dev/null 2>&1");
}

// Handle Add Domain
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['add_domain'])) {
    $domain = trim($_POST['domain']);
    if (!empty($domain) && filter_var($domain, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
        $webroot = "/var/www/$domain";
        $nginx_conf_path = "/etc/nginx/sites-available/$domain";
        
        // 1. Create Nginx config
        $nginx_conf = "server { listen 80; server_name $domain www.$domain; root $webroot; index index.php index.html; location / { try_files \$uri \$uri/ /index.php?\$args; } location ~ \.php$ { include snippets/fastcgi-php.conf; fastcgi_pass unix:/var/run/php/php" . phpversion() . "-fpm.sock; } }";
        file_put_contents($nginx_conf_path, $nginx_conf);
        
        // 2. Enable site
        run_command("ln -s $nginx_conf_path /etc/nginx/sites-enabled/");
        
        // 3. Create web root and install WordPress
        run_command("mkdir -p $webroot");
        run_command("wget https://wordpress.org/latest.tar.gz -O /tmp/wordpress.tar.gz");
        run_command("tar -xzf /tmp/wordpress.tar.gz -C $webroot --strip-components=1");
        run_command("chown -R www-data:www-data $webroot");
        
        // 4. Create database
        $db_name = preg_replace('/[^a-zA-Z0-9_]/', '_', $domain);
        $db_user = substr($db_name, 0, 16);
        $db_pass = substr(str_shuffle('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'), 0, 16);
        $root_db_pass = trim(file_get_contents('/root/.mail_db_password'));
        $conn = new mysqli('127.0.0.1', 'root', $root_db_pass);
        $conn->query("CREATE DATABASE $db_name;");
        $conn->query("CREATE USER '$db_user'@'localhost' IDENTIFIED BY '$db_pass';");
        $conn->query("GRANT ALL PRIVILEGES ON $db_name.* TO '$db_user'@'localhost';");
        $conn->query("FLUSH PRIVILEGES;");
        
        // 5. Configure wp-config.php
        $wp_config_path = "$webroot/wp-config.php";
        copy("$webroot/wp-config-sample.php", $wp_config_path);
        $config_content = file_get_contents($wp_config_path);
        $config_content = str_replace('database_name_here', $db_name, $config_content);
        $config_content = str_replace('username_here', $db_user, $config_content);
        $config_content = str_replace('password_here', $db_pass, $config_content);
        // Add salt keys
        $salts = file_get_contents('https://api.wordpress.org/secret-key/1.1/salt/');
        $config_content = preg_replace('/put your unique phrases here(.+?)\/put/s', $salts, $config_content);
        file_put_contents($wp_config_path, $config_content);
        
        // 6. Reload Nginx
        run_command("systemctl reload nginx");
        
        echo "<div style='color:green; padding:10px; background:#e8f5e9; border-radius:4px;'>Domain $domain added and WordPress installed.</div>";
    }
}

// Handle Delete Domain
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['delete_domain'])) {
    $domain = trim($_POST['domain']);
    if (!empty($domain)) {
        // 1. Disable and remove Nginx config
        run_command("rm /etc/nginx/sites-enabled/$domain");
        run_command("rm /etc/nginx/sites-available/$domain");
        
        // 2. Remove web root
        run_command("rm -rf /var/www/$domain");
        
        // 3. Drop database
        $db_name = preg_replace('/[^a-zA-Z0-9_]/', '_', $domain);
        $root_db_pass = trim(file_get_contents('/root/.mail_db_password'));
        $conn = new mysqli('127.0.0.1', 'root', $root_db_pass);
        $conn->query("DROP DATABASE IF EXISTS $db_name;");
        $conn->query("DROP USER IF EXISTS '" . substr($db_name, 0, 16) . "'@'localhost';");
        
        // 4. Reload Nginx
        run_command("systemctl reload nginx");
        echo "<div style='color:green; padding:10px; background:#e8f5e9; border-radius:4px;'>Domain $domain deleted.</div>";
    }
}
?>

<div class="page-header">
    <h2>Manage Domains</h2>
    <button class="btn btn-primary" onclick="openModal('addDomainModal')">Add New Domain</button>
</div>

<div class="card">
    <div class="card-header">Existing Domains</div>
    <div class="card-body">
        <table>
            <thead><tr><th>Domain Name</th><th>Actions</th></tr></thead>
            <tbody>
            <?php
            $sites = scandir('/etc/nginx/sites-available');
            foreach ($sites as $site) {
                if ($site !== '.' && $site !== '..' && $site !== 'default') {
                    echo "<tr><td><a href='http://{$site}' target='_blank'>{$site}</a></td><td>
                        <form method='POST' style='display:inline;' onsubmit='return confirm(\"Are you sure you want to delete {$site} and its WordPress installation?\");'>
                            <input type='hidden' name='domain' value='{$site}'>
                            <button type='submit' name='delete_domain' class='btn btn-danger'>Delete</button>
                        </form>
                    </td></tr>";
                }
            }
            ?>
            </tbody>
        </table>
    </div>
</div>

<!-- Add Domain Modal -->
<div id="addDomainModal" class="modal">
    <div class="modal-content">
        <span class="close-button" onclick="closeModal('addDomainModal')">&times;</span>
        <h3>Add New Domain</h3>
        <form method="POST">
            <div class="form-group">
                <label for="domain">Domain Name</label>
                <input type="text" id="domain" name="domain" class="form-control" placeholder="example.com" required>
            </div>
            <button type="submit" name="add_domain" class="btn btn-primary">Add Domain & Install WordPress</button>
        </form>
    </div>
</div>

<?php include 'includes/footer.php'; ?>
EOF

# --- Email Management Page (with Modals) ---
print_message "Creating enhanced email management page..."
cat > "$WEB_ROOT/emails.php" <<'EOF'
<?php
include 'includes/header.php';
$db_pass = trim(file_get_contents('/root/.mail_db_password'));
$db = new mysqli('127.0.0.1', 'mailuser', $db_pass, 'mailserver');

// Add Email
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['add_email'])) {
    $email = $db->real_escape_string($_POST['email']);
    $password = $_POST['password'];
    $domain_name = substr(strrchr($email, "@"), 1);

    $domain_res = $db->query("SELECT id FROM virtual_domains WHERE name = '{$domain_name}'");
    if ($domain_res->num_rows == 0) {
        $db->query("INSERT INTO virtual_domains (name) VALUES ('{$domain_name}')");
    }
    $domain_id_res = $db->query("SELECT id FROM virtual_domains WHERE name = '{$domain_name}'");
    $domain_id = $domain_id_res->fetch_assoc()['id'];
    
    $hashed_pass = trim(shell_exec("doveadm pw -s SHA512-CRYPT -p ".escapeshellarg($password)));
    $db->query("INSERT INTO virtual_users (domain_id, email, password, active) VALUES ({$domain_id}, '{$email}', '{$hashed_pass}', 1) ON DUPLICATE KEY UPDATE password='{$hashed_pass}'");
}

// Delete Email
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['delete_email'])) {
    $email = $db->real_escape_string($_POST['email']);
    $db->query("DELETE FROM virtual_users WHERE email = '{$email}'");
}

// Change Password
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['change_password'])) {
    $email = $db->real_escape_string($_POST['email']);
    $password = $_POST['password'];
    $hashed_pass = trim(shell_exec("doveadm pw -s SHA512-CRYPT -p ".escapeshellarg($password)));
    $db->query("UPDATE virtual_users SET password = '{$hashed_pass}' WHERE email = '{$email}'");
}

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

<!-- Add Email Modal -->
<div id="addEmailModal" class="modal"><div class="modal-content">
    <span class="close-button" onclick="closeModal('addEmailModal')">&times;</span>
    <h3>Add New Email Account</h3>
    <form method="POST">
        <div class="form-group"><label>Email</label><input type="email" name="email" class="form-control" required></div>
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

# --- Alias Management Page ---
print_message "Creating new email alias management page..."
cat > "$WEB_ROOT/aliases.php" <<'EOF'
<?php
include 'includes/header.php';
$db_pass = trim(file_get_contents('/root/.mail_db_password'));
$db = new mysqli('127.0.0.1', 'mailuser', $db_pass, 'mailserver');

// Add Alias
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['add_alias'])) {
    $source = $db->real_escape_string($_POST['source']);
    $destination = $db->real_escape_string($_POST['destination']);
    $domain_name = substr(strrchr($source, "@"), 1);

    // Ensure domain exists in virtual_domains table
    $domain_res = $db->query("SELECT id FROM virtual_domains WHERE name = '{$domain_name}'");
    if ($domain_res->num_rows == 0) {
        $db->query("INSERT INTO virtual_domains (name) VALUES ('{$domain_name}')");
    }
    $domain_id_res = $db->query("SELECT id FROM virtual_domains WHERE name = '{$domain_name}'");
    $domain_id = $domain_id_res->fetch_assoc()['id'];
    
    $db->query("INSERT INTO virtual_aliases (domain_id, source, destination, active) VALUES ({$domain_id}, '{$source}', '{$destination}', 1)");
}

// Delete Alias
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['delete_alias'])) {
    $alias_id = $db->real_escape_string($_POST['alias_id']);
    $db->query("DELETE FROM virtual_aliases WHERE id = {$alias_id}");
}

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

<!-- Add Alias Modal -->
<div id="addAliasModal" class="modal">
    <div class="modal-content">
        <span class="close-button" onclick="closeModal('addAliasModal')">&times;</span>
        <h3>Add New Alias</h3>
        <form method="POST">
            <div class="form-group">
                <label>Source Email (Alias)</label>
                <input type="email" name="source" class="form-control" placeholder="alias@example.com" required>
            </div>
            <div class="form-group">
                <label>Destination Email</label>
                <input type="email" name="destination" class="form-control" placeholder="real-account@example.com" required>
            </div>
            <button type="submit" name="add_alias" class="btn btn-primary">Add Alias</button>
        </form>
    </div>
</div>

<?php include 'includes/footer.php'; ?>
EOF


# 4. Configure Nginx
print_message "Configuring Nginx for the portal..."
NGINX_CONF="/etc/nginx/sites-available/default"
rm -f /etc/nginx/sites-enabled/default
cat > "$NGINX_CONF" <<EOF
server {
    listen 80 default_server;
    server_name _; # Catch-all for the IP
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
systemctl reload nginx
systemctl restart php${PHP_VERSION}-fpm

# 5. Final Permissions
print_message "Setting final permissions..."
chown -R www-data:www-data "$WEB_ROOT"
chmod -R 755 "$WEB_ROOT"

print_header "Enhanced Portal with Alias Management Setup Complete!"
echo "Portal URL: http://$DOMAIN_NAME"
echo "Login with the first email account created during installation: $ADMIN_USER_EMAIL"
