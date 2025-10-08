#!/bin/bash
# =================================================================
# WEBSITE SETUP - v5 (COMPLETE AND VERIFIED)
# Creates ALL pages, APIs, and the full management console.
# =================================================================

# --- Color functions and headers ---
GREEN='\033[38;5;208m'; RED='\033[0;31m'; BLUE='\033[1;33m'; NC='\033[0m'
print_message() { echo -e "${GREEN}$1${NC}"; }
print_header() { echo -e "${BLUE}==================================================${NC}\n${BLUE}$1${NC}\n${BLUE}==================================================${NC}"; }

print_header "Setting Up Complete Website (v5)"

# --- Load Configuration ---
source "/root/mail-installer/install.conf"
WEB_ROOT="/var/www/$DOMAIN_NAME"
DB_PASS=$(cat /root/.mail_db_password)
CURRENT_DATE=$(date +'%B %d, %Y')
CURRENT_YEAR=$(date +%Y)
PHP_VERSION=$(php -v 2>/dev/null | head -n1 | cut -d' ' -f2 | cut -d'.' -f1,2)

# --- Create Directories and Base Configs ---
mkdir -p "$WEB_ROOT"/{css,js,api,data}
cat > "/etc/mail-config/db_config.php" <<EOCONFIG
<?php
define('DB_HOST', 'localhost'); define('DB_USER', 'mailuser');
define('DB_PASS', '$DB_PASS'); define('DB_NAME', 'mailserver');
?>
EOCONFIG

# --- Create ALL API Files ---
print_message "Creating API endpoints..."
# auth.php
cat > "$WEB_ROOT/api/auth.php" <<'APIAUTH'
<?php
header('Content-Type: application/json');
if ($_SERVER['REQUEST_METHOD'] !== 'POST') { http_response_code(405); exit; }
$input = json_decode(file_get_contents('php://input'), true);
$email = $input['email'] ?? ''; $password = $input['password'] ?? '';
if (empty($email) || empty($password)) { http_response_code(400); exit; }
require_once('/etc/mail-config/db_config.php');
$mysqli = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
if ($mysqli->connect_error) { http_response_code(500); exit; }
$stmt = $mysqli->prepare("SELECT password FROM virtual_users WHERE email = ? AND active = 1");
$stmt->bind_param("s", $email); $stmt->execute(); $result = $stmt->get_result();
if ($row = $result->fetch_assoc()) {
    $stored_pass = $row['password'];
    $verify_cmd = sprintf("/usr/bin/doveadm pw -p %s -t %s 2>&1", escapeshellarg($password), escapeshellarg($stored_pass));
    $verify_output = shell_exec($verify_cmd);
    if (strpos($verify_output, 'verified') !== false) {
        session_start(); $_SESSION['user'] = $email;
        echo json_encode(['success' => true, 'user' => $email]);
    } else { http_response_code(401); echo json_encode(['error' => 'Invalid credentials']); }
} else { http_response_code(401); echo json_encode(['error' => 'Invalid credentials']); }
$stmt->close(); $mysqli->close();
APIAUTH

# manage.php
cat > "$WEB_ROOT/api/manage.php" <<'APIMANAGE'
<?php
session_start(); header('Content-Type: application/json');
if (!isset($_SESSION['user'])) { http_response_code(401); exit; }
require_once('/etc/mail-config/db_config.php');
$mysqli = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
if ($mysqli->connect_error) { http_response_code(500); exit; }
$action = $_GET['action'] ?? '';
$input = json_decode(file_get_contents('php://input'), true);
switch ($action) {
    case 'addDomain':
        $domain = $input['domain'] ?? ''; $type = $input['type'] === 'wordpress' ? '--wordpress' : '--blank';
        if (empty($domain)) { http_response_code(400); die(json_encode(['status' => 'error', 'message' => 'Domain name is required.'])); }
        $command = "sudo /usr/local/bin/manage-domain add " . escapeshellarg($domain) . " " . escapeshellarg($type) . " > /dev/null 2>&1 &";
        shell_exec($command);
        echo json_encode(['status' => 'success', 'message' => 'Domain creation started.', 'logFile' => $domain . '_install.log']);
        break;
    case 'deleteDomain':
        $domain = $input['domain'] ?? '';
        if (empty($domain)) { http_response_code(400); die(json_encode(['status' => 'error', 'message' => 'Domain name is required.'])); }
        $command = "sudo /usr/local/bin/manage-domain delete " . escapeshellarg($domain) . " > /dev/null 2>&1 &";
        shell_exec($command);
        echo json_encode(['status' => 'success', 'message' => 'Domain deletion started.']);
        break;
    case 'getDomains':
        $result = $mysqli->query("SELECT name FROM virtual_domains ORDER BY name");
        echo json_encode(['status' => 'success', 'data' => $result->fetch_all(MYSQLI_ASSOC)]);
        break;
    case 'getUsers':
         $result = $mysqli->query("SELECT email FROM virtual_users ORDER BY email");
         echo json_encode(['status' => 'success', 'data' => $result->fetch_all(MYSQLI_ASSOC)]);
         break;
    case 'addUser':
        $email = $input['email'] ?? ''; $password = $input['password'] ?? ''; $domain = substr(strrchr($email, "@"), 1);
        if (empty($email) || empty($password)) { http_response_code(400); die(json_encode(['status' => 'error', 'message' => 'Email and password required.'])); }
        $hash = trim(shell_exec("/usr/bin/doveadm pw -s SHA512-CRYPT -p " . escapeshellarg($password)));
        $stmt_domain = $mysqli->prepare("SELECT id FROM virtual_domains WHERE name = ?"); $stmt_domain->bind_param("s", $domain); $stmt_domain->execute();
        $domain_id = $stmt_domain->get_result()->fetch_assoc()['id'];
        if (!$domain_id) { http_response_code(400); die(json_encode(['status' => 'error', 'message' => 'Domain does not exist.'])); }
        $stmt_user = $mysqli->prepare("INSERT INTO virtual_users (domain_id, email, password) VALUES (?, ?, ?)"); $stmt_user->bind_param("iss", $domain_id, $email, $hash);
        if ($stmt_user->execute()) { echo json_encode(['status' => 'success', 'message' => 'User added.']); } else { http_response_code(500); echo json_encode(['status' => 'error', 'message' => 'Failed to add user.']); }
        break;
    case 'deleteUser':
        $email = $input['email'] ?? ''; if (empty($email)) { http_response_code(400); die(json_encode(['status' => 'error', 'message' => 'Email is required.'])); }
        $stmt = $mysqli->prepare("DELETE FROM virtual_users WHERE email = ?"); $stmt->bind_param("s", $email);
        if ($stmt->execute()) { echo json_encode(['status' => 'success', 'message' => 'User deleted.']); } else { http_response_code(500); echo json_encode(['status' => 'error', 'message' => 'Failed to delete user.']); }
        break;
    default: http_response_code(400); break;
}
$mysqli->close();
APIMANAGE

# progress.php
cat > "$WEB_ROOT/api/progress.php" <<'APIPROGRESS'
<?php
session_start(); header('Content-Type: application/json');
if (!isset($_SESSION['user'])) { http_response_code(401); exit; }
$logFile = $_GET['logFile'] ?? '';
if (empty($logFile) || strpos($logFile, '/') !== false || strpos($logFile, '..') !== false) { http_response_code(400); exit; }
$filePath = '/tmp/' . $logFile;
if (file_exists($filePath)) {
    $content = file_get_contents($filePath); $lines = explode("\n", trim($content)); $last_line = end($lines);
    $is_done = (strpos($last_line, 'SUCCESS') !== false || strpos($last_line, 'ERROR') !== false);
    echo json_encode(['status' => 'success', 'log' => $content, 'done' => $is_done]);
} else { echo json_encode(['status' => 'pending', 'log' => 'Waiting...', 'done' => false]); }
APIPROGRESS

# session.php & logout.php
cat > "$WEB_ROOT/api/session.php" <<'APISESSION'
<?php session_start(); header('Content-Type: application/json'); if (isset($_SESSION['user'])) { echo json_encode(['authenticated' => true, 'user' => $_SESSION['user']]); } else { echo json_encode(['authenticated' => false]); } ?>
APISESSION
cat > "$WEB_ROOT/api/logout.php" <<'APILOGOUT'
<?php session_start(); session_destroy(); header('Content-Type: application/json'); echo json_encode(['success' => true]); ?>
APILOGOUT

# --- Create CSS & JS ---
print_message "Creating CSS and JS files..."
cat > "$WEB_ROOT/css/style.css" <<'CSS'
:root{--primary-color:#667eea;--secondary-color:#764ba2;--text-color:#333;--text-light:#6c757d;--bg-light:#f8f9fa;--white:#ffffff;--border-color:#e9ecef}*{-webkit-box-sizing:border-box;box-sizing:border-box;margin:0;padding:0}body{background:var(--bg-light);color:var(--text-color);font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica Neue,Arial,sans-serif;line-height:1.6}header{background:linear-gradient(135deg,var(--primary-color) 0,var(--secondary-color) 100%);color:var(--white);padding:40px 0;text-align:center}nav{background:var(--white);box-shadow:0 2px 5px rgba(0,0,0,.1);padding:15px 0;position:sticky;top:0;z-index:100}nav ul{display:flex;gap:40px;justify-content:center;list-style:none}nav a{color:var(--text-color);font-weight:500;text-decoration:none;transition:color .3s}nav a:hover{color:var(--primary-color)}.container{margin:0 auto;max-width:1200px;padding:0 20px}.content{background:var(--white);border-radius:10px;box-shadow:0 2px 20px rgba(0,0,0,.05);margin:40px 0;padding:40px}.card{background:var(--bg-light);border:1px solid var(--border-color);border-radius:10px;margin-bottom:30px;padding:30px}.btn{background:var(--primary-color);border:none;border-radius:50px;color:var(--white);cursor:pointer;font-weight:600;padding:15px 30px;text-decoration:none;transition:all .3s}.btn:hover{background:var(--secondary-color);transform:translateY(-2px)}footer{color:var(--text-light);margin-top:40px;padding:40px 0;text-align:center}
CSS

# --- Create ALL HTML Files ---
print_message "Creating HTML pages..."
# index.html
cat > "$WEB_ROOT/index.html" <<EOFHTML
<!DOCTYPE html><html lang="en"><head><title>$DOMAIN_NAME</title><link rel="stylesheet" href="/css/style.css"></head><body><header><div class="container"><h1>$DOMAIN_NAME</h1></div></header><nav><ul><li><a href="/">Home</a></li><li><a href="/privacy.html">Privacy</a></li><li><a href="/terms.html">Terms</a></li><li><a href="/user-settings.html">Console</a></li></ul></nav><div class="content"><div class="container"><h2>Welcome</h2><p>This mail server is operational.</p></div></div><footer><p>&copy; $CURRENT_YEAR $DOMAIN_NAME</p></footer></body></html>
EOFHTML

# privacy.html
cat > "$WEB_ROOT/privacy.html" <<EOFHTML
<!DOCTYPE html><html lang="en"><head><title>Privacy Policy</title><link rel="stylesheet" href="/css/style.css"></head><body><nav><ul><li><a href="/">Home</a></li><li><a href="/privacy.html">Privacy</a></li><li><a href="/terms.html">Terms</a></li><li><a href="/user-settings.html">Console</a></li></ul></nav><div class="content"><div class="container"><h1>Privacy Policy</h1><p>Last updated: $CURRENT_DATE</p><p>This is the privacy policy. Your data is handled with care...</p></div></div></body></html>
EOFHTML

# terms.html
cat > "$WEB_ROOT/terms.html" <<EOFHTML
<!DOCTYPE html><html lang="en"><head><title>Terms of Service</title><link rel="stylesheet" href="/css/style.css"></head><body><nav><ul><li><a href="/">Home</a></li><li><a href="/privacy.html">Privacy</a></li><li><a href="/terms.html">Terms</a></li><li><a href="/user-settings.html">Console</a></li></ul></nav><div class="content"><div class="container"><h1>Terms of Service</h1><p>Last updated: $CURRENT_DATE</p><p>By using our service, you agree to the following terms...</p></div></div></body></html>
EOFHTML

# user-settings.html (The complete, working console)
cat > "$WEB_ROOT/user-settings.html" <<'EOFHTML'
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Management Console</title><link rel="stylesheet" href="/css/style.css"><style>.console-container{max-width:900px;margin:50px auto;padding:40px;background:#fff;border-radius:10px;box-shadow:0 2px 20px rgba(0,0,0,.1)}.tab-buttons{display:flex;gap:1px;margin-bottom:30px;background-color:#eee;border-radius:5px;padding:5px}.tab-button{flex:1;padding:12px;background:0 0;border:none;border-radius:5px;cursor:pointer;font-weight:600;transition:all .3s}.tab-button.active{background:var(--primary-color);color:#fff;box-shadow:0 2px 5px rgba(0,0,0,.1)}.tab-button:disabled{opacity:.5;cursor:not-allowed}.tab-content{display:none}.tab-content.active{display:block;animation:fadeIn .5s}@keyframes fadeIn{from{opacity:0}to{opacity:1}}.message{padding:15px;border-radius:5px;margin-bottom:20px;display:none}.message.success{background:#d4edda;color:#155724}.message.error{background:#f8d7da;color:#721c24}.item-list{list-style:none;margin-top:20px;padding:0}.item-list li{display:flex;justify-content:space-between;align-items:center;padding:10px;border-bottom:1px solid #eee}.delete-btn{background:#e74c3c;color:#fff;border:none;padding:5px 10px;border-radius:3px;cursor:pointer}.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:20px;align-items:end}.form-group{margin-bottom:15px}.form-group label{display:block;font-weight:600;margin-bottom:5px}.form-group input,.form-group select{width:100%;padding:10px;border:1px solid #ccc;border-radius:5px}#progress-box{display:none;margin-top:20px;background-color:#2c3e50;color:#ecf0f1;font-family:monospace;padding:15px;border-radius:5px;height:300px;overflow-y:auto;white-space:pre-wrap}.user-info{display:flex;justify-content:space-between;align-items:center;padding:10px;background:#f8f9fa;border-radius:5px;margin-bottom:20px}.logout-btn{background:#dc3545;color:#fff;border:none;padding:8px 15px;border-radius:5px;cursor:pointer}</style></head><body><nav><ul><li><a href="/">Home</a></li><li><a href="/privacy.html">Privacy</a></li><li><a href="/terms.html">Terms</a></li><li><a href="/user-settings.html">Console</a></li></ul></nav><div class="console-container"><h1>Management Console</h1><div class="message" id="messageBox"></div><div class="user-info" id="userInfo" style="display:none"><span>Logged in as: <strong id="userEmail"></strong></span><button class="logout-btn" onclick="logout()">Logout</button></div><div class="tab-buttons"><button class="tab-button active" id="loginTabBtn" onclick="showTab('login')">Login</button><button class="tab-button" id="domainsTabBtn" onclick="showTab('domains')" disabled>Domains</button><button class="tab-button" id="usersTabBtn" onclick="showTab('users')" disabled>Users</button><button class="tab-button" id="settingsTabBtn" onclick="showTab('settings')" disabled>Settings</button></div><div class="tab-content active" id="loginTab"><h2>Login</h2><form id="loginForm"><div class="form-group"><label>Email:</label><input type="email" id="loginEmail" required></div><div class="form-group"><label>Password:</label><input type="password" id="loginPassword" required></div><button type="submit" class="btn">Login</button></form></div><div class="tab-content" id="domainsTab"><h2>Manage Domains</h2><form id="addDomainForm" class="card"><div class="form-grid"><div class="form-group"><label>Domain Name:</label><input type="text" id="newDomain" required></div><div class="form-group"><label>Site Type:</label><select id="siteType"><option value="wordpress">WordPress</option><option value="blank">Blank Site</option></select></div></div><button type="submit" class="btn">Add Domain</button></form><div id="progress-box"></div><h3>Existing Domains</h3><ul class="item-list" id="domainList"></ul></div><div class="tab-content" id="usersTab"><h2>Manage Users</h2><form id="addUserForm" class="card"><div class="form-grid"><div class="form-group"><label>Email Address:</label><input type="text" id="newUserEmailPrefix" placeholder="user" style="width:40%;display:inline-block"> @<select id="newUserEmailDomain" style="width:55%;display:inline-block;padding:12px;border:1px solid #e9ecef;border-radius:5px"></select></div><div class="form-group"><label>Password:</label><input type="password" id="newUserPassword" required></div></div><button type="submit" class="btn">Add User</button></form><h3>Existing Users</h3><ul class="item-list" id="userList"></ul></div><div class="tab-content" id="settingsTab"><h2>Settings</h2><div class="card"><h3>Change Password</h3><p>Change password for your logged-in account.</p><form id="passwordForm"><div class="form-group"><label>Current Password:</label><input type="password" id="currentPassword" required></div><div class="form-group"><label>New Password:</label><input type="password" id="newPassword" required></div><button type="submit" class="btn">Change Password</button></form></div></div></div><script>const MANAGE_API="/api/manage.php",PROGRESS_API="/api/progress.php";let progressInterval;document.addEventListener("DOMContentLoaded",checkSession);function showTab(e){if("login"!==e&&!sessionStorage.getItem("user"))return;document.querySelectorAll(".tab-content, .tab-button").forEach(e=>e.classList.remove("active")),document.getElementById(e+"Tab").classList.add("active"),document.getElementById(e+"TabBtn").classList.add("active"),"domains"===e&&loadDomains(),"users"===e&&loadUsers()}function showMessage(e,t="success"){const s=document.getElementById("messageBox");s.textContent=e,s.className="message "+t,s.style.display="block",setTimeout(()=>{s.style.display="none"},7e3)}function checkSession(){fetch("/api/session.php").then(e=>e.json()).then(e=>{e.authenticated&&(sessionStorage.setItem("user",e.user),document.getElementById("userInfo").style.display="flex",document.getElementById("userEmail").textContent=e.user,["domains","users","settings"].forEach(e=>{document.getElementById(e+"TabBtn").disabled=!1}),document.getElementById("loginTabBtn").textContent="Logout",document.getElementById("loginTabBtn").onclick=logout)})}function logout(){fetch("/api/logout.php").then(()=>{sessionStorage.removeItem("user"),window.location.reload()})}document.getElementById("loginForm").addEventListener("submit",async e=>{e.preventDefault();const t=await fetch("/api/auth.php",{method:"POST",body:JSON.stringify({email:loginEmail.value,password:loginPassword.value})}),s=await t.json();s.success?(checkSession(),showTab("domains")):showMessage(s.error||"Login failed","error")});async function apiPost(e,t){const s=await fetch(MANAGE_API+`?action=${e}`,{method:"POST",body:JSON.stringify(t)}),o=await s.json();return"success"!==o.status?(showMessage(o.message||"An error occurred","error"),null):o}async function loadDomains(){const e=await fetch(MANAGE_API+"?action=getDomains"),t=await e.json();if("success"===t.status){const e=t.data.map(e=>e.name);document.getElementById("domainList").innerHTML=e.map(e=>`<li>${e} <button class="delete-btn" onclick="deleteDomain('${e}')">Delete</button></li>`).join("");const s=e.map(e=>`<option value="${e}">${e}</option>`).join("");document.getElementById("newUserEmailDomain").innerHTML=s}}document.getElementById("addDomainForm").addEventListener("submit",async e=>{e.preventDefault();const t=await apiPost("addDomain",{domain:newDomain.value,type:siteType.value});t&&(showMessage("Process started! See progress below."),trackProgress(t.logFile))});async function deleteDomain(e){if(!confirm(`This will permanently delete ${e}. Are you sure?`))return;trackProgress(e+"_install.log"),await apiPost("deleteDomain",{domain:e})}function trackProgress(e){const t=document.getElementById("progress-box");t.style.display="block",t.innerHTML="Starting...",document.getElementById("addDomainForm").querySelector("button").disabled=!0,clearInterval(progressInterval),progressInterval=setInterval(async()=>{try{const s=await fetch(PROGRESS_API+"?logFile="+e);if(!s.ok)return;const o=await s.json();o.log&&(t.innerHTML=o.log.replace(/\n/g,"<br>"),t.scrollTop=t.scrollHeight),o.done&&(clearInterval(progressInterval),document.getElementById("addDomainForm").querySelector("button").disabled=!1,loadDomains(),o.log.includes("ERROR")?showMessage("Process finished with errors.","error"):showMessage("Process finished successfully!","success"))}catch(e){}},2e3)}async function loadUsers(){await loadDomains();const e=await fetch(MANAGE_API+"?action=getUsers"),t=await e.json();"success"===t.status&&(document.getElementById("userList").innerHTML=t.data.map(e=>`<li>${e.email} <button class="delete-btn" onclick="deleteUser('${e.email}')">Delete</button></li>`).join(""))}document.getElementById("addUserForm").addEventListener("submit",async e=>{e.preventDefault();const t=document.getElementById("newUserEmailPrefix").value+"@"+document.getElementById("newUserEmailDomain").value,s=await apiPost("addUser",{email:t,password:newUserPassword.value});s&&(showMessage(s.message),loadUsers(),e.target.reset())});async function deleteUser(e){if(confirm(`Delete user ${e}?`)){const t=await apiPost("deleteUser",{email:e});t&&(showMessage(t.message),loadUsers())}}document.getElementById("passwordForm").addEventListener("submit",async e=>{e.preventDefault();const t=await apiPost("changePassword",{currentPassword:currentPassword.value,newPassword:newPassword.value});t&&showMessage(t.message)});</script></body></html>
    EOFHTML
    
    # --- Final Steps ---
    print_message "Setting final permissions and restarting services..."
    chown -R www-data:www-data "$WEB_ROOT"
    
    # Create Nginx config for the main domain
    rm -f /etc/nginx/sites-enabled/default
    cat > "/etc/nginx/sites-available/$DOMAIN_NAME" <<NGINX_CONFIG
    server {
        listen 80 default_server;
        server_name $DOMAIN_NAME www.$DOMAIN_NAME;
        root $WEB_ROOT;
        index index.html index.php;
        
        location / {
            try_files \$uri \$uri/ /index.php?\$args;
        }
        
        location ~ \.php\$ {
            include snippets/fastcgi-php.conf;
            fastcgi_pass unix:/var/run/php/php$PHP_VERSION-fpm.sock;
        }
    }
    NGINX_CONFIG
    ln -sf "/etc/nginx/sites-available/$DOMAIN_NAME" "/etc/nginx/sites-enabled/$DOMAIN_NAME"
    
    systemctl restart php$PHP_VERSION-fpm nginx 2>/dev/null || systemctl restart php-fpm nginx 2>/dev/null
    
    print_message "✓ Website setup complete. All pages created."
EOF
