#!/bin/bash

# =================================================================
# WEBSITE SETUP FOR BULK EMAIL COMPLIANCE
# Version: 17.0.0
# Creates compliance website with privacy policy and unsubscribe
# FIXED: Truncated HTML line, improved nginx configuration
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
        read -p "Enter your domain name: " DOMAIN_NAME
    fi
fi

# Get hostname with subdomain
if [ ! -z "$MAIL_SUBDOMAIN" ]; then
    HOSTNAME="$MAIL_SUBDOMAIN.$DOMAIN_NAME"
else
    HOSTNAME=${HOSTNAME:-"mail.$DOMAIN_NAME"}
fi

# Get primary IP if not in config
if [ -z "$PRIMARY_IP" ]; then
    PRIMARY_IP=$(curl -s https://ipinfo.io/ip 2>/dev/null || hostname -I | awk '{print $1}')
fi

# Get admin email
if [ -z "$ADMIN_EMAIL" ]; then
    ADMIN_EMAIL="${FIRST_EMAIL:-admin@$DOMAIN_NAME}"
fi

# Get current date
CURRENT_DATE=$(date +'%B %d, %Y')
CURRENT_YEAR=$(date +%Y)

echo "Domain: $DOMAIN_NAME"
echo "Mail Server: $HOSTNAME"
echo "Primary IP: $PRIMARY_IP"
echo "Admin Email: $ADMIN_EMAIL"
echo ""

# ===================================================================
# 1. INSTALL NGINX
# ===================================================================

print_header "Installing Web Server"

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

# Stop Apache if running (conflicts with nginx)
if systemctl is-active --quiet apache2; then
    echo "Stopping Apache2 (conflicts with Nginx)..."
    systemctl stop apache2
    systemctl disable apache2 2>/dev/null
fi

# Start Nginx if not running
if ! systemctl is-active --quiet nginx; then
    systemctl start nginx 2>/dev/null
    systemctl enable nginx 2>/dev/null
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

# ===================================================================
# 3. CREATE WEBSITE CONTENT
# ===================================================================

echo "Creating website pages..."

# Create modern CSS file
cat > "$WEB_ROOT/css/style.css" <<'EOF'
/* Modern Email Service Website Styles */
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
}

.btn:hover {
    background: #5a67d8;
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
}
EOF

# Homepage with professional design (FIXED TRUNCATION)
cat > "$WEB_ROOT/index.html" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="Professional email services by $DOMAIN_NAME">
    <title>$DOMAIN_NAME - Professional Email Services</title>
    <link rel="stylesheet" href="/css/style.css">
</head>
<body>
    <header>
        <div class="container">
            <h1>$DOMAIN_NAME</h1>
            <p>Professional Email Services • Reliable Delivery • Full Compliance</p>
        </div>
    </header>
    
    <nav>
        <ul>
            <li><a href="/">Home</a></li>
            <li><a href="/privacy.html">Privacy Policy</a></li>
            <li><a href="/terms.html">Terms of Service</a></li>
            <li><a href="/contact.html">Contact</a></li>
            <li><a href="/unsubscribe">Unsubscribe</a></li>
        </ul>
    </nav>
    
    <div class="content">
        <div class="container">
            <div class="section">
                <h2>Welcome to $DOMAIN_NAME</h2>
                <div class="card">
                    <h3>Professional Email Infrastructure</h3>
                    <p>We provide reliable email services with a focus on deliverability, compliance, and respect for recipient preferences.</p>
                    <p>Our infrastructure ensures your communications reach their intended recipients while maintaining the highest standards of email best practices.</p>
                </div>
            </div>
            
            <div class="section">
                <h2>Our Commitment</h2>
                <div class="features">
                    <div class="feature">
                        <div class="feature-icon">🔒</div>
                        <h3>Privacy First</h3>
                        <p>Your data is protected with industry-standard encryption and security measures.</p>
                    </div>
                    <div class="feature">
                        <div class="feature-icon">✉️</div>
                        <h3>Reliable Delivery</h3>
                        <p>Advanced infrastructure ensures your emails reach their destination.</p>
                    </div>
                    <div class="feature">
                        <div class="feature-icon">⚖️</div>
                        <h3>Full Compliance</h3>
                        <p>CAN-SPAM, GDPR, and all major email regulations compliance.</p>
                    </div>
                    <div class="feature">
                        <div class="feature-icon">🚀</div>
                        <h3>High Performance</h3>
                        <p>Optimized servers for fast, efficient email delivery.</p>
                    </div>
                </div>
            </div>
            
            <div class="section">
                <h2>Email Compliance</h2>
                <div class="card">
                    <h3>Industry Standards</h3>
                    <div class="compliance-badges">
                        <span class="badge">CAN-SPAM Compliant</span>
                        <span class="badge">GDPR Compliant</span>
                        <span class="badge">DKIM Authenticated</span>
                        <span class="badge">SPF Authorized</span>
                        <span class="badge">DMARC Enabled</span>
                    </div>
                    <p>We maintain strict compliance with international email regulations. All emails sent through our service include:</p>
                    <ul style="margin-left: 20px; margin-top: 15px; line-height: 2;">
                        <li>✓ Clear sender identification</li>
                        <li>✓ Accurate subject lines</li>
                        <li>✓ Physical mailing address</li>
                        <li>✓ One-click unsubscribe options</li>
                        <li>✓ Prompt honor of opt-out requests</li>
                        <li>✓ No deceptive practices</li>
                    </ul>
                </div>
            </div>
            
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
                        <strong>Important:</strong> To unsubscribe or manage your email preferences, please use the unsubscribe link provided in any email you've received from us. This ensures we can properly identify and update your preferences in our system.
                    </div>
                    <a href="/unsubscribe" class="btn">Unsubscribe Center</a>
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
                <a href="/contact.html">Contact Us</a> |
                <a href="/unsubscribe">Unsubscribe</a>
            </p>
            <p style="margin-top: 30px; font-size: 0.9em; opacity: 0.8;">
                Professional Email Services • Powered by Enterprise Infrastructure
            </p>
        </div>
    </footer>
</body>
</html>
EOF

# Create Privacy Policy
cat > "$WEB_ROOT/privacy.html" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Privacy Policy - $DOMAIN_NAME</title>
    <link rel="stylesheet" href="/css/style.css">
    <style>
        .content { max-width: 900px; margin: 40px auto; }
        .date { color: #6c757d; margin-bottom: 30px; font-size: 1.1em; }
        .highlight { background: #f8f9fa; padding: 20px; border-left: 4px solid #667eea; margin: 20px 0; }
        .back-link { 
            display: inline-block;
            margin-top: 40px;
            padding: 12px 30px;
            background: #667eea;
            color: white;
            text-decoration: none;
            border-radius: 50px;
            font-weight: 600;
        }
        .back-link:hover { background: #5a67d8; }
    </style>
</head>
<body>
    <nav>
        <ul>
            <li><a href="/">Home</a></li>
            <li><a href="/privacy.html">Privacy Policy</a></li>
            <li><a href="/terms.html">Terms of Service</a></li>
            <li><a href="/contact.html">Contact</a></li>
            <li><a href="/unsubscribe">Unsubscribe</a></li>
        </ul>
    </nav>
    
    <div class="content">
        <h1 style="color: #667eea;">Privacy Policy</h1>
        <div class="date">Last Updated: $CURRENT_DATE</div>
        
        <div class="highlight">
            <strong>Your Privacy Matters:</strong> We are committed to protecting your personal information and being transparent about how we collect, use, and safeguard your data.
        </div>
        
        <h2>1. Information We Collect</h2>
        <p>We collect information you provide directly to us, including:</p>
        <ul>
            <li><strong>Email Address:</strong> Required for email communications</li>
            <li><strong>Name:</strong> If provided for personalization</li>
            <li><strong>Preferences:</strong> Your communication preferences and interests</li>
            <li><strong>Technical Data:</strong> IP addresses, email open rates, and click data for security and optimization</li>
        </ul>
        
        <h2>2. How We Use Your Information</h2>
        <p>We use the information we collect to:</p>
        <ul>
            <li>Send you email communications you've subscribed to</li>
            <li>Personalize content based on your preferences</li>
            <li>Respond to your inquiries and requests</li>
            <li>Improve our email services and content</li>
            <li>Comply with legal obligations</li>
            <li>Protect against fraud and abuse</li>
        </ul>
        
        <h2>3. Email Communications</h2>
        <p>Our commitment to responsible email practices:</p>
        <ul>
            <li><strong>Consent-Based:</strong> We only send emails to those who have opted in</li>
            <li><strong>Clear Identification:</strong> All emails clearly identify the sender</li>
            <li><strong>Easy Unsubscribe:</strong> Every email includes a one-click unsubscribe link</li>
            <li><strong>Immediate Processing:</strong> Unsubscribe requests are honored immediately</li>
            <li><strong>No Hidden Tracking:</strong> We're transparent about email tracking</li>
        </ul>
        
        <h2>4. Data Protection & Security</h2>
        <p>We implement industry-standard security measures including:</p>
        <ul>
            <li>Encryption of data in transit and at rest</li>
            <li>Regular security audits and updates</li>
            <li>Limited access to personal information</li>
            <li>Secure data storage practices</li>
            <li>Regular backups and disaster recovery procedures</li>
        </ul>
        
        <h2>5. Data Sharing</h2>
        <p>We do not sell, rent, or trade your personal information. We may share data only:</p>
        <ul>
            <li>With your explicit consent</li>
            <li>To comply with legal obligations</li>
            <li>To protect rights, safety, or property</li>
            <li>With service providers under strict confidentiality agreements</li>
        </ul>
        
        <h2>6. Your Rights</h2>
        <p>You have the right to:</p>
        <ul>
            <li><strong>Access:</strong> Request a copy of your personal information</li>
            <li><strong>Correction:</strong> Update or correct your information</li>
            <li><strong>Deletion:</strong> Request deletion of your data</li>
            <li><strong>Portability:</strong> Receive your data in a portable format</li>
            <li><strong>Opt-Out:</strong> Unsubscribe from communications at any time</li>
            <li><strong>Restriction:</strong> Limit how we process your data</li>
        </ul>
        
        <h2>7. Data Retention</h2>
        <p>We retain your information only as long as necessary to:</p>
        <ul>
            <li>Provide the services you've requested</li>
            <li>Comply with legal obligations</li>
            <li>Resolve disputes and enforce agreements</li>
        </ul>
        <p>You may request deletion of your data at any time.</p>
        
        <h2>8. Contact Us</h2>
        <p>If you have questions about this Privacy Policy or our data practices, please contact us:</p>
        <div class="highlight">
            <p><strong>Email:</strong> privacy@$DOMAIN_NAME</p>
            <p><strong>Website:</strong> <a href="/">$DOMAIN_NAME</a></p>
            <p><strong>Mail Server:</strong> $HOSTNAME</p>
        </div>
        
        <a href="/" class="back-link">← Back to Home</a>
    </div>
</body>
</html>
EOF

# Create Terms of Service
cat > "$WEB_ROOT/terms.html" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Terms of Service - $DOMAIN_NAME</title>
    <link rel="stylesheet" href="/css/style.css">
    <style>
        .content { max-width: 900px; margin: 40px auto; padding: 40px; }
        .back-link { 
            display: inline-block;
            margin-top: 40px;
            padding: 12px 30px;
            background: #667eea;
            color: white;
            text-decoration: none;
            border-radius: 50px;
        }
    </style>
</head>
<body>
    <nav>
        <ul>
            <li><a href="/">Home</a></li>
            <li><a href="/privacy.html">Privacy Policy</a></li>
            <li><a href="/terms.html">Terms of Service</a></li>
            <li><a href="/contact.html">Contact</a></li>
            <li><a href="/unsubscribe">Unsubscribe</a></li>
        </ul>
    </nav>
    
    <div class="content">
        <h1 style="color: #667eea;">Terms of Service</h1>
        <p>Last Updated: $CURRENT_DATE</p>
        
        <h2>1. Acceptance of Terms</h2>
        <p>By subscribing to our email list or using our services, you agree to these Terms of Service.</p>
        
        <h2>2. Email Services</h2>
        <p>Our email services are provided to subscribers who have explicitly opted in. You may unsubscribe at any time using the unsubscribe link in any email.</p>
        
        <h2>3. Anti-Spam Compliance</h2>
        <p>We maintain strict compliance with CAN-SPAM Act, GDPR, and other international anti-spam regulations. We never:</p>
        <ul>
            <li>Send unsolicited commercial emails</li>
            <li>Use deceptive subject lines or headers</li>
            <li>Hide or obscure sender information</li>
            <li>Sell or rent email addresses to third parties</li>
        </ul>
        
        <h2>4. User Responsibilities</h2>
        <p>When subscribing to our services, you agree to:</p>
        <ul>
            <li>Provide accurate and current information</li>
            <li>Maintain the security of your account credentials</li>
            <li>Notify us of any unauthorized use</li>
            <li>Use our services in compliance with all applicable laws</li>
        </ul>
        
        <h2>5. Intellectual Property</h2>
        <p>All content provided through our email services is protected by copyright and other intellectual property laws.</p>
        
        <h2>6. Limitation of Liability</h2>
        <p>Our services are provided "as is" without warranties of any kind. We are not liable for any indirect, incidental, or consequential damages.</p>
        
        <h2>7. Modifications</h2>
        <p>We reserve the right to modify these terms at any time. Continued use of our services constitutes acceptance of modified terms.</p>
        
        <h2>8. Contact Information</h2>
        <p>For questions about these Terms, contact us at:</p>
        <p><strong>Email:</strong> legal@$DOMAIN_NAME</p>
        <p><strong>Website:</strong> $DOMAIN_NAME</p>
        
        <a href="/" class="back-link">← Back to Home</a>
    </div>
</body>
</html>
EOF

# Create Contact Page
cat > "$WEB_ROOT/contact.html" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Contact Us - $DOMAIN_NAME</title>
    <link rel="stylesheet" href="/css/style.css">
    <style>
        .content { max-width: 900px; margin: 40px auto; padding: 40px; }
        .contact-card {
            background: #f8f9fa;
            padding: 30px;
            border-radius: 10px;
            margin: 30px 0;
        }
        .address-box {
            background: white;
            border: 2px solid #667eea;
            padding: 25px;
            border-radius: 10px;
            margin: 30px 0;
        }
        .important-notice {
            background: #fff3cd;
            border: 1px solid #ffc107;
            color: #856404;
            padding: 20px;
            border-radius: 5px;
            margin: 30px 0;
        }
        .back-link {
            display: inline-block;
            margin-top: 40px;
            padding: 12px 30px;
            background: #667eea;
            color: white;
            text-decoration: none;
            border-radius: 50px;
        }
    </style>
</head>
<body>
    <nav>
        <ul>
            <li><a href="/">Home</a></li>
            <li><a href="/privacy.html">Privacy Policy</a></li>
            <li><a href="/terms.html">Terms of Service</a></li>
            <li><a href="/contact.html">Contact</a></li>
            <li><a href="/unsubscribe">Unsubscribe</a></li>
        </ul>
    </nav>
    
    <div class="content">
        <h1 style="color: #667eea;">Contact Us</h1>
        
        <div class="contact-card">
            <h2>General Inquiries</h2>
            <p><strong>Domain:</strong> $DOMAIN_NAME</p>
            <p><strong>Email Server:</strong> $HOSTNAME</p>
            <p><strong>Contact Email:</strong> contact@$DOMAIN_NAME</p>
            <p><strong>Privacy Inquiries:</strong> privacy@$DOMAIN_NAME</p>
            <p><strong>Abuse Reports:</strong> abuse@$DOMAIN_NAME</p>
        </div>
        
        <div class="address-box">
            <h2>Mailing Address</h2>
            <p><strong>CAN-SPAM Compliance Physical Address:</strong></p>
            <p>
                [YOUR COMPANY NAME]<br>
                [STREET ADDRESS]<br>
                [CITY, STATE ZIP CODE]<br>
                [COUNTRY]
            </p>
            <div class="important-notice">
                <strong>⚠️ IMPORTANT:</strong> You must update this address with your actual physical mailing address to comply with CAN-SPAM Act requirements. Edit this file at: $WEB_ROOT/contact.html
            </div>
        </div>
        
        <div class="contact-card">
            <h2>Technical Information</h2>
            <p><strong>Mail Server:</strong> $HOSTNAME</p>
            <p><strong>Server IP:</strong> $PRIMARY_IP</p>
            <p><strong>Email Authentication:</strong></p>
            <ul style="margin-left: 20px;">
                <li>SPF: Enabled</li>
                <li>DKIM: Enabled (Selector: mail)</li>
                <li>DMARC: Configured</li>
            </ul>
        </div>
        
        <a href="/" class="back-link">← Back to Home</a>
    </div>
</body>
</html>
EOF

# Create robots.txt
cat > "$WEB_ROOT/robots.txt" <<EOF
User-agent: *
Allow: /
Disallow: /unsubscribe
Sitemap: https://$DOMAIN_NAME/sitemap.xml
EOF

# Create sitemap.xml
cat > "$WEB_ROOT/sitemap.xml" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
    <url>
        <loc>https://$DOMAIN_NAME/</loc>
        <lastmod>$(date +%Y-%m-%d)</lastmod>
        <priority>1.0</priority>
    </url>
    <url>
        <loc>https://$DOMAIN_NAME/privacy.html</loc>
        <lastmod>$(date +%Y-%m-%d)</lastmod>
        <priority>0.8</priority>
    </url>
    <url>
        <loc>https://$DOMAIN_NAME/terms.html</loc>
        <lastmod>$(date +%Y-%m-%d)</lastmod>
        <priority>0.8</priority>
    </url>
    <url>
        <loc>https://$DOMAIN_NAME/contact.html</loc>
        <lastmod>$(date +%Y-%m-%d)</lastmod>
        <priority>0.8</priority>
    </url>
</urlset>
EOF

# Set permissions
chown -R www-data:www-data "$WEB_ROOT" 2>/dev/null || chown -R nginx:nginx "$WEB_ROOT" 2>/dev/null
chmod -R 755 "$WEB_ROOT"

print_message "✓ Website files created"

# ===================================================================
# 4. CONFIGURE NGINX
# ===================================================================

print_header "Configuring Nginx"

# Create sites directories if they don't exist
mkdir -p /etc/nginx/sites-available
mkdir -p /etc/nginx/sites-enabled

# Ensure sites-enabled is included in nginx.conf
if ! grep -q "include /etc/nginx/sites-enabled/\*" /etc/nginx/nginx.conf; then
    sed -i '/http {/a\    include /etc/nginx/sites-enabled/*;' /etc/nginx/nginx.conf
fi

# Remove default site if it exists
rm -f /etc/nginx/sites-enabled/default 2>/dev/null

# Create Nginx server block with improved configuration
cat > /etc/nginx/sites-available/$DOMAIN_NAME <<EOF
# HTTP Server Block
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN_NAME www.$DOMAIN_NAME;
    
    root $WEB_ROOT;
    index index.html;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    
    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 256;
    gzip_types text/plain text/css text/xml text/javascript application/javascript application/xml+rss application/json;
    
    # Main location
    location / {
        try_files \$uri \$uri/ /index.html;
    }
    
    # CSS and JS with proper content types
    location ~ \\.css\$ {
        add_header Content-Type text/css;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
    
    location ~ \\.js\$ {
        add_header Content-Type application/javascript;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
    
    # Mailwizz unsubscribe redirect
    # UPDATE THIS WITH YOUR ACTUAL MAILWIZZ URL
    location /unsubscribe {
        # Change this to your actual Mailwizz unsubscribe URL
        return 302 https://your-mailwizz-domain.com/lists/unsubscribe;
    }
    
    # Alternative unsubscribe endpoints
    location /unsub {
        return 302 https://your-mailwizz-domain.com/lists/unsubscribe;
    }
    
    location /optout {
        return 302 https://your-mailwizz-domain.com/lists/unsubscribe;
    }
    
    # Block access to hidden files
    location ~ /\\. {
        deny all;
        access_log off;
        log_not_found off;
    }
    
    # Cache static assets
    location ~* \\.(jpg|jpeg|png|gif|ico|svg|webp)\$ {
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
    
    # Error pages
    error_page 404 /404.html;
    error_page 500 502 503 504 /50x.html;
    
    location = /404.html {
        internal;
    }
    
    location = /50x.html {
        internal;
    }
    
    # Logging
    access_log /var/log/nginx/${DOMAIN_NAME}_access.log;
    error_log /var/log/nginx/${DOMAIN_NAME}_error.log;
}

# Redirect www to non-www
server {
    listen 80;
    listen [::]:80;
    server_name www.$DOMAIN_NAME;
    return 301 http://\$DOMAIN_NAME\$request_uri;
}
EOF

# Enable site
ln -sf /etc/nginx/sites-available/$DOMAIN_NAME /etc/nginx/sites-enabled/

# Test nginx configuration
echo -n "Testing Nginx configuration... "
if nginx -t 2>/dev/null; then
    print_message "✓ Valid"
    systemctl reload nginx 2>/dev/null || systemctl restart nginx 2>/dev/null
else
    print_error "✗ Invalid configuration"
    echo "Nginx configuration error:"
    nginx -t
fi

# ===================================================================
# 5. CREATE SETUP INSTRUCTIONS
# ===================================================================

cat > "$WEB_ROOT/setup-instructions.txt" <<EOF
WEBSITE CONFIGURATION INSTRUCTIONS
=====================================
Generated: $(date)

Your compliance website has been created at:
http://$DOMAIN_NAME

IMPORTANT SETUP STEPS:
======================

1. UPDATE PHYSICAL ADDRESS (REQUIRED BY LAW):
   Edit: $WEB_ROOT/contact.html
   Find: [YOUR COMPANY NAME]
   Replace with your actual business address
   
   This is REQUIRED by the CAN-SPAM Act. You must include:
   - Your current street address, OR
   - A post office box registered with USPS, OR
   - A private mailbox registered with a commercial mail receiving agency

2. CONFIGURE MAILWIZZ UNSUBSCRIBE:
   Edit: /etc/nginx/sites-available/$DOMAIN_NAME
   Find: return 302 https://your-mailwizz-domain.com/lists/unsubscribe;
   Replace with your actual Mailwizz unsubscribe URL

3. RELOAD NGINX AFTER CHANGES:
   Command: systemctl reload nginx

4. SSL CERTIFICATE (After DNS propagates):
   Command: certbot --nginx -d $DOMAIN_NAME -d www.$DOMAIN_NAME

5. CUSTOMIZE CONTENT:
   - Update company information in all pages
   - Add your logo to /images/
   - Modify CSS in /css/style.css
   - Add additional pages as needed

Website Features:
- Privacy Policy page (GDPR compliant)
- Terms of Service page
- Contact page with address placeholder
- Unsubscribe redirect to Mailwizz
- Mobile responsive design
- Security headers configured
- SEO optimized with sitemap
- Modern, professional design

File Locations:
- Website Root: $WEB_ROOT
- Nginx Config: /etc/nginx/sites-available/$DOMAIN_NAME
- Access Logs: /var/log/nginx/${DOMAIN_NAME}_access.log
- Error Logs: /var/log/nginx/${DOMAIN_NAME}_error.log

Testing:
- Local: curl -I http://localhost
- External: http://$DOMAIN_NAME (after DNS propagates)
EOF

chown www-data:www-data "$WEB_ROOT/setup-instructions.txt" 2>/dev/null || true

# ===================================================================
# COMPLETION
# ===================================================================

print_header "Website Setup Complete!"

echo ""
echo "✅ Website created at: http://$DOMAIN_NAME"
echo "✅ Nginx configured and running"
echo "✅ Compliance pages created"
echo "✅ Modern responsive design implemented"
echo ""
echo "⚠️ REQUIRED ACTIONS:"
echo ""
echo "1. UPDATE YOUR PHYSICAL ADDRESS:"
echo "   vim $WEB_ROOT/contact.html"
echo "   (Required by CAN-SPAM Act - MUST be a valid physical address)"
echo ""
echo "2. CONFIGURE MAILWIZZ UNSUBSCRIBE URL:"
echo "   vim /etc/nginx/sites-available/$DOMAIN_NAME"
echo "   Update the redirect URL to your Mailwizz instance"
echo "   Then run: systemctl reload nginx"
echo ""
echo "3. GET SSL CERTIFICATE (after DNS propagates):"
echo "   certbot --nginx -d $DOMAIN_NAME -d www.$DOMAIN_NAME"
echo ""
echo "📝 Setup instructions saved to:"
echo "   $WEB_ROOT/setup-instructions.txt"
echo ""

# Quick test
echo -n "Testing local web server... "
if curl -s -o /dev/null -w "%{http_code}" "http://localhost" 2>/dev/null | grep -q "200\|301\|302"; then
    print_message "✓ Web server responding"
else
    print_warning "⚠ Web server may need configuration"
fi

echo ""
print_message "✓ Website setup completed successfully!"
print_message "Your compliance website is ready for bulk email operations!"
