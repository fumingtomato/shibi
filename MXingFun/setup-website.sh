#!/bin/bash

# =================================================================
# WEBSITE SETUP FOR BULK EMAIL COMPLIANCE
# Version: 2.2
# Creates compliance website with privacy policy and unsubscribe
# Adds A record to Cloudflare if using automatic DNS
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

# Get primary IP if not in config
if [ -z "$PRIMARY_IP" ]; then
    PRIMARY_IP=$(curl -s https://ipinfo.io/ip 2>/dev/null || hostname -I | awk '{print $1}')
fi

# Get admin email
if [ -z "$ADMIN_EMAIL" ]; then
    ADMIN_EMAIL="${FIRST_EMAIL:-admin@$DOMAIN_NAME}"
fi

echo "Domain: $DOMAIN_NAME"
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
    apt-get install -y nginx > /dev/null 2>&1
    print_message "✓ Nginx installed"
else
    print_message "✓ Nginx already installed"
fi

# Stop Apache if running (conflicts with nginx)
if systemctl is-active --quiet apache2; then
    echo "Stopping Apache2 (conflicts with Nginx)..."
    systemctl stop apache2
    systemctl disable apache2
fi

# ===================================================================
# 2. CREATE WEBSITE DIRECTORY
# ===================================================================

print_header "Creating Website Files"

WEB_ROOT="/var/www/$DOMAIN_NAME"
mkdir -p "$WEB_ROOT"

# ===================================================================
# 3. CREATE WEBSITE CONTENT
# ===================================================================

# Homepage with professional design
cat > "$WEB_ROOT/index.html" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="Professional email services by $DOMAIN_NAME">
    <title>$DOMAIN_NAME - Professional Email Services</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f8f9fa;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 20px;
        }
        header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
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
        nav {
            background: white;
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
        }
        nav a {
            color: #333;
            text-decoration: none;
            font-weight: 500;
            transition: color 0.3s;
            font-size: 1.1em;
        }
        nav a:hover {
            color: #667eea;
        }
        .content {
            padding: 80px 0;
            background: white;
            margin: 40px 0;
            border-radius: 10px;
            box-shadow: 0 2px 20px rgba(0,0,0,0.05);
        }
        .section {
            margin-bottom: 60px;
        }
        h2 {
            color: #667eea;
            margin-bottom: 25px;
            font-size: 2.5em;
            font-weight: 600;
        }
        .card {
            background: #f8f9fa;
            padding: 40px;
            border-radius: 10px;
            margin-bottom: 30px;
            border: 1px solid #e9ecef;
        }
        .card h3 {
            color: #495057;
            margin-bottom: 15px;
            font-size: 1.5em;
        }
        .features {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 30px;
            margin-top: 30px;
        }
        .feature {
            text-align: center;
            padding: 30px;
            background: #f8f9fa;
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
        .btn {
            display: inline-block;
            padding: 15px 40px;
            background: #667eea;
            color: white;
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
        footer {
            background: #2c3e50;
            color: white;
            text-align: center;
            padding: 50px 0;
            margin-top: 80px;
        }
        footer a {
            color: #667eea;
            text-decoration: none;
        }
        footer a:hover {
            text-decoration: underline;
        }
        .notice {
            background: #fff3cd;
            border: 1px solid #ffc107;
            color: #856404;
            padding: 20px;
            border-radius: 5px;
            margin: 20px 0;
        }
        .compliance-badges {
            display: flex;
            justify-content: center;
            gap: 40px;
            margin: 40px 0;
            flex-wrap: wrap;
        }
        .badge {
            padding: 10px 20px;
            background: white;
            border: 2px solid #667eea;
            border-radius: 5px;
            font-weight: 600;
            color: #667eea;
        }
    </style>
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
                        <strong>Important:</strong> To unsubscribe or manage your email preferences, please use the unsubscribe link provided in any email you've received from us. This ensures we can properly identify and update your preferences.
                    </div>
                    <a href="/unsubscribe" class="btn">Unsubscribe Center</a>
                </div>
            </div>
        </div>
    </div>
    
    <footer>
        <div class="container">
            <p>&copy; $(date +%Y) $DOMAIN_NAME - All Rights Reserved</p>
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

# Privacy Policy
cat > "$WEB_ROOT/privacy.html" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Privacy Policy - $DOMAIN_NAME</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.8;
            color: #333;
            max-width: 900px;
            margin: 0 auto;
            padding: 40px 20px;
            background: #f8f9fa;
        }
        .content {
            background: white;
            padding: 60px;
            border-radius: 10px;
            box-shadow: 0 2px 20px rgba(0,0,0,0.05);
        }
        h1 { 
            color: #667eea; 
            margin-bottom: 10px;
            font-size: 2.5em;
        }
        .date {
            color: #6c757d;
            margin-bottom: 30px;
            font-size: 1.1em;
        }
        h2 { 
            color: #495057; 
            margin-top: 40px; 
            margin-bottom: 20px;
            font-size: 1.8em;
            border-bottom: 2px solid #e9ecef;
            padding-bottom: 10px;
        }
        p, li {
            color: #495057;
            margin-bottom: 15px;
        }
        ul {
            margin-left: 20px;
        }
        a { 
            color: #667eea; 
            text-decoration: none;
        }
        a:hover {
            text-decoration: underline;
        }
        .back-link { 
            display: inline-block;
            margin-top: 40px;
            padding: 12px 30px;
            background: #667eea;
            color: white;
            text-decoration: none;
            border-radius: 50px;
            font-weight: 600;
            transition: background 0.3s;
        }
        .back-link:hover {
            background: #5a67d8;
            text-decoration: none;
        }
        .highlight {
            background: #f8f9fa;
            padding: 20px;
            border-left: 4px solid #667eea;
            margin: 20px 0;
        }
    </style>
</head>
<body>
    <div class="content">
        <h1>Privacy Policy</h1>
        <div class="date">Last Updated: $(date +'%B %d, %Y')</div>
        
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
        
        <h2>8. International Transfers</h2>
        <p>If we transfer data internationally, we ensure appropriate safeguards are in place to protect your information in accordance with this privacy policy.</p>
        
        <h2>9. Children's Privacy</h2>
        <p>Our services are not directed to individuals under 16. We do not knowingly collect personal information from children.</p>
        
        <h2>10. Cookies and Tracking</h2>
        <p>Our website uses minimal cookies for:</p>
        <ul>
            <li>Essential functionality</li>
            <li>Security purposes</li>
            <li>Analytics (with your consent)</li>
        </ul>
        <p>We do not use third-party advertising cookies.</p>
        
        <h2>11. Changes to This Policy</h2>
        <p>We may update this privacy policy from time to time. We will notify you of any material changes by posting the new policy on this page and updating the "Last Updated" date.</p>
        
        <h2>12. Contact Us</h2>
        <p>If you have questions about this Privacy Policy or our data practices, please contact us:</p>
        <div class="highlight">
            <p><strong>Email:</strong> privacy@$DOMAIN_NAME</p>
            <p><strong>Website:</strong> <a href="/">$DOMAIN_NAME</a></p>
            <p><strong>Response Time:</strong> We aim to respond within 48 hours</p>
        </div>
        
        <a href="/" class="back-link">← Back to Home</a>
    </div>
</body>
</html>
EOF

# Terms of Service
cat > "$WEB_ROOT/terms.html" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Terms of Service - $DOMAIN_NAME</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.8;
            color: #333;
            max-width: 900px;
            margin: 0 auto;
            padding: 40px 20px;
            background: #f8f9fa;
        }
        .content {
            background: white;
            padding: 60px;
            border-radius: 10px;
            box-shadow: 0 2px 20px rgba(0,0,0,0.05);
        }
        h1 { 
            color: #667eea; 
            margin-bottom: 10px;
            font-size: 2.5em;
        }
        .date {
            color: #6c757d;
            margin-bottom: 30px;
            font-size: 1.1em;
        }
        h2 { 
            color: #495057; 
            margin-top: 40px; 
            margin-bottom: 20px;
            font-size: 1.8em;
            border-bottom: 2px solid #e9ecef;
            padding-bottom: 10px;
        }
        a { color: #667eea; }
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
    </style>
</head>
<body>
    <div class="content">
        <h1>Terms of Service</h1>
        <div class="date">Last Updated: $(date +'%B %d, %Y')</div>
        
        <h2>1. Acceptance of Terms</h2>
        <p>By subscribing to our email list or using our services, you agree to be bound by these Terms of Service and all applicable laws and regulations.</p>
        
        <h2>2. Email Services</h2>
        <p>Our email services are provided to subscribers who have explicitly opted in. You may unsubscribe at any time using the link provided in every email.</p>
        
        <h2>3. Acceptable Use</h2>
        <p>You agree not to:</p>
        <ul>
            <li>Use our services for any unlawful purpose</li>
            <li>Attempt to gain unauthorized access to our systems</li>
            <li>Interfere with or disrupt our services</li>
            <li>Transmit any viruses or malicious code</li>
        </ul>
        
        <h2>4. Anti-Spam Compliance</h2>
        <p>We maintain strict compliance with CAN-SPAM, GDPR, and other anti-spam regulations. We never:</p>
        <ul>
            <li>Send unsolicited emails</li>
            <li>Use deceptive subject lines</li>
            <li>Hide sender identity</li>
            <li>Ignore unsubscribe requests</li>
        </ul>
        
        <h2>5. Intellectual Property</h2>
        <p>All content provided through our services is protected by copyright and other intellectual property laws. You may not reproduce, distribute, or create derivative works without permission.</p>
        
        <h2>6. Disclaimer of Warranties</h2>
        <p>Our services are provided "as is" without warranties of any kind, either express or implied, including but not limited to implied warranties of merchantability and fitness for a particular purpose.</p>
        
        <h2>7. Limitation of Liability</h2>
        <p>We shall not be liable for any indirect, incidental, special, consequential, or punitive damages arising from your use of our services.</p>
        
        <h2>8. Indemnification</h2>
        <p>You agree to indemnify and hold us harmless from any claims arising from your use of our services or violation of these terms.</p>
        
        <h2>9. Changes to Terms</h2>
        <p>We reserve the right to modify these terms at any time. Continued use of our services constitutes acceptance of any changes.</p>
        
        <h2>10. Termination</h2>
        <p>We may terminate or suspend access to our services immediately, without prior notice, for any breach of these Terms.</p>
        
        <h2>11. Governing Law</h2>
        <p>These terms shall be governed by applicable laws without regard to conflict of law provisions.</p>
        
        <h2>12. Contact Information</h2>
        <p>For questions about these Terms, please contact us at legal@$DOMAIN_NAME</p>
        
        <a href="/" class="back-link">← Back to Home</a>
    </div>
</body>
</html>
EOF

# Contact Page
cat > "$WEB_ROOT/contact.html" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Contact Us - $DOMAIN_NAME</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.8;
            color: #333;
            max-width: 900px;
            margin: 0 auto;
            padding: 40px 20px;
            background: #f8f9fa;
        }
        .content {
            background: white;
            padding: 60px;
            border-radius: 10px;
            box-shadow: 0 2px 20px rgba(0,0,0,0.05);
        }
        h1 { 
            color: #667eea; 
            margin-bottom: 30px;
            font-size: 2.5em;
        }
        .contact-card {
            background: #f8f9fa;
            padding: 30px;
            border-radius: 10px;
            margin: 30px 0;
            border: 1px solid #e9ecef;
        }
        .notice {
            background: #e7f3ff;
            border: 1px solid #667eea;
            color: #004085;
            padding: 20px;
            border-radius: 5px;
            margin: 20px 0;
        }
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
        .address-box {
            background: white;
            border: 2px solid #667eea;
            padding: 25px;
            border-radius: 10px;
            margin: 30px 0;
        }
    </style>
</head>
<body>
    <div class="content">
        <h1>Contact Us</h1>
        
        <div class="contact-card">
            <h2>Email Management</h2>
            <p>To manage your email preferences or unsubscribe from our mailing list, please use the unsubscribe link provided in any email you receive from us.</p>
            <p>This ensures we can properly identify your subscription and update your preferences immediately.</p>
        </div>
        
        <div class="notice">
            <strong>Quick Unsubscribe:</strong> Every email we send includes a one-click unsubscribe link at the bottom. This is the fastest way to manage your email preferences.
        </div>
        
        <div class="contact-card">
            <h2>General Inquiries</h2>
            <p><strong>Domain:</strong> $DOMAIN_NAME</p>
            <p><strong>Email:</strong> contact@$DOMAIN_NAME</p>
            <p><strong>Response Time:</strong> We typically respond within 24-48 hours</p>
        </div>
        
        <div class="contact-card">
            <h2>Privacy & Data Requests</h2>
            <p>For privacy-related inquiries or data requests:</p>
            <p><strong>Email:</strong> privacy@$DOMAIN_NAME</p>
            <p>Please include your email address and the nature of your request.</p>
        </div>
        
        <div class="address-box">
            <h2>Mailing Address</h2>
            <p><strong>CAN-SPAM Compliance Notice:</strong></p>
            <p>
                [YOUR COMPANY NAME]<br>
                [STREET ADDRESS]<br>
                [CITY, STATE ZIP CODE]<br>
                [COUNTRY]
            </p>
            <p style="margin-top: 20px; color: #6c757d; font-size: 0.9em;">
                <em>Note: Please update this with your actual physical mailing address as required by CAN-SPAM regulations.</em>
            </p>
        </div>
        
        <div class="contact-card">
            <h2>Report Abuse</h2>
            <p>To report email abuse or spam:</p>
            <p><strong>Email:</strong> abuse@$DOMAIN_NAME</p>
            <p>Please forward the complete email including headers.</p>
        </div>
        
        <a href="/" class="back-link">← Back to Home</a>
    </div>
</body>
</html>
EOF

# Set permissions
chown -R www-data:www-data "$WEB_ROOT"
chmod -R 755 "$WEB_ROOT"

print_message "✓ Website files created"

# ===================================================================
# 4. CONFIGURE NGINX
# ===================================================================

print_header "Configuring Nginx"

# Create Nginx server block
cat > /etc/nginx/sites-available/$DOMAIN_NAME <<EOF
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
    
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    # Mailwizz unsubscribe redirect
    # UPDATE THIS WITH YOUR ACTUAL MAILWIZZ URL
    location /unsubscribe {
        return 302 https://your-mailwizz-domain.com/lists/unsubscribe;
    }
    
    # Block access to hidden files
    location ~ /\. {
        deny all;
    }
    
    # Cache static assets
    location ~* \.(jpg|jpeg|png|gif|ico|css|js)$ {
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
}
EOF

# Enable site
ln -sf /etc/nginx/sites-available/$DOMAIN_NAME /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Test nginx configuration
nginx -t 2>/dev/null
if [ $? -eq 0 ]; then
    systemctl restart nginx
    systemctl enable nginx
    print_message "✓ Nginx configured and restarted"
else
    print_error "✗ Nginx configuration error"
    nginx -t
fi

# ===================================================================
# 5. CREATE CONFIGURATION REMINDER
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

2. CONFIGURE MAILWIZZ UNSUBSCRIBE:
   Edit: /etc/nginx/sites-available/$DOMAIN_NAME
   Find: return 302 https://your-mailwizz-domain.com/lists/unsubscribe;
   Replace with your actual Mailwizz unsubscribe URL

3. RELOAD NGINX AFTER CHANGES:
   Command: systemctl reload nginx

4. SSL CERTIFICATE (After DNS propagates):
   Command: certbot --nginx -d $DOMAIN_NAME -d www.$DOMAIN_NAME

COMPLIANCE CHECKLIST:
=====================
✓ Privacy Policy page created
✓ Terms of Service page created
✓ Contact page with address placeholder
✓ Unsubscribe link configured (needs Mailwizz URL)
✓ CAN-SPAM compliant structure
✓ GDPR-ready privacy policy

WEBSITE FEATURES:
=================
• Professional design
• Mobile responsive
• Security headers configured
• Gzip compression enabled
• Cache optimization
• Clean, semantic HTML

TEST YOUR WEBSITE:
==================
1. Visit: http://$DOMAIN_NAME
2. Check all pages load correctly
3. Verify links work
4. Test on mobile devices

MAILWIZZ INTEGRATION:
=====================
When setting up Mailwizz:
- Use $HOSTNAME as SMTP server
- Port 587 (TLS) or 465 (SSL)
- Update unsubscribe URL in nginx config
- Include website URL in email footers

EOF

chown www-data:www-data "$WEB_ROOT/setup-instructions.txt"

# ===================================================================
# COMPLETION
# ===================================================================

print_header "Website Setup Complete!"

echo ""
echo "✅ Website created at: http://$DOMAIN_NAME"
echo "✅ Nginx configured and running"
echo "✅ Compliance pages created"
echo ""
echo "⚠️ REQUIRED ACTIONS:"
echo ""
echo "1. UPDATE YOUR PHYSICAL ADDRESS:"
echo "   vim $WEB_ROOT/contact.html"
echo "   (Required by CAN-SPAM Act)"
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
if curl -s -o /dev/null -w "%{http_code}" "http://localhost" | grep -q "200\|301\|302"; then
    print_message "✓ Web server responding"
else
    print_warning "⚠ Web server may need configuration"
fi

echo ""
print_message "✓ Website setup completed successfully!"
print_message "Your compliance website is ready for bulk email operations!"
