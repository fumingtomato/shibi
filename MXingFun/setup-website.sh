#!/bin/bash

# =================================================================
# SIMPLE WEBSITE SETUP FOR BULK EMAIL DOMAIN REPUTATION
# Version: 2.1
# Creates basic website with privacy policy and placeholder for Mailwizz
# No database, no tracking - Mailwizz handles everything
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

print_header "Simple Website Setup for Bulk Email"
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

echo "Domain: $DOMAIN_NAME"
echo "Primary IP: $PRIMARY_IP"
echo ""

# ===================================================================
# 1. INSTALL NGINX (LIGHTWEIGHT, NO PHP NEEDED)
# ===================================================================

print_header "Installing Web Server"

echo "Installing Nginx..."
apt-get update > /dev/null 2>&1
apt-get install -y nginx > /dev/null 2>&1

print_message "✓ Nginx installed"

# ===================================================================
# 2. ADD DNS A RECORD FOR DOMAIN (IF USING CLOUDFLARE)
# ===================================================================

if [[ "${USE_CLOUDFLARE,,}" == "y" ]] && [ ! -z "$CF_API_KEY" ]; then
    print_header "Adding Website DNS Record"
    
    echo "Adding A record for $DOMAIN_NAME to Cloudflare..."
    
    # Load Cloudflare credentials
    CREDS_FILE="/root/.cloudflare_credentials"
    if [ -f "$CREDS_FILE" ]; then
        source "$CREDS_FILE"
        CF_API_KEY="${SAVED_CF_API_KEY:-$CF_API_KEY}"
        CF_EMAIL="${SAVED_CF_EMAIL:-}"
    fi
    
    # Get Zone ID
    echo -n "Getting Zone ID... "
    ZONE_RESPONSE=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$DOMAIN_NAME" \
        -H "Authorization: Bearer $CF_API_KEY" \
        -H "Content-Type: application/json")
    
    SUCCESS=$(echo "$ZONE_RESPONSE" | jq -r '.success' 2>/dev/null)
    
    # Try with email if token fails
    if [ "$SUCCESS" != "true" ] && [ ! -z "$CF_EMAIL" ]; then
        ZONE_RESPONSE=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$DOMAIN_NAME" \
            -H "X-Auth-Email: $CF_EMAIL" \
            -H "X-Auth-Key: $CF_API_KEY" \
            -H "Content-Type: application/json")
        AUTH_METHOD="global"
    else
        AUTH_METHOD="token"
    fi
    
    ZONE_ID=$(echo "$ZONE_RESPONSE" | jq -r '.result[0].id' 2>/dev/null)
    
    if [ ! -z "$ZONE_ID" ] && [ "$ZONE_ID" != "null" ]; then
        echo "✓ Found"
        
        # Check for existing A record for domain
        echo -n "Checking for existing A record for $DOMAIN_NAME... "
        
        if [ "$AUTH_METHOD" == "global" ]; then
            EXISTING=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records?type=A&name=$DOMAIN_NAME" \
                -H "X-Auth-Email: $CF_EMAIL" \
                -H "X-Auth-Key: $CF_API_KEY" \
                -H "Content-Type: application/json")
        else
            EXISTING=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records?type=A&name=$DOMAIN_NAME" \
                -H "Authorization: Bearer $CF_API_KEY" \
                -H "Content-Type: application/json")
        fi
        
        RECORD_COUNT=$(echo "$EXISTING" | jq '.result | length' 2>/dev/null || echo "0")
        
        if [ "$RECORD_COUNT" -eq 0 ]; then
            echo "Not found"
            
            # Add A record for website
            echo -n "Adding A record for website... "
            
            JSON_DATA=$(jq -n \
                --arg type "A" \
                --arg name "$DOMAIN_NAME" \
                --arg content "$PRIMARY_IP" \
                '{type: $type, name: $name, content: $content, proxied: false}')
            
            if [ "$AUTH_METHOD" == "global" ]; then
                RESPONSE=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records" \
                    -H "X-Auth-Email: $CF_EMAIL" \
                    -H "X-Auth-Key: $CF_API_KEY" \
                    -H "Content-Type: application/json" \
                    --data "$JSON_DATA")
            else
                RESPONSE=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records" \
                    -H "Authorization: Bearer $CF_API_KEY" \
                    -H "Content-Type: application/json" \
                    --data "$JSON_DATA")
            fi
            
            if [ "$(echo "$RESPONSE" | jq -r '.success' 2>/dev/null)" == "true" ]; then
                print_message "✓ A record added for website!"
            else
                print_warning "⚠ Could not add A record"
            fi
        else
            print_message "✓ A record already exists"
        fi
    fi
    echo ""
fi

# ===================================================================
# 3. CONFIGURE NGINX
# ===================================================================

print_header "Configuring Nginx"

# Stop Apache if running
systemctl stop apache2 2>/dev/null || true
systemctl disable apache2 2>/dev/null || true

# Create website directory
WEB_ROOT="/var/www/$DOMAIN_NAME"
mkdir -p "$WEB_ROOT"

# Nginx configuration
cat > /etc/nginx/sites-available/$DOMAIN_NAME <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN_NAME www.$DOMAIN_NAME;
    
    root $WEB_ROOT;
    index index.html;
    
    # Security headers for domain reputation
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    # Placeholder for Mailwizz unsubscribe redirect
    location /unsubscribe {
        # UPDATE THIS WITH YOUR MAILWIZZ URL
        return 302 https://your-mailwizz-domain.com/lists/unsubscribe;
    }
}
EOF

# Enable site
ln -sf /etc/nginx/sites-available/$DOMAIN_NAME /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

print_message "✓ Nginx configured"

# ===================================================================
# 4. CREATE SIMPLE STATIC WEBSITE
# ===================================================================

print_header "Creating Website Files"

# Homepage
cat > "$WEB_ROOT/index.html" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$DOMAIN_NAME</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            color: #333;
        }
        .container {
            max-width: 1100px;
            margin: 0 auto;
            padding: 0 20px;
        }
        header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 60px 0;
            text-align: center;
        }
        header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        nav {
            background: #fff;
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
            gap: 30px;
        }
        nav a {
            color: #333;
            text-decoration: none;
            font-weight: 500;
            transition: color 0.3s;
        }
        nav a:hover {
            color: #667eea;
        }
        .content {
            padding: 60px 0;
        }
        .section {
            margin-bottom: 60px;
        }
        h2 {
            color: #667eea;
            margin-bottom: 20px;
            font-size: 2em;
        }
        .card {
            background: #f8f9fa;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 20px;
        }
        footer {
            background: #2c3e50;
            color: white;
            text-align: center;
            padding: 40px 0;
            margin-top: 60px;
        }
        footer a {
            color: #667eea;
            text-decoration: none;
        }
        .notice {
            background: #fff3cd;
            border: 1px solid #ffc107;
            color: #856404;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>$DOMAIN_NAME</h1>
            <p>Professional Email Services</p>
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
                <h2>Welcome</h2>
                <div class="card">
                    <p>This domain is configured for professional email communications.</p>
                    <p>We respect your privacy and comply with all email regulations including CAN-SPAM and GDPR.</p>
                </div>
            </div>
            
            <div class="section">
                <h2>Email Preferences</h2>
                <div class="card">
                    <p>To manage your email preferences or unsubscribe from our mailing list, please use the unsubscribe link provided in any email you receive from us.</p>
                    <div class="notice">
                        <strong>Note:</strong> The unsubscribe link in your email will take you to our email management system where you can update your preferences.
                    </div>
                </div>
            </div>
            
            <div class="section">
                <h2>Compliance</h2>
                <div class="card">
                    <h3>We Follow Best Practices:</h3>
                    <ul style="margin-left: 20px; margin-top: 10px;">
                        <li>✓ CAN-SPAM Act compliant</li>
                        <li>✓ GDPR compliant</li>
                        <li>✓ One-click unsubscribe in all emails</li>
                        <li>✓ Clear sender identification</li>
                        <li>✓ Honest subject lines</li>
                        <li>✓ Physical mailing address included</li>
                    </ul>
                </div>
            </div>
        </div>
    </div>
    
    <footer>
        <div class="container">
            <p>&copy; $(date +%Y) $DOMAIN_NAME - All Rights Reserved</p>
            <p style="margin-top: 10px;">
                <a href="/privacy.html">Privacy Policy</a> | 
                <a href="/terms.html">Terms of Service</a> | 
                <a href="/contact.html">Contact</a>
            </p>
            <p style="margin-top: 20px; font-size: 0.9em; opacity: 0.8;">
                Email services powered by professional infrastructure
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
            max-width: 800px;
            margin: 0 auto;
            padding: 40px 20px;
        }
        h1 { color: #667eea; margin-bottom: 30px; }
        h2 { color: #555; margin-top: 40px; margin-bottom: 20px; }
        a { color: #667eea; }
        .back-link { 
            display: inline-block;
            margin-top: 40px;
            padding: 10px 20px;
            background: #667eea;
            color: white;
            text-decoration: none;
            border-radius: 5px;
        }
    </style>
</head>
<body>
    <h1>Privacy Policy</h1>
    <p><strong>Last Updated:</strong> $(date +'%B %d, %Y')</p>
    
    <h2>1. Information We Collect</h2>
    <p>When you subscribe to our email list, we collect:</p>
    <ul>
        <li>Your email address</li>
        <li>Any additional information you choose to provide</li>
        <li>Technical information such as IP addresses for security purposes</li>
    </ul>
    
    <h2>2. How We Use Your Information</h2>
    <p>We use your information solely to:</p>
    <ul>
        <li>Send you the email communications you've subscribed to</li>
        <li>Respond to your inquiries</li>
        <li>Comply with legal obligations</li>
        <li>Improve our email services</li>
    </ul>
    
    <h2>3. Email Communications</h2>
    <p>All our emails include:</p>
    <ul>
        <li>Clear identification of the sender</li>
        <li>Accurate subject lines</li>
        <li>An unsubscribe link for easy opt-out</li>
        <li>Our physical mailing address</li>
    </ul>
    <p>You can unsubscribe at any time using the link in any email you receive from us. Unsubscribe requests are processed immediately.</p>
    
    <h2>4. Data Protection</h2>
    <p>We implement appropriate security measures to protect your personal information from unauthorized access, alteration, disclosure, or destruction.</p>
    
    <h2>5. Data Sharing</h2>
    <p>We do not sell, trade, or otherwise transfer your personal information to third parties without your consent, except as required by law.</p>
    
    <h2>6. Your Rights</h2>
    <p>You have the right to:</p>
    <ul>
        <li>Access the personal information we hold about you</li>
        <li>Request correction of any inaccurate information</li>
        <li>Request deletion of your information</li>
        <li>Opt-out of email communications at any time</li>
    </ul>
    
    <h2>7. Cookies</h2>
    <p>Our website uses minimal cookies only for essential functionality. We do not use tracking or advertising cookies.</p>
    
    <h2>8. Changes to This Policy</h2>
    <p>We may update this privacy policy from time to time. Any changes will be posted on this page with an updated revision date.</p>
    
    <h2>9. Contact Us</h2>
    <p>If you have any questions about this Privacy Policy or our practices, please contact us using the information on our <a href="/contact.html">contact page</a>.</p>
    
    <a href="/" class="back-link">← Back to Home</a>
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
            max-width: 800px;
            margin: 0 auto;
            padding: 40px 20px;
        }
        h1 { color: #667eea; margin-bottom: 30px; }
        h2 { color: #555; margin-top: 40px; margin-bottom: 20px; }
        a { color: #667eea; }
        .back-link { 
            display: inline-block;
            margin-top: 40px;
            padding: 10px 20px;
            background: #667eea;
            color: white;
            text-decoration: none;
            border-radius: 5px;
        }
    </style>
</head>
<body>
    <h1>Terms of Service</h1>
    <p><strong>Last Updated:</strong> $(date +'%B %d, %Y')</p>
    
    <h2>1. Acceptance of Terms</h2>
    <p>By subscribing to our email list or using our services, you agree to these Terms of Service.</p>
    
    <h2>2. Email Services</h2>
    <p>Our email services are provided to subscribers who have opted in to receive communications. You may unsubscribe at any time.</p>
    
    <h2>3. Acceptable Use</h2>
    <p>You agree not to use our services for any unlawful purpose or in any way that could damage, disable, or impair our services.</p>
    
    <h2>4. Anti-Spam Policy</h2>
    <p>We maintain a strict anti-spam policy. We only send emails to users who have explicitly opted in to our communications.</p>
    
    <h2>5. Intellectual Property</h2>
    <p>All content provided through our email services is protected by copyright and other intellectual property laws.</p>
    
    <h2>6. Disclaimer of Warranties</h2>
    <p>Our services are provided "as is" without warranties of any kind, either express or implied.</p>
    
    <h2>7. Limitation of Liability</h2>
    <p>We shall not be liable for any indirect, incidental, special, or consequential damages arising from your use of our services.</p>
    
    <h2>8. Changes to Terms</h2>
    <p>We reserve the right to modify these terms at any time. Continued use of our services constitutes acceptance of any changes.</p>
    
    <h2>9. Governing Law</h2>
    <p>These terms shall be governed by and construed in accordance with applicable laws.</p>
    
    <h2>10. Contact Information</h2>
    <p>For questions about these Terms of Service, please visit our <a href="/contact.html">contact page</a>.</p>
    
    <a href="/" class="back-link">← Back to Home</a>
</body>
</html>
EOF

# Simple Contact Page
cat > "$WEB_ROOT/contact.html" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Contact - $DOMAIN_NAME</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.8;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 40px 20px;
        }
        h1 { color: #667eea; margin-bottom: 30px; }
        .contact-info {
            background: #f8f9fa;
            padding: 30px;
            border-radius: 10px;
            margin: 30px 0;
        }
        .notice {
            background: #e7f3ff;
            border: 1px solid #667eea;
            color: #004085;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }
        a { color: #667eea; }
        .back-link { 
            display: inline-block;
            margin-top: 40px;
            padding: 10px 20px;
            background: #667eea;
            color: white;
            text-decoration: none;
            border-radius: 5px;
        }
    </style>
</head>
<body>
    <h1>Contact Us</h1>
    
    <div class="contact-info">
        <h2>Email Management</h2>
        <p>To manage your email preferences or unsubscribe, please use the link provided in any email you receive from us.</p>
    </div>
    
    <div class="notice">
        <strong>Important:</strong> This domain is configured for email services managed through our email platform. 
        All subscription management, including unsubscribe requests, are handled through the links in our emails.
    </div>
    
    <div class="contact-info">
        <h2>General Inquiries</h2>
        <p>Domain: $DOMAIN_NAME</p>
        <p>Email Service: Professional Bulk Email Platform</p>
        
        <p style="margin-top: 20px;">
            <strong>Note:</strong> For the fastest response regarding email subscriptions, 
            please use the unsubscribe link in your email.
        </p>
    </div>
    
    <div class="contact-info">
        <h2>Mailing Address</h2>
        <p>
            [UPDATE WITH YOUR PHYSICAL ADDRESS]<br>
            [City, State ZIP]<br>
            [Country]
        </p>
    </div>
    
    <a href="/" class="back-link">← Back to Home</a>
</body>
</html>
EOF

# Placeholder configuration file for Mailwizz integration
cat > "$WEB_ROOT/mailwizz-config.txt" <<EOF
MAILWIZZ INTEGRATION CONFIGURATION
===================================
Generated: $(date)

This mail server is configured to work with Mailwizz.

TO COMPLETE SETUP:
==================

1. Update Nginx unsubscribe redirect:
   Edit: /etc/nginx/sites-available/$DOMAIN_NAME
   Change: return 302 https://your-mailwizz-domain.com/lists/unsubscribe;
   To your actual Mailwizz unsubscribe URL

2. In Mailwizz, configure:
   - SMTP Host: $HOSTNAME
   - SMTP Port: 587 (STARTTLS) or 465 (SSL)
   - Username: $FIRST_EMAIL
   - Password: [your email password]
   - Encryption: TLS or SSL

3. Mailwizz Delivery Server Settings:
   - Type: SMTP
   - Hostname: $HOSTNAME
   - Port: 587
   - Protocol: TLS
   - From email: $FIRST_EMAIL

4. Required Headers (Mailwizz will add these):
   - List-Unsubscribe
   - List-Unsubscribe-Post
   - Precedence: bulk

5. Physical Address:
   Update /var/www/$DOMAIN_NAME/contact.html with your real mailing address

DOMAIN REPUTATION:
==================
This website provides:
- Valid domain presence for reputation
- Privacy policy page
- Terms of service page
- Contact information
- Unsubscribe redirect to Mailwizz

The website helps establish domain legitimacy for email providers.

EOF

# Set permissions
chown -R www-data:www-data "$WEB_ROOT"
chmod -R 755 "$WEB_ROOT"

# ===================================================================
# 5. SSL CERTIFICATE FOR WEBSITE
# ===================================================================

print_header "Configuring SSL for Website"

if command -v certbot &> /dev/null; then
    echo "Checking DNS for website SSL..."
    
    if host "$DOMAIN_NAME" 8.8.8.8 > /dev/null 2>&1; then
        echo "Attempting to get Let's Encrypt certificate..."
        
        # Check if certificate already exists
        if [ -d "/etc/letsencrypt/live/$DOMAIN_NAME" ]; then
            print_message "✓ SSL certificate already exists for $DOMAIN_NAME"
        else
            certbot certonly --webroot \
                -w "$WEB_ROOT" \
                -d "$DOMAIN_NAME" \
                -d "www.$DOMAIN_NAME" \
                --non-interactive \
                --agree-tos \
                --email "$ADMIN_EMAIL" \
                --no-eff-email 2>/dev/null
            
            if [ $? -eq 0 ]; then
                # Add SSL configuration to Nginx
                cat >> /etc/nginx/sites-available/$DOMAIN_NAME <<EOF

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $DOMAIN_NAME www.$DOMAIN_NAME;
    
    ssl_certificate /etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN_NAME/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    
    root $WEB_ROOT;
    index index.html;
    
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    location /unsubscribe {
        # UPDATE THIS WITH YOUR MAILWIZZ URL
        return 302 https://your-mailwizz-domain.com/lists/unsubscribe;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN_NAME www.$DOMAIN_NAME;
    return 301 https://\$server_name\$request_uri;
}
EOF
                print_message "✓ SSL certificate obtained"
            else
                print_warning "Could not get SSL certificate (DNS might not be ready)"
            fi
        fi
    else
        print_warning "DNS not resolving yet for website"
    fi
fi

# ===================================================================
# 6. RESTART SERVICES
# ===================================================================

print_header "Starting Web Services"

# Test nginx configuration
nginx -t 2>/dev/null

if [ $? -eq 0 ]; then
    systemctl restart nginx
    systemctl enable nginx
    print_message "✓ Nginx restarted successfully"
else
    print_error "✗ Nginx configuration error"
    nginx -t
fi

# ===================================================================
# COMPLETION
# ===================================================================

print_header "Website Setup Complete!"

echo ""
echo "✅ Website URL: http://$DOMAIN_NAME"
if [ -f "/etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem" ]; then
    echo "✅ SSL URL: https://$DOMAIN_NAME"
fi
echo ""
echo "Pages Created:"
echo "  • Homepage: http://$DOMAIN_NAME/"
echo "  • Privacy Policy: http://$DOMAIN_NAME/privacy.html"
echo "  • Terms of Service: http://$DOMAIN_NAME/terms.html"
echo "  • Contact: http://$DOMAIN_NAME/contact.html"
echo ""

if [[ "${USE_CLOUDFLARE,,}" == "y" ]]; then
    echo "DNS Status:"
    echo -n "  A record for $DOMAIN_NAME: "
    dig +short A $DOMAIN_NAME @1.1.1.1 2>/dev/null && echo "✓ Active" || echo "Propagating..."
fi

echo ""
print_warning "IMPORTANT NEXT STEPS:"
echo ""
echo "1. UPDATE MAILWIZZ UNSUBSCRIBE URL:"
echo "   Edit: /etc/nginx/sites-available/$DOMAIN_NAME"
echo "   Find: return 302 https://your-mailwizz-domain.com/lists/unsubscribe;"
echo "   Replace with your actual Mailwizz unsubscribe URL"
echo ""
echo "2. UPDATE PHYSICAL ADDRESS:"
echo "   Edit: $WEB_ROOT/contact.html"
echo "   Add your real mailing address (required for CAN-SPAM)"
echo ""
echo "3. CONFIGURE MAILWIZZ:"
echo "   See: $WEB_ROOT/mailwizz-config.txt"
echo "   SMTP Server: $HOSTNAME"
echo "   Port: 587 (TLS) or 465 (SSL)"
echo "   Username: $FIRST_EMAIL"
echo ""
echo "4. RESTART NGINX after changes:"
echo "   systemctl reload nginx"
echo ""
print_message "This simple website establishes domain reputation for bulk email."
print_message "Mailwizz will handle all unsubscribes and suppression lists."
echo ""
print_message "✓ Simple website setup completed successfully!"
