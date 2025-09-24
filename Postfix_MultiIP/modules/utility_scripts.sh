#!/bin/bash

# =================================================================
# UTILITY SCRIPTS MODULE
# Helper scripts and utilities for mail server management
# =================================================================

# Create utility scripts for mail sending and management
create_utility_scripts() {
    local domain=$1
    
    print_message "Creating utility scripts..."
    
    # Create external mail sending utility
    cat > /usr/local/bin/send-external-mail <<EOF
#!/bin/bash
# Send external mail without MySQL dependency

if [ \$# -lt 2 ]; then
  echo "Usage: \$0 recipient@example.com \"Subject\" [from_address]"
  echo "Example: \$0 user@example.com \"Test Email\" sender@yourdomain.com"
  exit 1
fi

RECIPIENT="\$1"
SUBJECT="\$2"
FROM="\${3:-newsletter@$domain}"

# Make sure we can send mail
echo "This is a test email sent at \$(date)" | mail -s "\$SUBJECT" -r "\$FROM" "\$RECIPIENT"
echo "Mail sent from \$FROM to \$RECIPIENT with subject '\$SUBJECT'"
echo "Check mail logs with: sudo tail -f /var/log/mail.log"
EOF

    chmod +x /usr/local/bin/send-external-mail
    
    # Create enhanced mail sending utility with MySQL check
    cat > /usr/local/bin/send-mail <<EOF
#!/bin/bash
# Utility to send emails with proper error handling

if [ \$# -lt 2 ]; then
  echo "Usage: \$0 recipient@example.com \"Subject\" [from_address]"
  echo "Example: \$0 user@example.com \"Test Email\" sender@yourdomain.com"
  exit 1
fi

RECIPIENT="\$1"
SUBJECT="\$2"
FROM="\${3:-newsletter@$domain}"

# Ensure MySQL is running
if ! systemctl is-active --quiet mysql; then
  echo "MySQL is not running. Starting MySQL..."
  systemctl start mysql
  sleep 2
fi

# Check if mail can be sent
echo "This is a test email sent at \$(date)" | mail -s "\$SUBJECT" -r "\$FROM" "\$RECIPIENT"
echo "Mail sent from \$FROM to \$RECIPIENT with subject '\$SUBJECT'"
echo "Check mail logs with: sudo tail -f /var/log/mail.log"
EOF

    chmod +x /usr/local/bin/send-mail
    
    # Create simple test email utility
    cat > /usr/local/bin/send-test-email <<EOF
#!/bin/bash
if [ \$# -ne 1 ]; then
  echo "Usage: \$0 recipient@example.com"
  exit 1
fi

# Ensure MySQL is running before sending email
systemctl is-active --quiet mysql || systemctl start mysql

echo "This is a test email from your mail server." | mail -s "Test Email" -r "admin@$domain" \$1
echo "Test email sent to \$1"
EOF
    
    chmod +x /usr/local/bin/send-test-email
    
    # Create mail queue management script
    cat > /usr/local/bin/manage-mail-queue <<EOF
#!/bin/bash

echo "Mail Queue Management Utility"
echo "=============================="

case "\$1" in
    status)
        echo "Queue Status:"
        mailq | tail -10
        ;;
    flush)
        echo "Flushing mail queue..."
        postqueue -f
        ;;
    clear)
        echo "WARNING: This will delete all queued mail!"
        read -p "Are you sure? (y/n): " confirm
        if [ "\$confirm" = "y" ]; then
            postsuper -d ALL
            echo "Queue cleared."
        fi
        ;;
    hold)
        echo "Putting all mail on hold..."
        postsuper -h ALL
        ;;
    release)
        echo "Releasing all held mail..."
        postsuper -H ALL
        ;;
    *)
        echo "Usage: \$0 {status|flush|clear|hold|release}"
        exit 1
        ;;
esac
EOF

    chmod +x /usr/local/bin/manage-mail-queue
    
    print_message "Utility scripts created."
}

# Create website with privacy policy and unsubscribe pages
setup_website() {
    local domain=$1
    local admin_email=$2
    local brand_name=$3
    
    print_header "Creating Front-Facing Website"
    print_message "Setting up basic website for $brand_name..."
    
    # Create a simple professional landing page
    print_message "Creating landing page..."
    cat > /var/www/html/index.html <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${brand_name} - Official Website</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 0;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        .container {
            width: 90%;
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }
        header {
            background-color: rgba(255, 255, 255, 0.95);
            padding: 1rem 0;
            text-align: center;
            border-radius: 10px;
            margin-bottom: 2rem;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }
        .content {
            background: rgba(255, 255, 255, 0.95);
            padding: 3rem;
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }
        h1 {
            color: #667eea;
            margin: 0;
        }
        h2, h3 {
            color: #764ba2;
        }
        footer {
            text-align: center;
            margin-top: 2rem;
            padding: 1rem 0;
            color: white;
        }
        a {
            color: #667eea;
            text-decoration: none;
        }
        a:hover {
            text-decoration: underline;
        }
        .button {
            display: inline-block;
            padding: 10px 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 5px;
            margin: 10px 5px;
        }
        .button:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>${brand_name}</h1>
        </header>
        
        <div class="content">
            <h2>Welcome to ${brand_name}</h2>
            <p>We provide professional email communication services with a focus on reliability, security, and compliance.</p>
            
            <h3>Our Services</h3>
            <ul>
                <li>High-volume email delivery</li>
                <li>Newsletter distribution</li>
                <li>Transactional email services</li>
                <li>Email analytics and reporting</li>
            </ul>
            
            <h3>Contact Information</h3>
            <p>For inquiries and support:</p>
            <p>Email: <a href="mailto:${admin_email}">${admin_email}</a></p>
            
            <h3>Important Links</h3>
            <p>
                <a href="privacy-policy.html" class="button">Privacy Policy</a>
                <a href="unsubscribe.html" class="button">Unsubscribe</a>
            </p>
        </div>
        
        <footer>
            <p>&copy; $(date +%Y) ${brand_name}. All rights reserved.</p>
        </footer>
    </div>
</body>
</html>
EOF

    # Create a privacy policy page template
    print_message "Creating privacy policy page template..."
    cat > /var/www/html/privacy-policy.html <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Privacy Policy - ${brand_name}</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.8;
            margin: 0;
            padding: 0;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        .container {
            width: 90%;
            max-width: 800px;
            margin: 0 auto;
            padding: 2rem;
        }
        .content {
            background: rgba(255, 255, 255, 0.95);
            padding: 3rem;
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }
        h1, h2, h3 {
            color: #764ba2;
        }
        footer {
            text-align: center;
            margin-top: 2rem;
            padding: 1rem 0;
            color: white;
        }
        a {
            color: #667eea;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="content">
            <h1>Privacy Policy</h1>
            <p>Last Updated: $(date +%Y-%m-%d)</p>
            
            <h2>1. Introduction</h2>
            <p>${brand_name} respects your privacy and is committed to protecting your personal data.</p>
            
            <h2>2. Information We Collect</h2>
            <p>We collect information that you provide directly to us, including:</p>
            <ul>
                <li>Email address</li>
                <li>Name (if provided)</li>
                <li>Communication preferences</li>
            </ul>
            
            <h2>3. How We Use Your Information</h2>
            <p>We use the information we collect to:</p>
            <ul>
                <li>Send you requested communications</li>
                <li>Improve our services</li>
                <li>Comply with legal obligations</li>
            </ul>
            
            <h2>4. Data Security</h2>
            <p>We implement appropriate technical and organizational measures to protect your personal data.</p>
            
            <h2>5. Your Rights</h2>
            <p>You have the right to:</p>
            <ul>
                <li>Access your personal data</li>
                <li>Correct inaccurate data</li>
                <li>Request deletion of your data</li>
                <li>Unsubscribe from communications</li>
            </ul>
            
            <h2>6. Contact Us</h2>
            <p>If you have questions about this Privacy Policy, please contact us at: <a href="mailto:${admin_email}">${admin_email}</a></p>
        </div>
        
        <footer>
            <p><a href="index.html" style="color: white;">Return to Home</a> | &copy; $(date +%Y) ${brand_name}</p>
        </footer>
    </div>
</body>
</html>
EOF

    # Create unsubscribe page
    print_message "Creating unsubscribe page..."
    cat > /var/www/html/unsubscribe.html <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Unsubscribe - ${brand_name}</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 0;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        .container {
            width: 90%;
            max-width: 600px;
            margin: 0 auto;
            padding: 2rem;
        }
        .content {
            background: rgba(255, 255, 255, 0.95);
            padding: 3rem;
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            text-align: center;
        }
        h1 {
            color: #764ba2;
        }
        .form-group {
            margin: 2rem 0;
        }
        input[type="email"] {
            width: 100%;
            padding: 1rem;
            border: 2px solid #e0e0e0;
            border-radius: 5px;
            font-size: 1rem;
        }
        button {
            background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);
            color: white;
            border: none;
            padding: 1rem 2rem;
            font-size: 1rem;
            border-radius: 5px;
            cursor: pointer;
            transition: all 0.3s;
        }
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }
        .alert {
            padding: 1rem;
            background: #ffeaa7;
            border-radius: 5px;
            margin: 1rem 0;
        }
        footer {
            text-align: center;
            margin-top: 2rem;
            color: white;
        }
        a {
            color: #667eea;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="content">
            <h1>Unsubscribe</h1>
            <p>We're sorry to see you go. Enter your email address below to unsubscribe from our mailing list.</p>
            
            <div class="alert">
                <strong>Note:</strong> Configure this form with your MailWizz unsubscribe URL.
            </div>
            
            <!-- REPLACE THE ACTION URL WITH YOUR MAILWIZZ UNSUBSCRIBE URL -->
            <form action="https://your-mailwizz-url.com/lists/unsubscribe" method="post">
                <!-- REPLACE LIST_UID_HERE WITH YOUR ACTUAL LIST UID -->
                <input type="hidden" name="list_uid" value="LIST_UID_HERE">
                
                <div class="form-group">
                    <input type="email" name="EMAIL" required placeholder="your@email.com">
                </div>
                
                <button type="submit">Unsubscribe</button>
            </form>
            
            <p style="margin-top: 2rem;">Questions? Contact us at <a href="mailto:${admin_email}">${admin_email}</a></p>
        </div>
        
        <footer>
            <p><a href="index.html" style="color: white;">Return to Home</a> | <a href="privacy-policy.html" style="color: white;">Privacy Policy</a></p>
        </footer>
    </div>
</body>
</html>
EOF

    # Set permissions for the new files
    chmod 644 /var/www/html/index.html
    chmod 644 /var/www/html/privacy-policy.html
    chmod 644 /var/www/html/unsubscribe.html

    print_message "Website created successfully with privacy policy and unsubscribe pages."
    print_message "NOTE: Remember to update the unsubscribe.html file with your actual MailWizz URL and List UID."
}

export -f create_utility_scripts setup_website
