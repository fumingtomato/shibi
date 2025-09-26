#!/bin/bash

# =================================================================
# PACKAGES AND SYSTEM CONFIGURATION MODULE
# Package installation and system setup functions
# =================================================================

# [Previous functions remain the same until setup_website function]

# Setup basic website for the mail server domain with privacy and unsubscribe
setup_website() {
    local domain=$1
    local admin_email=$2
    local brand_name=$3
    
    print_header "Setting Up Web Interface"
    
    print_message "Creating web directory structure..."
    
    # Create web root
    mkdir -p /var/www/html
    
    # Create main landing page with unsubscribe link and privacy policy
    cat > /var/www/html/index.html <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${brand_name} - Mail Server</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .container {
            max-width: 600px;
            margin: 2rem;
            padding: 3rem;
            background: white;
            border-radius: 10px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            text-align: center;
        }
        h1 {
            color: #764ba2;
            margin-bottom: 1rem;
            font-size: 2.5rem;
        }
        .status {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            background: #10b981;
            color: white;
            border-radius: 20px;
            font-size: 0.875rem;
            margin-bottom: 2rem;
        }
        .description {
            margin-bottom: 2rem;
            color: #555;
        }
        .links {
            margin-top: 2rem;
            padding-top: 2rem;
            border-top: 1px solid #e0e0e0;
        }
        .links a {
            color: #764ba2;
            text-decoration: none;
            margin: 0 1rem;
            padding: 0.5rem 1rem;
            border: 1px solid #764ba2;
            border-radius: 5px;
            display: inline-block;
            transition: all 0.3s ease;
        }
        .links a:hover {
            background: #764ba2;
            color: white;
        }
        .footer {
            margin-top: 3rem;
            padding-top: 2rem;
            border-top: 1px solid #e0e0e0;
            font-size: 0.875rem;
            color: #777;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>${brand_name}</h1>
        <span class="status">● Mail Server Active</span>
        <p class="description">Professional Email Service for ${domain}</p>
        
        <div class="links">
            <a href="/unsubscribe.html">Unsubscribe</a>
            <a href="/privacy.html">Privacy Policy</a>
        </div>
        
        <div class="footer">
            <p>© $(date +%Y) ${brand_name}. All rights reserved.</p>
            <p>Contact: ${admin_email}</p>
        </div>
    </div>
</body>
</html>
EOF
    
    # Create unsubscribe page with MailWizz integration
    cat > /var/www/html/unsubscribe.html <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Unsubscribe - ${brand_name}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 2rem;
        }
        .container {
            max-width: 600px;
            margin: 0 auto;
            padding: 3rem;
            background: white;
            border-radius: 10px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        h1 {
            color: #764ba2;
            margin-bottom: 1.5rem;
            text-align: center;
        }
        .content {
            margin-bottom: 2rem;
        }
        .form-group {
            margin-bottom: 1.5rem;
        }
        label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 500;
        }
        input[type="email"] {
            width: 100%;
            padding: 0.75rem;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 1rem;
        }
        button {
            background: #764ba2;
            color: white;
            border: none;
            padding: 0.75rem 2rem;
            border-radius: 5px;
            font-size: 1rem;
            cursor: pointer;
            transition: background 0.3s ease;
            width: 100%;
        }
        button:hover {
            background: #5a3885;
        }
        .info {
            background: #f7f7f7;
            padding: 1rem;
            border-radius: 5px;
            margin-top: 2rem;
            font-size: 0.875rem;
            color: #666;
        }
        .back-link {
            text-align: center;
            margin-top: 2rem;
        }
        .back-link a {
            color: #764ba2;
            text-decoration: none;
        }
        .mailwizz-note {
            background: #fff3cd;
            border: 1px solid #ffc107;
            padding: 1rem;
            border-radius: 5px;
            margin-bottom: 2rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Unsubscribe from Mailing List</h1>
        
        <div class="mailwizz-note">
            <strong>Note:</strong> If you received an email with an unsubscribe link, please use that link for instant removal. 
            The form below is for manual unsubscribe requests.
        </div>
        
        <div class="content">
            <p>We're sorry to see you go. Please enter your email address below to unsubscribe from our mailing list.</p>
        </div>
        
        <form id="unsubscribe-form" action="#" method="POST">
            <div class="form-group">
                <label for="email">Email Address:</label>
                <input type="email" id="email" name="email" required placeholder="your@email.com">
            </div>
            
            <button type="submit">Unsubscribe</button>
        </form>
        
        <div class="info">
            <p><strong>What happens when you unsubscribe:</strong></p>
            <ul style="margin-left: 1.5rem; margin-top: 0.5rem;">
                <li>You will be immediately removed from our mailing list</li>
                <li>You will receive a confirmation email</li>
                <li>You will no longer receive any promotional emails from us</li>
                <li>Your data will be retained for record-keeping as per our privacy policy</li>
            </ul>
        </div>
        
        <div class="back-link">
            <a href="/">← Back to Home</a>
        </div>
    </div>
    
    <script>
    document.getElementById('unsubscribe-form').addEventListener('submit', function(e) {
        e.preventDefault();
        
        // For MailWizz integration, redirect to MailWizz unsubscribe endpoint
        // Replace YOUR_MAILWIZZ_URL with actual MailWizz installation URL
        var email = document.getElementById('email').value;
        
        // Option 1: Direct to MailWizz unsubscribe page
        // window.location.href = 'YOUR_MAILWIZZ_URL/lists/unsubscribe-search';
        
        // Option 2: Show confirmation (for now, without MailWizz integration)
        alert('Unsubscribe request received for: ' + email + '\\n\\nPlease configure MailWizz integration to process this request automatically.');
        
        // In production, this would submit to MailWizz API or redirect to MailWizz unsubscribe page
    });
    </script>
</body>
</html>
EOF
    
    # Create privacy policy page
    cat > /var/www/html/privacy.html <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Privacy Policy - ${brand_name}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            line-height: 1.8;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 2rem;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            padding: 3rem;
            background: white;
            border-radius: 10px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        h1 {
            color: #764ba2;
            margin-bottom: 2rem;
            text-align: center;
        }
        h2 {
            color: #764ba2;
            margin-top: 2rem;
            margin-bottom: 1rem;
            font-size: 1.4rem;
        }
        p {
            margin-bottom: 1rem;
            text-align: justify;
        }
        ul {
            margin-left: 2rem;
            margin-bottom: 1rem;
        }
        .last-updated {
            text-align: center;
            color: #666;
            font-style: italic;
            margin-bottom: 2rem;
        }
        .contact-section {
            background: #f7f7f7;
            padding: 1.5rem;
            border-radius: 5px;
            margin-top: 2rem;
        }
        .back-link {
            text-align: center;
            margin-top: 2rem;
        }
        .back-link a {
            color: #764ba2;
            text-decoration: none;
            padding: 0.5rem 1rem;
            border: 1px solid #764ba2;
            border-radius: 5px;
            display: inline-block;
            transition: all 0.3s ease;
        }
        .back-link a:hover {
            background: #764ba2;
            color: white;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Privacy Policy</h1>
        <p class="last-updated">Last updated: $(date +"%B %d, %Y")</p>
        
        <h2>1. Introduction</h2>
        <p>
            ${brand_name} ("we", "our", or "us") respects your privacy and is committed to protecting your personal data. 
            This privacy policy explains how we collect, use, and safeguard your information when you interact with our email services.
        </p>
        
        <h2>2. Information We Collect</h2>
        <p>We may collect the following types of information:</p>
        <ul>
            <li><strong>Email Address:</strong> Required for sending you communications you've subscribed to</li>
            <li><strong>Name:</strong> Used for personalization of communications</li>
            <li><strong>Subscription Preferences:</strong> Your choices regarding which communications you wish to receive</li>
            <li><strong>Engagement Data:</strong> Whether you open emails or click on links (for improving our service)</li>
            <li><strong>Technical Data:</strong> IP address, browser type, and device information for security and analytics</li>
        </ul>
        
        <h2>3. How We Use Your Information</h2>
        <p>Your information is used to:</p>
        <ul>
            <li>Send you emails you've subscribed to receive</li>
            <li>Personalize your experience</li>
            <li>Improve our email content and delivery</li>
            <li>Comply with legal obligations</li>
            <li>Protect against fraud and abuse</li>
        </ul>
        
        <h2>4. Data Retention</h2>
        <p>
            We retain your personal information only for as long as necessary to fulfill the purposes for which it was collected. 
            When you unsubscribe, we maintain a record of your email address solely to ensure you don't receive future communications.
        </p>
        
        <h2>5. Your Rights</h2>
        <p>You have the right to:</p>
        <ul>
            <li><strong>Access:</strong> Request a copy of your personal data</li>
            <li><strong>Correction:</strong> Request correction of inaccurate data</li>
            <li><strong>Deletion:</strong> Request deletion of your data (subject to legal requirements)</li>
            <li><strong>Opt-out:</strong> Unsubscribe from our communications at any time</li>
            <li><strong>Portability:</strong> Request your data in a machine-readable format</li>
        </ul>
        
        <h2>6. Email Communications</h2>
        <p>
            All marketing emails we send include an unsubscribe link. You can also manage your preferences or unsubscribe 
            via our <a href="/unsubscribe.html">unsubscribe page</a>.
        </p>
        
        <h2>7. Data Security</h2>
        <p>
            We implement appropriate technical and organizational measures to protect your personal data against unauthorized access, 
            alteration, disclosure, or destruction. This includes encryption, secure servers, and regular security assessments.
        </p>
        
        <h2>8. Third-Party Services</h2>
        <p>
            We may use third-party services for email delivery and analytics. These services are bound by their own privacy policies 
            and we ensure they meet our security standards.
        </p>
        
        <h2>9. Cookies and Tracking</h2>
        <p>
            Our emails may contain tracking pixels to help us understand email engagement. This helps us improve our service 
            and send more relevant content.
        </p>
        
        <h2>10. International Transfers</h2>
        <p>
            Your information may be transferred to and processed in countries other than your own. We ensure appropriate 
            safeguards are in place for such transfers.
        </p>
        
        <h2>11. Children's Privacy</h2>
        <p>
            Our services are not directed to individuals under 16 years of age. We do not knowingly collect personal 
            information from children.
        </p>
        
        <h2>12. Changes to This Policy</h2>
        <p>
            We may update this privacy policy from time to time. We will notify you of any material changes by posting 
            the new policy on this page and updating the "Last updated" date.
        </p>
        
        <div class="contact-section">
            <h2>13. Contact Us</h2>
            <p>
                If you have any questions about this privacy policy or our data practices, please contact us at:
            </p>
            <p>
                <strong>Email:</strong> ${admin_email}<br>
                <strong>Website:</strong> ${domain}<br>
                <strong>Data Protection Officer:</strong> ${admin_email}
            </p>
        </div>
        
        <div class="back-link">
            <a href="/">← Back to Home</a>
        </div>
    </div>
</body>
</html>
EOF
    
    # Set proper permissions
    chown -R www-data:www-data /var/www/html
    chmod -R 755 /var/www/html
    
    print_message "Web interface with unsubscribe and privacy policy pages created"
}

# [Rest of the functions remain the same]

# Export all functions
export -f install_required_packages
export -f configure_hostname
export -f save_configuration
export -f create_final_documentation
export -f setup_website
