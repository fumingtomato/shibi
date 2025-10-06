#!/bin/bash

# =================================================================
# MAILWIZZ WEBHOOK API SETUP
# Version: 1.0.0
# Sets up a Python/Flask API to receive webhooks from MailWizz.
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

print_header "Setting Up MailWizz Webhook API"

# 1. Install Dependencies (Python, Pip, Flask, Gunicorn)
echo "Installing Python, Flask, and Gunicorn..."
apt-get update > /dev/null 2>&1
apt-get install -y python3 python3-pip python3-venv > /dev/null 2>&1
python3 -m pip install flask gunicorn > /dev/null 2>&1
print_message "✓ Dependencies installed."

# 2. Create Application Directory and Copy Script
echo "Configuring application..."
mkdir -p /opt/mailwizz-api
cp "$(pwd)/webhook_handler.py" /opt/mailwizz-api/webhook_handler.py
touch /var/log/mailwizz_webhook.log
chown www-data:www-data /var/log/mailwizz_webhook.log
print_message "✓ Application configured."

# 3. Generate a Secret Token for the Webhook
WEBHOOK_SECRET=$(openssl rand -hex 32)
echo "Generated Webhook Secret: $WEBHOOK_SECRET"
echo "This will be saved in /etc/mail-config/webhook_secret"
echo "$WEBHOOK_SECRET" > /etc/mail-config/webhook_secret
chmod 644 /etc/mail-config/webhook_secret
print_message "✓ Secret token generated."

# 4. Create a systemd Service to Run the API
echo "Creating systemd service for the API..."
cat > /etc/systemd/system/mailwizz-api.service <<EOF
[Unit]
Description=Gunicorn instance to serve MailWizz Webhook API
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/opt/mailwizz-api
Environment="WEBHOOK_SECRET_TOKEN=$WEBHOOK_SECRET"
ExecStart=/usr/bin/python3 -m gunicorn --workers 3 --bind 127.0.0.1:5001 webhook_handler:app
Restart=always

[Install]
WantedBy=multi-user.target
EOF
print_message "✓ Systemd service created."

# 5. Configure nginx as a Reverse Proxy
echo "Configuring nginx..."
# Load domain name from install.conf
source /root/mail-installer/install.conf
NGINX_CONFIG="/etc/nginx/sites-available/$DOMAIN_NAME.conf"

# Add the API location block to the existing nginx config
if [ -f "$NGINX_CONFIG" ]; then
    # Insert the location block before the last closing brace '}'
    sed -i '$i \
    location /api/mailwizz-webhook { \
        proxy_pass http://127.0.0.1:5001/webhook; \
        proxy_set_header Host \$host; \
        proxy_set_header X-Real-IP \$remote_addr; \
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for; \
    }' "$NGINX_CONFIG"
    print_message "✓ nginx configured."
else
    print_error "✗ Nginx config not found at $NGINX_CONFIG"
fi

# 6. Enable and Start Services
echo "Enabling and starting services..."
systemctl daemon-reload
systemctl start mailwizz-api
systemctl enable mailwizz-api
systemctl reload nginx
print_message "✓ Webhook API is now running."

# 7. Add sudoers rule for the webserver user
echo "Adding sudoers rule for www-data..."
echo "www-data ALL=(root) NOPASSWD: /usr/local/bin/bulk-ip-manage" >> /etc/sudoers.d/mail-commands
print_message "✓ Sudoers rule added."

print_header "Webhook API Setup Complete!"
echo "Your API is available at: http://$HOSTNAME/api/mailwizz-webhook"
echo "Your secret token is: $WEBHOOK_SECRET"
echo "Use these details to configure the webhook in MailWizz."
