#!/bin/bash

# =================================================================
# UTILITY SCRIPTS MODULE
# Helper scripts for mail server management with proper functionality
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

export -f create_utility_scripts
