#!/bin/bash

# =================================================================
# MAILWIZZ INTEGRATION MODULE
# MailWizz configuration guidance and integration scripts
# =================================================================

# Create enhanced MailWizz integration guide for multi-IP
create_mailwizz_multi_ip_guide() {
    local domain=$1
    
    print_message "Creating MailWizz Multi-IP Integration Guide..."
    
    cat > /root/mailwizz-multi-ip-guide.txt <<EOF
======================================================
   MailWizz Multi-IP Bulk Mail Integration Guide
======================================================

This guide explains how to configure MailWizz for optimal
multi-IP bulk mail delivery with load balancing and rotation.

CONFIGURED IP ADDRESSES:
------------------------
EOF
    
    local ip_index=0
    for ip in "${IP_ADDRESSES[@]}"; do
        ip_index=$((ip_index + 1))
        echo "IP #${ip_index}: $ip (Transport: smtp-ip${ip_index})" >> /root/mailwizz-multi-ip-guide.txt
    done
    
    cat >> /root/mailwizz-multi-ip-guide.txt <<'EOF'

STEP 1: CREATE DELIVERY SERVERS IN MAILWIZZ
-------------------------------------------

For EACH IP address, create a separate delivery server:

1. Go to: Backend → Delivery Servers → Create new server
2. Select "SMTP" as server type
3. Configure as follows:

   For IP #1 (Primary):
   ====================
   Name: Production-IP1
   Hostname: localhost
   Port: 25
   Protocol: None
   Timeout: 30
   From email: noreply@yourdomain.com
   
   Under "Additional headers":
   X-Mail-Server: IP1
   
   Under SMTP settings:
   Bounce server: [Configure bounce handling]
   Tracking domain: [Your tracking domain]
   
   IMPORTANT - Force specific transport:
   In "Custom headers" add:
   X-Transport: smtp-ip1
   
   Set hourly/daily limits based on IP warmup status:
   - New IP (Days 1-7): 100 emails/hour, 1000/day
   - Warming (Days 8-30): 500 emails/hour, 5000/day
   - Warmed (Days 31+): 2000 emails/hour, 20000/day

   Repeat for each additional IP, changing:
   - Name to Production-IP2, Production-IP3, etc.
   - X-Transport header to smtp-ip2, smtp-ip3, etc.
   - Adjust limits per IP warmup status

STEP 2: CONFIGURE DELIVERY SERVER GROUPS
----------------------------------------

Create groups for different sending strategies:

1. Round-Robin Group (Even distribution):
   - Add all IP delivery servers
   - Set equal probabilities (e.g., 25% each for 4 IPs)
   
2. Primary-Fallback Group:
   - Add primary IP with 80% probability
   - Add backup IPs with 20% split among them
   
3. Domain-Specific Groups:
   - Create separate groups for different sender domains
   - Assign specific IPs to specific domains

STEP 3: CUSTOMER GROUP CONFIGURATION
------------------------------------

1. Go to: Backend → Customers → Groups
2. For each customer group, assign:
   - Appropriate delivery server group
   - Sending quota based on combined IP capacity
   - Sending speed limits to prevent overwhelming

STEP 4: CONFIGURE PCNTL FOR PARALLEL PROCESSING
-----------------------------------------------

For optimal multi-IP performance:

1. Ensure PHP PCNTL extension is installed
2. In MailWizz settings → Cron:
   - Set "Campaigns at once": 10-20
   - Set "Subscribers at once": 300-500
   - Enable "Parallel processing"
   - Set "Parallel processes": 4-8 (based on CPU cores)

STEP 5: WARMUP SCHEDULE AUTOMATION
----------------------------------

Use the IP warmup manager to track sending:

# Check current warmup status
/usr/local/bin/ip-warmup-manager status

# Update send counts (integrate with MailWizz hooks)
/usr/local/bin/ip-warmup-manager update [IP] [count]

STEP 6: MONITORING AND OPTIMIZATION
-----------------------------------

1. Monitor delivery rates per IP:
   /usr/local/bin/mail-stats ip [IP_ADDRESS]

2. Check overall performance:
   /usr/local/bin/mail-stats overall

3. Generate daily reports:
   /usr/local/bin/mail-stats report

4. Monitor queue health:
   mailq | tail -20
   
5. Check specific transport queues:
   postqueue -p | grep smtp-ip1

STEP 7: HANDLING BOUNCES AND FEEDBACK LOOPS
-------------------------------------------

1. Configure bounce servers for each IP:
   - Create separate bounce@ addresses for each IP
   - Configure Feedback Loop processing
   - Set up complaint handling

2. Regular maintenance tasks:
   # Clear old bounce logs
   find /var/log/mail-bounces -mtime +30 -delete
   
   # Process feedback loops
   /usr/local/bin/process-feedback-loops

STEP 8: LOAD BALANCING STRATEGIES
---------------------------------

Strategy 1: Equal Distribution
- Configure all IPs with equal sending limits
- Use round-robin in delivery server groups

Strategy 2: Weighted Distribution
- Set higher limits on better-performing IPs
- Adjust weights in delivery server groups

Strategy 3: Reputation-Based
- Monitor IP reputation scores
- Dynamically adjust sending limits
- Move traffic away from problematic IPs

STEP 9: TROUBLESHOOTING
-----------------------

Common issues and solutions:

1. Emails stuck in queue:
   postqueue -f  # Flush queue
   postsuper -r ALL  # Requeue all

2. Specific IP not sending:
   # Check transport
   postconf -M | grep smtp-ip1
   
   # Test specific transport
   echo "test" | mail -s "test" -S smtp=smtp-ip1: test@example.com

3. Uneven distribution:
   # Check sender_dependent_default_transport_maps
   postmap -q "sender@domain.com" /etc/postfix/sender_dependent_default_transport_maps

4. Rate limiting issues:
   # Adjust in main.cf:
   smtp_destination_rate_delay = 1s
   smtp_destination_concurrency_limit = 20

PERFORMANCE TUNING TIPS:
------------------------

1. Database optimization for MailWizz:
   - Use InnoDB engine
   - Optimize tables regularly
   - Enable query cache

2. Redis for queue management:
   - Install Redis for better queue handling
   - Configure MailWizz to use Redis

3. CDN for tracking pixels:
   - Offload tracking to CDN
   - Reduces server load

4. Separate servers for different roles:
   - Consider dedicated tracking server
   - Separate database server for large volumes

COMPLIANCE AND BEST PRACTICES:
------------------------------

1. Always warm up new IPs gradually
2. Monitor blacklists daily
3. Maintain < 0.1% complaint rate
4. Keep bounce rate < 5%
5. Implement proper unsubscribe handling
6. Use double opt-in for better reputation
7. Segment lists based on engagement
8. Regular list hygiene

API INTEGRATION EXAMPLE:
------------------------

To integrate with MailWizz API for automated IP rotation:

<?php
// Example PHP code for MailWizz API
\$endpoint = new MailWizzApi_Endpoint_DeliveryServers();
\$response = \$endpoint->getServers(\$pageNumber = 1, \$perPage = 10);

// Rotate through servers based on current load
foreach (\$response->body['data']['records'] as \$server) {
    // Check server load and adjust
    if (\$server['hourly_quota_used'] < \$server['hourly_quota']) {
        // Use this server for next batch
    }
}
?>

For support: admin@$domain
EOF
    
    chmod 644 /root/mailwizz-multi-ip-guide.txt
    print_message "MailWizz Multi-IP integration guide created at /root/mailwizz-multi-ip-guide.txt"
}

export -f create_mailwizz_multi_ip_guide
