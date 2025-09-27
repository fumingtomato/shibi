#!/bin/bash

# =================================================================
# MAILWIZZ INTEGRATION MODULE
# MailWizz configuration guidance and integration scripts
# =================================================================

# Create enhanced MailWizz integration guide for multi-IP with numbered subdomains
create_mailwizz_multi_ip_guide() {
    local domain=$1
    
    print_message "Creating MailWizz Multi-IP Integration Guide..."
    
    cat > /root/mailwizz-multi-ip-guide.txt <<EOF
======================================================
   MailWizz Multi-IP Bulk Mail Integration Guide
======================================================

This guide explains how to configure MailWizz for optimal
multi-IP bulk mail delivery with load balancing and rotation.

SUBDOMAIN CONFIGURATION: ${SUBDOMAIN}
BASE DOMAIN: ${domain}

CONFIGURED IP ADDRESSES AND HOSTNAMES:
---------------------------------------
EOF
    
    # List IPs with their corresponding numbered hostnames
    for ((i=0; i<${#IP_ADDRESSES[@]}; i++)); do
        local ip="${IP_ADDRESSES[$i]}"
        local hostname_display
        local transport_num=$((i + 1))
        
        if [ $i -eq 0 ]; then
            hostname_display="${SUBDOMAIN}.${domain}"
        else
            local suffix=$(printf "%03d" $i)
            hostname_display="${SUBDOMAIN}${suffix}.${domain}"
        fi
        
        echo "IP #${transport_num}: $ip" >> /root/mailwizz-multi-ip-guide.txt
        echo "  Hostname: $hostname_display" >> /root/mailwizz-multi-ip-guide.txt
        echo "  Transport: smtp-ip${transport_num}" >> /root/mailwizz-multi-ip-guide.txt
        echo "  PTR Record: $hostname_display" >> /root/mailwizz-multi-ip-guide.txt
        echo "" >> /root/mailwizz-multi-ip-guide.txt
    done
    
    cat >> /root/mailwizz-multi-ip-guide.txt <<'EOF'

STEP 1: CREATE DELIVERY SERVERS IN MAILWIZZ
-------------------------------------------

For EACH IP address, create a separate delivery server:

1. Go to: Backend → Delivery Servers → Create new server
2. Select "SMTP" as server type
3. Configure as follows:

EOF
    
    # Generate specific configuration for each IP
    for ((i=0; i<${#IP_ADDRESSES[@]}; i++)); do
        local ip="${IP_ADDRESSES[$i]}"
        local transport_num=$((i + 1))
        local server_name
        local hostname_display
        
        if [ $i -eq 0 ]; then
            server_name="Production-${SUBDOMAIN^^}"
            hostname_display="${SUBDOMAIN}.${domain}"
        else
            local suffix=$(printf "%03d" $i)
            server_name="Production-${SUBDOMAIN^^}${suffix}"
            hostname_display="${SUBDOMAIN}${suffix}.${domain}"
        fi
        
        cat >> /root/mailwizz-multi-ip-guide.txt <<EOF
   For IP #${transport_num} ($ip):
   ================================
   Name: ${server_name}
   Hostname: localhost
   Port: 25
   Protocol: None
   Timeout: 30
   From email: noreply@${domain}
   From name: Your Brand Name
   Reply-to email: reply@${domain}
   Return-path: bounces@${domain}
   
   Under "Additional headers":
   X-Mail-Server: ${hostname_display}
   X-Transport: smtp-ip${transport_num}
   
   Under SMTP settings:
   Bounce server: [Configure bounce handling]
   Tracking domain: [Your tracking domain]
   
   IMPORTANT - Force specific transport:
   In "Custom headers" add:
   X-Transport: smtp-ip${transport_num}
   
   Set hourly/daily limits based on IP warmup status:
   - New IP (Days 1-7): 100 emails/hour, 1000/day
   - Warming (Days 8-30): 500 emails/hour, 5000/day
   - Warmed (Days 31+): 2000 emails/hour, 20000/day

EOF
    done
    
    cat >> /root/mailwizz-multi-ip-guide.txt <<EOF

STEP 2: CONFIGURE DELIVERY SERVER GROUPS
----------------------------------------

Create groups for different sending strategies:

1. Round-Robin Group (Even distribution):
   Name: "All-IPs-RoundRobin"
   - Add all ${#IP_ADDRESSES[@]} IP delivery servers
   - Set equal probabilities (e.g., $((100 / ${#IP_ADDRESSES[@]}))% each for ${#IP_ADDRESSES[@]} IPs)
   
2. Primary-Fallback Group:
   Name: "Primary-with-Backup"
   - Add ${SUBDOMAIN}.${domain} server with 80% probability
   - Add backup IPs with remaining 20% split among them
   
3. Numbered Hostname Groups:
   - Create separate groups based on subdomain numbers
   - Useful for segregating traffic by campaign type

STEP 3: CUSTOMER GROUP CONFIGURATION
------------------------------------

1. Go to: Backend → Customers → Groups
2. For each customer group, assign:
   - Appropriate delivery server group
   - Sending quota based on combined IP capacity
   - Sending speed limits to prevent overwhelming

   Example settings for ${#IP_ADDRESSES[@]} IPs:
   - Total hourly quota: $((2000 * ${#IP_ADDRESSES[@]})) emails
   - Total daily quota: $((20000 * ${#IP_ADDRESSES[@]})) emails

STEP 4: CONFIGURE PCNTL FOR PARALLEL PROCESSING
-----------------------------------------------

For optimal multi-IP performance:

1. Ensure PHP PCNTL extension is installed
2. In MailWizz settings → Cron:
   - Set "Campaigns at once": $((5 * ${#IP_ADDRESSES[@]}))
   - Set "Subscribers at once": $((100 * ${#IP_ADDRESSES[@]}))
   - Enable "Parallel processing"
   - Set "Parallel processes": ${#IP_ADDRESSES[@]} (one per IP)

STEP 5: WARMUP SCHEDULE AUTOMATION
----------------------------------

Use the IP warmup manager to track sending:

# Check current warmup status
/usr/local/bin/ip-warmup-manager status

# Initialize warmup for specific IPs
EOF
    
    for ip in "${IP_ADDRESSES[@]}"; do
        echo "/usr/local/bin/ip-warmup-manager init $ip" >> /root/mailwizz-multi-ip-guide.txt
    done
    
    cat >> /root/mailwizz-multi-ip-guide.txt <<'EOF'

# Update send counts (integrate with MailWizz hooks)
/usr/local/bin/ip-warmup-manager update [IP] [count]

STEP 6: HOSTNAME VERIFICATION
-----------------------------

Verify that each hostname resolves correctly:

EOF
    
    # Add verification commands for each hostname
    for ((i=0; i<${#IP_ADDRESSES[@]}; i++)); do
        local hostname_check
        if [ $i -eq 0 ]; then
            hostname_check="${SUBDOMAIN}.${domain}"
        else
            local suffix=$(printf "%03d" $i)
            hostname_check="${SUBDOMAIN}${suffix}.${domain}"
        fi
        echo "dig A $hostname_check" >> /root/mailwizz-multi-ip-guide.txt
    done
    
    cat >> /root/mailwizz-multi-ip-guide.txt <<'EOF'

Expected result: Each command should return the corresponding IP address.

STEP 7: MONITORING AND OPTIMIZATION
-----------------------------------

1. Monitor delivery rates per IP:
EOF
    
    for ip in "${IP_ADDRESSES[@]}"; do
        echo "   /usr/local/bin/mail-stats ip $ip" >> /root/mailwizz-multi-ip-guide.txt
    done
    
    cat >> /root/mailwizz-multi-ip-guide.txt <<'EOF'

2. Check overall performance:
   /usr/local/bin/mail-stats overall

3. Generate daily reports:
   /usr/local/bin/mail-stats report

4. Monitor queue health:
   mailq | tail -20
   
5. Check specific transport queues:
EOF
    
    for ((i=1; i<=${#IP_ADDRESSES[@]}; i++)); do
        echo "   postqueue -p | grep smtp-ip${i}" >> /root/mailwizz-multi-ip-guide.txt
    done
    
    cat >> /root/mailwizz-multi-ip-guide.txt <<EOF

STEP 8: HANDLING BOUNCES AND FEEDBACK LOOPS
-------------------------------------------

1. Configure bounce servers for each IP:
EOF
    
    # Generate bounce email suggestions for each hostname
    for ((i=0; i<${#IP_ADDRESSES[@]}; i++)); do
        if [ $i -eq 0 ]; then
            echo "   - bounce-${SUBDOMAIN}@${domain} for ${SUBDOMAIN}.${domain}" >> /root/mailwizz-multi-ip-guide.txt
        else
            local suffix=$(printf "%03d" $i)
            echo "   - bounce-${SUBDOMAIN}${suffix}@${domain} for ${SUBDOMAIN}${suffix}.${domain}" >> /root/mailwizz-multi-ip-guide.txt
        fi
    done
    
    cat >> /root/mailwizz-multi-ip-guide.txt <<'EOF'
   
   - Configure Feedback Loop processing
   - Set up complaint handling

2. Regular maintenance tasks:
   # Clear old bounce logs
   find /var/log/mail-bounces -mtime +30 -delete
   
   # Process feedback loops
   /usr/local/bin/process-feedback-loops

STEP 9: LOAD BALANCING STRATEGIES
---------------------------------

Strategy 1: Equal Distribution (Recommended for start)
- Configure all IPs with equal sending limits
- Use round-robin in delivery server groups
- Best for: New setups, testing phase

Strategy 2: Weighted Distribution
- Set higher limits on better-performing IPs
- Adjust weights in delivery server groups
- Best for: After identifying top-performing IPs

Strategy 3: Reputation-Based
- Monitor IP reputation scores
- Dynamically adjust sending limits
- Move traffic away from problematic IPs
- Best for: Mature setups with reputation data

STEP 10: TROUBLESHOOTING
------------------------

Common issues and solutions:

1. Emails stuck in queue:
   postqueue -f  # Flush queue
   postsuper -r ALL  # Requeue all

2. Specific IP not sending:
   # Check transport
   postconf -M | grep smtp-ip[NUMBER]
   
   # Test specific transport
   echo "test" | mail -s "test" -S smtp=smtp-ip[NUMBER]: test@example.com

3. Verify hostname configuration:
   # Check HELO names in Postfix
   grep -A1 "smtp-ip" /etc/postfix/master.cf | grep smtp_helo_name

4. Uneven distribution:
   # Check sender_dependent_default_transport_maps
   postmap -q "sender@domain.com" /etc/postfix/sender_dependent_default_transport_maps

5. Rate limiting issues:
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

NUMBERED SUBDOMAIN ADVANTAGES:
------------------------------

Your setup uses the numbered subdomain format (${SUBDOMAIN}001, ${SUBDOMAIN}002, etc.):

1. Professional appearance in email headers
2. Easy to identify which IP/hostname sent each email
3. Scalable up to 999 IPs without naming conflicts
4. Consistent PTR records that match HELO names
5. Clear organization in MailWizz delivery servers

COMPLIANCE AND BEST PRACTICES:
------------------------------

1. Always warm up new IPs gradually
2. Monitor blacklists daily for all ${#IP_ADDRESSES[@]} IPs
3. Maintain < 0.1% complaint rate
4. Keep bounce rate < 5%
5. Implement proper unsubscribe handling
6. Use double opt-in for better reputation
7. Segment lists based on engagement
8. Regular list hygiene
9. Monitor each hostname's reputation separately

API INTEGRATION EXAMPLE:
------------------------

To integrate with MailWizz API for automated IP rotation:

<?php
// Example PHP code for MailWizz API with numbered subdomains
\$endpoint = new MailWizzApi_Endpoint_DeliveryServers();
\$response = \$endpoint->getServers(\$pageNumber = 1, \$perPage = 10);

// Map server names to our numbered format
\$serverMapping = [
EOF
    
    # Generate PHP array mapping
    for ((i=0; i<${#IP_ADDRESSES[@]}; i++)); do
        if [ $i -eq 0 ]; then
            echo "    'Production-${SUBDOMAIN^^}' => 'smtp-ip$((i+1))'," >> /root/mailwizz-multi-ip-guide.txt
        else
            local suffix=$(printf "%03d" $i)
            echo "    'Production-${SUBDOMAIN^^}${suffix}' => 'smtp-ip$((i+1))'," >> /root/mailwizz-multi-ip-guide.txt
        fi
    done
    
    cat >> /root/mailwizz-multi-ip-guide.txt <<'EOF'
];

// Rotate through servers based on current load
foreach ($response->body['data']['records'] as $server) {
    // Check server load and adjust
    if ($server['hourly_quota_used'] < $server['hourly_quota']) {
        // Use this server for next batch
        $transport = $serverMapping[$server['name']] ?? 'smtp';
        // Configure sending with specific transport
    }
}
?>

QUICK REFERENCE:
---------------
EOF
    
    # Generate quick reference table
    echo "Transport | IP Address      | Hostname                    | Server Name" >> /root/mailwizz-multi-ip-guide.txt
    echo "----------------------------------------------------------------------" >> /root/mailwizz-multi-ip-guide.txt
    
    for ((i=0; i<${#IP_ADDRESSES[@]}; i++)); do
        local ip="${IP_ADDRESSES[$i]}"
        local transport="smtp-ip$((i+1))"
        local hostname_ref
        local server_ref
        
        if [ $i -eq 0 ]; then
            hostname_ref="${SUBDOMAIN}.${domain}"
            server_ref="Production-${SUBDOMAIN^^}"
        else
            local suffix=$(printf "%03d" $i)
            hostname_ref="${SUBDOMAIN}${suffix}.${domain}"
            server_ref="Production-${SUBDOMAIN^^}${suffix}"
        fi
        
        printf "%-9s | %-15s | %-27s | %s\n" "$transport" "$ip" "$hostname_ref" "$server_ref" >> /root/mailwizz-multi-ip-guide.txt
    done
    
    cat >> /root/mailwizz-multi-ip-guide.txt <<EOF

For support: admin@$domain
Generated: $(date)
EOF
    
    chmod 644 /root/mailwizz-multi-ip-guide.txt
    print_message "MailWizz Multi-IP integration guide created at /root/mailwizz-multi-ip-guide.txt"
}

export -f create_mailwizz_multi_ip_guide
