#!/bin/bash

# =================================================================
# DNS AND SSL MODULE
# Cloudflare DNS management and SSL certificate configuration
# =================================================================

# Check if any Cloudflare DNS record exists
check_any_cf_record_exists() {
    local name=$1
    
    response=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records?name=$name" \
        -H "Authorization: Bearer $CF_API_TOKEN" \
        -H "Content-Type: application/json")
    
    echo "$response"
}

# Check if specific Cloudflare DNS record exists
check_cf_record_exists() {
    local type=$1
    local name=$2
    
    response=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records?type=$type&name=$name" \
        -H "Authorization: Bearer $CF_API_TOKEN" \
        -H "Content-Type: application/json")
    
    record_count=$(echo "$response" | grep -o '"count":[0-9]*' | cut -d ':' -f2)
    
    if [ "$record_count" -gt 0 ]; then
        record_id=$(echo "$response" | grep -o '"id":"[^"]*"' | head -1 | cut -d '"' -f4)
        echo "$record_id"
    else
        echo ""
    fi
}

# Delete Cloudflare DNS record by ID
delete_cf_record() {
    local record_id=$1
    
    if [ -z "$record_id" ]; then
        return 1
    fi
    
    response=$(curl -s -X DELETE "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records/$record_id" \
        -H "Authorization: Bearer $CF_API_TOKEN" \
        -H "Content-Type: application/json")
    
    success=$(echo "$response" | grep -o '"success":true')
    if [ -n "$success" ]; then
        return 0
    else
        return 1
    fi
}

# Create Cloudflare DNS records
create_cf_record() {
    local type=$1
    local name=$2
    local content=$3
    local proxied=${4:-false}
    local force=${5:-false}
    
    print_debug "Creating $type record for $name..."
    
    record_id=$(check_cf_record_exists "$type" "$name")
    
    if [ ! -z "$record_id" ]; then
        if [ "$force" = true ]; then
            curl -s -X DELETE "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records/$record_id" \
                -H "Authorization: Bearer $CF_API_TOKEN" \
                -H "Content-Type: application/json" > /dev/null
            print_message "Force deleted existing $type record for $name"
        else
            read -p "Record $type for $name already exists. Overwrite? (y/n): " overwrite
            if [[ "$overwrite" != "y" && "$overwrite" != "Y" ]]; then
                print_message "Skipping creation of $type record for $name"
                return 0
            else
                curl -s -X DELETE "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records/$record_id" \
                    -H "Authorization: Bearer $CF_API_TOKEN" \
                    -H "Content-Type: application/json" > /dev/null
                print_message "Deleted existing $type record for $name"
            fi
        fi
    fi
    
    # Prepare JSON data based on record type
    if [ "$type" = "MX" ]; then
        priority=$(echo "$content" | cut -d ' ' -f1)
        mx_content=$(echo "$content" | cut -d ' ' -f2-)
        json_data="{\"type\":\"$type\",\"name\":\"$name\",\"content\":\"$mx_content\",\"priority\":$priority,\"ttl\":1,\"proxied\":false}"
    elif [ "$type" = "TXT" ]; then
        json_data="{\"type\":\"$type\",\"name\":\"$name\",\"content\":\"$content\",\"ttl\":1,\"proxied\":false}"
    else
        json_data="{\"type\":\"$type\",\"name\":\"$name\",\"content\":\"$content\",\"ttl\":1,\"proxied\":$proxied}"
    fi
    
    print_debug "Sending JSON: $json_data"
    
    response=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records" \
        -H "Authorization: Bearer $CF_API_TOKEN" \
        -H "Content-Type: application/json" \
        --data "$json_data")
    
    print_debug "Response: $response"
    
    success=$(echo "$response" | grep -o '"success":true')
    if [ -n "$success" ]; then
        print_message "Created $type record for $name"
    else
        print_error "Failed to create $type record for $name"
        print_debug "API call failed: $response"
        return 1
    fi
}

# Create DNS records for multiple IPs
create_multi_ip_dns_records() {
    local domain=$1
    local hostname=$2
    
    print_header "Creating DNS Records for Multiple IPs"
    
    if [ -z "$CF_API_TOKEN" ] || [ -z "$CF_ZONE_ID" ]; then
        print_warning "Cloudflare API credentials not provided. Skipping DNS configuration."
        print_message "Please manually create the following DNS records:"
        
        echo "1. A Records:"
        for ip in "${IP_ADDRESSES[@]}"; do
            echo "   - mail.${domain} -> $ip"
        done
        
        echo "2. SPF Record:"
        local spf_ips=""
        for ip in "${IP_ADDRESSES[@]}"; do
            spf_ips="${spf_ips} ip4:${ip}"
        done
        echo "   TXT @ -> v=spf1 mx a${spf_ips} ~all"
        
        echo "3. Reverse DNS (PTR Records):"
        echo "   Configure with your hosting provider for each IP"
        
        return
    fi
    
    # Create A records for each IP
    local ip_index=0
    for ip in "${IP_ADDRESSES[@]}"; do
        ip_index=$((ip_index + 1))
        
        if [ $ip_index -eq 1 ]; then
            create_cf_record "A" "$hostname" "$ip" false true
            create_cf_record "A" "$domain" "$ip" false true
        else
            create_cf_record "A" "mail${ip_index}.${domain}" "$ip" false true
        fi
    done
    
    # Create MX record
    create_cf_record "MX" "$domain" "10 $hostname" false true
    
    # Create SPF record with all IPs
    local spf_ips=""
    for ip in "${IP_ADDRESSES[@]}"; do
        spf_ips="${spf_ips} ip4:${ip}"
    done
    local spf_content="v=spf1 mx a${spf_ips} ~all"
    create_cf_record "TXT" "$domain" "$spf_content" false true
    
    # Create DKIM record
    local dkim_value=$(get_dkim_value "$domain")
    create_cf_record "TXT" "mail._domainkey.$domain" "v=DKIM1; k=rsa; p=$dkim_value" false true
    
    # Create DMARC record
    create_cf_record "TXT" "_dmarc.$domain" "v=DMARC1; p=none; rua=mailto:$ADMIN_EMAIL" false true
    
    print_message "Multi-IP DNS records created"
}

# Configure Nginx for Let's Encrypt and SSL
setup_nginx() {
    local domain=$1
    local hostname=$2
    
    print_message "Configuring Nginx for the main domain and mail subdomain..."
    
    # Create Nginx configuration for main domain
    cat > /etc/nginx/sites-available/$domain <<EOF
server {
    listen 80;
    server_name $domain;
    root /var/www/html;
    
    location ~ /.well-known {
        allow all;
    }
    
    location / {
        return 301 https://\$server_name\$request_uri;
    }
}
EOF
    
    # Create Nginx configuration for mail subdomain
    cat > /etc/nginx/sites-available/$hostname <<EOF
server {
    listen 80;
    server_name $hostname;
    
    location ~ /.well-known {
        allow all;
    }
    
    location / {
        return 301 https://$domain\$request_uri;
    }
}
EOF
    
    # Enable sites and create web root
    mkdir -p /etc/nginx/sites-enabled/
    ln -sf /etc/nginx/sites-available/$domain /etc/nginx/sites-enabled/
    ln -sf /etc/nginx/sites-available/$hostname /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true
    mkdir -p /var/www/html
    
    print_message "Nginx configuration completed."
}

# Advanced SSL certificate management
get_ssl_certificates() {
    local domain=$1
    local hostname=$2
    local email=$3
    
    print_header "SSL Certificate Management"
    print_message "Checking for existing certificates and setting up SSL..."
    
    local domain_cert_dir="/etc/letsencrypt/live/$domain"
    local hostname_cert_dir="/etc/letsencrypt/live/$hostname"
    local domain_cert_exists=false
    local hostname_cert_exists=false
    
    # Check if certificates already exist
    if [ -d "$domain_cert_dir" ] && [ -f "$domain_cert_dir/fullchain.pem" ]; then
        domain_cert_exists=true
        print_message "Found existing certificate for $domain"
    fi
    
    if [ -d "$hostname_cert_dir" ] && [ -f "$hostname_cert_dir/fullchain.pem" ]; then
        hostname_cert_exists=true
        print_message "Found existing certificate for $hostname"
    fi
    
    # If both certificates exist, skip obtaining new ones
    if $domain_cert_exists && $hostname_cert_exists; then
        print_message "Using existing certificates for both domains"
    else
        # Stop services that might be using port 80
        print_message "Temporarily stopping Nginx to free port 80..."
        systemctl stop nginx 2>/dev/null || true
        
        # Obtain certificates if needed
        if ! $domain_cert_exists; then
            print_message "Obtaining certificate for $domain..."
            
            for attempt in {1..3}; do
                if certbot certonly --standalone -d $domain --non-interactive --agree-tos --email $email; then
                    print_message "Certificate for $domain obtained successfully"
                    domain_cert_exists=true
                    break
                else
                    if [ $attempt -lt 3 ]; then
                        print_warning "Failed to obtain certificate for $domain (attempt $attempt/3). Retrying in 30 seconds..."
                        sleep 30
                    else
                        print_error "Failed to obtain certificate for $domain after 3 attempts."
                    fi
                fi
            done
        fi
        
        if ! $hostname_cert_exists; then
            print_message "Obtaining certificate for $hostname..."
            
            for attempt in {1..3}; do
                if certbot certonly --standalone -d $hostname --non-interactive --agree-tos --email $email; then
                    print_message "Certificate for $hostname obtained successfully"
                    hostname_cert_exists=true
                    break
                else
                    if [ $attempt -lt 3 ]; then
                        print_warning "Failed to obtain certificate for $hostname (attempt $attempt/3). Retrying in 30 seconds..."
                        sleep 30
                    else
                        print_error "Failed to obtain certificate for $hostname after 3 attempts."
                        
                        # If main domain cert exists, try to use it for hostname
                        if $domain_cert_exists; then
                            print_warning "Attempting to use main domain certificate for $hostname..."
                            mkdir -p "$hostname_cert_dir"
                            cp "$domain_cert_dir"/* "$hostname_cert_dir/"
                            if [ -f "$hostname_cert_dir/fullchain.pem" ]; then
                                hostname_cert_exists=true
                                print_message "Using main domain certificate for $hostname"
                            fi
                        fi
                    fi
                fi
            done
        fi
    fi
    
    # Setup certificate auto-renewal
    print_message "Setting up certificate auto-renewal..."
    if ! grep -q "certbot renew" /etc/crontab; then
        echo "0 3 * * * root certbot renew --quiet --post-hook 'systemctl reload nginx postfix dovecot'" >> /etc/crontab
        print_message "Certificate auto-renewal configured"
    else
        print_message "Certificate auto-renewal already configured"
    fi
    
    # Update Nginx configuration with SSL
    if $domain_cert_exists; then
        cat > /etc/nginx/sites-available/$domain <<EOF
server {
    listen 80;
    server_name $domain;
    location ~ /.well-known {
        allow all;
    }
    location / {
        return 301 https://\$server_name\$request_uri;
    }
}

server {
    listen 443 ssl http2;
    server_name $domain;
    
    ssl_certificate /etc/letsencrypt/live/$domain/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$domain/privkey.pem;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers 'EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH';
    
    root /var/www/html;
    index index.html;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF
    fi
    
    if $hostname_cert_exists; then
        cat > /etc/nginx/sites-available/$hostname <<EOF
server {
    listen 80;
    server_name $hostname;
    location ~ /.well-known {
        allow all;
    }
    location / {
        return 301 https://$domain\$request_uri;
    }
}

server {
    listen 443 ssl http2;
    server_name $hostname;
    
    ssl_certificate /etc/letsencrypt/live/$hostname/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$hostname/privkey.pem;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers 'EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH';
    
    location / {
        return 301 https://$domain\$request_uri;
    }
}
EOF
    fi
    
    # Ensure proper permissions
    if [ -d "/etc/letsencrypt/live" ]; then
        chmod -R 755 /etc/letsencrypt/archive
        chmod -R 755 /etc/letsencrypt/live
    fi
    
    # Start Nginx
    print_message "Starting Nginx with SSL configuration..."
    systemctl start nginx || true
    
    print_message "SSL certificate setup completed"
}

export -f check_any_cf_record_exists check_cf_record_exists delete_cf_record
export -f create_cf_record create_multi_ip_dns_records setup_nginx get_ssl_certificates
