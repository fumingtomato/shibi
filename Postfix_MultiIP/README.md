# Multi-IP Bulk Mail Server Installer

A comprehensive mail server installer optimized for commercial bulk mailing with multiple IP address support, designed for integration with MailWizz.

## Features

- **Multi-IP Support**: Configure multiple IP addresses for load balancing and IP rotation
- **IP Warmup Management**: Gradual volume increase for new IPs
- **MailWizz Integration**: Optimized for MailWizz bulk mail operations
- **Monitoring & Statistics**: Per-IP statistics and performance monitoring
- **Auto-configuration**: Cloudflare DNS, SSL certificates, SPF/DKIM/DMARC
- **Security Hardening**: Built-in security measures and rate limiting

## Quick Installation

```bash
wget https://raw.githubusercontent.com/fumingtomato/maileristhegame/main/install.sh
chmod +x install.sh
sudo ./install.sh
