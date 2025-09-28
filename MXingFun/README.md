# Multi-IP Bulk Mail Server with DKIM Authentication
## Version 16.3.0 - Professional Email Infrastructure

A comprehensive mail server installation script with automatic DKIM configuration, Cloudflare DNS integration, and compliance website for bulk email operations.

## ✨ Key Features

- **Automatic DKIM Setup**: Generates 2048-bit DKIM keys and adds them to Cloudflare automatically
- **Multi-IP Support**: Configure multiple IP addresses for high-volume sending
- **Cloudflare Integration**: Automatic DNS configuration including SPF, DKIM, and DMARC
- **Compliance Website**: Auto-generated website with privacy policy, terms, and unsubscribe pages
- **Mailwizz Compatible**: Ready for integration with Mailwizz email marketing platform
- **SSL Certificates**: Automatic Let's Encrypt SSL for both mail server and website
- **Complete Management Tools**: Suite of commands for easy server administration

## 🚀 Quick Installation

```bash
# Download and run installer
wget https://raw.githubusercontent.com/fumingtomato/shibi/main/MXingFun/install.sh
chmod +x install.sh
sudo ./install.sh
