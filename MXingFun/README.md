# Multi-IP Bulk Mail Server Installer v16.0.2

A simplified, single-option mail server installer with multi-IP support for Ubuntu/Debian systems.

## 🚀 Quick Start

Just run ONE command to install everything:

```bash
wget https://raw.githubusercontent.com/fumingtomato/shibi/main/MultiIPMail/install.sh
chmod +x install.sh
sudo ./install.sh
```

That's it! The installer will:
1. Download all necessary modules
2. Install and configure mail server components
3. Set up database and authentication
4. Create helpful management utilities
5. Generate DNS records for you

## 📋 What Gets Installed

- **Postfix** - Mail Transfer Agent (SMTP)
- **Dovecot** - IMAP/POP3 server
- **MySQL/MariaDB** - User and domain database
- **OpenDKIM** - Email authentication
- **SpamAssassin** - Spam filtering
- **Fail2ban** - Brute force protection
- **UFW** - Firewall
- **SSL/TLS** - Secure connections (Let's Encrypt or self-signed)

## 🛠️ Included Scripts

After installation, you'll have these commands available:

| Command | Purpose |
|---------|---------|
| `mail-account` | Add/delete/list email accounts |
| `mail-queue` | Manage mail queue |
| `mail-status` | Check server status |
| `mail-backup` | Backup mail server |
| `mail-log` | View mail logs |
| `test-email` | Send test emails |
| `check-dns` | Verify DNS records |
| `maildb` | Database management |
| `mail-test` | Quick server test |

## 📝 Post-Installation Steps

### 1. Add DNS Records

After installation, check `/root/dns-records-YOURDOMAIN.txt` for the exact records to add:

- **A Record**: `mail.yourdomain.com` → `YOUR_IP`
- **MX Record**: `yourdomain.com` → `mail.yourdomain.com` (Priority: 10)
- **SPF Record**: `TXT` → `v=spf1 mx a ip4:YOUR_IP ~all`
- **DKIM Record**: `mail._domainkey` → `(check the file for key)`
- **DMARC Record**: `_dmarc` → `v=DMARC1; p=none; rua=mailto:admin@yourdomain.com`
- **PTR Record**: Contact your hosting provider to set reverse DNS

### 2. Get SSL Certificate (Optional but Recommended)

The installer will offer to get a Let's Encrypt certificate automatically, or you can run later:

```bash
certbot certonly --standalone -d mail.yourdomain.com
```

### 3. Add Email Accounts

```bash
# Add a new email account
mail-account add user@yourdomain.com password123

# List all accounts
mail-account list

# Delete an account
mail-account delete user@yourdomain.com
```

### 4. Test Your Server

```bash
# Quick test
mail-test

# Send test email to check authentication
test-email check-auth@verifier.port25.com

# Check DNS records
check-dns yourdomain.com

# View server status
mail-status
```

## 🔧 Troubleshooting

If you encounter any issues, run the diagnostic tool:

```bash
sudo ./troubleshoot.sh
```

This will:
- Check all services
- Verify configurations
- Test connectivity
- Fix common issues automatically

## 📁 File Structure

```
/root/
├── install.sh                 # Main installer (downloads everything)
├── dns-records-*.txt          # DNS records to add
├── .mail_db_password          # Database password (keep safe!)
└── mail-installer/            # Installation files
    ├── run-installer.sh       # Main execution script
    └── modules/               # Feature modules

/usr/local/bin/
├── mail-account              # Account management
├── mail-queue                # Queue management
├── mail-status               # Status checker
├── mail-backup               # Backup utility
├── mail-log                  # Log viewer
├── test-email                # Test sender
├── check-dns                 # DNS checker
├── mail-test                 # Quick test
└── maildb                    # Database tool

/etc/
├── postfix/                  # Postfix configuration
├── dovecot/                  # Dovecot configuration
├── opendkim/                 # DKIM keys and config
└── mysql/                    # Database config
```

## 🔍 Common Issues and Solutions

### Services Not Starting

```bash
# Check service status
systemctl status postfix dovecot opendkim

# View detailed logs
journalctl -xe

# Run diagnostics
sudo ./troubleshoot.sh
```

### Emails Not Sending

1. Check DNS records: `check-dns yourdomain.com`
2. Verify services: `mail-status`
3. Check queue: `mail-queue show`
4. View logs: `mail-log follow`

### Database Connection Issues

```bash
# Check database
maildb console

# Reset database password if needed
mysql -u root
ALTER USER 'mailuser'@'localhost' IDENTIFIED BY 'newpassword';
# Update password in /root/.mail_db_password
```

### Port 25 Blocked

Many cloud providers block port 25. Contact your provider to unblock it, or use an SMTP relay service.

## 🚨 Security Notes

1. **Change default passwords** immediately after installation
2. **Keep your system updated**: `apt update && apt upgrade`
3. **Monitor logs regularly**: `mail-log errors`
4. **Check fail2ban**: `fail2ban-client status`
5. **Backup regularly**: `mail-backup`

## 📊 Multi-IP Configuration

To add additional IPs after installation:

```bash
# Add IP to system (if not already configured)
ip addr add 192.168.1.2/24 dev eth0

# Add to mail configuration
maildb add-ip 192.168.1.2

# Update DNS records for the new IP
# Add SPF record: ip4:192.168.1.2
```

## 🆘 Getting Help

1. **Check logs**: `/var/log/mail.log`
2. **Run diagnostics**: `sudo ./troubleshoot.sh`
3. **Test configuration**: `postfix check`
4. **Verify DNS**: `check-dns yourdomain.com`
5. **GitHub Issues**: [https://github.com/fumingtomato/shibi/issues](https://github.com/fumingtomato/shibi/issues)

## ✅ Installation Checklist

- [ ] Server with Ubuntu 20.04+ or Debian 10+
- [ ] Root or sudo access
- [ ] Domain name with DNS control
- [ ] Public IP address
- [ ] Port 25 unblocked (check with provider)
- [ ] At least 1GB RAM
- [ ] 10GB free disk space

## 📜 License

This project is open source and available under the MIT License.

## 🙏 Credits

Created by [@fumingtomato](https://github.com/fumingtomato)

Repository: [https://github.com/fumingtomato/shibi](https://github.com/fumingtomato/shibi)

---

**Version**: 16.0.2  
**Last Updated**: September 27, 2025  
**Status**: Production Ready

## 💡 Quick Tips

- Always test with `check-auth@verifier.port25.com` first
- Wait 5-30 minutes for DNS propagation
- Keep your server updated regularly
- Monitor your IP reputation on sites like MXToolbox
- Start with low volume when using new IPs (warmup)

## 🎯 One-Line Install

For the brave souls who want to run everything in one go:

```bash
curl -sSL https://raw.githubusercontent.com/fumingtomato/shibi/main/MultiIPMail/install.sh | sudo bash
```

**Note**: Always review scripts before running them with sudo!

---

**Enjoy your new mail server! 📧**
