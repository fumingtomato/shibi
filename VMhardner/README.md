# VM Host Hardener

A comprehensive security hardening script for Ubuntu 24.04 LTS hosts running KVM/libvirt virtual machines.

## Overview

This script automates the hardening of VM host systems, particularly for setups where virtual machines have external IPs.
It's designed to work with existing mail and web server VMs and provides multiple layers of security hardening.

## Features

- Initial system and virtualization checks
- System updates and security package installation
- SSH hardening and secure user management
- Firewall configuration for VM environments
- libvirt/QEMU security hardening
- VM resource controls and isolation
- Network security for VM traffic
- Storage security including encryption options
- System monitoring and auditing
- VM backup automation
- Kernel hardening
- Comprehensive security reporting

## Requirements

- Ubuntu 24.04 LTS (may work on other versions but not tested)
- Root or sudo privileges
- Working internet connection (for downloads and updates)
- KVM/libvirt virtualization environment

## Installation

Download and run the installer script:

```bash
wget https://raw.githubusercontent.com/fumingtomato/shibi/main/VMhardner/install.sh
chmod +x install.sh
sudo ./install.sh
```

The installer will automatically download all necessary files and install them to `/opt/vm-host-hardener/`.

## Usage

After installation, run the hardening script:

```bash
sudo vm-hardener
```

### Command Options

- `sudo vm-hardener --help` - Display help information
- `sudo vm-hardener --check` - Verify all required files are present
- `sudo vm-hardener --version` - Display version information
- `sudo vm-hardener` - Run the full hardening process

## Configuration

The configuration file is located at `/opt/vm-host-hardener/config/settings.conf`. You can modify this file before running the hardening script to customize the settings.

Key configuration options include:
- SSH port and authentication settings
- Firewall rules
- Backup locations and retention
- VM resource limits
- Monitoring intervals

## What the Script Does

1. **System Checks** - Verifies KVM/libvirt installation and detects existing VMs
2. **System Updates** - Installs security updates and essential security packages
3. **SSH Hardening** - Configures secure SSH settings and creates VM admin user
4. **Firewall Setup** - Configures UFW with appropriate rules for VM hosting
5. **Libvirt Hardening** - Secures libvirt/QEMU configuration
6. **VM Resources** - Sets up resource controls and OOM protection
7. **Network Security** - Configures VM network isolation and traffic filtering
8. **Storage Security** - Secures VM storage permissions and offers encryption
9. **Monitoring** - Sets up system auditing and VM monitoring
10. **Backups** - Configures automated VM backups
11. **Kernel Hardening** - Applies kernel security parameters
12. **Security Report** - Generates comprehensive security report

## Post-Installation

After running the hardening script:

1. Review the security report at `/root/vm-host-security-report.txt`
2. Restart the system to ensure all security settings are applied
3. Test SSH access with the new configuration
4. Verify your VMs are still accessible and functioning properly

## Logs and Reports

- Main log file: `/var/log/vm-host-hardening.log`
- Security report: `/root/vm-host-security-report.txt`
- VM monitor logs: `/var/log/vm-monitor-*.log`
- Backup logs: `/var/log/vm-backup.log`

## Uninstallation

To remove the VM Host Hardener:

```bash
sudo rm -rf /opt/vm-host-hardener
sudo rm -f /usr/local/bin/vm-hardener
```

Note: This will not undo the hardening changes made to your system.

## Support

For issues, questions, or contributions, please visit:
https://github.com/fumingtomato/shibi

## License

This project is open source and available under the MIT License.
