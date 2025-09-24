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

Download and run the main script:

```bash
wget https://raw.githubusercontent.com/fumingtomato/vm-host-hardener/main/harden-vm-host.sh
chmod +x harden-vm-host.sh
sudo ./harden-vm-host.sh
