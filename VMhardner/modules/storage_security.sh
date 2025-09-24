#!/bin/bash

# =================================================================
# SECTION 7: SECURE STORAGE AND PERMISSIONS
# =================================================================

secure_vm_storage() {
    print_header "VM Storage Security"
    
    # Find the VM storage directory
    VM_STORAGE_DIR=$(virsh pool-dumpxml default 2>/dev/null | grep -o '<path>.*</path>' | sed 's/<path>//g' | sed 's/<\/path>//g')
    
    if [ -z "$VM_STORAGE_DIR" ]; then
        print_warning "Default VM storage pool not found."
        print_message "Checking for common VM storage locations..."
        
        for dir in "/var/lib/libvirt/images" "/srv/vm" "/srv/vms"; do
            if [ -d "$dir" ]; then
                VM_STORAGE_DIR="$dir"
                print_message "Found VM storage directory: $VM_STORAGE_DIR"
                break
            fi
        done
        
        if [ -z "$VM_STORAGE_DIR" ]; then
            read -p "Enter your VM storage directory: " VM_STORAGE_DIR
            if [ ! -d "$VM_STORAGE_DIR" ]; then
                print_error "Directory $VM_STORAGE_DIR does not exist. Cannot secure VM storage."
                return
            fi
        fi
    else
        print_message "VM storage directory: $VM_STORAGE_DIR"
    fi
    
    # Secure permissions on VM storage
    print_message "Securing VM storage permissions..."
    
    # Check if directory is owned by proper user
    if [ "$(stat -c '%U' "$VM_STORAGE_DIR")" != "root" ] || [ "$(stat -c '%G' "$VM_STORAGE_DIR")" != "root" ]; then
        chown root:root "$VM_STORAGE_DIR"
        print_message "Changed ownership of $VM_STORAGE_DIR to root:root"
    fi
    
    # Ensure proper permissions
    chmod 750 "$VM_STORAGE_DIR"
    
    # Check for individual VM disk files and secure them
    print_message "Securing VM disk files..."
    find "$VM_STORAGE_DIR" -type f -name "*.qcow2" -o -name "*.img" | while read disk_file; do
        chmod 640 "$disk_file"
        print_message "Secured permissions for $disk_file"
    done
    
    # Enable disk encryption for new VMs
    read -p "Do you want to encrypt new VM disk images? (y/n): " encrypt_disks
    
    if [[ "$encrypt_disks" == "y" || "$encrypt_disks" == "Y" ]]; then
        print_message "Setting up VM disk encryption template..."
        
        # Create directory for templates if it doesn't exist
        mkdir -p /etc/libvirt/storage/
        
        # Create a template for encrypted disks
        cat > /etc/libvirt/storage/encrypted-disk.xml.template <<EOF
<volume>
  <name>DISK_NAME.qcow2</name>
  <capacity unit="G">20</capacity>
  <target>
    <format type="qcow2"/>
    <encryption format="luks">
      <secret type="passphrase" uuid="DISK_SECRET_UUID"/>
    </encryption>
    <permissions>
      <mode>0640</mode>
      <owner>0</owner>
      <group>0</group>
    </permissions>
  </target>
</volume>
EOF
        
        print_message "Created encrypted disk template at /etc/libvirt/storage/encrypted-disk.xml.template"
        print_message "To use encryption for new VMs, follow these steps:"
        print_message "1. Generate a new UUID: uuidgen"
        print_message "2. Create a secret: virsh secret-define-as --file /path/to/secret.xml"
        print_message "3. Set the secret value: virsh secret-set-value UUID --interactive"
        print_message "4. Use the template to create an encrypted disk"
        
        # Create a helper script for encryption
        cat > /usr/local/bin/create-encrypted-vm-disk <<EOF
#!/bin/bash
# Script to create an encrypted VM disk

if [ \$# -lt 2 ]; then
  echo "Usage: \$0 <disk-name> <size-in-GB>"
  exit 1
fi

DISK_NAME=\$1
DISK_SIZE=\$2
DISK_SECRET_UUID=\$(uuidgen)

# Create secret XML
cat > /tmp/secret.xml <<EOSECRET
<secret ephemeral='no' private='yes'>
  <uuid>\$DISK_SECRET_UUID</uuid>
  <usage type='volume'>
    <volume>\$DISK_NAME</volume>
  </usage>
</secret>
EOSECRET

# Define the secret
virsh secret-define --file /tmp/secret.xml

# Set the secret value (prompt for password)
echo "Enter encryption passphrase for \$DISK_NAME:"
read -s SECRET_PASS
echo "\$SECRET_PASS" | virsh secret-set-value \$DISK_SECRET_UUID --interactive

# Create disk XML from template
sed "s/DISK_NAME/\$DISK_NAME/g; s/DISK_SECRET_UUID/\$DISK_SECRET_UUID/g" \\
    /etc/libvirt/storage/encrypted-disk.xml.template > /tmp/disk.xml
sed -i "s/<capacity unit=\"G\">20<\/capacity>/<capacity unit=\"G\">\$DISK_SIZE<\/capacity>/" /tmp/disk.xml

# Create the volume
virsh vol-create default /tmp/disk.xml

# Clean up
rm -f /tmp/secret.xml /tmp/disk.xml

echo "Encrypted disk \$DISK_NAME created successfully with \$DISK_SIZE GB capacity."
echo "UUID: \$DISK_SECRET_UUID (save this for reference)"
EOF
        
        chmod +x /usr/local/bin/create-encrypted-vm-disk
        print_message "Created helper script: /usr/local/bin/create-encrypted-vm-disk"
    fi
}
