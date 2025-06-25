# Ubuntu VPS Security Hardening - Complete Setup Guide

This guide provides a complete workflow for securely setting up and hardening a fresh Ubuntu VPS from initial access to full security hardening.

## 📋 Prerequisites

- Fresh Ubuntu VPS (18.04+ or Debian 12+)
- Root access (password-based initially)
- VNC or console access for emergency recovery
- SSH client on your local machine

## 🚀 Quick Start Workflow

### Step 1: Initial VPS Access
Connect to your fresh VPS as root:
```bash
ssh root@your-vps-ip
```

### Step 2: Download the Scripts
```bash
# Download both scripts to your VPS
wget https://raw.githubusercontent.com/your-repo/prepare_for_hardening.sh
wget https://raw.githubusercontent.com/your-repo/improved_harden_linux.sh

# Or upload them via SCP if you have them locally
# scp prepare_for_hardening.sh root@your-vps-ip:/root/
# scp improved_harden_linux.sh root@your-vps-ip:/root/

# Make scripts executable
chmod +x prepare_for_hardening.sh
chmod +x improved_harden_linux.sh
```

### Step 3: Run the Preparation Script
```bash
sudo ./prepare_for_hardening.sh
```

This script will:
- ✅ Create a new non-root user with sudo privileges
- ✅ Set up SSH key authentication
- ✅ Validate SSH key format and permissions
- ✅ Configure basic SSH security
- ✅ Test SSH key access
- ✅ Provide clear next steps

### Step 4: Test SSH Key Access
**CRITICAL**: Before proceeding, test SSH access in a new terminal:
```bash
ssh your-username@your-vps-ip
```
You should login without entering a password.

### Step 5: Switch to the New User
Logout from root and login as your new user:
```bash
exit  # logout from root
ssh your-username@your-vps-ip  # login as new user
```

### Step 6: Run the Main Hardening Script
```bash
sudo ./improved_harden_linux.sh
```

The hardening script will:
- ✅ Verify SSH key access before disabling password authentication
- ✅ Apply comprehensive security hardening
- ✅ Protect against lockouts with safety checks
- ✅ Create backups of all modified configurations

## 📝 What Each Script Does

### `prepare_for_hardening.sh`
**Purpose**: Prepares a fresh VPS for security hardening

**Features**:
- Creates a non-root user with sudo privileges
- Validates username (no reserved names, proper format)
- Sets up SSH key authentication with validation
- Provides clear instructions for SSH key generation
- Validates SSH public key format
- Sets proper file permissions (700 for .ssh, 600 for authorized_keys)
- Shows SSH key fingerprint for verification
- Tests SSH key access interactively
- Configures basic SSH security (disables root login)
- Provides step-by-step next instructions

**Safety Features**:
- Username validation against reserved names
- SSH key format validation
- Interactive testing of SSH access
- Backup of SSH configuration
- Clear error messages and troubleshooting tips

### `improved_harden_linux.sh`
**Purpose**: Comprehensive Ubuntu/Debian security hardening

**Key Safety Features**:
- Smart user detection (works with sudo)
- SSH key access verification before disabling password auth
- Comprehensive backup system
- Non-root user verification before disabling root
- Interactive prompts for potentially disruptive changes

## 🔐 SSH Key Setup Instructions

### On Your Local Machine

#### Generate SSH Key (Ed25519 - Recommended)
```bash
ssh-keygen -t ed25519 -C "your_email@example.com"
```

#### Or Generate RSA Key (More Compatible)
```bash
ssh-keygen -t rsa -b 4096 -C "your_email@example.com"
```

#### Display Your Public Key
```bash
# For Ed25519
cat ~/.ssh/id_ed25519.pub

# For RSA
cat ~/.ssh/id_rsa.pub
```

Copy the entire output (starts with `ssh-ed25519` or `ssh-rsa`) and paste it when the preparation script asks for your SSH public key.

## ⚠️ Important Safety Notes

### Before Running Scripts
1. **Always have VNC/console access** for emergency recovery
2. **Test SSH key access** before running the hardening script
3. **Keep a backup** of your SSH private key
4. **Note the server IP** and new username for future access

### During Execution
1. **Run preparation script as root**: `sudo ./prepare_for_hardening.sh`
2. **Test SSH access** in a new terminal before proceeding
3. **Run hardening script as the new user**: `sudo ./improved_harden_linux.sh`
4. **Never run hardening script as root**

### After Hardening
1. **SSH password authentication will be disabled**
2. **Root login will be disabled**
3. **Only SSH key authentication will work**
4. **Firewall will be enabled with limited access**

## 🛠️ Troubleshooting

### SSH Key Access Issues
```bash
# Check SSH service status
systemctl status ssh

# Check SSH configuration
sudo sshd -t

# Check file permissions
ls -la ~/.ssh/
ls -la ~/.ssh/authorized_keys

# Check SSH logs
sudo tail -f /var/log/auth.log
```

### Firewall Issues
```bash
# Check firewall status
sudo ufw status

# Allow SSH if blocked
sudo ufw allow ssh
```

### User Issues
```bash
# Check if user exists
id username

# Check sudo access
sudo -l
```

## 🔄 Recovery Options

### If Locked Out
1. **Use VNC/console access** to login locally
2. **Check SSH service**: `systemctl status ssh`
3. **Temporarily enable password auth**:
   ```bash
   sudo sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
   sudo systemctl restart ssh
   ```
4. **Fix SSH key issues** then re-disable password auth

### Restore from Backup
```bash
# The hardening script creates backups in /root/security_backup_*
sudo ./improved_harden_linux.sh --restore
```

## 📊 Security Features Applied

The complete setup provides:
- ✅ Non-root user with sudo access
- ✅ SSH key-only authentication
- ✅ Disabled root login
- ✅ UFW firewall with rate limiting
- ✅ Fail2Ban intrusion prevention
- ✅ System hardening (sysctl, kernel parameters)
- ✅ Audit logging
- ✅ AppArmor mandatory access control
- ✅ Automatic security updates
- ✅ Malware scanning (ClamAV)
- ✅ File integrity monitoring (AIDE)
- ✅ Comprehensive logging and monitoring

## 📞 Support

If you encounter issues:
1. Check the troubleshooting section above
2. Review the script logs in `/var/log/security_hardening.log`
3. Ensure you have VNC/console access for recovery
4. Test each step individually if automated process fails

## ⚖️ License

These scripts are provided as-is for educational and security hardening purposes. Always test in a non-production environment first. 