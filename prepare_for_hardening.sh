#!/bin/bash

# Preparation Script for Ubuntu VPS Hardening
# This script prepares a fresh Ubuntu VPS for security hardening
# Run this BEFORE running the main hardening script

VERSION="1.0"
SCRIPT_NAME=$(basename "$0")

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}$1${NC}"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "This preparation script must be run as root."
        echo "Please run: sudo $0"
        exit 1
    fi
}

display_help() {
    echo "Ubuntu VPS Hardening Preparation Script v$VERSION"
    echo ""
    echo "Usage: sudo ./$SCRIPT_NAME [OPTIONS]"
    echo ""
    echo "This script prepares a fresh Ubuntu VPS for security hardening by:"
    echo "  - Creating a non-root user with sudo privileges"
    echo "  - Setting up SSH key authentication"
    echo "  - Configuring basic security settings"
    echo ""
    echo "Options:"
    echo "  -h, --help     Display this help message"
    echo "  --version      Display script version"
    echo ""
    echo "After running this script, logout and login as the new user,"
    echo "then run the main hardening script."
    exit 0
}

display_version() {
    echo "Ubuntu VPS Hardening Preparation Script v$VERSION"
    exit 0
}

validate_username() {
    local username="$1"
    
    # Check if username is valid (alphanumeric, underscore, hyphen)
    if [[ ! "$username" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        print_error "Invalid username. Use only letters, numbers, underscores, and hyphens."
        return 1
    fi
    
    # Check if username is not too long
    if [ ${#username} -gt 32 ]; then
        print_error "Username too long. Maximum 32 characters."
        return 1
    fi
    
    # Check if user already exists
    if id "$username" &>/dev/null; then
        print_error "User '$username' already exists."
        return 1
    fi
    
    # Check if username is not a system reserved name
    local reserved_names=("root" "daemon" "bin" "sys" "sync" "games" "man" "lp" "mail" "news" "uucp" "proxy" "www-data" "backup" "list" "irc" "gnats" "nobody" "systemd-network" "systemd-resolve" "syslog" "messagebus" "uuidd" "dnsmasq" "usbmux" "rtkit" "cups-pk-helper" "speech-dispatcher" "avahi" "saned" "colord" "hplip" "geoclue" "pulse" "gdm" "systemd-coredump")
    
    for reserved in "${reserved_names[@]}"; do
        if [ "$username" = "$reserved" ]; then
            print_error "Username '$username' is reserved. Please choose a different name."
            return 1
        fi
    done
    
    return 0
}

validate_ssh_key() {
    local key="$1"
    
    # Check if key starts with valid SSH key types
    if [[ ! "$key" =~ ^(ssh-rsa|ssh-dss|ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521) ]]; then
        print_error "Invalid SSH key format. Key must start with ssh-rsa, ssh-ed25519, etc."
        return 1
    fi
    
    # Check if key has at least 3 parts (type, key, comment)
    local key_parts=$(echo "$key" | wc -w)
    if [ "$key_parts" -lt 2 ]; then
        print_error "SSH key appears incomplete. It should have at least key type and key data."
        return 1
    fi
    
    # Try to validate the key format using ssh-keygen
    local temp_key="/tmp/temp_validate_key_$$"
    echo "$key" > "$temp_key"
    
    if ssh-keygen -lf "$temp_key" &>/dev/null; then
        rm -f "$temp_key"
        return 0
    else
        rm -f "$temp_key"
        print_error "SSH key validation failed. Please check the key format."
        return 1
    fi
}

create_user() {
    local username="$1"
    
    print_status "Creating user '$username'..."
    
    # Create user with home directory
    adduser --gecos "" "$username" || {
        print_error "Failed to create user '$username'"
        return 1
    }
    
    # Add user to sudo group
    usermod -aG sudo "$username" || {
        print_error "Failed to add user '$username' to sudo group"
        return 1
    }
    
    print_status "User '$username' created successfully and added to sudo group"
    return 0
}

setup_ssh_key() {
    local username="$1"
    local user_home="/home/$username"
    local ssh_dir="$user_home/.ssh"
    local authorized_keys="$ssh_dir/authorized_keys"
    
    print_header "=== SSH Key Setup ==="
    echo ""
    echo "To secure your VPS, you need to set up SSH key authentication."
    echo ""
    echo "If you don't have an SSH key pair yet, run this command on your LOCAL machine:"
    echo ""
    echo -e "${BLUE}ssh-keygen -t ed25519 -C \"your_email@example.com\"${NC}"
    echo ""
    echo "Then display your public key with:"
    echo -e "${BLUE}cat ~/.ssh/id_ed25519.pub${NC}"
    echo ""
    echo "Or if you prefer RSA (older but more compatible):"
    echo -e "${BLUE}ssh-keygen -t rsa -b 4096 -C \"your_email@example.com\"${NC}"
    echo -e "${BLUE}cat ~/.ssh/id_rsa.pub${NC}"
    echo ""
    
    # Create SSH directory
    print_status "Creating SSH directory for user '$username'..."
    sudo -u "$username" mkdir -p "$ssh_dir" || {
        print_error "Failed to create SSH directory"
        return 1
    }
    
    # Set proper permissions
    sudo -u "$username" chmod 700 "$ssh_dir" || {
        print_error "Failed to set SSH directory permissions"
        return 1
    }
    
    # Get public key from user
    echo ""
    echo "Please paste your SSH PUBLIC key below:"
    echo "(It should start with ssh-rsa, ssh-ed25519, etc.)"
    echo ""
    read -r -p "SSH Public Key: " ssh_public_key
    
    # Validate the key
    if ! validate_ssh_key "$ssh_public_key"; then
        print_error "Invalid SSH key provided"
        return 1
    fi
    
    # Add key to authorized_keys
    print_status "Adding SSH key to authorized_keys..."
    echo "$ssh_public_key" | sudo -u "$username" tee "$authorized_keys" > /dev/null || {
        print_error "Failed to write SSH key to authorized_keys"
        return 1
    }
    
    # Set proper permissions
    sudo -u "$username" chmod 600 "$authorized_keys" || {
        print_error "Failed to set authorized_keys permissions"
        return 1
    }
    
    print_status "SSH key added successfully"
    
    # Display key fingerprint for verification
    print_status "Verifying SSH key..."
    local fingerprint=$(ssh-keygen -lf "$authorized_keys" 2>/dev/null | awk '{print $2}')
    if [ -n "$fingerprint" ]; then
        print_status "SSH key fingerprint: $fingerprint"
        echo ""
        echo "Please verify this fingerprint matches your local key:"
        echo -e "${BLUE}ssh-keygen -lf ~/.ssh/id_ed25519.pub${NC} (or id_rsa.pub)"
        echo ""
    else
        print_warning "Could not generate fingerprint for verification"
    fi
    
    return 0
}

test_ssh_access() {
    local username="$1"
    
    print_header "=== SSH Access Test ==="
    echo ""
    echo "Testing SSH key authentication..."
    echo ""
    echo "Please open a NEW terminal/SSH session and try to connect:"
    echo -e "${BLUE}ssh $username@$(hostname -I | awk '{print $1}')${NC}"
    echo ""
    echo "You should be able to login without entering a password."
    echo ""
    read -p "Were you able to login successfully with SSH keys? (y/N): " ssh_test_result
    
    case $ssh_test_result in
        [Yy]* )
            print_status "SSH key authentication confirmed working!"
            return 0
            ;;
        * )
            print_warning "SSH key authentication test failed or not confirmed"
            echo ""
            echo "Please check:"
            echo "1. SSH service is running: systemctl status ssh"
            echo "2. Firewall allows SSH: ufw status"
            echo "3. SSH key permissions are correct"
            echo "4. You're using the correct private key"
            echo ""
            echo "You can continue, but ensure SSH key access works before running the hardening script."
            return 1
            ;;
    esac
}

configure_basic_ssh() {
    print_status "Configuring basic SSH security..."
    
    # Backup original SSH config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d_%H%M%S) || {
        print_error "Failed to backup SSH config"
        return 1
    }
    
    # Ensure SSH is configured properly but don't disable password auth yet
    # (The main hardening script will handle that with proper verification)
    
    # Disable root login via SSH (this is safe to do now)
    sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    
    # Ensure SSH protocol 2
    if ! grep -q "^Protocol 2" /etc/ssh/sshd_config; then
        echo "Protocol 2" >> /etc/ssh/sshd_config
    fi
    
    # Test SSH configuration
    if sshd -t; then
        print_status "SSH configuration test passed"
        systemctl restart ssh || {
            print_error "Failed to restart SSH service"
            return 1
        }
        print_status "SSH service restarted successfully"
    else
        print_error "SSH configuration test failed"
        return 1
    fi
    
    return 0
}

display_final_instructions() {
    local username="$1"
    
    print_header "=== Preparation Complete! ==="
    echo ""
    print_status "VPS preparation completed successfully!"
    echo ""
    echo "Next steps:"
    echo "1. ${YELLOW}IMPORTANT:${NC} Test SSH key access in a new terminal:"
    echo "   ${BLUE}ssh $username@$(hostname -I | awk '{print $1}')${NC}"
    echo ""
    echo "2. Once confirmed working, logout from root and login as '$username'"
    echo ""
    echo "3. Run the main hardening script as the new user:"
    echo "   ${BLUE}sudo ./improved_harden_linux.sh${NC}"
    echo ""
    echo "4. The hardening script will:"
    echo "   - Verify your SSH key access before disabling password auth"
    echo "   - Apply comprehensive security hardening"
    echo "   - Keep you safe from lockouts"
    echo ""
    print_warning "Do NOT run the hardening script as root!"
    print_warning "Always test SSH key access before proceeding!"
    echo ""
}

# Main execution logic
main() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                display_help
                ;;
            --version)
                display_version
                ;;
            *)
                echo "Unknown option: $1"
                display_help
                ;;
        esac
    done

    check_root
    
    print_header "========================================"
    print_header "Ubuntu VPS Hardening Preparation Script"
    print_header "========================================"
    echo ""
    
    # Get username
    while true; do
        read -p "Enter username for the new sudo user: " username
        if validate_username "$username"; then
            break
        fi
        echo ""
    done
    
    # Create user
    if ! create_user "$username"; then
        print_error "Failed to create user. Exiting."
        exit 1
    fi
    
    echo ""
    
    # Setup SSH key
    if ! setup_ssh_key "$username"; then
        print_error "Failed to setup SSH key. Exiting."
        exit 1
    fi
    
    echo ""
    
    # Configure basic SSH security
    if ! configure_basic_ssh; then
        print_error "Failed to configure SSH security. Exiting."
        exit 1
    fi
    
    echo ""
    
    # Test SSH access
    test_ssh_access "$username"
    
    echo ""
    
    # Display final instructions
    display_final_instructions "$username"
}

# Run the main function
main "$@" 