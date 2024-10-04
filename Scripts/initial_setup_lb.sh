#!/bin/bash

# Colors for output using tput
YELLOW=$(tput setaf 3)
GREEN=$(tput setaf 2)
RED=$(tput setaf 1)
RESET=$(tput sgr0)

# Function for formatted output
output_status() {
    local message=$1
    local status=$2
    local color=$3

    # Output the message and the status, right-aligned
    printf "%-65s [%b%s%b]\n" "$message" "$color" "$status" "$RESET"
}

# Set HostName and log the result
output_status "Setting hostname to 'load-balancing'" "In Progress" "$GREEN"
if hostnamectl set-hostname load-balancing; then
    output_status "Hostname set to 'load-balancing'" "Done" "$GREEN"
else
    output_status "Failed to set hostname" "Failed" "$RED"
    exit 1  # Exit if hostname setup fails
fi

# Check if the user "deploy" exists
if id "deploy" &>/dev/null; then
    output_status "User \"deploy\" already exists" "Skipped" "$YELLOW"
else
    output_status "Creating user \"deploy\"..." "Done" "$GREEN"
    useradd -m -s /bin/bash deploy
    usermod -aG sudo deploy
fi

# Check if user deploy is in sudoers
if sudo grep -q "^deploy ALL=(ALL) NOPASSWD: ALL" /etc/sudoers; then
    output_status "User deploy has already been added to sudoers" "Skipped" "$YELLOW"
else
    output_status "Adding user deploy to sudoers" "Done" "$GREEN"
    echo "deploy ALL=(ALL) NOPASSWD: ALL" | sudo tee -a /etc/sudoers >/dev/null
fi

# Check and configure SSH directory for deploy
output_status "Configuring SSH for the deploy user" "Done" "$GREEN"

SSH_DIR="/home/deploy/.ssh"
AUTH_KEYS_FILE="$SSH_DIR/authorized_keys"
SSH_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFkoAZCoYSs+Sy1FVN01PoSpmYTAdzNeyvjcWPtxTxo1 MySSHKey"

# Check if the .ssh directory exists
if [ ! -d "$SSH_DIR" ]; then
    mkdir -p "$SSH_DIR"                      # Create the .ssh directory
    chmod 700 "$SSH_DIR"                     # Set the correct permissions
    chown deploy:deploy "$SSH_DIR"           # Set the ownership
    output_status "Created .ssh directory for deploy" "Done" "$GREEN"
else
    output_status ".ssh directory for deploy already exists" "Skipped" "$YELLOW"
fi

# Check if the authorized_keys file exists
if [ ! -f "$AUTH_KEYS_FILE" ]; then
    touch "$AUTH_KEYS_FILE"                       # Create the authorized_keys file
    output_status "Created authorized_keys file for deploy" "Done" "$GREEN"
fi

# Check if the SSH key is already in the authorized_keys file
if ! grep -q "$SSH_KEY" "$AUTH_KEYS_FILE"; then
    echo "$SSH_KEY" >> "$AUTH_KEYS_FILE"           # Add the SSH key to the authorized_keys file
    output_status "Added SSH key to authorized_keys" "Done" "$GREEN"
else
    output_status "SSH key already exists in authorized_keys" "Skipped" "$YELLOW"
fi

# Ensure the correct permissions and ownership for the authorized_keys file
chmod 600 "$AUTH_KEYS_FILE"                         # Set correct permissions
chown deploy:deploy "$AUTH_KEYS_FILE"               # Set correct ownership
output_status "Set correct permissions and ownership for authorized_keys" "Done" "$GREEN"

# Update system packages
output_status "Updating system packages" "In Progress" "$GREEN"

# Attempt to update and upgrade packages with error logging
if apt-get update -qq > /dev/null 2>&1 && apt-get upgrade -y -qq > /dev/null 2>&1; then
    output_status "System packages updated" "Done" "$GREEN"
else
    output_status "Failed to update system packages (see update_error.log)" "Failed" "$RED"
    exit 1  # Exit the script if the update/upgrade fails
fi

# Install OpenVPN and necessary components
output_status "Installing OpenVPN and components" "In Progress" "$GREEN"
if apt-get install openvpn easy-rsa net-tools python3-venv dos2unix -y -qq > /dev/null 2>&1; then
    output_status "OpenVPN and components installed" "Done" "$GREEN"
else
    output_status "Failed to install OpenVPN and components" "Failed" "$RED"
    exit 1
fi

# Check if /root/work/ directory exists
WORK_DIR="/root/work"
if [ ! -d "$WORK_DIR" ]; then
    output_status "Creating /root/work directory..." "In Progress" "$GREEN"
    if mkdir -p "$WORK_DIR"; then
        output_status "/root/work directory created" "Done" "$GREEN"
    else
        output_status "Failed to create /root/work directory" "Failed" "$RED"
        exit 1
    fi
else
    output_status "/root/work directory already exists" "Skipped" "$YELLOW"
fi

# Check for OpenVPN key directory
OPENVPN_DIR="$WORK_DIR/openvpn-ca"
if [ -d "$OPENVPN_DIR" ]; then
    output_status "OpenVPN directory already exists" "Skipped" "$YELLOW"
else
    output_status "Creating OpenVPN directory..." "In Progress" "$GREEN"
    if command -v make-cadir >/dev/null 2>&1; then
        if make-cadir "$OPENVPN_DIR"; then
            output_status "OpenVPN directory created" "Done" "$GREEN"
        else
            output_status "Failed to create OpenVPN directory" "Failed" "$RED"
            exit 1
        fi
    else
        output_status "make-cadir command not found. Please install easy-rsa properly." "Failed" "$RED"
        exit 1
    fi
fi

# Move into directory
if cd "$OPENVPN_DIR"; then
    output_status "Navigated to OpenVPN directory" "Done" "$GREEN"
else
    output_status "Error: could not navigate to OpenVPN directory" "Failed" "$RED"
    exit 1
fi

# Backup the vars file and configure variables
output_status "Configuring variables for key generation" "In Progress" "$GREEN"
cp -rp "$(pwd)/vars" "$(pwd)/vars_orig"
cat <<EOF > "$(pwd)/vars"
export KEY_COUNTRY="UA"
export KEY_PROVINCE="Odessa"
export KEY_CITY="Chernomorsk"
export KEY_ORG="TestTask"
export KEY_EMAIL="support@testtask.com"
export KEY_OU="IT Department for Test Task"
export EASYRSA_REQ_CN="TestTask CA"
EOF
output_status "Variables configured" "Done" "$GREEN"
# Initialize PKI only if it does not exist
if [ ! -d "$OPENVPN_DIR/pki" ]; then
    output_status "Initializing PKI and creating CA" "In Progress" "$GREEN"
    printf "yes\n" | ./easyrsa init-pki > /dev/null 2>&1
    ./easyrsa --batch build-ca nopass > /dev/null 2>&1
    output_status "PKI initialized and CA created" "Done" "$GREEN"
else
    output_status "PKI already initialized" "Skipped" "$YELLOW"
fi

# Check if server certificate already exists
CERT_FILE="$OPENVPN_DIR/pki/issued/server-certificate.crt"
if [ -f "$CERT_FILE" ]; then
    output_status "Server certificate already exists, skipping generation" "Skipped" "$YELLOW"
else
    # Remove EASYRSA_REQ_CN variable before generating server certificate
    output_status "Removing EASYRSA_REQ_CN variable..." "In Progress" "$GREEN"
    if sed -i '/EASYRSA_REQ_CN/d' "$(pwd)/vars"; then
        output_status "EASYRSA_REQ_CN variable removed" "Done" "$GREEN"
    else
        output_status "Failed to remove EASYRSA_REQ_CN variable, continuing anyway" "Warning" "$YELLOW"
    fi

    # Generate server certificate
    output_status "Generating server certificate" "In Progress" "$GREEN"
    if ./easyrsa --batch build-server-full server-certificate nopass > /dev/null 2>&1; then
        output_status "Server certificate generated" "Done" "$GREEN"
    else
        output_status "Failed to generate server certificate, skipping this step" "Skipped" "$YELLOW"
    fi
fi

# Check for Diffie-Hellman parameters
output_status "Checking for Diffie-Hellman parameters" "In Progress" "$GREEN"
DH_FILE="/root/work/openvpn-ca/pki/dh.pem"

if [ -f "$DH_FILE" ]; then
    output_status "Diffie-Hellman parameters already exist" "Skipped" "$YELLOW"
else
    output_status "Generating Diffie-Hellman parameters (this may take a while)" "In Progress" "$GREEN"

    # Запускаем генерацию DH параметров
    ./easyrsa gen-dh > /dev/null 2>&1

    if [ $? -eq 0 ]; then
        output_status "Diffie-Hellman parameters generated" "Done" "$GREEN"
    else
        output_status "Failed to generate Diffie-Hellman parameters" "Failed" "$RED"
        exit 1
    fi
fi

# Create HMAC to protect from DoS attacks
HMAC_FILE="$OPENVPN_DIR/pki/ta.key"
if [ -f "$HMAC_FILE" ]; then
    output_status "HMAC file already exists, skipping creation" "Skipped" "$YELLOW"
else
    output_status "Creating HMAC for DoS protection" "In Progress" "$GREEN"
    if openvpn --genkey --secret "$HMAC_FILE"; then
        output_status "HMAC created" "Done" "$GREEN"
    else
        output_status "Failed to create HMAC" "Failed" "$RED"
        exit 1
    fi
fi

# Generate client key
output_status "Checking if client key already exists" "In Progress" "$GREEN"

REQ_FILE="/root/work/openvpn-ca/pki/reqs/deployssh.req"
KEY_FILE="/root/work/openvpn-ca/pki/private/deployssh.key"
CERT_FILE="/root/work/openvpn-ca/pki/issued/deployssh.crt"

# Check if the req, key, and cert files exist
if [ -f "$REQ_FILE" ] && [ -f "$KEY_FILE" ] && [ -f "$CERT_FILE" ]; then
    output_status "Client key already exists, skipping creation" "Skipped" "$YELLOW"
else
    output_status "Generating client key" "In Progress" "$GREEN"

    # Generate new client key
    if printf "yes\n" | ./easyrsa build-client-full deployssh nopass >/dev/null 2>&1; then
        output_status "Client key generated" "Done" "$GREEN"
    else
        output_status "Failed to generate client key" "Failed" "$RED"
        exit 1
    fi
fi

# Copy keys and certificates to OpenVPN directory
output_status "Copying keys and certificates to OpenVPN directory" "In Progress" "$GREEN"
if cp /root/work/openvpn-ca/pki/{issued/server-certificate.crt,private/server-certificate.key,ca.crt,dh.pem,ta.key} /etc/openvpn/; then
    output_status "Keys and certificates copied" "Done" "$GREEN"
else
    output_status "Failed to copy keys and certificates" "Failed" "$RED"
    exit 1
fi

# Create server configuration file for OpenVPN
output_status "Creating OpenVPN server configuration file" "In Progress" "$GREEN"
cat <<EOF > /etc/openvpn/server.conf
port 3194
proto tcp
dev tun
topology subnet
client-to-client
ca ca.crt
cert server-certificate.crt
key server-certificate.key
dh dh.pem
auth SHA256
tls-auth ta.key 0
server 172.21.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
client-config-dir /etc/openvpn/ccd
keepalive 10 120
cipher AES-256-CBC
persist-key
persist-tun
status openvpn-status.log
verb 3
EOF

if [ $? -eq 0 ]; then
    output_status "OpenVPN server configuration created" "Done" "$GREEN"
else
    output_status "Failed to create OpenVPN server configuration" "Failed" "$RED"
    exit 1
fi

# Create client configuration for OpenVPN
output_status "Checking if OpenVPN client configuration already exists" "In Progress" "$GREEN"
CONFIG_FILE="/etc/openvpn/ccd/deployssh"

# Check if the client configuration file already exists
if [ -f "$CONFIG_FILE" ]; then
    output_status "Client configuration already exists, skipping creation" "Skipped" "$YELLOW"
else
    # Create new client configuration file
    output_status "Creating OpenVPN client configuration" "In Progress" "$GREEN"
    mkdir -p /etc/openvpn/ccd

    if touch "$CONFIG_FILE"; then
        output_status "New client configuration created" "Done" "$GREEN"
    else
        output_status "Failed to create new client configuration" "Failed" "$RED"
        exit 1
    fi

    # Write client-specific configuration
    if echo "ifconfig-push 172.21.0.2 255.255.255.0" > "$CONFIG_FILE"; then
        output_status "Client configuration set up" "Done" "$GREEN"
    else
        output_status "Failed to set up client configuration" "Failed" "$RED"
        exit 1
    fi
fi

# Start OpenVPN service and enable it to start on boot
output_status "Checking OpenVPN server status..." "In Progress" "$GREEN"

# Check if the service is running
if systemctl is-active --quiet openvpn@server; then
    output_status "OpenVPN service is already running" "Skipped" "$YELLOW"
else
    output_status "OpenVPN service is not running. Starting..." "In Progress" "$GREEN"
    if systemctl start openvpn@server > /dev/null 2>&1; then
        output_status "OpenVPN service started" "Done" "$GREEN"
    else
        output_status "Failed to start OpenVPN service" "Failed" "$RED"
        exit 1
    fi
fi

# Check if OpenVPN service is enabled to start on boot
if systemctl is-enabled --quiet openvpn@server; then
    output_status "OpenVPN service is already enabled at startup" "Skipped" "$YELLOW"
else
    output_status "Enabling OpenVPN service at startup" "In Progress" "$GREEN"
    if systemctl enable openvpn@server > /dev/null 2>&1; then
        output_status "OpenVPN service enabled at startup" "Done" "$GREEN"
    else
        output_status "Failed to enable OpenVPN service at startup" "Failed" "$RED"
        exit 1
    fi
fi

# Enable traffic forwarding
output_status "Configuring traffic forwarding..." "In Progress" "$GREEN"
sed -i '/net.ipv4.ip_forward=1/d' /etc/sysctl.conf
echo "net.ipv4.ip_forward=1" | tee -a /etc/sysctl.conf > /dev/null 2>&1
sysctl -p > /dev/null 2>&1
output_status "Traffic forwarding configured" "Done" "$GREEN"

# Create OpenVPN client configuration
output_status "Creating OpenVPN client configuration..." "In Progress" "$GREEN"
CLIENT_NAME="deployssh"
CONFIG_DIR="/root/client-configs"
OUTPUT_FILE="$CONFIG_DIR/$CLIENT_NAME.ovpn"
CA_CERT="/root/work/openvpn-ca/pki/ca.crt"
CLIENT_CERT="/root/work/openvpn-ca/pki/issued/$CLIENT_NAME.crt"
CLIENT_KEY="/root/work/openvpn-ca/pki/private/$CLIENT_NAME.key"
TA_KEY="/root/work/openvpn-ca/pki/ta.key"
MAIN_IP=$(curl -s ifconfig.me)

mkdir -p "$CONFIG_DIR"
cat <<EOF > "$OUTPUT_FILE"
client
dev tun
proto tcp
remote $MAIN_IP 3194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA256
cipher AES-256-CBC
key-direction 1
verb 3

<ca>
$(cat $CA_CERT)
</ca>

<cert>
$(cat $CLIENT_CERT)
</cert>

<key>
$(cat $CLIENT_KEY)
</key>

<tls-auth>
$(cat $TA_KEY)
</tls-auth>
EOF

output_status "OpenVPN client configuration created" "Done" "$GREEN"

# SSH and UFW configuration
output_status "Configuring SSH and UFW..." "In Progress" "$GREEN"
apt-get install ufw -y -qq > /dev/null 2>&1

# Change SSH port to 7856 if not already changed
if ! grep -q "^Port 7856" /etc/ssh/sshd_config; then
    output_status "Changing SSH port to 7856..." "In Progress" "$GREEN"
    sed -i 's/^#Port 22/Port 7856/' /etc/ssh/sshd_config
    output_status "SSH port changed to 7856" "Done" "$GREEN"
else
    output_status "SSH port is already set to 7856" "Skipped" "$YELLOW"
fi

# Check and add SSH access restriction for 172.21.0.0/24
if ! grep -q "^Match Address 172.21.0.0/24" /etc/ssh/sshd_config; then
    output_status "Adding SSH access restriction for subnet 172.21.0.0/24" "In Progress" "$GREEN"
    echo "Match Address 172.21.0.0/24" >> /etc/ssh/sshd_config
    echo "    PermitRootLogin no" >> /etc/ssh/sshd_config
    echo "    PasswordAuthentication no" >> /etc/ssh/sshd_config
    echo "    AllowUsers deploy" >> /etc/ssh/sshd_config
    output_status "SSH access restriction added" "Done" "$GREEN"
else
    output_status "SSH access restriction for subnet 172.21.0.0/24 already exists" "Skipped" "$YELLOW"
fi

# UFW firewall rules
ufw allow from 172.21.0.0/24 to any port 7856 > /dev/null 2>&1
ufw allow 3194/udp > /dev/null 2>&1
ufw allow 443 > /dev/null 2>&1
ufw deny 22 > /dev/null 2>&1
output_status "Allow inbound connections for 443, 3194 (UDP), and 7856 ports" "Done" "$GREEN"

# Disable ssh.socket and restart SSH and UFW
output_status "Disabling ssh.socket and restarting SSH and UFW..." "In Progress" "$GREEN"
systemctl stop ssh.socket > /dev/null 2>&1
systemctl disable ssh.socket > /dev/null 2>&1
systemctl restart ssh > /dev/null 2>&1

ufw enable --force enable > /dev/null 2>&1
output_status "UFW enabled and configured" "Done" "$GREEN"

# Final message
echo ""
output_status "Setup completed successfully!" "Done" "$GREEN"

echo ""
echo "You may find the VPN file to connect to the LoadBalancing server here: /root/client-configs/deployssh.ovpn"
