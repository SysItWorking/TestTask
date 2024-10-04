#!/bin/bash

# Define function to request confirmation
confirm() {
    read -r -p "${1} [y/N]: " response
    case "$response" in
        [yY][eE][sS]|[yY])
            true
            ;;
        *)
            false
            ;;
    esac
}

# Function to create backups of files before deletion
backup_file() {
    local file=$1
    local backup_dir=$2
    if [ -f "$file" ]; then
        mkdir -p "$backup_dir"
        cp "$file" "$backup_dir"
    fi
}

# Remove EASYRSA_REQ_CN variable to avoid conflict
VARS_FILE="/root/work/openvpn-ca/vars"
if grep -q "EASYRSA_REQ_CN" "$VARS_FILE"; then
    echo "Removing EASYRSA_REQ_CN variable to avoid conflict..."
    sed -i '/EASYRSA_REQ_CN/d' "$VARS_FILE"
    echo "EASYRSA_REQ_CN variable removed."
fi

# Define the main configuration files of our OpenVPN server
CONFIG_DIR="/root/client-configs"
CCD_DIR="/etc/openvpn/ccd"
BASE_IP="172.21.0."
SUBNET_MASK="255.255.255.0"
MAIN_IP=$(curl -s ifconfig.me)

# Set Client Name for our new certificate
read -p "Please enter the certificate client name (for example - webserver1): " CLIENT_NAME
OUTPUT_FILE="$CONFIG_DIR/$CLIENT_NAME.ovpn"
CA_CERT="/root/work/openvpn-ca/pki/ca.crt"
CLIENT_CERT="/root/work/openvpn-ca/pki/issued/$CLIENT_NAME.crt"
CLIENT_KEY="/root/work/openvpn-ca/pki/private/$CLIENT_NAME.key"
TA_KEY="/root/work/openvpn-ca/pki/ta.key"
CCD_FILE="$CCD_DIR/$CLIENT_NAME"
REQ_FILE="/root/work/openvpn-ca/pki/reqs/$CLIENT_NAME.req"
BACKUP_DIR="/root/work/openvpn-ca/backups/$CLIENT_NAME/$(date +'%Y%m%d_%H%M%S')"

# Check if the certificate with the same name has already present in the system
if [ -f "$CLIENT_CERT" ] || [ -f "$CLIENT_KEY" ]; then
    if confirm "Certificate already exists for $CLIENT_NAME. Do you want to regenerate it?"; then
        echo "Regenerating the certificate..."

        # Backup and remove the request, key, and certificate files
        backup_file "$REQ_FILE" "$BACKUP_DIR"
        rm -f "$REQ_FILE"

        backup_file "$CLIENT_KEY" "$BACKUP_DIR"
        rm -f "$CLIENT_KEY"

        backup_file "$CLIENT_CERT" "$BACKUP_DIR"
        rm -f "$CLIENT_CERT"

        # Generate a new certificate
        cd /root/work/openvpn-ca || exit
        ./easyrsa build-client-full "$CLIENT_NAME" nopass

        echo -e "\e[32mBackup of removed files you can find here: $BACKUP_DIR\e[0m"
    else
        echo "Aborting the script. Please choose a different client name."
        exit 0
    fi
else
    # Generate a new certificate if it doesn't exist
    echo "Generating a new certificate for the client $CLIENT_NAME..."
    cd /root/work/openvpn-ca || exit
    ./easyrsa build-client-full "$CLIENT_NAME" nopass
fi

# Check if the certificate has been created successfully
if [ ! -f "$CLIENT_CERT" ] || [ ! -f "$CLIENT_KEY" ]; then
    echo "Error: Certificate or key for client $CLIENT_NAME not found."
    exit 1
fi

# Find the first available IP address
NEW_IP=""
for i in $(seq 2 254); do
    if ! grep -rq "$BASE_IP$i" "$CCD_DIR"; then
        NEW_IP=$i
        break
    fi
done

# Check if a free IP has been found
if [ -z "$NEW_IP" ]; then
    echo "Error: No available IP addresses."
    exit 1
fi

# Check if the file with the IP address is present in the CCD directory
if [ -f "$CCD_FILE" ]; then
    if confirm "CCD file for $CLIENT_NAME already exists. Do you want to overwrite it?"; then
        echo "Overwriting CCD file with the same IP..."
    else
        echo "Keeping existing CCD file."
        NEW_IP=$(grep -oP '(?<=ifconfig-push )\d+\.\d+\.\d+\.\d+' "$CCD_FILE" | awk -F. '{print $4}')
        echo "Keeping the IP $BASE_IP$NEW_IP from the existing CCD file."
    fi
else
    echo "Assigning IP $BASE_IP$NEW_IP to client $CLIENT_NAME..."
    mkdir -p "$CCD_DIR"
    cat <<EOF > "$CCD_FILE"
ifconfig-push $BASE_IP$NEW_IP $SUBNET_MASK
EOF
fi

# Creating a Configuration for the OpenVPN Client
mkdir -p "$CONFIG_DIR"
echo "Generating configuration file for client $CLIENT_NAME..."
cat <<EOF > "$OUTPUT_FILE"
client
dev tun
proto udp
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

echo ""
echo -e "\e[32mConfiguration file created: $OUTPUT_FILE\e[0m"
echo -e "\e[32mCCD file created or updated: $CCD_FILE with IP $BASE_IP$NEW_IP\e[0m"
