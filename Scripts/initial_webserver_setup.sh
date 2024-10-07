#!/bin/bash

# Function to print messages in color
print_color() {
    case $2 in
        "yellow") echo -e "\e[33m$1\e[0m" ;;
        "green") echo -e "\e[32m$1\e[0m" ;;
        "red") echo -e "\e[31m$1\e[0m" ;;
        "purple") echo -e "\e[35m$1\e[0m" ;;
        "cyan") echo -e "\e[36m$1\e[0m" ;;
        *) echo "$1" ;;
    esac
}

# Setting the hostname
print_color "Setup HostName:" "yellow"
read -p "Enter new Hostname: " NEW_HOSTNAME
hostnamectl set-hostname "$NEW_HOSTNAME"
if [ $? -eq 0 ]; then
    print_color "Hostname was successfully set to $NEW_HOSTNAME" "green"
else
    print_color "Failed to set hostname. Please check the input or permissions." "red"
fi

print_color "" "none" # Blank line

# Creating deploy user
print_color "Creating 'deploy' user" "yellow"
if id "deploy" &>/dev/null; then
    print_color "User 'deploy' already exists" "purple"
else
    useradd -m -s /bin/bash deploy && usermod -aG sudo deploy
    if [ $? -eq 0 ]; then
        print_color "User 'deploy' created and added to sudo group" "green"
    else
        print_color "Failed to create user 'deploy'" "red"
    fi
fi
print_color "" "none" # Blank line

# Adding sudoers entry for 'deploy' user without password
print_color "Adding sudo privileges for deploy user without password" "yellow"
echo "deploy ALL=(ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/deploy > /dev/null
if [ $? -eq 0 ]; then
    print_color "Sudo privileges for deploy user added successfully" "green"
else
    print_color "Failed to add sudo privileges for deploy user" "red"
fi

print_color "" "none" # Blank line

# Preparing directory for SSH keys
print_color "Prepare directory structure to add public key" "yellow"
mkdir -p /home/deploy/.ssh && chmod 700 /home/deploy/.ssh && chown deploy:deploy /home/deploy/.ssh
touch /home/deploy/.ssh/authorized_keys && chmod 600 /home/deploy/.ssh/authorized_keys && chown deploy:deploy /home/deploy/.ssh/authorized_keys

print_color "" "none" # Blank line

# Configuring Firewall and SSH
print_color "Configure Default Firewall Rules and SSH settings" "yellow"
apt update &>/dev/null
apt install ufw net-tools -y &>/dev/null

# Configuring SSH
sed -i 's/^#Port 22/Port 7856/' /etc/ssh/sshd_config && echo "AllowUsers deploy@172.21.0.0/24 deploy@185.247.20.223/32" >> /etc/ssh/sshd_config
ufw allow from 172.21.0.0/24 to any port 7856 > /dev/null 2>&1
ufw allow from 185.247.20.223/32 to any port 7856 > /dev/null 2>&1
ufw deny 22

# Restarting SSH and enabling UFW
systemctl stop ssh.socket
systemctl disable ssh.socket
systemctl restart ssh
ufw --force enable > /dev/null 2>&1

if [ $? -eq 0 ]; then
    print_color "Firewall and SSH settings configured successfully" "green"
else
    print_color "Failed to configure Firewall or SSH" "red"
fi

print_color "" "none" # Blank line

# Configuring OpenVPN client
print_color "Configure OpenVPN client" "yellow"
apt install openvpn -y &>/dev/null
mkdir -p /etc/openvpn/client/
touch /etc/openvpn/client/$(uname -n).ovpn
ln -s /etc/openvpn/client/$(uname -n).ovpn /etc/openvpn/client/client.conf

# Regular system updates
print_color "Configuring automatic system updates" "yellow"

# Creating script for auto-updates
cat <<EOF >/usr/local/bin/auto-update.sh
#!/bin/bash
apt-get update -qq
apt-get upgrade -y -qq
apt-get autoremove -y -qq
apt-get autoclean -qq
EOF

# Making the script executable
chmod +x /usr/local/bin/auto-update.sh

# Adding the script to cron for daily execution at 3 AM
(crontab -l 2>/dev/null; echo "0 3 * * * /usr/local/bin/auto-update.sh >> /var/log/auto-update.log 2>&1") | crontab -

if [ $? -eq 0 ]; then
    print_color "Automatic updates configured successfully" "green"
else
    print_color "Failed to configure automatic updates" "red"
fi

print_color "" "none" # Blank line

# Instructions for copying keys and configuration
print_color "" "none" # Blank line
print_color "Please copy SSH public key from /home/deploy/.ssh/id_rsa.pub on the LoadBalancing server to /home/deploy/.ssh/authorized_keys" "yellow"
print_color "" "none" # Blank line
print_color "Please copy OpenVPN configuration file from /root/client-configs/$(uname -n).ovpn on the LoadBalancing server to /etc/openvpn/client/$(uname -n).ovpn" "yellow"
print_color "" "none" # Blank line
print_color "Please do not forget to start and enable the OpenVPN client service" "cyan"
print_color "systemctl start openvpn-client@client.service; systemctl enable openvpn-client@client.service" "cyan"
