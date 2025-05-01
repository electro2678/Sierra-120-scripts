#!/bin/bash

# Please read through this script! It is not very long, but you should understand what is being configured on here.

if ! grep -qi 'debian\|ubuntu' /etc/os-release; then
    echo "[-] Unsupported distro. This script is built for Debian-based systems only. Change configs for dnf/yum if CentOS/RHEL/Fedora, and swap UFW for firewalld. Then remove this part."
    exit 1
fi

# Requires root.
if [ "$EUID" -ne 0 ]; then
    echo "Run as root, choomba."
    exit 1
fi

# Logging.
LOGFILE="/var/log/system-hardening.log"
exec > >(tee -a "$LOGFILE") 2>&1
echo "[*] Logging to $LOGFILE"

if [[ -f "$LOGFILE" ]]; then
    chmod 600 "$LOGFILE"
    chown root:root "$LOGFILE"
fi


echo "===> Updating system..."
apt update && apt upgrade -y

# If using non-standard ports, replace OpenSSH with the port. Example: ufw allow (port number)/tcp. Make sure you change the /etc/ssh/sshd_config if using a non-standard port as well. 
echo "===> Setting up UFW (Uncomplicated Firewall)..."
apt install -y ufw
ufw default deny incoming
ufw default allow outgoing
ufw allow OpenSSH
ufw enable

echo "===> Disabling root SSH login..."
sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config

echo "===> Enforcing SSH protocol v2 only..."
sed -i 's/^#Protocol .*/Protocol 2/' /etc/ssh/sshd_config

echo "===> Disabling password authentication over SSH..."
sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config

echo "===> Restarting SSH daemon..."
systemctl restart ssh

# Faill2Ban is a daemon that scans log files and blocks those who repeatedly fail authentication.
echo "===> Installing Fail2Ban..."
apt install -y fail2ban
systemctl enable fail2ban
systemctl start fail2ban

echo "===> Setting up automatic security updates..."
apt install -y unattended-upgrades
dpkg-reconfigure -plow unattended-upgrades

echo "===> Removing unnecessary packages..."
apt autoremove -y

echo "===> Setting permissions on /boot..."
chmod -R go-rwx /boot

echo "===> Done. Reboot recommended."

