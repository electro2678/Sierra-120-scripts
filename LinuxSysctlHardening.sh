#!/bin/bash

# PLEASE!!!!! READ THE COMMANDS AND WHAT THEY DO!!!
# Some of them may disable some critical services depending on the machines usage, which you may want enabled either way.

# This script checks services and abilities of a machine to detect whether it's a router, service node, or dev box.
# Created because some of these configs could disable some critical services depending on the purpose of the machine.
# Run this as root choom.

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root." >&2
    exit 1
fi

if [[ "$1" == "--dry-run" ]]; then
    echo "[*] Dry run mode: Configuration would be written to /etc/sysctl.d/99-custom-hardening.conf"
    echo "[*] No changes have been made."
    exit 0
fi

LOGFILE="/var/log/sysctl-hardening.log"
exec > >(tee -a "$LOGFILE") 2>&1
echo "[*] Logging to $LOGFILE"

echo "===> Scanning environment..."

# Detect multiple interfaces with IPs (possible router/multi-homed)
nic_count=$(ip -4 addr show | grep -c 'inet ')
has_forwarding=$(sysctl -n net.ipv4.ip_forward)

is_router=0
is_devbox=0

# Router: Loose RP filter, no redirect disabling.
# Devbox: Full protection, except log restriction is optional.
# Server (Not Counted): Full lockdown. Strict RP, no redirects, dmesg restricted.

if [[ "$nic_count" -gt 1 || "$has_forwarding" -eq 1 ]]; then
    is_router=1
    echo "Detected: Router or multi-homed system."
fi

# Check for user desktop environment (GNOME, KDE, etc.)
if pgrep -x gnome-session > /dev/null || pgrep -x plasmashell > /dev/null; then
    is_devbox=1
    echo "Detected: Developer or desktop environment."
fi

# If neither router nor devbox, assume it's a production server
if [[ "$is_router" -eq 0 && "$is_devbox" -eq 0 ]]; then
    echo "Detected: Server role."
fi

SYSCTL_TMP="/etc/sysctl.d/99-custom-hardening.conf"

SYSCTL_TMP="/etc/sysctl.d/99-custom-hardening.conf"

# Backup existing config if present
if [[ -f "$SYSCTL_TMP" ]]; then
    cp "$SYSCTL_TMP" "${SYSCTL_TMP}.bak.$(date +%s)"
    echo "[*] Existing config backed up to ${SYSCTL_TMP}.bak.$(date +%s)"
fi

# Build sysctl hardening config dynamically
echo "===> Applying sysctl hardening rules..."
SYSCTL_TMP="/etc/sysctl.d/99-custom-hardening.conf"

cat <<EOF > "$SYSCTL_TMP"
# -- Core Hardening --
net.ipv4.icmp_echo_ignore_broadcasts = 1	# Blocks ICMP broadcast pings, which can be abused for DDoS amplification. Will block the ping util.
net.ipv4.icmp_ignore_bogus_error_responses = 1  # Protects against malformed or spoofed ICMP error messages.
net.ipv4.tcp_syncookies = 1			# Enables SYN cookies, a defense against SYN flood attacks.
kernel.randomize_va_space = 2			# Makes memory layout unpredictable, defeating many buffer overflow and ROP-style attacks. 2 = Full randomization.
kernel.kptr_restrict = 2			# Restricts access to /proc/kallsyms, which maps kernel addresses. Prevents leaking of kernel addresses to non-root users.
kernel.dmesg_restrict = 1			# Blocks unprivileged users from reading kernel logs via dmesg.
fs.protected_hardlinks = 1			# Stops users from creating hardlinks to files they don't own, which can be abused in some local privilege escalation attacks.
fs.protected_symlinks = 1			# Prevents symlink race attacks, where a malicious user tricks a privileged process into following a symlink they control.
EOF

if [[ "$is_router" -eq 0 ]]; then
    cat <<EOF >> "$SYSCTL_TMP"
# -- Non-router: Safe to restrict redirects --
net.ipv4.conf.all.accept_redirects = 0		# Disables ICMP redirect acceptance, where attackers trick your computer into routing traffic through malicious gateways.
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0		# Prevents your system from sending ICMP redirects, which should only be enabled on routers.
net.ipv4.conf.default.send_redirects = 0
EOF
else
    echo "# Skipping redirect rules for router role." >> "$SYSCTL_TMP"
fi

if [[ "$is_router" -eq 0 ]]; then
    cat <<EOF >> "$SYSCTL_TMP"
# -- RP filter safe on single-homed hosts --
net.ipv4.conf.all.rp_filter = 1			# Helps prevent IP spoofing. If the source IP of a packet doesn't match the route back, it's dropped. 1 = Strict mode.
net.ipv4.conf.default.rp_filter = 1
EOF
else
    cat <<EOF >> "$SYSCTL_TMP"
# -- Router mode: Use loose RP filter --
net.ipv4.conf.all.rp_filter = 2			# 2 = Loose filter, more accepting.
net.ipv4.conf.default.rp_filter = 2
EOF
fi

echo "===> Applying sysctl settings..."
sysctl --system

echo "===> Hardening complete based on environment."

echo "Sysctl rules written to: $SYSCTL_TMP"
echo "Role: $( [[ $is_router -eq 1 ]] && echo 'Router' || ( [[ $is_devbox -eq 1 ]] && echo 'Devbox' || echo 'Server') )"


