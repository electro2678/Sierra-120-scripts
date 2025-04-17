#!/bin/bash

# Output file
OUTPUT_FILE="system_audit_$(date +%Y%m%d_%H%M%S).log"

# Redirect all output to both stdout and the output file
exec > >(tee "$OUTPUT_FILE") 2>&1

echo "\n===== System Nmap Scan ====="
sudo nmap -sV 127.0.0.1

echo "===== SYSTEM HARDWARE INFO ====="

echo -n "Chassis Type: "
sudo dmidecode -s chassis-type

echo -n "Hostname: "
hostname

echo -n "System Manufacturer: "
sudo dmidecode -s system-manufacturer

echo -n "System Product Name: "
sudo dmidecode -s system-product-name

echo -n "System Serial Number: "
sudo dmidecode -s system-serial-number

echo -e "\n===== SYSTEM & CPU INFO ====="
echo "Kernel & OS:"
uname -a

echo -e "\nCPU Info:"
cat /proc/cpuinfo

echo -e "\nMemory Info:"
grep MemTotal /proc/meminfo

echo -e "\nBlock Devices Info:"
dmesg | grep blocks

echo -e "\nDisk Usage (df -h):"
df -h

echo -e "\nNetwork Devices (lspci -v | grep net):"
lspci -v | grep -i net

echo -e "\n===== INSTALLED SOFTWARE ====="
echo "Software Name | Version | Maintainer/Publisher | Install Date (if available)"
echo "--------------------------------------------------------------"

echo -e "\n--- APT Packages ---"
dpkg-query -W -f='${Package} | ${Version} | ${Maintainer}\n' | sort

echo -e "\n--- Snap Packages ---"
snap list --all | awk 'NR==1 {next} {printf "%s | %s | %s | %s | %s\n", $1, $2, $3, $4, $5}'

echo -e "\n--- Flatpak Packages ---"
flatpak list --columns=application,version,origin

echo -e "\n===== INSTALL DATE INFO (DPKG File Metadata) ====="
# Replace <package-name> with actual package or loop through a few top ones
for pkg in $(dpkg-query -W -f='${Package}\n' | head -n 5); do
    echo -n "$pkg: "
    stat /var/lib/dpkg/info/${pkg}.list 2>/dev/null | grep Modify
done

echo -e "\n===== Security Assessment ====="

echo -e "\n--- SSH Grace Time---"
grep "^LoginGraceTime" /etc/ssh/sshd_config

echo -e "\n--- SSH ACCESS Limited---"
grep "^AllowUsers" /etc/ssh/sshd_config
grep "^AllowGroups" /etc/ssh/sshd_config
grep "^DenyUsers" /etc/ssh/sshd_config
grep "^DenyGroups" /etc/ssh/sshd_config

echo -e "\n--- Lockout for Failed Password---"
grep "pam_tally2" /etc/pam.d/common-auth

echo -e "\n--- Password Hash algorithm---"
egrep '^password\s+\S+\s+pam_unix.so' /etc/pam.d/common-password

echo -e "\n--- Shadow PW Peramiters---"
grep PASS_MAX_DAYS /etc/login.defs
grep PASS_MIN_DAYS /etc/login.defs
grep PASS_WARN_AGE /etc/login.defs

echo -e "\n--- Ensure system accounts are non-login ---"
egrep -v "^\+" /etc/passwd | awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<1000 && $7!="/usr/sbin/nologin" && $7!="/bin/false") {print}'

echo -e "\n--- Ensure access to the su command is restricted ---"
grep pam_wheel.so /etc/pam.d/su
grep wheel /etc/group

echo -e "\n--- verify file permissions ---"
stat /etc/passwd
stat /etc/shadow
stat /etc/group

echo -e "\n--- Ensure core dumps are restricted ---"
grep "hard core" /etc/security/limits.conf /etc/security/limits.d/*
sysctl fs.suid_dumpable
grep "fs\.suid_dumpable" /etc/sysctl.conf /etc/sysctl.d/*

echo -e "\n--- Ensure DHCP Server is not enabled ---"
initctl show-config isc-dhcp-server
initctl show-config isc-dhcp-server6

echo -e "\n--- Ensure LDAP server is not enabled ---"
ls /etc/rc*.d/S*slapd

echo -e "\n--- Ensure DNS Server is not enabled ---"
ls /etc/rc*.d/S*bind9

echo -e "\n--- Ensure FTP Server is not enabled ---"
initctl show-config vsftpd

echo -e "\n--- Ensure HTTP server is not enabled ---"
ls /etc/rc*.d/S*apache2

echo -e "\n--- Ensure IMAP and POP3 server is not enabled ---"
initctl show-config dovecot

echo -e "\n--- Ensure Samba is not enabled ---"
initctl show-config smbd

echo -e "\n--- Ensure SNMP Server is not enabled ---"
ls /etc/rc*.d/S*snmpd

echo -e "\n--- Ensure telnet client is not installed ---"
dpkg -s telnet

echo -e "\n===== AUDIT COMPLETE ====="
echo "Results saved to $OUTPUT_FILE"