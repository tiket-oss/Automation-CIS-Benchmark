#!/bin/bash

clear

check_root() {
	if [ $EUID -ne 0 ]; then
		echo "Permission denied"
		echo "Can onlu run as root"
		exit
	else
		echo "[+] Permission is allowed"
		echo "[+] This script could be run"
	fi
}

check_root

echo "[+] 1.1 Filesystem Configuration"
echo -e "\t[+] 1.1.1 Disable unused filesystems"
echo -e "\t\t[+] 1.1.1.1 Ensure mounting of cramfs filesystems is disabled (Scored)"
dpkg -s cramfs &> /dev/null
if [ $? -ne 1 ]; then
    touch /etc/modprobe.d/CIS.conf
    cat /etc/modprobe.d/CIS.conf | grep cramfs &> /dev/null
    if [ $? -ne 1 ]; then
        echo -e "\t\t\t[-] cramfs is already disabled"
    else
        echo -e "\t\t\t[*] cramfs is installed so it will disable"
        echo "installl cramfs /bin/true" >> /etc/modprobe.d/CIS.conf
        echo -e "\t\t\t\t[*] Done"
    fi
else
    echo -e "\t\t\t[-] cramfs is not installed"
fi

echo -e "\t\t[+] 1.1.1.2 Ensure mounting of freevxfs filesystems is disabled (Scored)"
dpkg -s freevxfs &> /dev/null
if [ $? -ne 1 ]; then
    cat /etc/modprobe.d/CIS.conf | grep freevxfs &> /dev/null
    if [ $? -ne 1 ]; then
        echo -e "\t\t\t[-] freevxfs is already disabled"
    else
        echo -e "\t\t\t[*] freevxfs is installed so it will disable"
        echo "install freevxfs /bin/true" >> /etc/modprobe.d/CIS.conf
        echo -e "\t\t\t\t[*] Done"
    fi
else
    echo -e "\t\t\t[-] freevxfs is not installed"
fi

echo -e "\t\t[+] 1.1.1.3 Ensure mounting of jffs2 filesystems is disabled (Scored)"
dpkg -s jffs2 &> /dev/null
if [ $? -ne 1 ]; then
    cat /etc/modprobe.d/CIS.conf | grep jffs2 &> /dev/null
    if [ $? -ne 1 ]; then
        echo -e "\t\t\t[-] jffs2 is already disabled"
    else
        echo -e "\t\t\t[*] jffs2 is installed so it will disable"
        echo "install jffs2 /bin/true" >> /etc/modprobe.d/CIS.conf
        echo -e "\t\t\t\t[*] Done"
    fi
else
    echo -e "\t\t\t[-] jffs2 is not installed"
fi

echo -e "\t\t[+] 1.1.1.4 Ensure mounting of hfs filesystems is disabled (Scored)"
dpkg -s hfs &> /dev/null
if [ $? -ne 1 ]; then
    cat /etc/modprobe.d/CIS.conf | grep hfs &> /dev/null
    if [ $? -ne 1 ]; then
        echo -e "\t\t\t[-] hfs is already disabled"
    else
        echo -e "\t\t\t[*] hfs is installed so it will disable"
        echo "install hfs /bin/true" >> /etc/modprobe.d/CIS.conf
        echo -e "\t\t\t\t[*] Done"
    fi
else
    echo -e "\t\t\t[-] hfs is not installed"
fi

echo -e "\t\t[+] 1.1.1.5 Ensure mounting of hfsplus filesystems is disabled (Scored)"
dpkg -s hfsplus &> /dev/null
if [ $? -ne 1 ]; then
    cat /etc/modprobe.d/CIS.conf | grep hfsplus &> /dev/null
    if [ $? -ne 1 ]; then
        echo -e "\t\t\t[-] hfsplus is already disabled"
    else
        echo -e "\t\t\t[*] hfsplus is installed so it will disable"
        echo "install hfsplus /bin/true" >> /etc/modprobe.d/CIS.conf
        echo -e "\t\t\t\t[*] Done"
    fi
else
    echo -e "\t\t\t[-] hfsplus is not installed"
fi

echo -e "\t\t[+] 1.1.1.6 Ensure mounting of udf filesystems is disabled (Scored)"
dpkg -s udf &> /dev/null
if [ $? -ne 1 ]; then
    cat /etc/modprobe.d/CIS.conf | grep udf &> /dev/null
    if [ $? -ne 1 ]; then
        echo -e "\t\t\t[-] udf is already disabled"
    else
        echo -e "\t\t\t[*] udf is installed so it will disable"
        echo "install udf /bin/true" >> /etc/modprobe.d/CIS.conf
        echo -e "\t\t\t\t[*] Done"
    fi
else
    echo -e "\t\t\t[-] udf is not installed"
fi

echo -e "\t[+] 1.1.2 Ensure separate partition exists for /tmp (scored)"
echo -e "\t[+] 1.1.3 Ensure nodev option set on /tmp partitino (Scored)"
echo -e "\t[+] 1.1.4 Ensure nosuid option set on /tmp partition (scored)"
echo -e "\t[+] 1.1.5 Ensure separate partition exists for /var (scored)"
echo -e "\t[+] 1.1.6 Ensure separate partition exists for /var/tmp (Scored)"
echo -e "\t[+] 1.1.7 Ensure nodev option set on /var/tmp partition (scored)"
echo -e "\t[+] 1.1.8 Ensure nosuid option set on /var/tmp partition (Scored)"
echo -e "\t[+] 1.1.9 Ensure noexec option set on /var/tmp partition (Scored)"
echo -e "\t[+] 1.1.10 Ensure separate partition exists for /var/log (Scored)"
echo -e "\t[+] 1.1.11 Ensure separate partition exists for /var/log/audit (Scored)"
echo -e "\t[+] 1.1.12 Ensure separate partition exists for /home (Scored)"
echo -e "\t[+] 1.1.13 Ensure nodev option set on /home partition (Scored)"
echo -e "\t[+] 1.1.14 Ensure nodev option set on /dev/shm partition (Scored)"
echo -e "\t[+] 1.1.15 Ensure nosuid option set on /dev/shm partition (Scored)"
echo -e "\t[+] 1.1.16 Ensure noexec option set on /dev/shm partition (Scored)"
echo -e "\t[+] 1.1.17 Ensure nodev option set on removable media partitions (Not Scored)"
echo -e "\t[+] 1.1.18 Ensure nosuid option set on removable media partitions (Not Scored)"
echo -e "\t[+] 1.1.19 Ensure noexec option set on removable media partitions (Not Scored)"

echo -e "\t[+] 1.1.20 Ensure sticky bit is set on all world-writable directories (Scored)"
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d \ { -p
erm -0002 -a ! -perm -1000 \) 2>/dev/null
if [ $? -ne 1 ]; then
    echo -e "\t[-] No world writable directories exist without the sticky bit set"
else
    echo -e "\t[+] Set the sticky bit on all world writable directories"
    df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | chmod a+t; echo -e "\t\t[*] Done"
fi
echo -e "\t\t[*] Done"

echo -e "\t[+] 1.1.21 Disable Automounting (Scored)"
dpkg -s autofs &> /dev/null
if [ $? -ne 0 ]; then
    echo -e "\t\t[-] autofs is not installed, so it will skipped"
else
    systemctl is-enabled autofs &> /dev/null
    if [ $? -ne 1 ]; then
        echo -e "\t\t\t[+] autofs is enabled, so it will disabled"
        systemctl disable autofs &> /dev/null; echo -e "\t\t\t[*] Done"
    else
        echo -e "\t\t\t[-] autofs is not enabled"
    fi
fi

