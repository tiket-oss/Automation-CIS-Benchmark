#!/bin/bash

clear

check_root(){
if [ $EUID -ne 0 ]; then
     echo "Permission denied"
     echo "Can only run as root"
     exit
else 
     echo "[+] Permission is allowed"
     echo "[+] This script could be run"
fi
}

check_root

echo "[+] 1.1.1 Disable unused filesystems"
echo -e "\t[+] 1.1.1.1 Ensure mounting of cramfs filesystems is disabled (Scored)"
dpkg -s cramfs &> /dev/null
if [ $? -ne 1  ]; then
     echo -e "\t\t[+] cramfs is installed so it will disable"
     echo "install cramfs/bin/true" >> /etc/modprobe.d/CIS.conf
else
     echo -e "\t\t[-] cramfs is not installed"
fi

dpkg -s freexvfs &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t[+] freexvfs is installed so it will be disable"
     echo "install freexvfs /bin/true" >> /etc/modprobe.d/CIS.conf
else
     echo -e "\t\t[-] freexvfs is not installed"
fi

dpkg -s jffs2 &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t[+] jffs2 is installed so it will be disable"
     echo "install jffs2 /bin/true" >> /etc/modprobe.d/CIS.conf
else
     echo -e "\t\t[-] jffs2 is not installed"
fi

dpkg -s hfs &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t[+] hfs is installed so it will be disable"
     echo "install hfs /bin/true" >> /etc/modprobe.d/CIS.conf
else
     echo -e "\t\t[-] hfs is not installed"
fi

dpkg -s hfsplus &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t[+] hfsplus is installed so it will be disable"
     echo "install hfsplus /bin/true" >> /etc/modprobe.d/CIS.conf
else
     echo -e "\t\t[-] hfsplus is not installed"
fi

dpkg -s squashfs &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t[+] squashfs is installed so it will be disable"
     echo "install squashfs /bin/true" >> /etc/modprobe.d/CIS.conf
else
     echo -e "\t\t[-] squashfs is not installed"
fi

dpkg -s udf &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t[+] udf is installed so it will be disable"
     echo "install udf /bin/true" >> /etc/modprobe.d/CIS.conf
else
     echo -e "\t\t[-] udf is not installed"
fi

dpkg -s vfat &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t[+] vfat is installed so it will be disalbe"
     echo "install vfat /bin/true" >> /etc/modprobe.d/CIS.conf
else
     echo -e "\t\t[-] vfat is not installed"
fi

echo "[+] 1.1.14 Ensure nodev option set on /dev/shm partition (Scored)"

cat /proc/1/cgroup | grep docker &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t[-] You're inside a container so it will skipped"
else
   mount | grep /dev/shm | grep nodev &> /dev/null
   if [ $? -ne 1 ]; then
        echo -e "\t[+] nodev is available on /dev/shm"
        echo -e "\t\t[*] remount /dev/shm"
        mount -o remount,nosuid /dev/shm && echo -e "\t\t[*] Done"
   else
        echo -e "\t[-] nodev is not available on /dev/shm"
   fi
fi

echo "[+] 1.1.15 Ensure nosuid option set on /dev/shm partition (Scored)"

cat /proc/1/cgroup | grep docker &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t[-] You're inside a container so it will skipped"
else
   mount | grep /dev/shm | grep nosuid &> /dev/null
   if [ $? -ne 1 ]; then
        echo -e "\t[+] nosuid is available on /dev/shm"
        echo -e "\t\t[*] remount /dev/shm"
        mount -o remount,nosuid /dev/shm && echo -e "\t\t[*] Done"
   else
        echo -e "\t[-] nosuid is not available on /dev/shm"
   fi
fi

echo "[+] 1.1.16 Ensure noexec option set on /dev/shm partition (Scored)"

cat /proc/1/cgroup | grep docker &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t[-] You're inside a container so it will skipped"
else
   mount | grep /dev/shm | grep noexec &> /dev/null
   if [ $? -ne 1 ]; then
        echo -e "\t[+] noexec is available on /dev/shm"
        echo -e "\t\t[*] remount /dev/shm"
        mount -o remount,noexec /dev/shm && echo -e "\t\t[*] Done"
   else
        echo -e "\t[-] noexec is not available on /dev/shm"
   fi
fi

echo "[+] 1.1.17 Ensure nodev option set on removable media partitions (Not Scored)"
echo -e "\t[+] It's not scored so it will skipped"

echo "[+] 1.1.18 Ensure nosuid option set on removable media partitions (Not Scored)"
echo -e "\t[+] It's not scored so it will skipped"

echo "[+] 1.1.19 Ensure noexec option set on removable media partitions (Not Scored)"
echo -e "\t[+] It's not scored so it will skipped"

echo "[+] 1.1.20 Ensure sticky bit is set on all world-writable directoried (Scored)"

cat /proc/1/cgroup | grep docker &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t[-] You're inside a container so it will skipped"
else
   df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d \ { -perm -0002 -a ! -perm -1000 \) 2>/dev/null
   if [ $? -ne 1 ]; then
        echo -e "\t[-] No world writable directories exist without the sticky bit set"
   else
        echo -e "\t[+] Set the sticky bit on all world writable directories"
        df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | chmod a+t && echo -e "\t\t[*] Done"
   fi
fi

