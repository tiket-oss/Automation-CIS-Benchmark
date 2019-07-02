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
        mount -o remount,nosuid /dev/shm; echo -e "\t\t[*] Done"
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
        mount -o remount,nosuid /dev/shm; echo -e "\t\t[*] Done"
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
        mount -o remount,noexec /dev/shm; echo -e "\t\t[*] Done"
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

#cat /proc/1/cgroup | grep docker &> /dev/null
#if [ $? -ne 1 ]; then
#     echo -e "\t[-] You're inside a container so it will skipped"
#else
   df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d \ { -perm -0002 -a ! -perm -1000 \) 2>/dev/null
   if [ $? -ne 1 ]; then
        echo -e "\t[-] No world writable directories exist without the sticky bit set"
   else
        echo -e "\t[+] Set the sticky bit on all world writable directories"
        df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | chmod a+t; echo -e "\t\t[*] Done"
   fi
#fi

echo "[+] 1.1.21 Disable Automounting (Scored"

cat /proc/1/cgroup | grep docker &> /dev/null
#if [ $? -ne 1 ]; then
#     echo -e "\t[-] You're inside a container so it will skipped"
#else
   dpkg -s autofs &> /dev/null
   if [ $? -ne 0 ]; then
        echo -e "\t[-] autofs is not installed, so it will skipped"
   else
        systemctl is-enabled autofs &> /dev/null
        if [ $? -ne 1 ]; then
             echo -e "\t[+] autofs is enabled, so it will disabled"
             systemctl disable autofs &> /dev/null; echo -e "\t[*] Done"
        else
             echo -e "\t[-] autofs is not enabled"
        fi
   fi
#fi

echo "[+][+] 1.2 Configure Software Updates [+][+]"

echo "[+] 1.2.1 Ensure package manager repositories are configured (Not Scored)"
echo -e "\t[-] It's not scored so it will skipped"

echo "[+] 1.2.2 Ensure GPG keys are configured (Not Scored)"
echo -e "\t[-] It's not scored so it will skipped"

echo "[+] 1.3 Filesystem Integrity Checking"

echo "[+] 1.3.1 Ensure AIDE is intalled (Scored)"
dpkg -s aide &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t[+] AIDE is already installed"
     echo -e "\t[*] Configuring AIDE"
     aide --init &> /dev/null; echo -e "\t\t[*] Done"
else
     echo -e "\t[+] AIDE is not installed yet, so it will installed now"
     apt-get install aide -y &> /dev/null
     echo -e "\t[*] Installed is done, now it will configured"
     aide --init &> /dev/null; echo -e "\t\t[*] Done"
fi

echo "[+] 1.3.2 Ensure filesystem integrity is regulary checked (Scored)"
crontab -u root -l | grep aide &> /dev/null
if [ $? -ne 1 ]; then
   echo -e "\t[-] Filesystem integrity is already regulary checked"
else
   echo -e "\t[+] Filesystem integrity is not regulary checked yet"
   echo -e "\t\t[*] Creating cron filesystem integrity regulary checked"
   crontab -l > /usr/src/cronaide
   echo "0 5 * * * /usr/bin/aide --check" >> /usr/src/cronaide
   crontab /usr/src/cronaide; echo -e "\t\t[*] Restarting cron"
   rm /usr/src/cronaide
   service cron restart &> /dev/null; echo -e "\t\t[*] Done"
fi

echo "[+][+] 1.4 Secure Boot Settings [+][+]"
echo "[+] 1.4.1 Ensure permissions on bootloader config are configured (Scored)"
echo -e "\t[*] Configuring permission bootloader"
chown root:root /boot/grub/grub.cfg &> /dev/null
chown og-rwx /boot/grub/grub.cfg &> /dev/null; echo -e "\t\t[*] Done"

echo "[+] 1.4.2 Ensure bootloader password is set (Scored)"
echo -e "\t[+] We will now set a Bootloader password"
cat /proc/1/cgroup | grep docker &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t[-] You're inside a container so it will skipped"
else
     grub-mkpasswd-pbkdf2 | tee grubpassword.tmp
     grubpassword=$(cat grubpassword.tmp | sed -e '1,2d' | cut -d ' ' -f7)
     echo " set superusers="root" " >> /etc/grub.d/40_custom
     echo " password_pbkdf2 root $grubpassword " >> /etc/grub.d/40_custom
     rm grubpassword.tmp
     update-grub; echo -e "\t\t [*] Done"
fi

echo "[+] 1.4.3 Ensure authentication required for single user mode (Scored)"
grep ^root:[*\!]: /etc/shadow &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t[+] Your root user is doesn't have password yet, so we will create it"
     passwd root; echo -e "\t[*] Your root password already changed"
     echo -e "\t[*] Done"
else
     echo -e "\t[-] Your root user is already have a password"
fi

echo "[+][+] Additional Process Hardening"
echo "[+] 1.5.1 Ensure core dumps are restricted (Scored)"
grep "hard core" /etc/security/limits.conf /etc/security/limit.d/* &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t[-] hardcore already set on limits.conf"
else
     echo "[*] Set hard core to 0 on limits.conf "
     echo "* hard core 0" >> /etc/security/limits.conf; echo -e "\t\t[*] Done"
     echo "[*] Change fs.suid_dumpable to 0 on sysctl.conf"
     cp templates/sysctl-CIS.conf /etc/sysctl.conf
     sysctl -e -p &> /dev/null; echo -e "\t\t[*] Done"
fi

