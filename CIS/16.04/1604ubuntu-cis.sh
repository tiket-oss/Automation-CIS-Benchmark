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

echo "[+][+] 1.5 Additional Process Hardening [+][+]"
echo "[+] 1.5.1 Ensure core dumps are restricted (Scored)"
grep "hard core" /etc/security/limits.conf /etc/security/limit.d/* &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t[-] hardcore already set on limits.conf"
     echo -e "\t[-] fs.suid_dumpable already set to 0 on sysctl.conf"
else
     echo "[*] Set hard core to 0 on limits.conf "
     echo "* hard core 0" >> /etc/security/limits.conf; echo -e "\t\t[*] Done"
     echo "[*] Change fs.suid_dumpable to 0 on sysctl.conf"
     cp templates/sysctl-CIS.conf /etc/sysctl.conf
     sysctl -w fs.suid_dumpable=0 &> /dev/null
     sysctl -e -p &> /dev/null; echo -e "\t\t[*] Done"
fi

echo "[+] 1.5.2 Ensure XD/NX support is enabled (Not Scored)"
echo -e "\t [-]It's not scored so it will skipped"

echo "[+] 1.5.3 Ensure address aspace layour randomization (ASLR) is enabled (Scored)"
sysctl kernel.randomize_va_space &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t[-] kernel.randomize_va_space already set to 2"
     echo -e "\t[*] Activated Kernel Parameter"
     sysctl -w kernel.randomize_va_space=2 &> /dev/null; echo -e "\t\t[*] Done"
else
     echo -e "\t[+] Activated Kernel Parameter"
     sysctl -w kernel.randomize_va_sapce=2 &> /dev/null; echo -e "\t\t[*] Done"
fi

echo "[+] 1.5.4 Ensure prelink is disabled (Scored)"
dpkg -s prelink &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t[-] prelink is installed so it will removed"
     echo -e "\t[*] Restore binaries to normal"
     prelink -ua &> /dev/null; echo -e "\t\t[*] Done"
     echo -e "\t[*] Removing prelink"
     apt-get remove -y prelink &> /dev/null; echo -e "\t\t[*] Done"
else
     echo -e "\t[-] prelink is not installed"
fi

echo "[+][+] 1.6 Mandatory Access Control [+][+]"
echo "[+] 1.6.1 Configure SELinux"
echo -e "\t[+] 1.6.1.1 Ensure SELinux is not disabled is bootloader configuration (Scored)"
cat /proc/1/cgroup | grep docker &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t[-] You're inside a container so it will skipped"
else
     grep "^\s*linux" /boot/grup/grub.cfg | grep selinux=0 &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t[*] Please remove all instances of selinux=0 and enforcing=0"
          sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"/GRUB_CMDLINE_LINUX_DEFAULT="quiet"' /etc/default/grub
          echo -e "\t\t\t[*] Done"
          echo -e "\t\t[*] Updating grub2 configuration"
          update-grub; echo -e "\t\t\t[*] Done"
     else
          echo -e "\t\t[-] Nothing Change"
     fi
fi

echo -e "\t[+] 1.6.1.2 Ensure the SELinux state is enforcing (Scored)"
dpkg -s selinux &> /dev/null
if [ $? -ne 1 ]; then
     grep SELINUX=enforcing /etc/selinux/config &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t[-] SELinux is already set to enforcing"
     else
          echo -e "\t\t[*] Change SELINUX paramater to enforcing"
          sed -i 's/SELINUX=/#SELINUX/g' /etc/selinux/config
          echo "SELINUX=enforcing" >> /etc/selinux/config
          echo -e "\t\t\t[*] Done"
     fi
else
     echo -e "\t\t[-] SELinux is not installed"
fi

echo -e "\t[+] 1.6.1.3 Ensure SELinux policy is configured (Scored)"
dpkg -s selinux &> /dev/null
if [ $? -ne 1 ]; then
     grep SELINUXTYPE=ubuntu /etc/selinux/config &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t[-] SELINUXTYPE is already set to ubuntu"
     else
          echo -e "\t\t[+] SELINUXTYPE is not ubuntu so it will change"
          echo -e "\t\t[*] Change SELINUXTYPE to ubuntu"
          sed -i 's/SELINUXTYPE/#SELINUXTYPE/g' /etc/selinux/config
          echo "SELINUXTYPE=ubuntu" >> /etc/selinux/config
          echo -e "\t\t\t[*] Done"
     fi
else
     echo -e "\e\e[-] SELinux is not installed yet"
fi

echo -e "\t[+] 1.6.1.4 Ensure no unconfined daemons exist (Scored)"
ps -eZ | egrep "initrc" | egrep -vw "tr|ps|egrep|bash|awk" | tr ':' ' ' | awk '{ print $NF }' &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t[-] No unconfined daemons exist"
else
     ps -eZ | egrep "initrc" | egrep -vw "tr|ps|egrep|bash|awk" | tr ':' ' ' | awk '{ print $NF }' >> Unconfined-Daemons.txt
     echo -e "\t\t[*] Uncofined daemons is found, saved at Unconfined-Daemons.txt"
     echo -e "\t\t[*] Done"
fi

echo -e "[+] 1.6.2 Configure AppArmor"
echo -e "\t[+] 1.6.2.1 Ensure AppArmor is not disabled in bootloader configuration (Scored)"
grep "quiet" /etc/default/grub &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t[-] This requirement is already set on requirement 1.6.1.1"
else
     sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="quite splash"/GRUB_CMDLINE_LINUX_DEFAULT="quite"' /etc/default/grub
     update-grub; echo -e "\t\t[*] Done"
fi

echo "[+] 1.6.2.2 Ensure all AppArmor Profiles are enforcing (Scored)"
dpkg -s apparmor &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t[-] AppArmor is already installed"
     echo -e "\t[*] Set all profiles to enforce mode"
     aa-enforce /etc/apparmor.d/* &> /dev/null
     echo -e "\t\t[*] Done"
else
     echo -e "\t[-] AppArmor is not installed"
fi

echo "[+] 1.6.3 Ensure SELinux or AppArmor are installed (Not Scored)"
dpkg -s selinux &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t[-] SELinux is already installed"
else
     echo -e "\t[+] Installed SELinux"
     apt-get install selinux -y &> /dev/null
     echo -e "\t\t[*] Done"
fi
dpkg -s apparmor &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t[-] AppArmor is already installed"
else
     echo -e "\t[+] Installed AppArmor"
     apt-get install apparmor -y &> /dev/null
     echo -e "\t\t[*] Done"
fi

echo "[+][+] 1.7 Warning Banners [+][+]"
echo -e "\t[+] 1.7.1 Command Line Warning Banners"
echo -e "\t\t[+] 1.7.1.1 Ensure message of the day is configured properly (Scored)"
egrep '(\\v|\\r|\\m|\\s)' /etc/motd  &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t\t[+] Please remove any instances of \m, \r, \s, or \v"
else
     echo -e "\t\t\t[-] Message of the day is already configured properly"
fi

echo -e "\t\t[+] 1.7.1.2 Ensure local login warning banner is configured properly (Not Scored)"
egrep '(\\v|\\r|\\m|\\s)' /etc/issue &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t\t[+] Please remove \m, \r, \s, or \v from any instances"
else
     echo -e "\t\t\t[-] /etc/issue Already configured properly"
fi

echo -e "\t\t[+] 1.7.1.3 Ensure remote login warning banner is configured properly (Not Scored)"
egrep '(\\v|\\r|\\m|\\s)' /etc/issue.net &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t\t[+] Please remove \m, \r, \s, or \v from any instances"
else
     echo -e "\t\t\t[-] /etc/issue.net Already configured properly"
fi

echo -e "\t\t[+] 1.7.1.4 Ensure permissions on /etc/motd are configured (Not Scored)"
MOTD=/etc/motd
if test -f "$MOTD"; then
     echo -e "\t\t\t[*] Changing permission on /etc/motd"
     chown root:root /etc/motd
     chown 644 /etc/motd; echo -e "\t\t\t\t[*] Done"
else
     echo -e "\t\t\t[-] File /etc/motd is not exists"
fi

echo -e "\t\t[+] 1.7.1.5 Ensure permissions on /etc/issue are configured (Scored)"
echo -e "\t\t\t[*] Changing permissions on /etc/issue"
chown root:root /etc/issue
chmod 644 /etc/issue; echo -e "\t\t\t\t[*] Done"

echo -e "\t\t[+] 1.7.1.6 Ensure permissions on /etc/issue.net are configured (Not Scored)"
echo -e "\t\t\t[*] Changing permssions on /etc/issue.net"
chown root:root /etc/issue.net
chmod 644 /etc/issue.net; echo -e "\t\t\t\t[*] Done"

echo -e "\t[+] 1.7.2 Ensure GDM login banner is configured (Scored)"
dpkg -s gdm &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t[*] Configuring /etc/dconf/profile/gdm and /etc/dconf/db/gdm.d/01-banner-message"
     sed -i 's/user-db/#user-db/g' /etc/dconf/profile/gdm
     sed -i 's/system-db/#system-db/g' /etc/dconf/profile/gdm
     sed -i 's/file-db/#file-db/g' /etc/dconf/profile/gdm
     sed -i 's/banner-message/#banner-message/g' /etc/dconf/db/gdm.d/01-banner-message
     echo "user-db:user" >> /etc/dconf/profile/gdm
     echo "system-db:gdm" >> /etc/dconf/profile/gdm
     echo "file-db:/usr/share/gdm/greeter-dconf-defaults" >> /etc/dconf/profile/gdm
     echo "banner-message-enable=true" >> /etc/dconf/db/gdm.d/01-banner-message
     echo "banner-message-text='Authorized uses only. All activity may be monitored and reported.'" >> /etc/dconf/db/gdm.d/01-banner-message
     echo -e "\t\t\t[*] Done"
     echo -e "\t\t[*] Updating dconf"
     dconf update; echo -e "\t\t\t[*] Done"
else
     echo -e "\t\t[-] Dconf is not installed"
fi

echo "[+] 1.8 Ensure updates, patches, and additional security software are installed (Not Scored)"
apt-get -s upgrade -y &> /dev/null; echo -e "\t[*] Done"

echo "[+][+] 2.1 inetd Services [+][+]"
echo -e "\t[+] 2.1.1 Ensure chargen services are not enabled (Scored)"
dpkg -s xinetd &> /dev/null 
if [ $? -ne 1 ]; then
     echo -e "\t\t[*] Disabling charged services"
     sed -i 's/chargen/#chargen/g' /etc/xinetd.conf
     find /etc/xinetd.d -type f -exec sed -i "s/chargen/#chargen/g" {} \;
     echo -e "\t\t\t[*] Done"
else
     echo -e "\t\t[-] inetd or xinetd is not installed yet"
fi
