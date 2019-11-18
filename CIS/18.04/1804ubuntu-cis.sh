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

echo "[+] 1.2 Configure SOftware Updates"
echo -e "\t[+] 1.2.1 Ensure package manager repositories are configured (Not Scored)"
echo -e "\t\t[=] It's not scored so it will skipped"

echo -e "\t[+] 1.2.2 Ensure GPG keys are configured (Not Scored)"
echo -e "\t\t[-] It's not scored so it will skipped"

echo "[+] 1.3 Filesystem Integrity Checking"

echo -e "\t[+] 1.3.1 Ensure AIDE is installed (Scored)"
dpkg -s aide &> /dev/null
if [ $? -ne 1 ]; then
    echo -e "\t\t[+] AIDE is already installed"
    echo -e "\t\t[*] Configuring AIDE"
    aide --init &> /dev/null; echo -e "\t\t[*] Done"
else
    echo -e "\t\t[-] AIDE is not installed yet, so it will installed now"
    apt-get install -y aide &> /dev/null
    echo -e "\t\t[*] Installed is done, now it will configured"
    aide --init &> /dev/null; echo -e "\t\t[*] Done"
fi

echo -e "\t[+] 1.3.2 Ensure filesystem integrity is regulary checked (SCored)"
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

echo "[+] 1.4 Secure Boot Settings"
echo -e "\t[+] 1.4.1 Ensure permissions on bootloader config are configured (Scored)"
echo -e "\t\t[*] Configuring permission bootloader"
GRUBCFG=/boot/grub/grub.cfg
if test -f "$GRUBCFG"; then
    chown root:root /boot/grub/grub.cfg &> /dev/null
    chown og-rwx /boot/grub/grub.cfg &> /dev/null; echo -e "\t\t\t[*] Done"
else
    echo -e "\t\t[-] /boot/grub/grub.cfg is not found"
fi

echo -e "\t[+] 1.4.2 Ensure bootloader password is set (Scored)"
echo -e "\t\t[*] Now we will set a Bootloader password"
cat /proc/1/group | grep docker &> /dev/null
if [ $? -ne 1 ]; then
    echo -e "\t\t\t[-] You're inside a container so it will skipped"
else
    grub-mkpasswd-pbkdf2 | tee grubpassword.tmp
    grubpassword=$(cat grubpassword.tmp | sed -e '1,2d' | cut -d ' ' -f7)
    echo " set superusers="root" " >> /etc/grub.d/40_custom
    echo " password_pbkdf2 root $grubpassword " >> /etc/grub.d/40_custom
    rm grubpassword.tmp
    update-grub; echo -e "\t\t\t [*] Done"
fi

echo -e "\t[+] 1.4.3 Ensure authentication required for single user mode (Scored)"
grep ^root:[*\!]: /etc/shadow &> /dev/null
if [ $? -ne 1 ]; then
    echo -e "\t\t[+] Your root user is doesn't have password yet, so it will be set"
    passwd root; echo -e "\t\t\t[*] Your root password already changed"
    echo -e "\t\t\t\t[*] Done"
else
    echo -e "\t\t[-] Your root user is already have a password"
fi

echo "[+] 1.5 Additional Process Hardening"
echo -e "\t[+] 1.5.1 Ensure core dumps are restricted (Scored)"
grep "hard core" /etc/security/limits.conf /etc/security/limits.d/* &> /dev/null
if [ $? -ne 1 ]; then
    echo -e "\t\t[-] hardcore already set on limits.conf"
    echo -e "\t\t[-] fs.suid_dumpable already set to 0 on sysctl.conf"
else
    echo -e "\t\t[*] Set hard core to 0 on limits.conf"
    echo "* hard core 0" >> /etc/security/limits.conf; echo -e "\t\t\t[*] Done"
    echo -e "\t\t[*] Change fs.suid_dumpable to 0 on sysctl.conf"
    cp templates/sysctl-CIS.conf /etc/sysctl.conf
    sysctl -w fs.suid_dumpable=0 &> /dev/null
    sysctl -e -p &> /dev/null; echo -e "\t\t\t[*] Done"
fi

echo -e "\t[+] 1.5.2 Ensure XD/NX support is enabled (Not Scored)"
echo -e "\t\t[-] It's not scored so it will skipped"

echo -e "\t[+] 1.5.3 Ensure address space layout randomization (ASLR) is enabled (Scored)"
sysctl kernel.randomize_va_space &> /dev/null
if [ $? -ne 1 ]; then
    echo -e "\t\t[-] kernel.randomize_va_space is already set to 2"
    echo -e "\t\t[*] Activated Kernel Parameter"
    sysctl -w kernel.randomize_va_space=2 &> /dev/null; echo -e "\t\t\t[*] Done"
else
    echo -e "\t\t[+] Activated Kernel Parameter"
    sysctl -w kernel.randomize_va_space=2 &> /dev/null; echo -e "\t\t\t[*] Done"
fi

echo -e "\t[+] 1.5.4 Ensure prelink is disabled (Scored)"
dpkg -s prelink &> /dev/null
if [ $? -ne 1 ]; then
    echo -e "\t\t[-] prelink is installed so it will removed"
    echo -e "\t\t[*] Restore binaries to normal"
    prelink -ua &> /dev/null; echo -e "\t\t\t[*] Done"
    echo -e "\t\t[*] Removing prelink"
    apt-get remove -y prelink &> /dev/null; echo -e "\t\t[*] Done"
else
    echo -e "\t\t[-] prelink is not installed"
fi

echo "[+] 1.6 Mandatory Access Control"
echo -e "\t[+] 1.6.1 Configure SELinux"
echo -e "\t\t[+] 1.6.1.1 Ensure SELinux is not disabled in bootloader configuration (Scored)"
grep "^\s*linux" /boot/grub/grub.cfg | grep selinux=0 &> /dev/null
if [ $? -ne 1 ]; then
    echo -e "\t\t\t[*] Please remove all instances of selinux=0 and enforcing=0"
    sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"/GRUB_CMDLINE_LINUX_DEFAULT="quiet"/g' /etc/default/grub
    echo -e "\t\t\t\t[*] Done"
    echo -e "\t\t\t[*] Updating grub2 configuration"
    update-grub; echo -e "\t\t\t\t[*] Done"
else
    echo -e "\t\t\t[-] Nothing Change"
fi

echo -e "\t\t[+] 1.6.1.2 Ensure the SELinux state is enforcing (Scored)"
dpkg -s selinux &> /dev/null
if [ $? -ne 1 ]; then
    grep SELINUX=enforcing /etc/selinux/config &> /dev/null
    if [ $? -ne 1 ]; then
        echo -e "\t\t\t[-] SELinux is already set to enforcing"
    else
        echo -e "\t\t\t[*] Change SELinux parameter to enforcing"
        sed -i 's/SELINUX=/#SELINUX/g' /etc/selinux/config
        echo "SELINUX=enforcing" >> /etc/selinux/config
        echo -e "\t\t\t\t[*] Done"
    fi
else
    echo -e "\t\t[-] SELinux is not installed"
fi

echo -e "\t\t[+] 1.6.1.3 Ensure SELinux policy is configured (Scored)"
dpkg -s selinux &> /dev/null
if [ $? -ne 1 ]; then
    grep SELINUXTYPE=ubuntu /etc/selinux/config &> /dev/null
    if [ $? -ne 1 ]; then
        echo -e "\t\t\t[-] SELINUXTYPE is already set to ubuntu"
    else
        echo -e "\t\t\t[+] SELINUXTYPE is not ubuntu so it will change"
        echo -e "\t\t\t[*] Change SELINUXTYPE to ubuntu"
        sed -i 's/SELINUXTYPE/#SELINUXTYPE/g' /etc/selinux/config
        echo "SELINUXTYPE=ubuntu" >> /etc/selinux/config
        echo -e "\t\t\t\t[*] Done"
    fi
else
    echo -e "\t\t\t[-] SELinux is not installed yet"
fi

echo -e "\t\t[+] 1.6.1.4 Ensure no unconfined daemons exist (Scored)"
ps -eZ | egrep "initrc" | egrep -vw "tr|ps|egrep|bash|awk" | tr ':' ' ' | awk '{ print $NF }' &> /dev/null
if [ $? -ne 1 ]; then
    echo -e "\t\t\t[-] No unconed daemons exist"
else
    ps -eZ | egrep "initrc" | egrep -vw "tr|ps|egrep|bash|awk" | tr ':' ' ' | awk '{ print $NF }' >> Unconfined-Daemons.txt
    echo -e "\t\t\t[*] Unconfined daemons is found, saved at Unconfined-Daemons.txt"
    echo -e "\t\t\t[*] Done"
fi

echo -e "\t[+] 1.6.2 Configure AppArmor"
echo -e "\t\t[+] 1.6.2.1 Ensure AppArmor is not disabled in bootloader configuration (Scored)"
grep "quiet" /etc/default/grub &> /dev/null
if [ $? -ne 1 ]; then
    echo -e "\t\t\t[-] This requirements is already set on requirement 1.6.1.1"
else
    sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="quite splash"/GRUB_CMDLINE_LINUX_DEFAULT="quite"' /etc/default/grub
    update-grub; echo -e "\t\t\t[*] Done"
fi

echo -e "\t\t[+] 1.6.2.2 Ensure all AppArmor Profiles are enforcing (Scored)"
dpkg -s apparmor &> /dev/null
if [ $? -ne 1 ]; then
    echo -e "\t\t\t[-] AppArmor is already installed"
    echo -e "\t\t\t[*] Set all profiles to enforce mode"
    aa-enforce /etc/apparmor.d/* &> /dev/null
    echo -e "\t\t\t\t[*] Done"
else
    echo -e "\t[-] AppArmor is not installed"
fi

echo -e "\t[+] 1.6.3 Ensure SELinux or AppArmor are installed (Not Scored)"
dpkg -s selinux &> /dev/null
if [ $? -ne 1 ]; then
    echo -e "\t\t[-] SELinux is already installed"
else
    echo -e "\t\t[+] Installed SELinux"
    apt-get install -y selinux
    echo -e "\t\t[*] Done"
fi
dpkg -s apparmor &> /dev/null
if [ $? -ne 1 ]; then
    echo -e "\t\t[-] AppArmor is already installed"
else
    echo -e "\t\t[+] Installed AppArmor"
    apt-get install -y apparmor
    echo -e "\t\t[*] Done"
fi

echo "[+] 1.7 Warning Banners"
echo -e "\t[+] 1.7.1 Command Line Warning Banners"
echo -e "\t\t[+] 1.7.1.1 Ensure message of the day is configured properly (Scored)"
egrep '(\\v|\\r|\\m|\\s)' /etc/motd  &> /dev/null
if [ $? -ne 1 ]; then
     echo -e '\t\t\t[+] Please remove any instances of "\m", "\r", "\s", or "\v"'
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

### 2 SERVICES
echo "[+] 2.1 inetd Services"
echo -e "\t[+] 2.1.1 Ensure chargen services are not enabled (Scored)"
dpkg -s xinetd &> /dev/null
if [ $? -ne 1 ]; then
     cat /etc/xinetd.d/* | grep "#service chargen" &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t[-] chargen already disabled"
     else
          echo -e "\t\t[*] Disabling chargen services"
          sed -i 's/chargen/#chargen/g' /etc/xinetd.conf
          find /etc/xinetd.d -type f -exec sed -i "s/service chargen/#service chargen/g" {} \;
          sed -i '1,26 s/^/#/' /etc/xinetd.d/chargen
          echo -e "\t\t\t[*] Done"
     fi
else
     echo -e "\t\t[-] inetd or xinetd is not installed yet"
fi

echo -e "\t[+] 2.1.2 Ensure daytime services are not enabled (Scored)"
dpkg -s xinetd &> /dev/null
if [ $? -ne 1 ]; then
     cat /etc/xinetd.d/* | grep "#service daytime" &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t[-] daytime services already disabled"
     else
          echo -e "\t\t[*] Disabling daytime services"
          sed -i 's/daytime/#daytime/g' /etc/xinetd.conf
          find /etc/xinetd.d -type f -exec sed -i "s/service daytime/#service daytime/g" {} \;
          sed -i '1,26 s/^/#/' /etc/xinetd.d/daytime
          echo -e "\t\t\t[*] Done"
     fi
else
     echo -e "\t\t[-] inetd or xinetd is not installed yet"
fi

echo -e "\t[+] 2.1.3 Ensure discard services are not enabled (Scored)"
dpkg -s xinetd &> /dev/null
if [ $? -ne 1 ]; then
     cat /etc/xinetd.d/* | grep "#service discard" &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t[-] discard services already disabled"
     else
          echo -e "\t\t[*] Disabling discard services"
          sed -i 's/discard/#discard/g' /etc/xinetd.conf
          find /etc/xinetd.d -type f -exec sed -i "s/service daytime/#service daytime/g" {} \;
          sed -i '1,26 s/^/#/' /etc/xinetd.d/discard
          echo -e "\t\t\t[*] Done"
     fi
else
     echo -e "\t\t[-] inetd or xinetd is not installed yet"
fi

echo -e "\t[+] 2.1.4 Ensure echo services are not enabled (Scored)"
dpkg -s xinetd &> /dev/null
if [ $? -ne 1 ]; then
     cat /etc/xinetd.d/* | grep "#service echo" &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t[-] echo services already disabled"
     else
          echo -e "\t\t[*] Disabling echo services"
          sed -i 's/echo/#echo/g' /etc/xinetd.conf
          find /etc/xinetd.d -type f -exec sed -i "s/service echo/#service echo/g" {} \;
          sed -i '1,26 s/^/#/' /etc/xinetd.d/echo
          echo -e "\t\t\t[*] Done"
     fi
else
     echo -e "\t\t[-] inetd or xinetd is not installed yet"
fi

echo -e "\t[+] 2.1.5 Ensure time services are not enabled (Scored)"
dpkg -s xinetd &> /dev/null
if [ $? -ne 1 ]; then
     cat /etc/xinetd.d/* | grep "#service time" &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t[-] time services already disabled"
     else
          echo -e "\t\t[*] Disabling time servies"
          sed -i 's/time/#time/g' /etc/xinetd.conf
          find /etc/xinetd.d -type f -exec sed -i "s/service time/#service time/g" {} \;
          sed -i '1,26 s/^/#/' /etc/xinetd.d/time
          echo -e "\t\t\t[*] Done"
     fi
else
     echo -e "\t\t[-] inetd or xinetd is not installed yet"
fi

echo -e "\t[+] 2.1.6 Ensure rsh server is not enabled (Scored)"
dpkg -s xinetd &> /dev/null
if [ $? -ne 1 ]; then
     cat /etc/xinetd.d/* | grep "shell" &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t[*] Disabling shell on inet or xinet"
          find /etc/xinetd.d -type f -exec sed -i "/s/shell/#shell/g" {} \;
          echo -e "\t\t\t[*] Done"
     #else
     #     echo -e "\t\t\t[-] shell services already disabled"
     fi
else
     echo -e "\t\t[-] shell on inet or xinet is not found"
fi

dpkg -s xinetd &> /dev/null
if [ $? -ne 1 ]; then
     cat /etc/xinetd.d/* | grep "login" &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t[*] Disabling login on inet or xinet"
          find /etc/xinetd.d -type f -exec sed -i "/s/login/#login/g" {} \;
          echo -e "\t\t\t[*] Done"
     #else
      #    echo -e "\t\t\t[-] login services already disabled"
     fi
else
     echo -e "\t\t[-] login on inet or xinet is not found"
fi

dpkg -s xinetd &> /dev/null
if [ $? -ne 1 ]; then
     cat /etc/xinetd.d/* | grep "exec" &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t[*] Disabling exec on inet or xinet"
          find /etc/xinetd.d -type f -exec sed -i "/s/exec/#exec/g" {} \;
          echo -e "\t\t\t\[*] Done"
     fi
else
     echo -e "\t\t[-] exec on inet or xinet is not found"
fi

echo -e "\t[+] 2.1.7 Ensure talk server is not enabled (Scored)"
dpkg -s xinetd &> /dev/null
if [ $? -ne 1 ]; then
     cat /etc/xinetd.d/* | grep talk &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t[*] Disabling talk on inet or xinet"
          find /etc/xinetd.d -type f -exec sed -i "/s/talk/#talk/g" {} \;
     #apt-get remove talk -y &> /dev/null
          echo -e "\t\t\t[*] Done"
     fi
else
     echo -e "\t\t[-] talk on inet or xinet is not found"
fi

dpkg -s xinetd &> /dev/null
if [ $? -ne 1 ]; then
     cat /etc/xinetd.d/* | grep ntalk &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t[*] Disabling ntalk on inet or xinet"
          find /etc/xinetd.d -type f -exec sed -i "/s/ntalk/#ntalk/g" {} \;
     #apt-get remove ntalk -y &> /dev/null
          echo -e "\t\t\t[*] Done"
     fi
else
     echo -e "\t\t[-] ntalk on inet or xinet is not found"
fi

echo -e "\t[+] 2.1.8 Ensure telnet server is not enabled (Scored)"
dpkg -s xinetd &> /dev/null
if [ $? -ne 1 ]; then
     cat /etc/xinetd.d/* | grep telnet &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t[*] Disabling telnet on inet or xinet"
          find /etc/xinetd.d -type f -exec sed -i "/s/telnet/#telnet/g" {} \;
          echo -e "\t\t\t[*] Done"
     fi
else
     echo -e "\t\t[-] telnet on inet or xinet is not found"
fi

echo -e "\t[+] 2.1.9 Ensure tftp server is not enabled (Scored)"
dpkg -s xinetd &> /dev/null
if [ $? -ne 1 ]; then
     cat /etc/xinetd.d/* | grep tftp &> /dev/null
     if [ $? -ne  1 ]; then
          echo -e "\t\t[*] Disabling telnet on inet or xinet"
          find /etc/xinetd.d -type f -exec sed -i "/s/tftp/#tftp/g" {} \;
          echo -e "\t\t\t[*] Done"
     fi
else
     echo -e "\t\t[-] tftp on inet or xinet is not found"
fi

echo -e "\t[+] 2.1.10 Ensure xinetd is not enabled (Scored)"
dpkg -s xinetd &> /dev/null
if [ $? -ne 1 ]; then
     systemctl is-enabled xinetd &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t[+] xinetd is enabled so it will disabled now"
          echo -e "\t\t[*] Disabled xinetd"
          systemctl disable xinetd &> /dev/null; echo -e "\t\t\t[*] Done"
     fi
else
     echo -e "\t\t[-] xinetd is already disabled"
fi

echo -e "\t[+] 2.1.11 Ensure openbsd-inetd is not installed (Scored)"
dpkg -s openbsd-inetd &> /dev/null
if [ $? -ne 1 ]; then
    echo -e "\t\t[+] openbsd-inetd is installed so it will be removed"
    apt-get remove -y openbsd-inetd
    echo -e "\t\t\t[*] Done"
else
    echo -e "\t\t[-] openbsd-inetd is not installed"
fi

echo "[+] 2.2 Special Purpose Services"
echo -e "\t[+] 2.2.1 Time Synchronization"
echo -e "\t\t[+] 2.2.1.1 Ensure time synchronization is in use (Not Scored)"
dpkg -s ntp &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t\t[-] Ntp is already installed"
else
     echo -e "\t\t\t[+] Ntp is not installed yet, so it will be install now"
     echo -e "\t\t\t[*] Installing Ntp"
     apt-get install ntp -y &> /dev/null
     echo -e "\t\t\t\t[*] Done"
fi

dpkg -s chrony &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t\t[-] Chrony is already installed"
else
     echo -e "\t\t\t[+] Ntp is not installed yet, so it will be install now"
     echo -e "\t\t\t[*] Installing Chrony"
     apt-get install chrony -y &> /dev/null
     echo -e "\t\t\t\t[*] Done"
fi

echo -e "\t\t[+] 2.2.1.2 Ensure ntp is configured (Scored)"
grep "restrict -4" /etc/ntp.conf &> /dev/null && grep "restrict -6" /etc/ntp.conf &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t\t[*] Configuring ntp.conf"
     grep "restrict -4 default kod nomodify notrap nopeer noquery" /etc/ntp.conf &> /dev/null && grep "restrict -6 default kod nomodify notrap nopeer noquery" /etc/ntp.conf &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t\t[-] restrict already configured"
     else
          sed -i "s/restrict -4 default kod notrap nomodify nopeer noquery limited/restrict -4 default kod nomodify notrap nopeer noquery/g" /etc/ntp.conf &> /dev/null
          sed -i "s/restrict -6 default kod notrap nomodify nopeer noquery limited/restrict -6 default kod nomodify notrap nopeer noquery/g" /etc/ntp.conf &> /dev/null
     fi
     grep "RUNASUSER=ntp" /etc/ntp.conf &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t\t[-] Runuser already configured as ntp"
     else
          sed -i "s/RUNASUSER=/#RUNASUSER=/g" /etc/ntp.conf
          echo "RUNASUSER=ntp" >> /etc/ntp.conf
     fi
     echo -e "\t\t\t\t[*] Done"
else
     echo -e "\t\t\t[-] ntp.conf already configured"
fi

echo -e "\t\t[+] 2.2.1.3 Ensure chrony is configured (Scored)"
grep "^server" /etc/chrony/chrony.conf &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t\t[-] chrony is already configured"
else
     echo -e '\t\t\t[*] Please configure "server" on /etc/chrony/chrony.conf'
fi

echo -e "\t[+] 2.2.2 Ensure X Windows System is not installed (Scored)"
dpkg -l xserver-xorg* &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t[+] X Windows System is installed, so it will removed"
     echo -e "\t\t[*] Removing package"
     apt-get remove xserver-xorg* -y &> /dev/null
     echo -e "\t\t\t[*] Done"
else
     echo -e "\t\t[-] X Windows System is not installed on this server"
fi

echo -e "\t[+] 2.2.3 Ensure Avahi Server is not enabled (Scored)"
dpkg -s avahi-daemon &> /dev/null
if [ $? -ne 1 ]; then
     systemctl is-enabled avahi-daemon &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t[+] Avahi daemon is enable, so it will disabled"
          echo -e "\t\t\t[*] Disabling avahi daemon"
          systemctl disable avahi-daemon &> /dev/null
          echo -e "\t\t\t\t[*] Done"
     else
          echo -e "\t\t[-] Avahi daemon is already disabled"
     fi
else
     echo -e "\t\t[-] Avahi daemon is not installed"
fi

echo -e "\t[+] 2.2.4 Ensure CUPS is not enabled (Scored)"
dpkg -s cups &> /dev/null
if [ $? -ne 1 ]; then
     systemctl is-enabled cups &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t[+] CUPS is enable, so it will disabled"
          echo -e "\t\t\t[*] Disabling CUPS"
          systemctl disable cups &> /dev/null
          echo -e "\t\t\t\t[*] Done"
     else
          echo -e "\t\t[-] CUPS is alreadu disabled"
     fi
else
     echo -e "\t\t[-] CUPS is not installed"
fi

echo -e "\t[+] 2.2.5 Ensure DHCP Server is not enabled (Scored)"
dpkg -s isc-dhcp-server &> /dev/null
if [ $? -ne 1 ]; then
     systemctl is-enabled isc-dhcp-server &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t[+] DHCP Server is enable, so it will disabled"
          echo -e "\t\t\t[*] Disabling DHCP Server"
          systemctl disable isc-dhcp-server &> /dev/null
          echo -e "\t\t\t\t[*] Done"
     else
          echo -e "\t\t[-] DHCP Server is already disabled"
     fi
else
     echo -e "\t\t[-] DHCP Server is not installed"
fi

echo -e "\t[+] 2.2.6 Ensure LDAP server is not enabled (Scored)"
dpkg -s slapd &> /dev/null
if [ $? -ne 1 ]; then
     systemctl is-enabled slapd &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t[+] LDAP Server is enable, so it will disabled"
          echo -e "\t\t\t[*] Disabling LDAP Server"
          systemctl disable slapd &> /dev/null
          echo -e "\t\t\t\t[*] Done"
     else
          echo -e "\t\t[-] LDAP Server is already disabled"
     fi
else
     echo -e "\t\t[-] LDAP Server is not installed"
fi

echo -e "\t[+] 2.2.7 Ensure NFS and RPC are not enabled (Scored)"
dpkg -s nfs-kernel-server &> /dev/null
if [ $? -ne 1 ]; then
     systemctl is-enabled nfs-kernel-server &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t[+] nfs-kernel-server is enabled, so it will disabled"
          echo -e "\t\t[*] Disabling nfs-kernel-server"
          systemctl disable nfs-kernel-server &> /dev/null
          echo -e "\t\t\t[*] Done"
     else
          echo -e "\t\t[-] nfs-kernel-server is already disabled"
     fi
else
     echo -e "\t\t[-] nfs-kernel-server is not installed"
fi

echo -e "\t[+] 2.2.7 Ensure NFS and RPC are not enabled (Scored)"
dpkg -s nfs-kernel-server &> /dev/null
if [ $? -ne 1 ]; then
     systemctl is-enabled nfs-kernel-server &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t[+] nfs-kernel-server is enabled, so it will disabled"
          echo -e "\t\t[*] Disabling nfs-kernel-server"
          systemctl disable nfs-kernel-server &> /dev/null
          echo -e "\t\t\t[*] Done"
     else
          echo -e "\t\t[-] nfs-kernel-server is already disabled"
     fi
else
     echo -e "\t\t[-] nfs-kernel-server is not installed"
fi

dpkg -s rpcbind &> /dev/null
if [ $? -ne 1 ]; then
     systemctl is-enabled rpcbind &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t[+] rpcbind is enabled, so it will disabled"
          echo -e "\t\t[*] Disabling rpcbind"
          service rpcbind stop &> /dev/null
          systemctl disable rpcbind &> /dev/null
          echo -e "\t\t\t[*] Done"
     else
          echo -e "\t\t[-] rpcbind is already disabled"
     fi
else
     echo -e "\t\t[-] rpcbind is not installed"
fi

echo -e "\t[+] 2.2.8 Ensure DNS Server is not enabled (Scored)"
dpkg -s bind9 &> /dev/null
if [ $? -ne 1 ]; then
     systemctl is-enabled bind9 &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t[+] bind9 is enabled, so it will disabled"
          echo -e "\t\t[*] Disabling bind9"
          systemctl disable bind9 &> /dev/null
          echo -e "\t\t\t[*] Done"
    else
          echo -e "\t\t[-] bind9 is already disabled"
    fi
else
    echo -e "\t\t[-] bind9 is not installed"
fi

echo -e "\t[+] 2.2.9 Ensure FTP Server is not enabled (Scored)"
dpkg -s vsftpd &> /dev/null
if [ $? -ne 1 ]; then
     systemctl is-enabled vsftpd &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t[+] vsftpd is enabled, so it will disabled"
          echo -e "\t\t[*] Disabling vsftpd"
          systemctl disable vsftpd &> /dev/null
          echo -e "\t\t\t[*] Done"
     else
          echo -e "\t\t[-] vsftpd is already disabled"
     fi
else
     echo -e "\t\t[-] vsftpd is not installed"
fi

echo -e "\t[+] 2.2.10 Ensure HTTP server is not enabled (Scored)"
dpkg -s apache2 &> /dev/null
if [ $? -ne 1 ]; then
     systemctl is-enabled apache2 &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t[+] apache2 is enabled, so it will disabled"
          echo -e "\t\t[*] Disabling apache2"
          systemctl disable apache2 &> /dev/null
          echo -e "\t\t\t[*] Done"
     else
          echo -e "\t\t[-] apache2 is already disabled"
     fi
else
     echo -e "\t\t[-] apache2 is not installed"
fi

echo -e "\t[+] 2.2.11 Ensure IMAP and POP3 server is not enabled (Scored)"
dpkg -s dovecot &> /dev/null
if [ $? -ne 1 ]; then
     systemctl is-enabled dovecot &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t[+] dovecot is enabled, so it will disabled"
          echo -e "\t\t[*] Disabling dovecot"
          systemctl disable dovecot &> /dev/null
          echo -e "\t\t\t[*] Done"
     else
          echo -e "\t\t[-] dovecot is already disabled"
     fi
else
     echo -e "\t\t[-] dovecot is not installed"
fi

echo -e "\t[+] 2.2.12 Ensure Samba is not enabled (Scored)"
dpkg -s samba &> /dev/null
if [ $? -ne 1 ]; then
     systemctl is-enabled smbd &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t[+] samba is enabled, so it will disabled"
          echo -e "\t\t[*] Disabling samba"
          systemctl disable smbd &> /dev/null
          echo -e "\t\t\t[*] Done"
     else
          echo -e "\t\t[-] samba is already disabled"
     fi
else
     echo -e "\t\t[-] samba is not installed"
fi

echo -e "\t[+] 2.2.13 Ensure HTTP Proxy Server is not enabled (Scored)"
dpkg -s squid &> /dev/null
if [ $? -ne 1 ]; then
     systemctl is-enabled squid &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t[+] squid is enabled, so it will disabled"
          echo -e "\t\t[*] Disabling squid"
          systemctl disable squid &> /dev/null
          echo -e "\t\t\t[*] Done"
     else
          echo -e "\t\t[-] squid is already disabled"
     fi
else
     echo -e "\t\t[-] squid is not installed"
fi

echo -e "\t[+] 2.2.14 Ensure SNMP Server is not enabled (Scored)"
dpkg -s snmpd &> /dev/null
if [ $? -ne 1 ]; then
     systemctl is-enabled snmpd &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t[+] snmpd is enabled, so it will disabled"
          echo -e "\t\t[*] Disabling snmpd"
          systemctl disable snmpd &> /dev/null
          echo -e "\t\t\t[*] Done"
     else
          echo -e "\t\t[-] snmpd is already disabled"
     fi
else
     echo -e "\t\t[-] snmpd is not installed"
fi

echo -e "\t[+] 2.2.15 Ensure mail transfer agent is configured for local-only mode (Scored)"
dpkg -s postfix &> /dev/null
if [ $? -ne 1 ]; then
     grep "inet_interfaces = localhost" /etc/postfix/main.cf &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t[-] It's already configured"
     else
          echo -e "\t\t[+] Adding inet_interfaces on /etc/postfix/main.cf"
          echo -e "\t\t\t[*] Configuring"
          echo "inet_interfaces = loopback-only" >> /etc/postfix/main.cf
          echo -e "\t\t\t\t[*] Done"
          echo -e "\t\t[+] Restarting postfix service"
          systemctl restart postfix &> /dev/null
          echo -e "\t\t\t[*] Done"
    fi
else
     echo -e "\t\t[-] postfix is not installed"
fi

echo -e "\t[+] 2.2.16 Ensure rsync service is not enabled (Scored)"
dpkg -s rsync &> /dev/null
if [ $? -ne 1 ]; then
     systemctl is-enabled rsync &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t[+] rsync is enabled, so it will disabled"
          echo -e "\t\t[*] Disabling rsync"
          systemctl disable rsync &> /dev/null
          echo -e "\t\t\t[*] Done"
     else
          echo -e "\t\t[-] rsync is already disabled"
     fi
else
     echo -e "\t\t[-] rsync is not installed"
fi

echo -e "\t[+] 2.2.17 Ensure NIS Server is not enabled (Scored)"
dpkg -s nis &> /dev/null
if [ $? -ne 1 ]; then
     systemctl is-enabled nis &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t[+] nis is enabled, so it will disabled"
          echo -e "\t\t[*] Disabling nis"
          systemctl disable nis &> /dev/null
          echo -e "\t\t\t[*] Done"
     else
          echo -e "\t\t[-] nis is already disabled"
     fi
else
     echo -e "\t\t[-] nis is not installed"
fi

echo "[+] 2.3 Service Clients"
echo -e "\t[+] 2.3.1 Ensure NIS Client is not installed (Scored)"
dpkg -s nis &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t[+] NIS client is installed, so it will removed"
     echo -e "\t\t[*] Removing nis"
     apt-get remove nis -y &> /dev/null
     echo -e "\t\t\t[*] Done"
else
     echo -e "\t\t[-] nis client is not installed"
fi

echo -e "\t[+] 2.3.2 Ensure rsh client is not installed (Scored)"
dpkg -s rsh-client &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t[+] rsh-client is installed, so it will removed"
     echo -e "\t\t[*] Removing rsh-client"
     apt-get remove rsh-client -y &> /dev/null
     echo -e "\t\t\t[*] Done"
else
     echo -e "\t\t[-] rsh-client is not installed"
fi

dpkg -s rsh-redone-client &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t[+] rsh-redone-client is installed, so it will removed"
     echo -e "\t\t[*] Removing rsh-redone-client"
     apt-get remove rsh-redone-client -y &> /dev/null
     echo -e "\t\t\t[*] Done"
else
     echo -e "\t\t[-] rsh-redone-client is not installed"
fi

echo -e "\t[+] 2.3.3 Ensure talk client is not installed (Scored)"
dpkg -s talk &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t[+] talk is installed, so it will removed"
     echo -e "\t\t[*] Removing talk"
     apt-get remove talk -y &> /dev/null
     echo -e "\t\t\t[*] Done"
else
     echo -e "\t\t[-] talk is not installed"
fi

echo -e "\t[+] 2.3.4 Ensure telnet client is not installed (Scored)"
dpkg -s telnet &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t[+] telnet is installed, so it will removed"
     echo -e "\t\t[*] Removing telnet"
     apt-get remove telnet -y &> /dev/null
     echo -e "\t\t\t[*] Done"
else
     echo -e "\t\t[-] telnet is not installed"
fi

echo -e "\t[+] 2.3.5 Ensure LDAP client is not installed (Scored)"
dpkg -s ldap-utils &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t[+] LDAP client is installed, so it will removed"
     echo -e "\t\t[*] Removing ldap-utils"
     apt-get remove ldap-utils -y &> /dev/null
     echo -e "\t\t\t[*] Done"
else
     echo -e "\t\t[-] LDAP client is not installed"
fi

### 3 Network Configuration
echo "[+] 3.1 Network Parameters (Host Only)"
echo -e "\t[+] 3.1.1 Ensure IP Forwarding is disabled (Scored)"
sysctl net.ipv4.ip_forward | grep 0 &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t[-] IP Forwarding is already disabled"
else
     grep "net.ipv4.ip_forward = 0" /etc/sysctl.conf &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t[-] IP Forwarding is already disabled"
     else
          echo -e "\t\t[+] IP Forwarding is enabled, so it will disabled"
          echo -e "\t\t[*] Configuring IP Forwarding"
          sed -i 's/net.ipv4.ip_forward = 1/net.ipv4.ip_forward = 0/g' /etc/sysctl.conf
          sysctl -w net.ipv4.ip_forward=0 &> /dev/null
          sysctl -w net.ipv4.route.flush=1 &> /dev/null
          echo -e "\t\t\t[*] Done"
     fi
fi

echo -e "\t[+] 3.1.2 Ensure packet redirect sending is disabled (Scored)"
sysctl net.ipv4.conf.all.send_redirects | grep 0 &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t[-] net.ipv4.conf.all.send_redirects is already set to 0"
else
     grep "net.ipv4.conf.all.send_redirects = 0" /etc/sysctl.conf &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t[-] net.ipv4.conf.all.send_redirects is already set to 0"
     else
          echo -e "\t\t[+] net.ipv4.conf.all.send_redirects is not set to 0"
          echo -e "\t\t[*] Configuring net.ipv4.conf.all.send_redirects"
          sed -i 's/net.ipv4.conf.all.send_redirects/#net.ipv4.conf.all.send_redirects/g' /etc/sysctl.conf
          echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
          echo -e "\t\t\t[*] Done"
    fi
fi

sysctl net.ipv4.conf.default.send_redirects | grep 0 &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t[-] net.ipv4.conf.default.send_redirects is already set to 0"
else
     grep "net.ipv4.conf.default.send_redirects = 0" /etc/sysctl.conf &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t[-] net.ipv4.conf.default.send_redirects is already set to 0"
     else
          echo -e "\t\t[+] net.ipv4.conf.default.send_redirects is not set to 0"
          echo -e "\t\t[*] Configuring net.ipv4.conf.default.send_redirects"
          sed -i 's/net.ipv4.conf.default.send_redirects/#net.ipv4.conf.default.send_redirects/g' /etc/sysctl.conf
          echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf
          echo -e "\t\t\t[*] Done"
     fi
fi

echo -e "\t\t[*] Set the active kernel parameters"
sysctl -w net.ipv4.conf.all.send_redirects=0 &> /dev/null
sysctl -w net.ipv4.conf.default.send_redirects=0 &> /dev/null
sysctl -w net.ipv4.route.flush=1 &> /dev/null; echo -e "\t\t\t[*] Done"

echo "[+] 3.2 Network Parameters (Host and Router)"
echo -e "\t[+] 3.2.1 Ensure source routed packets are not accepted (Scored)"
sysctl net.ipv4.conf.all.accept_source_route | grep 0 &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t[-] net.ipv4.conf.all.accept_source_route is already set to 0"
else
     grep "net.ipv4.conf.all.accept_source_route = 0" /etc/sysctl.conf &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t[-] net.ipv4.conf.all.accept_source_route is already set to 0"
     else
          echo -e "\t\t[+] net.ipv4.conf.all.accept_source_route is not set to 0"
          echo -e "\t\t[*] Configuring net.ipv4.conf.all.accept_source_route"
          sed -i 's/net.ipv4.conf.all.accept_source_route/#net.ipv4.conf.all.accpet_source_route/g' /etc/sysctl.conf
          echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
          echo -e "\t\t\t[*] Done"
     fi
fi

sysctl net.ipv4.conf.default.accept_source_route | grep 0 &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t[-] net.ipv4.conf.default.accept_source_route is already set to 0"
else
     grep "net.ipv4.conf.default.accept_source_route = 0" /etc/sysctl.conf &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t[-] net.ipv4.conf.default.accept_source_route is already set to 0"
     else
          echo -e "\t\t[+] net.ipv4.conf.default.accept_source_route is not set to 0"
          echo -e "\t\t[*] Configuring net.ipv4.conf.default.accept_source_route"
          sed -i 's/net.ipv4.conf.default.accept_source_route/#net.ipv4.conf.default.accept_source_route/g' /etc/sysctl.conf
          echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
          echo -e "\t\t\t[*] Done"
    fi
fi

echo -e "\t\t[*] Set the active kernel parameters"
sysctl -w net.ipv4.conf.all.accept_source_route=0 &> /dev/null
sysctl -w net.piv4.conf.default.accept_source_route=0 &> /dev/null
sysctl -w net.ipv4.route.flush=1 &> /dev/null; echo -e "\t\t\t[*] Done"

echo -e "\t[+] 3.2.2 Ensure ICMP redirects are not accepted (Scored)"
sysctl net.ipv4.conf.all.accept_redirects | grep 0 &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t[-] net.ipv4.conf.all.accept_redirects is already set to 0"
else
     grep "net.ipv4.conf.all.accept_redirects = 0" /etc/sysctl.conf &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t[-] net.ipv4.conf.all.accept_redirects is already set to 0"
     else
          echo -e "\t\t[+] net.ipv4.conf.all.accept_redirects is not set to 0"
          echo -e "\t\t[*] Configuring net.ipv4.conf.all.accept_redirects"
          sed -i 's/net.ipv4.conf.all.accept_redirects/#net.ipv4.conf.all.accept_redirects/g' /etc/sysctl.conf
          echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
          echo -e "\t\t\t[*] Done"
     fi
fi

sysctl net.ipv4.conf.default.accept_redirects | grep 0 &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t[-] net.ipv4.conf.default.accept_rediects is already set to 0"
else
     grep "net.ipv4.conf.default.accept_redirects = 0" /etc/sysctl.conf &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t[-] net.ipv4.conf.default.accept_redirects is already set to 0"
     else
          echo -e "\t\t[+] net.ipv4.conf.default.accept_redirects is not set to 0"
          echo -e "\t\t[*] Configuring net.ipv4.conf.default.accept_redirects"
          sed -i 's/net.ipv4.conf.default.accept_redirects/#net.ipv4.conf.default.accept_redirects/g' /etc/sysctl.conf
          echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
          echo -e "\t\t\t[*] Done"
     fi
fi

echo -e "\t\t[*] Set the active kernel parameters"
sysctl -w net.ipv4.conf.all.accept_redirects=0 &> /dev/null
sysctl -w net.ipv4.conf.default.accept_redirects=0 &> /dev/null
sysctl -w net.ipv4.route.flush=1 &> /dev/null; echo -e "\t\t\t[*] Done"

echo -e "\t[+] 3.2.3 Ensure secure ICMP redirects are not accepted (Scored)"
sysctl net.ipv4.conf.all.secure_redirects | grep 0 &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t[-] net.ipv4.conf.all.secure_redirects is already set to 0"
else
     grep "net.ipv4.conf.all.accept_redirects = 0" /etc/sysctl.conf &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t[-] net.ipv4.conf.all.secure_redirects is already set to 0"
     else
          echo -e "\t\t[+] net.ipv4.conf.all.secure_redirects is not set to 0"
          echo -e "\t\t[*] Configuring net.ipv4.conf.all.secure_redirects"
          sed -i 's/net.ipv4.conf.all.secure_redirects/#net.ipv4.conf.all.secure_redirects/g' /etc/sysctl.conf
          echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf
          echo -e "\t\t\t[*] Done"
     fi
fi

sysctl net.ipv4.conf.default.secure_redirects | grep 0 &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t[-] net.ipv4.conf.default.secure_redirects is already set to 0"
else
     grep "net.ipv4.conf.default.secure_redirects = 0" /etc/sysctl.conf &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t[-] net.ipv4.conf.default.secure_redirects is already set to 0"
     else
          echo -e "\t\t[+] net.ipv4.conf.default.secure_redirects is not set to 0"
          echo -e "\t\t[*] Configuring net.ipv4.conf.default.secure_redirects"
          sed -i 's/net.ipv4.conf.default.secure_redirects/#net.ipv4.conf.default.secure_redirects/g' /etc/sysctl.conf
          echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf
          echo -e "\t\t\t[*] Done"
     fi
fi

echo -e "\t\t[*] Set the active kernel parameters"
sysctl -w net.ipv4.conf.all.secure_redirects=0 &> /dev/null
sysctl -w net.ipv4.conf.default.secure_redirects=0 &> /dev/null
sysctl -w.net.ipv4.route.flush=1 &> /dev/null; echo -e "\t\t\t[*] Done"

echo -e "\t[+] 3.2.4 Ensure suspicious packets are logged (Scored)"
sysctl net.ipv4.conf.all.log_martians | grep 1 &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t[-] net.ipv4.conf.all.log_martians is already set to 1 (on)"
else
     grep "net.ipv4.conf.all.log_martians = 1" /etc/sysctl.conf &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t[-] net.ipv4.conf.all.log_martians is already set to 1 (on)"
     else
          echo -e "\t\t[+] net.ipv4.conf.all.log_martians is not set to 1 (on)"
          echo -e "\t\t[*] Configuring net.ipv4.conf.all.log_martians"
          sed -i 's/net.ipv4.conf.all.log_martians/#net.ipv4.conf.all.log_martians/g' /etc/sysctl.conf
          echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf
          echo -e "\t\t\t[*] Done"
     fi
fi

sysctl net.ipv4.conf.default.log_martians | grep 1 &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t[-] net.ipv4.conf.default.log_martians is already set to 1 (on)"
else
     grep "net.ipv4.conf.default.log_martians = 1" /etc/sysctl.conf &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t[-] net.ipv4.conf.default.log_martians is already set to 1 (on)"
     else
          echo -e "\t\t[+] net.ipv4.conf.default.log_martians is not set to 1 (on)"
          echo -e "\t\t[*] Configuring net.ipv4.conf.default.log_martians"
          sed -i 's/net.ipv4.conf.default.log_martians/#net.ipv4.conf.default.log_martians/g' /etc/sysctl.conf
          echo "net.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.conf
          echo -e "\t\t\t[*] Done"
     fi
fi

echo -e "\t\t[*] Set the active kernel parameters"
sysctl -w net.ipv4.conf.all.log_martians=1 &> /dev/null
sysctl -w net.ipv4.conf.default.log_martians=1 &> /dev/null
sysctl -w net.ipv4.route.flush=1 &> /dev/null; echo -e "\t\t\t[*] Done"

echo -e "\t[+] 3.2.5 Ensure broadcast ICMP requests are ignored (Scored)"
sysctl net.ipv4.icmp_echo_ignore_broadcasts | grep 1 &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t[-] net.ipv4.icmp_echo_ignore_broadcasts is already set to 1 (Ignored)"
else
     grep "net.ipv4.icmp_echo_ignore_broadcasts = 1" /etc/sysctl.conf &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t[-] net.ipv4.icmp_echo_ignore_broadcasts is already set to 1 (Ignored)"
     else
          echo -e "\t\t[+] net.ipv4.icmp_echo_ignore_broadcasts is not set to 1 (Ignored)"
          echo -e "\t\t[*] Configuring net.ipv4.icmp_echo_ignore_broadcasts"
          sed -i 's/net.ipv4.icmp_echo_ignore_broadcasts/#net.ipv4.icmp_echo_ignore_broadcasts/g' /etc/sysctl.conf
          echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
          echo -e "\t\t\t[*] Done"
    fi
fi

echo -e "\t\t[*] Set the active kernel parameters"
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1 &> /dev/null
sysctl -w net.ipv4.route.flush=1 &> /dev/nul; echo -e "\t\t\t[*] Done"

echo -e "\t[+] 3.2.6 Ensure bogus ICMP responses are ignored (Scored)"
sysctl net.ipv4.icmp_ignore_bogus_error_responses | grep 1 &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t[-] net.ipv4.icmp_ignore_bogus_error_responses is already set to 1 (Ignored)"
else
     grep "net.ipv4.icmp_ignore_bogus_error_responses = 1" /etc/sysctl.conf &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t[-] net.ipv4.icmp_ignore_bogus_error_responses is already set to 1 (Ignored)"
     else
          echo -e "\t\t[+] net.ipv4.icmp_ignore_bogus_error_responses is not set to 1 (Ignored)"
          echo -e "\t\t[*] Configuring net.ipv4.icmp_ignore_bogus_error_responses"
          sed -i 's/net.ipv4.icmp_ignore_bogus_error_responses/#net.ipv4.icmp_ignore_bogus_responses/g' /etc/sysctl.conf
          echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf
          echo -e "\t\t\t[*] Done"
     fi
fi

echo -e "\t\t[*] Set the active kernel parameters"
sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1 &> /dev/null
sysctl -w net.ipv4.route.flush=1 &> /dev/null; echo -e "\t\t\t[*] Done"

echo -e "\t[+] 3.2.7 Ensure Reverse Path Filtering is enabled (Scored)"
sysctl net.ipv4.conf.all.rp_filter | grep 1 &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t[-] net.ipv4.conf.all.rp_filter is already set to 1 (Enabled)"
else
     grep "net.ipv4.conf.all.rp_filter = 1" /etc/sysctl.conf &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t[-] net.ipv4.conf.all.rp_filter is already set to 1 (Enabled)"
     else
          echo -e "\t\t[-] net.ipv4.conf.all.rp_filter is not set to 1 (Enabled)"
          echo -e "\t\t[*] Configuring net.ipv4.conf.all.rp_filter"
          sed -i 's/net.ipv4.conf.all.rp_filter/#net.ipv4.conf.all.rp_filter/g' /etc/sysctl.conf
          echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf
          echo -e "\t\t\t[*] Done"
     fi
fi

sysctl net.ipv4.conf.default.rp_filter | grep 1 &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t[-] net.ipv4.conf.default.rp_filter is already set to 1 (Enabled)"
else
     grep "net.ipv4.conf.default.rp_filter = 1" /etc/sysctl.conf &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t[-] net.ipv4.conf.default.rp_filter is already set to 1 (Enabled)"
     else
          echo -e "\t\t[+] net.ipv4.conf.default.rp_filter is not set to 1 (Enabled)"
          echo -e "\t\t[*] Configuring net.ipv4.conf.default.rp_filter"
          sed -i 's/net.ipv4.conf.default.rp_filter/#net.ipv4.conf.default.rp_filter/g' /etc/sysctl.conf
          echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.conf
          echo -e "\t\t\t[*] Done"
    fi
fi

echo -e "\t\t[*] Set the active kernel parameters"
sysctl -w net.ipv4.conf.all.rp_filter=1 &> /dev/null
sysctl -w net.ipv4.conf.default.rp_filter=1 &> /dev/null
sysctl -w net.ipv4.route.flush=1 &> /dev/null; echo -e "\t\t\t[*] Done"

echo -e "\t[+] 3.2.8 Ensure TCP SYN Cookies is enabled (Scored)"
sysctl net.ipv4.tcp_syncookies | grep 1 &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t[-] net.ipv4.tcp_syncookies is already set to 1 (Enabled)"
else
     grep "net.ipv4.tcp_syncookies = 1" /etc/sysctl.conf &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t[-] net.ipv4.tcp_syncookies is already set to 1 (Enabled)"
     else
          echo -e "\t\t[+] net.ipv4.tcp_syncookies is not set to 1 (Enabled)"
          echo -e "\t\t[*] Configuring net.ipv4.tcp_syncookies"
          sed -i 's/net.ipv4.tcp_syncookies/#net.ipv4.tcp_syncookies/g' /etc/sysctl.conf
          echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
          echo -e "\t\t\t[*] Done"
    fi
fi

echo -e "\t\t[*] Sset the active kernel parameters"
sysctl -w net.ipv4.tcp_syncookies=1 &> /dev/null
sysctl -w net.ipv4.route.flush=1 &> /dev/null; echo -e "\t\t\t[*] Done"

echo "[+] 3.3 IPv6"
echo -e "\t[+] 3.3.1 Ensure IPv6 router advertisements are not accepted (Not Scored)"
sysctl net.ipv6.conf.all.accept_ra | grep 0 &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t[-] net.ipv6.conf.all.accept_ra is already set to 0"
else
     grep "net.ipv6.conf.all.accept_ra = 0" /etc/sysctl.conf &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t[-] net.ipv6.conf.all.accept_ra is already set to 0"
     else
          echo -e "\t\t[+] net.ipv6.conf.all.accept_ra is not set to 0"
          echo -e "\t\t[*] Configuring net.ipv6.conf.all.accpet_ra"
          sed -i 's/net.ipv6.conf.all.accept_ra/#net.ipv6.conf.all.accept_ra/g' /etc/sysctl.conf
          echo "net.ipv6.conf.all.accept_ra = 0" >> /etc/sysctl.conf
          echo -e "\t\t\t[*] Done"
     fi
fi

sysctl net.ipv6.conf.default.accept_ra | grep 0 &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t[-] net.ipv6.conf.default.accept_ra is already set to 0"
else
    grep "net.ipv6.conf.default.accept_ra = 0" /etc/sysctl.conf &> /dev/null
    if [ $? -ne 1 ]; then
         echo -e "\t\t[-] net.ipv6.conf.default.accept_ra is already set to 0"
    else
         echo -e "\t\t[+] net.ipv6.conf.default.accept_ra is not set to 0"
         echo -e "\t\t[*] Configuring net.ipv6.conf.default.accept_ra"
         sed -i 's/net.ipv6.conf.default.accept_ra/#net.ipv6.conf.default.accept_ra/g' /etc/sysctl.conf
         echo "net.ipv6.conf.default.accept_ra = 0" >> /etc/sysctl.conf
         echo -e "\t\t\t[*] Done"
    fi
fi

echo -e "\t\t[*] Set the active kernel parameters"
sysctl -w net.ipv6.conf.all.accept_ra=0 &> /dev/null
sysctl -w net.ipv6.conf.default.accept_ra=0 &> /dev/null
sysctl -w net.ipv6.route.flush=1 &> /dev/null; echo -e "\t\t\t[*] Done"

echo -e "\t[+] 3.3.2 Ensure IPv6 redirects are not accepted (Not Scored)"
sysctl net.ipv6.conf.all.accept_redirects | grep 0 &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t[-] net.ipv6.conf.all.accept_redirects is already set to 0"
else
     grep "net.ipv6.conf.all.accept_redirects = 0" /etc/sysctl.conf &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t[-] net.ipv6.conf.all.accept_redirects is already set to to 0"
     else
          echo -e "\t\t[+] net.ipv6.conf.all.accept_redirects is not set to 0"
          echo -e "\t\t[*] Configuring net.ipv6.conf.all.accept_redirects"
          sed -i 's/net.ipv6.conf.all.accept_redirects/#net.ipv6.conf.all.accept_redirects/g' /etc/sysctl.conf
          echo "net.ipv6.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
          echo -e "\t\t\t[*] Done"
     fi
fi

sysctl net.ipv6.conf.default.accept_redirects | grep 0 &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t[-] net.ipv6.conf.default.accept_redirects is already set to 0"
else
     grep "net.ipv6.conf.default.accept_redirects = 0" /etc/sysctl.conf &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t[-] net.ipv6.conf.default.accept_redirects is already set to 0"
     else
          echo -e "\t\t[+] net.ipv6.conf.default.accept_redirects is not set to 0"
          echo -e "\t\t[*] Configuring net.ipv6.conf.default.accept_redirects"
          sed -i 's/net.ipv6.conf.default.accept_redirects/#net.ipv6.conf.default.accept_redirects/g' /etc/sysctl.conf
          echo "net.ipv6.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
          echo -e "\t\t\t[*] Done"
    fi
fi

echo -e "\t\t[*] Set the active kernel parameters"
sysctl -w net.ipv6.conf.all.accept_redirects=0 &> /dev/null
sysctl -w net.ipv6.conf.default.accept_redirects=0 &> /dev/null
sysctl -w net.ipv6.route.flush=1 &> /dev/null; echo -e "\t\t\t[*] Done"

echo -e "\t[+] 3.3.3 Ensure IPv6 is disabled (Not Scored)"
cat /proc/1/cgroup | grep docker &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t[-] You're inside a container so it will skipped"
else
     echo -e "\t\t[+] Disabling IPv6"
     echo 'GRUB_CMDLINE_LINUX="ipv6.disable=1"' >> /etc/default/grub; echo -e "\t\t\t[*] Done"
     echo -e "\t\t[*] Updating grub2"
     update-grub; echo -e "\t\t\t[*] Done"
fi

echo "[+] 3.4 TCP Wrappers"
echo -e "\t[+] 3.4.1 Ensure TCP Wrappers is installed (Scored)"
dpkg -s tcpd &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t[-] tcpd is already installed"
else
     echo -e "\t\t[+] tcpd is not installed yet, so it will installed"
     echo -e "\t\t[*] Installing tcpd"
     apt-get install -y tcpd; echo -e "\t\t\t[*] Done"
fi

echo -e "\t[+] 3.4.2 Ensure /etc/hosts.allow is configured (Scored)"
echo -e "\t\t[-] No specific IP, so it will skipped"

echo -e "\t[+] 3.4.2 Ensure /etc/hosts.deny is configured (Scored)"
echo -e "\t\t[-] No specific IP, so it will skipped"

echo -e "\t[+] 3.4.4 Ensure permissions on /etc/hosts.allow are configured (Scored)"
echo -e "\t\t[*] Configuring permissions hosts.allow"
chown root:root /etc/hosts.allow
chmod 644 /etc/hosts.allow; echo -e "\t\t\t[*] Done"

echo -e "\t[+] 3.4.5 Ensure permissions on /etc/hosts.deny are 644 (Scored)"
chown root:root /etc/hosts.deny
chmod 644 /etc/hosts.deny; echo -e "\t\t\t[*] Done"

echo "[+] 3.5 Uncommon Network Protocols"
echo -e "\t[+] 3.5.1 Ensure DCCP is disabled (Not Scored)"
cat /etc/modprobe.d/CIS.conf | grep dccp &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t[-] dccp is already disabled"
else
     echo -e "\t\t[+] dccp is still enable, so it will disabled"
     echo -e "\t\t[*] Disabling dccp"
     echo "install dccp /bin/true" >> /etc/modprobe.d/CIS.conf
     echo -e "\t\t\t[*] Done"
fi

echo -e "\t[+] 3.5.2 Ensure SCTP is disabled (Not Scored)"
cat /etc/modprobe.d/CIS.conf | grep sctp &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t[-] sctp is already disabled"
else
     echo -e "\t\t[+] stcp is still enable, so it will disabled"
     echo -e "\t\t[*] Disabling sctp"
     echo "install sctp /bin/true" >> /etc/modprobe.d/CIS.conf
     echo -e "\t\t\t[*] Done"
fi

echo -e "\t[+] 3.5.3 Ensure RDS is disabled (Not Scored)"
cat /etc/modprobe.d/CIS.conf | grep rds &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t[-] rds is already disabled"
else
     echo -e "\t\t[+] rds is still enable, so it will disabled"
     echo -e "\t\t[*] Disabling rds"
     echo "install rds /bin/true" >> /etc/modprobe.d/CIS.conf
     echo -e "\t\t\t[*] Done"
fi

echo -e "\t[+] 3.5.4 Enssure TIPC is disabled (Not Scored)"
cat /etc/modprobe.d/CIS.conf | grep tipc &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t[-] tipc is already disabled"
else
     echo -e "\t\t[+] tipc is still enable, so it will disabled"
     echo -e "\t\t[*] Disabling tipc"
     echo "install tipc /bin/true" >> /etc/modprobe.d/CIS.conf
     echo -e "\t\t\t[*] Done"
fi

echo "[+] 3.6 Firewall Configuration"
echo -e "\t[+] 3.6.1 Ensure iptables is installed (Scored)"
dpkg -s iptables &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t[-] iptables is already installed"
else
     echo -e "\t\t[+] iptables is not installed, so it will be install"
     echo -e "\t\t[*] Installing iptables"
     apt-get install -y iptables &> /dev/null; echo -e "\t\t\t[*] Done"
fi

cat /proc/1/cgroup | grep docker &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t[-] You're inside a container so the requirements below will not execute"
     echo -e "\t\t[1] 3.6.2 Ensure default deny firewall policy (Scored)"
     echo -e "\t\t[2] 3.6.3 Ensure loopback traffic is configured (Scored)"
     echo -e "\t\t[3] 3.6.4 Ensure outbound and established connections are configured (Not Scored)"
     echo -e "\t\t[4] 3.6.5 Ensure firewall rules exist for all open ports (Scored)"
else
     echo -e "\t[+] Requirements below will execute with iptables script"
     echo -e "\t\t[1] 3.6.2 Ensure default deny firewall policy (Scored)"
     echo -e "\t\t[2] 3.6.3 Ensure loopback traffic is configured (Scored)"
     echo -e "\t\t[3] 3..6.4 Ensure outbound and established connections are configured (Not Scored)"
     echo -e "\t\t[4] 3.6.5 Ensure firewall rules exist for all open ports (scored)"
     echo -e "\t\t\t[*] Executing iptables rules"
     sh templates/iptables-CIS.sh &> /dev/null; echo -e "\t\t\t\t[*] Done"
fi

echo "[+] 3.7 Ensure wireless interfaces are disabled (Not Scored)"
echo -e "\t[+] Please disable wireless interfaces on the system if not needed"

echo "[+] 4 Logging and Auditing"
echo -e "\t[+] 4.1 Configure System Accounting (auditd)"
dpkg -s auditd &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t[+] auditd is installed so it will reload"
     echo -e "\t\t[*] Reload auditd"
     service auditd reload &> /dev/null; echo -e "\t\t\t[*] Done"
else
     echo -e "\t\t[-] auditd is not installed so it will installed"
     echo -e "\t\t[*] Installing auditd"
     apt-get install -y auditd &> /dev/null; echo -e "\t\t\t\[*] Done"
fi

echo -e "\t\t[+] 4.1.1 Configure Data Retention"
echo -e "\t\t\t[+] Requirements below will execute with auditd-CIS.conf script"
echo -e "\t\t\t\t[1] 4.1.1.1 Ensure audit log storage size is configured (Not Scored)"
apt-get install -y auditd &> /dev/null
echo -e "\t\t\t\t[2] 4.1.1.2 Ensure system is disabled when audit logs are full (Scored)"
echo -e "\t\t\t\t[3] 4.1.1.3 Ensure audit logs are not automatically deleted (Scored)"
echo -e "\t\t\t\t[4] Ensure audit logs are not automatically deleted (Scored)"
echo -e "\t\t\t\t\t[*] Executing script"
cp -f templates/auditd-CIS.conf /etc/audit/auditd.conf; echo -e "\t\t\t\t\t\t[*] Done"

echo -e "\t\t[+] 4.1.2 Ensure auditd service is enabled (Scored)"
systemctl is-enabled auditd &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t\t[+] auditd is already enabled"
else
     echo -e "\t\t\t[-] auditd is disabled, so it will enabled"
     echo -e "\t\t\t[*] Enabling auditd service"
     systemctl enable auditd &> /dev/null
     echo -e "\t\t\t\t[*] Done"
fi

echo -e "\t\t[+] 4.1.3 Ensure auditing for processes that start prior to auditd is enabled (Scored)"
cat /etc/default/grub | grep "audit=1" /etc/default/grub &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t\t[+] auditd is already exists on default grub"
else
     echo -e "\t\t\t[-] auditd is not exists on default grub, so it will added"
     echo -e "\t\t\t[*] Processing"
     echo 'GRUB_CMDLINE_LINUX="audit=1"' >> /etc/default/grub
     echo -e "\t\t\t\t[*] Done"
     echo -e "\t\t\t[*] Updating grub"
     update-grub &> /dev/null; echo -e "\t\t\t\t[*] Done"
fi

echo -e "\t\t[+] Requirements below will execute with audit.rules"
echo -e "\t\t\t[1] 4.1.4 Ensure events that modify date and time information are collected (Scored)"
echo -e "\t\t\t[2] 4.1.5 Ensure events that modify user/group information are collected (Scored)"
echo -e "\t\t\t[3] 4.1.6 Ensure events that modify system's network environment are collected (Scored)"
echo -e "\t\t\t[4] 4.1.7 Ensure events that modify system's Mandatory Access Controls are collected (Scored)"
echo -e "\t\t\t[5] 4.1.8 Ensure login and logout events are collected (Scored)"
echo -e "\t\t\t[6] 4.1.9 Ensure session intiation information is collected (Scored)"
echo -e "\t\t\t[7] 4.1.10 Ensure disretionary access control permission modification events are collected (Scored)"
echo -e "\t\t\t[8] 4.1.11 Ensure unsuccessful unauthorized file access attempts are collected (Scored)"
echo -e "\t\t\t[9] 4.1.12 Ensure use of privileged commands is collected (Scored)"
echo -e "\t\t\t[10] 4.1.13 Ensure successful file system mounts are collected (Scored)"
echo -e "\t\t\t[11] 4.1.14 Ensure file deletion events by users are collected (Scored)"
echo -e "\t\t\t[12] 4.1.15 Ensure changes to system administration scope (sudoers) is collected (Scored)"
echo -e "\t\t\t[13] 4.1.16 Ensure system administrator actions (sudolog) are collected (Scored)"
echo -e "\t\t\t[14] 4.1.17 Ensure kernel module loading and unloading is collected (Scored)"
echo -e "\t\t\t[15] 4.1.18 Ensure the audit configuration is immutable (Scored)"
echo -e "\t\t\t\t[*] Executing script"
cp -f templates/audit-CIS.rules /etc/audit/audit.rules

find / -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print \
"-a always,exit -F path=" $1 " -F perm=x -F auid>=1000 -F auid!=4294967295 \
-k privileged" } ' >> /etc/audit/audit.rules

echo " " >> /etc/audit/audit.rules
echo "#End of Audit Rules" >> /etc/audit/audit.rules
echo "-e 2" >> /etc/audit/audit.rules

cp -f /etc/audit/audit.rules /etc/audit/rules.d/audit.rules; echo -e "\t\t\t\t\t[*] Done"

echo -e "\t[+] 4.2 Configure Logging"
echo -e "\t\t[+] 4.2.1 Configure rsyslog"
echo -e "\t\t\t[+] 4.2.1.1 Ensure rsyslog Service is enabled (Scored)"
systemctl is-enabled rsyslog &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t\t\t[+] rsyslog is already enabled"
else
     echo -e "\t\t\t\t[-] rsyslog is disabled, so it will enabled"
     echo -e "\t\t\t\t\t[*] Enabling rsyslog"
     systemctl enable rsyslog &> /dev/null; echo -e "\t\t\t\t\t\t[*] Done"
fi

echo -e "\t\t\t[+] 4.2.1.2 Ensure logging is configured (Not Scored)"
echo -e "\t\t\t\t[*] Restarting rsyslog"
pkill -HUP rsyslogd &> /dev/null; echo -e "\t\t\t\t\t[*] Done"

echo -e "\t\t\t[+] 4.2.1.3 Ensure rsyslog default file permissions configured (Scored)"
grep "^\$FileCreateMode 0640" /etc/rsyslog.conf &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t\t\t[+] default file permissions is already configured"
else
     echo -e "\t\t\t\t[-] default file permissions is not configured, so it will configured"
     echo -e "\t\t\t\t\t[*] Configure rsyslog.conf"
     sed -i 's/$FileCreateMode/#FileCreateMode/g' /etc/rsyslog.conf
     echo "$FileCreateMode 0640" >> /etc/rsyslog.conf
     echo -e "\t\t\t\t\t\t[*] Done"
fi

echo -e "\t\t\t[+] 4.2.1.4 Ensure rsyslog is configured to send logs to a remote log host (Scored)"
echo -e "\t\t\t\t[-] This requirements not available to automate, please configure manually"

echo -e "\t\t\t[+] 4.1.2.5 Ensure remote rsyslog messages are only accepted on designated log hosts (Not Scored)"
echo -e "\t\t\t\t[-] This hosts are not designated as log hosts so it will skipped"

echo -e "\t\t[+] 4.2.2 Configure syslog-ng"
echo -e "\t\t\t[+] 4.2.2.1 Ensure syslog-ng service is enabled (Scored)"
dpkg -s syslog-ng &> /dev/null
if [ $? -ne 1 ]; then
     systemctl is-enabled syslog-ng &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t\t\t[+] syslog-ng service is already enabled"
     else
          echo -e "\t\t\t\t[-] syslog-ng service is disabled, so it will enabled"
          echo -e "\t\t\t\t\t[*] Enabling syslog-ng service"
          update-rc.d syslog-ng enable &> /dev/null; echo -e "\t\t\t\t\t\t[*] Done"
     fi
else
     echo -e "\t\t\t\t[-] syslog-ng is not installed, so it will skipped"
fi

echo -e "\t\t\t[+] 4.2.2.2 Ensure logging is configured (Not Scored)"
dpkg -s syslog-ng &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t\t\t[+] Please edit the log on /etc/syslog-ng/syslog-ng.conf make sure file as appropiate for your environment"
else
     echo -e "\t\t\t\t[-] syslog-ng is not installed, so it will skipped"
fi

echo -e "\t\t\t[+] 4.2.2.3 Ensure syslog-ng default file permissions configured (Scored)"
dpkg -s syslog-ng &> /dev/null
if [ $? -ne 1 ]; then
     grep "^options { chain_hostnames(off); flush_lines(0); perm(0640); stats_freq(3600); threaded(yes); };" /etc/syslog-ng/syslog-ng.conf &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t\t\t[+] syslog-ng default file permissions is already configured"
     else
          echo "options { chain_hostnames(off); flush_lines(0); perm(0640); stats_freq(3600); threaded(yes); };" >> /etc/syslog-ng/syslog-ng.conf
     fi
else
     echo -e "\t\t\t\t[-] syslog-ng is not installed, so it will skipped"
fi

echo -e "\t\t\t[+] 4.2.2.4 Ensure syslog-ng is configured to send logs to a remote log host (Scored)"
dpkg -s syslog-ng &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t\t\t[+] This requirements is not available to automate, please configure manually"
else
     echo -e "\t\t\t\t[-] syslog-ng is not installed, so it will skipped"
fi

echo -e "\t\t\t[+] 4.2.2.5 Ensure remote syslog-ng messages are only accepted on designated log hosts (Scored)"
echo -e "\t\t\t\t[-] This requirements not available to automate, please configure manually"

echo -e "\t\t[+] 4.2.3 Ensure rsyslog or syslog-ng is installed (Scored)"
dpkg -s rsyslog &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t\t[+] rsyslog is already installed"
else
     dpkg -s syslog-ng &> /dev/null
     if [ $? -ne 1 ]; then
          echo -e "\t\t\t[+] syslog-ng is already installed"
     else
          echo -e "\t\t\t[-] rsyslog or syslog-ng is not installed, so rsyslog will installed"
          echo -e "\t\t\t\t[*] Installing rsyslog"
          apt-get install rsyslog -y &> /dev/null; echo -e "\t\t\t\t\t[*] Done"
     fi
fi

echo -e "\t\t[+] 4.2.4 Ensure permissions on all logfiles are configured (Scored)"
echo -e "\t\t\t[*] Configuring permissions logfiles"
chmod -R g-wx,o-rwx /var/log/* &> /dev/null; echo -e "\t\t\t\t[*] Done"

echo -e "\t[+] 4.3 Ensure logrotate is configurated (Not Scored)"
echo -e "\t\t[*] Done"

echo "[+] Access, Authentication, Authorization"
echo -e "\t[+] 5.1 Configure cron"
echo -e "\t\t[+] 5.1.1 Ensure cron daemon is enabled (Scored)"

systemctl is-enabled cron &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t\t[+] Cron is already enabled"
else
     echo -e "\t\t\t[-] Cron is disabled, so it will enabled"
     echo -e "\t\t\t\t[*] Enabling cron"
     systemctl enable cron; echo -e "\t\t\t\t\t[*] Done"
fi

echo -e "\t\t[+] 5.1.2 Ensure permissions on /etc/crontab are configured (Scored)"
echo -e "\t\t\t[*] Configuring permissions on /etc/crontab"
chown root:root /etc/crontab
chmod og-rwx /etc/crontab; echo -e "\t\t\t\t[*] Done"

echo -e "\t\t[+] 5.1.3 Ensure permissions on /etc/cron.hourly are configured (Scored)"
echo -e "\t\t\t[*] Configuring permissions on /etc/cron.hourly"
chown root:root /etc/cron.hourly
chmod og-rwx /etc/cron.hourly; echo -e "\t\t\t\t[*] Done"

echo -e "\t\t[+] 5.1.4 Ensure permissions on /etc/cron.daily are configured (Scored)"
echo -e "\t\t\t[*] Configuring permissions on /etc/cron.daily"
chown root:root /etc/cron.daily
chmod og-rwx /etc/cron.daily; echo -e "\t\t\t\t[*] Done"

echo -e "\t\t[+] 5.1.5 Ensure permissions on /etc/cron.weekly are configured (Scored)"
echo -e "\t\t\t[*] Configuring permissions on /etc/cron.weekly"
chown root:root /etc/cron.weekly
chmod og-rwx /etc/cron.weekly; echo -e "\t\t\t\t[*] Done"

echo -e "\t\t[+] 5.1.6 Ensure permissions on /etc/cron.monthly are configured (Scored)"
echo -e "\t\t\t[*] Configuring permissions on /etc/cron.monthly"
chown root:root /etc/cron.monthly
chmod og-rwx /etc/cron.monthly; echo -e "\t\t\t\t[*] Done"

echo -e "\t\t[+] 5.1.7 Ensure permissions on /etc/cron.d are configured (Scored)"
echo -e "\t\t\t[*] Configuring permissions on /etc/cron.d"
chown root:root /etc/cron.d
chmod og-rwx /etc/cron.d; echo -e "\t\t\t\t[*] Done"

echo -e "\t\t[+] 5.1.8 Ensure at/cron is restricted to authorized users (Scored)"
echo -e "\t\t\t[*] Removing /etc/cron.deny"; rm -f /etc/cron.deny; echo -e "\t\t\t\t[*] Done"
echo -e "\t\t\t[*] Removing /etc/at.deny"; rm -f /etc/at.deny; echo -e "\t\t\t\t[*] Done"
echo -e "\t\t\t[*] Creating file /etc/cron.allow"
CRONALLOW=/etc/cron.allow
if test -f "$CRONALLOW"; then
     echo -e "\t\t\t\t[+] cron.allow is already exists"
else
     touch /etc/cron.allow
     echo -e "\t\t\t\t[*] Done"
fi
echo -e "\t\t\t[*] Creating file /etc/at.allow"
CRONAT=/etc/at.allow
if test -f "$CRONAT"; then
     echo -e "\t\t\t\t[+] at.allow is already exists"
else
     touch /etc/at.allow
     echo -e "\t\t\t\t[*] Done"
fi
echo -e "\t\t\t[*] Configuring permissions cron.allow and at.allow"
chmod og-rwx /etc/cron.allow
chmod og-rwx /etc/at.allow
chown root:root /etc/cron.allow
chown root:root /etc/at.allow
echo -e "\t\t\t\t[*] Done"

echo -e "\t[+] 5.2 SSH Server Configuration"
echo -e "\t\t[+] 5.2.1 Ensure ppermissions on /etc/sshd_config are configured (Scored)"
echo -e "\t\t[+] 5.2.2 Ensure SSH Protocol is set to 2 (Scored)"
echo -e "\t\t[+] 5.2.3 Ensure SSH LogLevel is set to INFO (Scored)"
echo -e "\t\t[+] 5.2.4 Ensure SSH X11 forwarding is disabled (Scored)"
echo -e "\t\t[+] 5.2.5 Ensure SSH MaxAuthTries is set to 4 or less (Scored)"
echo -e "\t\t[+] 5.2.6 Ensure SSH IgnoreRhosts is enabled (Scored)"
echo -e "\t\t[+] 5.2.7 Ensure SSH HostbasedAuthentication is disabled (Scored)"
echo -e "\t\t[+] 5.2.8 Ensure SSH root login is disabled (Scored)"
echo -e "\t\t[+] 5.2.9 Ensure SSH PermitEmptyPasswords is disabled (Scored)"
echo -e "\t\t[+] 5.2.10 Ensure SSH PermitUserEnvironment is disabled (Scored)"
echo -e "\t\t[+] 5.2.11 Ensure only approved MAC algorithms are used (Scored)"
echo -e "\t\t[+] 5.2.12 Ensure SSH Idle Timeout Interval is configured (Scored)"
echo -e "\t\t[+] 5.2.13 Ensure SSH LoginGraceTime is set to one minute or less (Scored)"
echo -e "\t\t[+] 5.2.14 Ensure SSH access is limited (Scored)"
echo -e "\t\t[+] 5.2.15 Ensure SSH warning banner is configured (Scored)"
echo -e "\t\t\t[*] Requirements above will execute below"
echo -e "\t\t\t\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
echo -e "\t\t\t\e[93m[+]\e[00m We will now Create a New User for SSH Access"
echo -e "\t\t\t\e[34m---------------------------------------------------------------------------------------------------------\e[00m"
echo ""
echo -ne "\t\t\t Type the new username: "; read username
echo -e "\t\t\t" && adduser $username

echo -n "Securing SSH..."
sed s/USERNAME/$username/g templates/sshd_config-CIS > /etc/ssh/sshd_config; echo "OK"
service ssh restart

chown root:root /etc/ssh/sshd_config
chmod og-rwx /etc/ssh/sshd_config
echo -e "\t\t\t\t[*] Done"

echo -e "\t[+] 5.3 Configure PAM"
echo -e "\t\t[+] 5.3.1 Ensure password creation requirements are configured (Scored)"
echo -e "\t\t[+] 5.3.2 Ensure lockout for failed password attempts is configured (Not Scored)"
echo -e "\t\t[+] 5.3.3 Ensure password reuse is limited (Scored)"
echo -e "\t\t[+] 5.3.4 Ensure password hashing algorithm is SHA-512 (Scored)"
echo -e "\t\t\t[*] Requirements above will execute below"
echo -e "\t\t\t[*] Configuring"
cp templates/common-passwd-CIS /etc/pam.d/common-passwd
cp templates/pwquality-CIS.conf /etc/security/pwquality.conf
cp templates/common-auth-CIS /etc/pam.d/common-auth
echo -e "\t\t\t\t[*] Done"

echo -e "\t[+] 5.4 User Accounts and Environment"
echo -e "\t\t[+] 5.4.1 Set Shadow Password Suite Parameters"
echo -e "\t\t\t[+] 5.4.1.1 Ensure password expiration is 90 days or less (Scored)"
echo -e "\t\t\t[+] 5.4.1.2 Ensure minimum days between password changes is 7 or more (Scored)"
echo -e "\t\t\t[+] 5.4.1.3 Ensure password expiration warning days is 7 or more (Scored)"
echo -e "\t\t\t\t[*] Requirements above will execute below"
echo -e "\t\t\t\t[*] Configuring /etc/login.defs"
cp templates/login.defs-CIS /etc/login.defs; echo -e "\t\t\t\t[*] Done"
echo -e "\t\t\t[+] 5.4.1.4 Ensure inactive password lock is 30 days or less (Scored)"
useradd -D | grep "INACTIVE=30" &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t\t\t[-] Inactive password lock is already set to 30"
else
     echo -e "\t\t\t\t[+] Inactive password is not set to 30, so it will set to 30"
     echo -e "\t\t\t\t\t[*] Configure inactive password"
     useradd -D -f 30; echo -e "\t\t\t\t\t\t[*] Done"
fi

echo -e "\t\t[+] 5.4.2 Ensure system accounts are non-login (Scored)"
echo -e "\t\t\t[*] Configure accounts are non-login"
for user in `awk -F: '($3 < 1000) {print $1 }' /etc/passwd`; do
  if [ $user != "root" ]; then
    usermod -L $user &> /dev/null
    if [ $user != "sync" ] && [ $user != "shutdown" ] && [ $user != "halt" ]; then
      usermod -s /usr/sbin/nologin $user &> /dev/null
    fi
  fi
done
echo -e "\t\t\t\t[*] Done"

echo -e "\t\t[+] 5.4.3 Ensure default group for the root account is GID 0 (Scored)"
echo -e "\t\t\t[*] Configuring"
usermod -g 0 root &> /dev/null; echo -e "\t\t\t\t[*] Done"

echo -e "\t\t[+] 5.4.4 Ensure default user umask is 027 or more restrictive (Scored)"
echo -e "\t\t\t[*] Configuring default user"
umask 027 /etc/bash.bashrc; umask 027 /etc/profile; echo -e "\t\t\t\t[*] Done"

echo -e "\t[+] 5.5 Ensure root login is restricted to system console (Not Scored)"
echo -e "\t\t[-] This requirements is not available to automate, please configure manually"
echo -e "\t\t[+] Please see manually system console at /etc/securetty"

echo -e "\t[+] 5.6 Ensure access to the su command is restricted (Scored)"
grep "auth required pam_wheel.so use_uid" /etc/pam.d/su &> /dev/null
if [ $? -ne 1 ]; then
     echo -e "\t\t[-] su command is already restricted on /etc/pam.d/su"
else
     echo -e "\t\t[+] su command is not restricted yet"
     echo -e "\t\t\t[*] restricted su command"
     echo "auth required pam_wheel.so use_uid" >> /etc/pam.d/su; echo -e "\t\t\t\t[*] Done"
fi

echo "[+] 6 System Maintenance"
echo -e "\t[+] 6.1 System File Permissions"
echo -e "\t\t[+] 6.1.1 Audit system file permissions (Not Scored)"
echo -e "\t\t\t[-] This requirements is not available to automate, please configure manually"
echo -e "\t\t\t[+] You could manually verify using dpkg --verify > <filename>"

echo -e "\t\t[+] 6.1.2 Ensure permissions on /etc/passwd are configured (Scored)"
echo -e "\t\t\t[*] Configuring permissions on /etc/passwd"
chown root:root /etc/passwd; chmod 644 /etc/passwd; echo -e "\t\t\t\t[*] Done"

echo -e "\t\t[+] 6.1.3 Ensure permissions on /etc/shadow are configured (Scored)"
echo -e "\t\t\t[*] Configuring permissions on /etc/shadow"
chown root:shadow /etc/shadow; chmod o-rwx,g-wx /etc/shadow; echo -e "\t\t\t\t[*] Done"

echo -e "\t\t[+] 6.1.4 Ensure permissions on /etc/group are configured (Scored)"
echo -e "\t\t\t[*] Configuring permissions on /etc/group"
chown root:root /etc/group; chmod 644 /etc/group; echo -e "\t\t\t\t[*] Done"

echo -e "\t\t[+] 6.1.5 Ensure permissions on /etc/gshadow are configured (Scored)"
echo -e "\t\t\t[*] Configuring permissions on /etc/gshadow"
chown root:shadow /etc/gshadow; chmod o-rwx,g-wx /etc/gshadow; echo -e "\t\t\t\t[*] Done"

echo -e "\t\t[+] 6.1.6 Ensure permissions on /etc/passwd- are configured (Scored)"
echo -e "\t\t\t[*] Configuring permissions on /etc/passwd-"
chown root:root /etc/passwd-; chmod 600 /etc/passwd-; echo -e "\t\t\t\t[*] Done"

echo -e "\t\t[+] 6.1.7 Ensure permissions on /etc/shadow- are configured (Scored)"
echo -e "\t\t\t[*] Configuring permissions on /etc/shadow-"
chown root:root /etc/shadow-; chmod 600 /etc/shadow-; echo -e "\t\t\t\t[*] Done"

echo -e "\t\t[+] 6.1.8 Ensure permissions on /etc/group- are configured (Scored)"
echo -e "\t\t\t[*] Configuring permissions on /etc/group-"
chown root:root /etc/group-; chmod 600 /etc/group-; echo -e "\t\t\t\t[*] Done"

echo -e "\t\t[+] 6.1.9 Ensure permissions on /etc/gshadow- are configured (Scored)"
echo -e "\t\t\t[*] Configuring permissions on /etc/gshadow-"
chown root:root /etc/gshadow-; chmod 600 /etc/gshadow-; echo -e "\t\t\t\t[*] Done"

echo -e "\t\t[+] 6.1.10 Ensure no world writable files exist (Scored)"
echo -e '\t\t\t[*] Please removing access for "other" category(chmod o-w <filename>)'
rm -r result &> /dev/null; mkdir result
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -00
02 > result/6.1.10.txt
echo -e "\t\t\t[+] File is stored on result/6.1.10.txt"; echo -e "\t\t\t\t[*] Done"

echo -e "\t\t[+] 6.1.11 Ensure no unowned files or directories exist (Scored)"
echo -e "\t\t\t[*] Please reset the ownership of files to some active user"
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser > result/
6.1.11.txt
echo -e "\t\t\t[+] File is stored on result/6.1.11.txt"; echo -e "\t\t\t\t[*] Done"

echo -e "\t\t[+] 6.1.12 Ensure no upgrouped files or directories exist (Scored)"
echo -e "\t\t\t[*] Please reset the ownership of files to some active group"
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nogroup > result
/6.1.12.txt
echo -e "\t\t\t[+] File is stored on result/6.1.12.txt"; echo -e "\t\t\t\t[*] Done"

echo -e "\t\t[+] 6.1.13 Audit SUID executables (Not Scored)"
echo -e "\t\t\t[*] Ensure that no rogue SUID programs have been introduced into the system"
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -40
00 > result/6.1.13.txt
echo -e "\t\t\t[+] File is stored on result/6.1.13.txt"; echo -e "\t\t\t\t[*] Done"

echo -e "\t\t[+] 6.1.14 Audit SGID executables (Not Scored)"
echo -e "\t\t\t[*] Ensure that no rogue SGID programs have been introduces into the system"
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -20
00 > result/6.1.14.txt
echo -e "\t\t\t[+] File is stored on result/6.1.14.txt"; echo -e "\t\t\t\t[*] Done"

echo -e "\t[+] 6.2 User an d Group Settings"
echo -e "\t\t[+] 6.2.1 Ensure password fields are not empty (Scored)"
cat /etc/shadow | awk -F: '($2 == "" ) { print $1 " does not have a password "}' > result/6.2
.1.txt
sed -i '1s/^/[+] You could lock the account until it can be determined why it does not have a
 password\n/' result/6.2.1.txt
sed -i '2s/^/[*] Lock account using command: passwd -l <username>\n/' result/6.2.1.txt
echo -e "\t\t\t[+] File is stored on result/6.2.1.txt"; echo -e "\t\t\t\t[*] Done"

echo -e "\t\t[+] 6.2.2 Ensure no legacy "+" entries exist in /etc/passwd (Scored)"
grep '^+:' /etc/passwd > result/6.2.2.txt
#sed -i '1s/^/[+] Please remove any legacy and entries exist in /etc/passwd\n/' result/6.2.2.
txt
#sed -i -e '1s/^/[+] Please remove any legacy "+" entries exist in /etc/passwd\n/' result/6.2
.2.txt
echo -e "\t\t\t[+] File is stored on result/6.2.2.txt"; echo -e "\t\t\t\t[*] Done"

echo -e "\t\t[+] 6.2.3 Ensure no legacy "+" entries exist in /etc/shadow (Scored)"
grep '^+:' /etc/shadow > result/6.2.3.txt
#sed -i -e '1s/^/[+] Please remove "+" legacy and entries from /etc/shadow\n/' result/6.2.3.t
xt
echo -e "\t\t\t[+] File is stored on result/6.2.3.txt"; echo -e "\t\t\t\t[*] Done"


echo -e "\t\t[+] 6.2.4 Ensure no legacy "+" entries exist in /etc/group (Scored)"
grep '^+:' /etc/group > result/6.2.4.txt
#sed -i -e '1s/^/[+] Please remove any legacy "+" entries from /etc/group\n/' result/6.2.4.tx
t
echo -e "\t\t\t[+] File is stored on result/6.2.4.txt"; echo -e "\t\t\t\t[*] Done"

echo -e "\t\t[+] 6.2.5 Ensure root is the only UID 0 account (Scored)"
cat /etc/passwd | awk -F: '($3 == 0) { print $1 }' > result/6.2.5.txt
sed -i '1s/^/[+] Please remove any user than root with UID 0 or assign them a new UID if appr
opiate\n/' result/6.2.5.txt
echo -e "\t\t\t[+] File is stored on result/6.2.5.txt"; echo -e "\t\t\t\t[*] Done"

echo -e "\t\t[+] 6.2.6 Ensure root PATH Integrity (Scored)"
echo -e "\t\t\t[+] Executing script 6.2.6.sh"
chmod +x templates/6.2.6.sh
./templates/6.2.6.sh > result/6.2.6.txt; echo -e "\t\t\t\t[*] Done"
echo -e "\t\t\t[+] File is stored on result/6.2.6.txt"
sed -i '1s/^/[+] Correct or justify any items discovered in the Audit Step\n/' result/6.2.6.t
xt

echo -e "\t\t[+] 6.2.7 Ensure all users' home directories exist (Scored)"
echo -e "\t\t\t[+] Executing script 6.2.7.sh"
chmod +x templates/6.2.7.sh
./templates/6.2.7.sh > result/6.2.7.txt; echo -e "\t\t\t\t[*] Done"
echo -e "\t\t\t[+] File is stored on result/6.2.7.txt"
sed -i '1s/^/[+] If any users home directories do not exist, create them and make sure the re
sprective user owns the directory\n/' result/6.2.7.txt
sed -i '2s/^/[+] Users without an assigned home directory should be removed or assigned a hom
e directory as appropiate\n/' result/6.2.7.txt

echo -e "\t\t[+] 6.2.8 Ensure users' home directories permissions are 750 or more restrictive (Scored)"
echo -e "\t\t\t[+] Executing script 6.2.8.sh"
chmod +x templates/6.2.8.sh
./templates/6.2.8.sh > result/6.2.8.txt; echo -e "\t\t\t\t[*] Done"
echo -e "\t\t\t[+] File is stored on result/6.2.8.txt"
sed -i '1s/^/[+] Making global modificiations to user home directories without alerting the user community can result in unexpected outages and unhappy users\n/' result/6.2.8.txt
sed -i '2s/^/[+] Please monitoring policy that could be established to report user file permissions and determine the action to be taken in accordance with site policy\n/' result/6.2.8.txt

echo -e "\t\t[+] 6.2.9 Ensure users own their home directories (Scored)"
echo -e "\t\t\t[+] Executing script 6.2.9.sh"
chmod +x templates/6.2.9.sh
./templates/6.2.9.sh > result/6.2.9.txt; echo -e "\t\t\t\t[*] Done"
echo -e "\t\t\t[+] File is stored on result/6.2.9.txt"
sed -i '1s/^/[+] Change the ownership of any home directories that are not owned by the defined user to the correct user\n/' result/6.2.9.txt

echo -e "\t\t[+] 6.2.10 Ensure users' dot files are not group or world writable (Scored)"
echo -e "\t\t\t[+] Executing script 6.2.10.sh"
chmod +x templates/6.2.10.sh
./templates/6.2.10.sh > result/6.2.10.txt; echo -e "\t\t\t\t[*] Done"
echo -e "\t\t\t[+] File is stored on result/6.2.10.txt"
sed -i '1s/^/[+] Making global modifications to users files without alerting the user community can result in unexpected outages and unhappy users\n/' result/6.2.10.txt
sed -i '2s/^/[+] It is recommended that a monitoring policy be established to report user dot file permissions and determine the action to be taken in accordance with site policy\n/' result/6.2.10.txt

echo -e "\t\t[+] 6.2.11 Ensure no users have .forward files (Scored)"
echo -e "\t\t\t[+] Executing script 6.2.11.sh"
chmod +x templates/6.2.11.sh
./templates/6.2.11.sh > result/6.2.11.txt; echo -e "\t\t\t\t[*] Done"
echo -e "\t\t\t[+] File is stored on result/6.2.11.txt"
sed -i '1s/^/[+] Making global modifications to users files without alerting the user community can result in unexpected outages and unhappy users\n/' result/6.2.11.txt
sed -i '2s/^/[+] It is recommended that a monitoring policy is established to report user .forward files and determined the action to be taken in accordance with site policy\n/' result/6.2.11.txt

echo -e "\t\t[+] 6.2.12 Ensure no users have .netrc files (Scored)"
echo -e "\t\t\t[+] Executing script 6.2.12.sh"
chmod +x templates/6.2.12.sh
./templates/6.2.12.sh > result/6.2.12.txt; echo -e "\t\t\t\t[*] Done"
echo -e "\t\t\t[+] File is stored on result/6.2.12.txt"
sed -i '1s/^/[+] Making global modifications to users files without alerting the user community can result in unexpected outages and unhappy users\n/' result/6.2.12.txt
sed -i '2s/^/[+] It is recommended that a monitoring policy is established to report user .netrc files and determined the action to be taken in accordance with the site policy\n/' result/6.2.12.txt

echo -e "\t\t[+] 6.2.13 Ensure users' .netrc Files are not group or world accessible (Scored)"
echo -e "\t\t\t[+] Executing script 6.2.13.sh"
chmod +x templates/6.2.13.sh
./templates/6.2.13.sh > result/6.2.13.txt; echo -e "\t\t\t\t[*] Done"
echo -e "\t\t\t[+] File is stored on result/6.2.13.txt"
sed -i '1s/^/[+] Making global modifications to users files without alerting the user community can result in unexpected outages and unhappy users\n/' result/6.2.13.txt
sed -i '2s/^/[+] It is recommended that a monitoring policy is established to report user .netrc file permissions and determine the action to be taken in accordance with site policy\n/' result/6.2.13.txt

echo -e "\t\t[+] 6.2.14 Ensure no users have .rhosts files (Scored)"
echo -e "\t\t\t[+] Executing script 6.2.14.sh"
chmod +x templates/6.2.14.sh
./templates/6.2.14.sh > result/6.2.14.txt; echo -e "\t\t\t\t[*] Done"
echo -e "\t\t\t[+] File is stored on result/6.2.14.txt"
sed -i '1s/^/[+] Making global modifications to users files without alerting the user community can result in unexpected outages and unhappy users\n/' result/6.2.13.txt
sed -i '2s/^/[+] It is recommended that a monitoring policy be established to report user .rhosts files and determined the action to be taken in accordance with site policy\n/' result/6.2.14.txt

echo -e "\t\t[+] 6.2.15 Ensure all groups in /etc/passwd exist in /etc/group (Scored)"
echo -e "\t\t\t[+] Executing script 6.2.15.sh"
chmod +x templates/6.2.15.sh
./templates/6.2.15.sh > result/6.2.15.txt; echo -e "\t\t\t\t[*] Done"
echo -e "\t\t\t[+] File is stored on result/6.2.15.txt"
sed -i '1s/^/[+] Analyze the output of the Audit step above and perform the appropiate action to correct any discrepancies found\n/' result/6.2.15.txt

echo -e "\t\t[+] 6.2.16 Ensure no duplicate UIDs exist (Scored)"
echo -e "\t\t\t[+] Executing script 6.2.16.sh"
chmod +x templates/6.2.16.sh
./templates/6.2.16.sh > result/6.2.16.txt; echo -e "\t\t\t\t[*] Done"
echo -e "\t\t\t[+] File is stored on result/6.2.16.txt"
sed -i '1s/^/[+] Based on the results of the audit script, establish unique UUIDs and review all files owned by the shared UIDs to determine which UID they are supposed to belong to\n/' result/6.2.16.txt

echo -e "\t\t[+] 6.2.17 Ensure no duplicate GIDs exist (Scored)"
echo -e "\t\t\t[+] Executing script 6.2.17.sh"
chmod +x templates/6.2.17.sh
./templates/6.2.17.sh > result/6.2.17.txt; echo -e "\t\t\t\t[*] Done"
echo -e "\t\t\t[+] File is stored on result/6.2.17.txt"
sed -i '1s/^/[+] Based on the results of the audit script, establish unique GIDs and review all files owned by the shared GID to determine which group\n/' result/6.2.17.txt

echo -e "\t\t[+] 6.2.18 Ensure no duplicate user names exist (Scored)"
echo -e "\t\t\t[+] Executing script 6.2.18.sh"
chmod +x templates/6.2.18.sh
./templates/6.2.18.sh > result/6.2.18.txt; echo -e "\t\t\t\t[*] Done"
echo -e "\t\t\t[+] File is stored on result/6.2.18.txt"
sed -i '1s/^/[+] Based on the results of the audit script, establish unique user names for the users. File ownerships will automatically reflect the change as long as the users have unique UIDs\n/' result/6.2.18.txt

echo -e "\t\t[+] 6.2.19 Ensure no duplicate group names exist (Scored)"
echo -e "\t\t\t[+] Executing script 6.2.19.sh"
chmod +x templates/6.2.19.sh
./templates/6.2.19.sh > result/6.2.19.txt; echo -e "\t\t\t\t[*] Done"
echo -e "\t\t\t[+] File is stored on result/6.2.19.txt"
sed -i '1s/^/[+] Based on the results of the audit script, establish unique names for the user groups. File group ownerships will automatically reflect the change as long as the groups have unique GIDs\n/' result/6.2.19.txt

echo -e "\t\t[+] 6.2.20 Ensure shadow group is empty (Scored)"
grep ^shadow:[^:]*:[^:]*:[^:]+ /etc/group > result/6.2.20.txt
sed -i '1s/^/[+] Remove all useres from the shadow group, and change the primary group of any user with shadow as their primary group\n/' result/6.2.20.txt
echo -e "\t\t\t[+] File is stored on result/6.2.20.txt"
echo -e "\t\t\t\t[*] Done"

echo "=========================================================================== DONE ==========================================================================="
