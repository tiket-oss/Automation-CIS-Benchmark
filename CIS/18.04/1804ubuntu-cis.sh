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


