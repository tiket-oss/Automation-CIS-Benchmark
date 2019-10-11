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
