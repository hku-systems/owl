#!/bin/bash
#
#Shell script for adding or removing libsafe entry from /etc/ld.so.preload
#
libsafe=/lib/libsafe.so.2
preload=/etc/ld.so.preload
tload=/tmp/ld.so.preload


install-libsafe() {
	if [ -f $libsafe ]
	then
		if [ -f $preload ] 
		then
			cp -fp $preload $preload.bak
			grep -v libsafe $preload > $tload
			echo "$libsafe" >> $tload
			cp -fp $tload $preload
		else
			echo "$libsafe" > $preload
		fi
		echo "The system will be protected by libsafe from now on."
	else
	    	echo "No change made as libsafe is not installed on the system."
	fi
}

remove-libsafe() {
	if [ -f $preload ]
	then
		cp -fp $preload $preload.bak
		grep -v libsafe $preload.bak > $tload
		if [ -s $tload ]
		then 
			cp -fp  $tload $preload
		else
			rm -f $preload
		fi
	        rm -f $tload
		echo "Libsafe Removed."
	else
		echo "No change made as /etc/ld.so.preload does not exist."
	fi
}
	

usage="Usage: $0 [-i] [-r]"

if [ $UID -ne 0 ]
then
   echo "You must be a root to run $0"
   exit 0
fi

while getopts ":ir" opt; do
	case $opt in
		i  ) install-libsafe  ;;
		r  ) remove-libsafe   ;;
		\? ) echo $usage
		     exit 1 ;;
	esac
done


if [ -z "$@" ]
then
	echo $usage
	exit 1
fi
