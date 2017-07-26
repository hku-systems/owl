#!/bin/bash

path="$CONANAL_ROOT/concurrency-exploits/mysql-24988/mysql-install/bin/mysql"

COUNT=0
while [[ $COUNT -lt 100 ]]; do 
	echo 'select count(*) from t1;' | $path -f -u root -p '' -h 127.0.0.1 db1 > /dev/null
	let "COUNT++"
done
