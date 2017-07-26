#!/bin/bash

path="$CONANAL_ROOT/concurrency-exploits/mysql-24988/mysql-install/bin/mysql"

while true; do 
	echo 'select count(*) from t1;' | $path -f -u root -p '' -h 127.0.0.1 db1 > /dev/null
done
