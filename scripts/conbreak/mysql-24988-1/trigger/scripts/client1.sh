#!/bin/bash

COUNT=0
while [[ $COUNT -lt 100 ]]; do 
	$CONANAL_ROOT/concurrency-exploits/mysql-24988/mysql-install-clang/bin/mysql \
		-u root -e "FLUSH PRIVILEGES;"

	let "COUNT++"
done
