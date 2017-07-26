#!/bin/bash

cd $CONANAL_ROOT/concurrency-exploits/mysql-35589

env TSAN_OPTIONS="log_path=$CONANAL_ROOT/TESTS/mysql-35589/output/tsan" \
	mysql-install-tsan/libexec/mysqld --skip-grant &

sleep 5

mysql-install/bin/mysql -u root < $CONANAL_ROOT/TESTS/mysql-35589/cmd.sql

sleep 1

pkill -TERM mysql

