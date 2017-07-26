#!/bin/bash

cd $CONANAL_ROOT/concurrency-exploits/mysql-24988

mysql-install/bin/mysql_install_db --user=root
mysql-install/libexec/mysqld --user=root &

sleep 5

mysql-install/bin/mysql -u root < $CONANAL_ROOT/TESTS/mysql-24988/cmd.sql

sleep 1

pkill -TERM mysql

