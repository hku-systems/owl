#!/bin/bash

# Code in this script will be run every time before lldb starts
# This script is optional, only include it if your executable has a complex
# start up proceedure

# Start up code goes here
echo "Starting mysql..."
cd $CONANAL_ROOT/concurrency-exploits/mysql-24988
mysql-install/bin/mysql_install_db --user=root
mysql-install/libexec/mysqld --user=root &

# Give MySQL a little time to startup
sleep 3

echo "Populating database..."
sysbench --test=oltp --oltp-table-size=1000000 --mysql-db=dbca \
         --mysql-user=root prepare

# Give Sysbench a little time
sleep 1

pkill -TERM mysqld

