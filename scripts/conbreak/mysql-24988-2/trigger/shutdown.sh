#!/bin/bash

# This script will be run after each lldb analysis
# Like startup.sh, this script is completely optional.  Only include this
# file if your program has additional cleanup/shutdown procedures beyond just
# killing the target executable (handled by wrapper.sh)

# Shutdown code starts here
cd $CONANAL_ROOT/concurrency-exploits/mysql-24988

# Make sure mysqld daemon is running so sysbench can modify dbca
mysql-install/libexec/mysqld --user=root &

# Wait for mysql to start up
sleep 5

# Cleanup
sysbench --test=oltp --mysql-db=dbca --mysql-user=root cleanup

pkill mysql
pkill mysqld
