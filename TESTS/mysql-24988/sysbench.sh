#!/bin/bash

# This script will start mysql using the run.sh script, setup sysbench
# and benchmark mysql with 1000 "complex" transactions.  Please ensure
# MySQL is not already running before starting this script
#
# NOTE: Before running, make sure mysql has a database called 'dbca'
#       If not, create one using the command `create database dbca;`

set -e

echo "Starting MySQL..."
./run.sh

# Give MySQL a little time...
sleep 3

echo "Populating table..."
sysbench --test=oltp --oltp-table-size=1000000 --mysql-db=dbca \
         --mysql-user=root prepare

echo "Starting test..."
sysbench --test=oltp --oltp-table-size=1000000 --oltp-test-mode=complex \
         --oltp-read-only=off  --num-threads=10 --max-requests=1000 \
         --mysql-db=dbca --mysql-user=root run

echo "Cleaning up..."	
sysbench --test=oltp --mysql-db=dbca --mysql-user=root cleanup

pkill mysqld
pkill mysql

echo "Done!"
