#!/bin/bash
while true; do $CONANAL_ROOT/concurrency-exploits/mysql-24988/mysql-install-clang/bin/mysql -u root -e "FLUSH PRIVILEGES;"; done
