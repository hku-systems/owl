#!/bin/bash

cd $CONANAL_ROOT/concurrency-exploits/memcached-1.4.25/memcached-1.4.25/

env TSAN_OPTIONS="log_path=$CONANAL_ROOT/TESTS/memcached-1.4.25/output/tsan" \
	./memcached-debug &

sleep 5

cd $CONANAL_ROOT/scripts/conbreak/memcached-1.4.25/trigger/scripts/

python2.7 testClient.py

sleep 1

pkill memcached-debug

echo "Done!"

