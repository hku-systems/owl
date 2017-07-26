#!/bin/bash

cd $CONANAL_ROOT/concurrency-exploits/ssdb-1.9.2/ssdb-master-tsan/

env TSAN_OPTIONS="log_path=$CONANAL_ROOT/TESTS/ssdb-1.9.2/output/tsan" \
	./ssdb-server -d ssdb.conf -s start


