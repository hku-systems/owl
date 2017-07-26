#!/bin/bash

# The wrapper script will call this script once lldb is loaded
# and the target executable is ready

# Put your benchmarking / bug-triggering input code here...
trap "pkill client1; pkill client2" TERM

cd scripts

COUNT=0
while [[ $COUNT -lt 5 ]]; do
	./client1.sh &>/dev/null &
	./client2.sh &>/dev/null &

	sleep 5

	./client1.sh &>/dev/null &
	./client2.sh &>/dev/null &

	sleep 10
	
	let "COUNT++"
done

pkill client1
pkill client2

