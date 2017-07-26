#!/bin/bash

# The wrapper script will call this script once lldb is loaded
# and the target executable is ready

# Put your benchmarking / bug-triggering input code here...
cd scripts

env LD_LIBRARY_PATH="$CONANAL_ROOT/concurrency-exploits/mysql-35589/mysql-install/lib/mysql" \
	./attack

trap "pkill attack" TERM

# Wait until TERM signal from wrapper.sh
wait $!

