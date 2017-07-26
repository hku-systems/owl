#!/bin/bash

# The wrapper script will call this script once lldb is loaded
# and the target executable is ready

# Put your benchmarking / bug-triggering input code here...
CMD="sysbench --test=oltp --oltp-table-size=1000000 --oltp-test-mode=complex \
              --oltp-read-only=off  --num-threads=10 --max-requests=1000 \
              --mysql-db=dbca --mysql-user=root run"

RUNTIME=0
THRESHOLD=3
while [[ $(echo "$RUNTIME < $THRESHOLD" | bc) -eq 1 ]]; do
	RUNTIME=`(TIMEFORMAT="%R"; time $CMD 1>/dev/null) 2>&1`
done

echo "Benchmark Done!"

