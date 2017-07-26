#!/bin/bash

# The wrapper script will call this script once lldb is loaded
# and the target executable is ready

# Put your benchmarking / bug-triggering input code here...
ab -n 100 -c 10 127.0.1.1:7000/pippo.php?variable=88 &>/dev/null
