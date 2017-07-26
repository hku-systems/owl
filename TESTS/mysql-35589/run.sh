#!/bin/bash

# This script combines our front end & back end together to analyze vulnerable
# data races. Before running this script, we're assuming you've already build
# our project using CMake.

BUILD_DIRECTORY=$CONANAL_ROOT/build

# Step 1: You *must* build our project using CMake before running this script.
# Create a folder named build in the top level source code folder.
if [[ -d "$BUILD_DIRECTORY" ]]; then
    echo "Seems you've built our project, very good!"
else
    echo "Error: Build ConAnalysis using CMake before running this script!"
    exit 1
fi

# Step 2: We'll run tsan to detect race during this step.
if [[ $CONANAL_ROOT = '' ]]; then
    echo "Error: Please set CONANAL_ROOT in your enviroment!"
    exit 1
fi

pushd $CONANAL_ROOT/concurrency-exploits/mysql-35589
if [[ $? -ne 0 ]]; then
    echo "Error: Couldn't enter submodule concurrency-exploits."
    echo "Did you forget to \"git submodule update --init --recursive\""
    exit 1
fi

if [[ -f "mysql-install/libexec/mysqld" ]]; then
    echo "Seems you've built mysql already, very good!"
else
    echo "Error: You need to build mysql before running this script."
    echo "You can use mk.sh to automatically build it."
fi

# Set up databases
echo "Setting up databases..."

env TSAN_OPTIONS="log_path=$CONANAL_ROOT/TESTS/mysql-35589/output/tsan" \
    mysql-install-tsan/libexec/mysqld --skip-grant &

sleep 5

popd

if [[ ! -f "attack" ]]; then
    clang bug35589.c -g -o attack -L mysql-install-tsan/lib/mysql \
		  -I mysql-install-tsan/include/mysql -lmysqlclient_r -lz -lpthread
fi

env LD_LIBRARY_PATH="$CONANAL_ROOT/concurrency-exploits/mysql-35589/mysql-install/lib/mysql" \
	TSAN_OPTIONS="log_path=$CONANAL_ROOT/TESTS/mysql-35589/output/tsan" ./attack
 


