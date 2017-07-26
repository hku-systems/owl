#!/bin/bash

# This script combines our front end & back end together to analyze vulnerable
# data races. Before running this script, we're assuming you've already build
# our project using CMake.

BUILD_DIRECTORY=$CONANAL_ROOT/build

if [ $# -gt "1" ]
then
    echo "Usage: $0 [ no_race_detector | no_static_analysis ]"
    echo "Example (enable race detection and llvm analysis): $0"
    echo "Example (llvm static analysis only): $0 no_race_detector"
    exit 1;
fi

# Do some clean up
pkill -9 inotifywait

if [ "$1" != "no_race_detector" ]
then
    # Step 1: You *must* build our project using CMake before running this script.
    # Create a folder named build in the top level source code folder.
    if [ -d "$BUILD_DIRECTORY" ]
    then
        echo "Seems you've built our project, very good!"
    else
        echo "Error: Build ConAnalysis using CMake before running this script!"
        exit 1
    fi

    # Step 2: We'll run valgrind to detect race during this step.
    if [ $CONANAL_ROOT = '' ]
    then
        echo "Error: Please set CONANAL_ROOT in your enviroment!"
        exit 1
    fi

    cd $CONANAL_ROOT/concurrency-exploits/apache-21287
    if [ $? -ne 0 ]
    then
        echo "Error: Couldn't enter submodule concurrency-exploits."
        echo "Did you forget to \"git submodule update --init --recursive\""
        exit 1
    fi

    if [ -f "apache-install/bin/apachectl" ] 
    then
        echo "Seems you've built apache already, very good!"
    else
        echo "Error: You need to build apache before running this script."
        echo "You can use mk.sh to automatically build it."
    fi

    cd $CONANAL_ROOT/TESTS/apache-21287
    
	# Start apache w/ tsan output 
    env TSAN_OPTIONS="log_path=$CONANAL_ROOT/TESTS/apache-21287/output/tsan" $CONANAL_ROOT/concurrency-exploits/apache-21287/apache-install/bin/apachectl -k start

	# Start benchmark
	ab -n 1000 -c 100 127.0.1.1:7000/pippo.php?variable=88

	# Kill apache
	sleep 3
	pkill httpd
fi

if [ "$1" != "no_static_analysis" ]
then
    # Step 3: We'll run our LLVM static analysis pass to analyze the race
    # Use inotify to monitor any new files within the folder
    inotifywait -m `pwd` -e create |
        while read path action file; do
            # Remove the duplicated files if there is any
            fdupes  -dqN . > /dev/null
            if [ -f $file ]
            then
                echo "The race report is newly added '$file'. Start static analysis"
                # do something with the file
                cp $file $CONANAL_ROOT/build/TESTS/apache-21287/
                pushd $CONANAL_ROOT/build/TESTS/apache-21287/ > /dev/null
                ./autotest.sh apache-21287 $file >| "finalReport_$file" 2>&1
                popd > /dev/null        
            else
                echo "Duplication found! Skip!"
            fi
        done &

    # Monitor Valgrind's output file to add new race reports
    if [ -f valgrind_latest.output ]
    then
        echo "Using valgrind_lastest.output to analyze."
        ./valgrindOutputParser.py --input valgrind_latest.output --output race_report --mode overnight &
    else
        ./valgrindOutputParser.py --input standard-output/valgrind.output --output race_report --mode normal
    fi
fi
