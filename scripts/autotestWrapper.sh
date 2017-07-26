#!/bin/bash
# Usage: ./autotestWrapper.sh apache-21287 syncloop

if [ ! $# -eq 2 ]; then
  echo -e "Please input the argument"
  echo -e "./autotestWrapper.sh mysql-35589 race_report*"
  exit -1
fi

APP=$1
FILES=$2
for f in $FILES*
do
    echo $f
	./autotestSyncLoop.sh $APP $f >| "finalReport_$f" 2>&1
done
