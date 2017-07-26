#!/bin/bash
# Usage: ./tsanOutputConverger.sh folder1 folder2 output_folder

if [ ! $# -eq 3 ]; then
  echo -e "Usage: ./tsanOutputConverger.sh folder1 folder2 output_folder"
  exit 1
fi

FOLDER1=$1
FOLDER2=$2
FOLDERMERGED=$3

# Check whether the two comparison folders exist.
if [ ! -d "$FOLDER1" ] || [ ! -d "$FOLDER2" ]; then
    echo "Error: Comparison folders does not exist."
    exit 1
fi

# Check whether the two comparison folders are different.
if [ "$1" == "$2" ]; then
    echo "Error: Comparison folders should be different."
    exit 1
fi

# Check if the result folder exists.
if [ -d "$FOLDERMERGED" ]; then
    echo "Error: Destination folder $3 exists."
    exit 1
fi

cp -r $FOLDER1 $FOLDERMERGED

md5sum $FOLDER1/* > md5_folder1
md5sum $FOLDER2/* > md5_folder2

for f1 in $FOLDER2/*
do
    IFDIFFERENT=1
    prev_sum=$(grep $f1 md5_folder2 | awk '{print $1}')
    for f2 in $FOLDER1/*
    do
        sum=$(grep $f2 md5_folder1 | awk '{print $1}')
        if [ "$sum" == "$prev_sum" ] ; then
            IFDIFFERENT=0
        else
            continue
        fi
    done
    if [ "$IFDIFFERENT" -eq 1 ]; then
        cp $f1 $FOLDERMERGED
    fi
done

rm md5_folder1 md5_folder2

echo "Finish Two Folder Merging. Please check the result folder!"
