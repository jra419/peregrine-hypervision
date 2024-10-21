#!/usr/bin/env bash

set -eux

ninja


ARR=(
    # "sshpwdsm-1"
    # "sshpwdsm-64"
    # "sshpwdsm-256"
    # "sshpwdsm-1024"
    # "sshpwdla-1"
    # "sshpwdla-64"
    # "sshpwdla-256"
    # "sshpwdla-1024"
    # "telnetpwdmd-1"
    # "telnetpwdmd-64"
    # "telnetpwdmd-256"
    # "telnetpwdmd-1024"
    # "telnetpwdla-1"
    # "telnetpwdla-64"
    # "telnetpwdla-256"
    # "telnetpwdla-1024"
    # "spam1-1"
    # "spam1-64"
    # "spam1-256"
    # "spam1-1024"
    # "spam50-1"
    # "spam50-64"
    # "spam50-256"
    # "spam50-1024"
    # "spam100-1"
    # "spam100-64"
    # "spam100-256"
    # "spam100-1024"
    # "crossfiresm-1"
    # "crossfiresm-64"
    # "crossfiresm-256"
    # "crossfiresm-1024"
)

for item in ${ARR[@]}; do
    for (( counter=1; counter<="@1"; counter++ )) do
        ./HyperVision -config ../configuration/misc/${item}.json > ../cache/${item}.log # &
        mv  ../cache/${item}.log ../cache/misc/${item}-$counter.log
        mv  ../temp/${item}.txt ../temp/misc/${item}-$counter.txt
    done
    cd ../result_analyze
    python3 batch_analyzer-single.py -g ${item}-mass
    cd ../build
    rm  ../temp/misc/${item}*.txt
done
