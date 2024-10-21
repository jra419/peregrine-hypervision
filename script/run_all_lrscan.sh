#!/usr/bin/env bash

set -eux

ninja


ARR=(
    # "icmp_lrscan-1"
    # "icmp_lrscan-64"
    # "icmp_lrscan-256"
    # "icmp_lrscan-1024"
    # "rdp_lrscan-1"
    # "rdp_lrscan-64"
    # "rdp_lrscan-256"
    # "rdp_lrscan-1024"
    # "telnet_lrscan-1"
    # "telnet_lrscan-64"
    # "telnet_lrscan-256"
    # "telnet_lrscan-1024"
)

for item in ${ARR[@]}; do
    for (( counter=1; counter<="@1"; counter++ )) do
        ./HyperVision -config ../configuration/lrscan/${item}.json > ../cache/${item}.log # &
        mv  ../cache/${item}.log ../cache/lrscan/${item}-$counter.log
        mv  ../temp/${item}.txt ../temp/lrscan/${item}-$counter.txt
    done
    cd ../result_analyze
    python3 batch_analyzer-single.py -g ${item}-mass
    cd ../build
    rm  ../temp/lrscan/${item}*.txt
done
