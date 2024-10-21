#!/usr/bin/env bash

set -eux

ninja


ARR=(
    # "charrdos-1"
    # "charrdos-64"
    # "charrdos-256"
    # "charrdos-1024"
    # "cldaprdos-1"
    # "cldaprdos-64"
    # "cldaprdos-256"
    # "cldaprdos-1024"
    # "dnsrdos-1"
    # "dnsrdos-64"
    # "dnsrdos-256"
    # "dnsrdos-1024"
    # "dnsscan-1"
    # "dnsscan-64"
    # "dnsscan-256"
    # "dnsscan-1024"
    # "httpscan-1"
    # "httpscan-64"
    # "httpscan-256"
    # "httpscan-1024"
    # "httpsscan-1"
    # "httpsscan-64"
    # "httpsscan-256"
    # "httpsscan-1024"
    # "icmpscan-1"
    # "icmpscan-64"
    # "icmpscan-256"
    # "icmpscan-1024"
    # "memcachedrdos-1"
    # "memcachedrdos-64"
    # "memcachedrdos-256"
    # "memcachedrdos-1024"
    # "ntprdos-1"
    # "ntprdos-64"
    # "ntprdos-256"
    # "ntprdos-1024"
    # "ntpscan-1"
    # "ntpscan-64"
    # "ntpscan-256"
    # "ntpscan-1024"
    # "riprdos-1"
    # "riprdos-64"
    # "riprdos-256"
    # "riprdos-1024"
    # "sqlscan-1"
    # "sqlscan-64"
    # "sqlscan-256"
    # "sqlscan-1024"
    # "ssdprdos-1"
    # "ssdprdos-64"
    # "ssdprdos-256"
    # "ssdprdos-1024"
    # "sshscan-1"
    # "sshscan-64"
    # "sshscan-256"
    # "sshscan-1024"
)

for item in ${ARR[@]}; do
    for (( counter=1; counter<="$1"; counter++ )) do
        ./HyperVision -config ../configuration/bruteforce/sampl/${item}.json > ../cache/${item}.log # &
        mv  ../cache/${item}.log ../cache/brute/${item}-$counter.log
        mv  ../temp/${item}.txt ../temp/brute/${item}-$counter.txt
    done
    cd ../result_analyze
    python3 batch_analyzer-single.py -g ${item}-mass
    cd ../build
    rm  ../temp/brute/${item}*.txt
done
