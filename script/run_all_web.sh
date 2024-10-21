#!/usr/bin/env bash

set -eux

ninja


ARR=(
    # "oracle-1"
    # "oracle-64"
    # "oracle-256"
    # "oracle-1024"
    # "persistence-1"
    # "persistence-64"
    # "persistence-256"
    # "persistence-1024"
    # "scrapy-1"
    # "scrapy-64"
    # "scrapy-256"
    # "scrapy-1024"
)

for item in ${ARR[@]}; do
    for (( counter=1; counter<="@1"; counter++ )) do
        ./HyperVision -config ../configuration/web/${item}.json > ../cache/${item}.log # &
        mv  ../cache/${item}.log ../cache/web/${item}-$counter.log
        mv  ../temp/${item}.txt ../temp/web/${item}-$counter.txt
    done
    cd ../result_analyze
    python3 batch_analyzer-single.py -g ${item}-mass
    cd ../build
    rm  ../temp/web/${item}*.txt
done
