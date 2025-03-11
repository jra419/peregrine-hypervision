#!/bin/bash

set -euo pipefail

DATETIME="$(date +%Y-%m-%d-%H-%M-%S-%3N)"

DATASET="kitsune"
TRACE="os-scan"

./build/release/HyperVision conf/$DATASET/$TRACE.json | tee "eval/logs/$DATASET/$TRACE/$TRACE-$DATETIME.log"
cat tmp/$DATASET/$TRACE/* > tmp/$DATASET/$TRACE/$TRACE.csv
mkdir "tmp/$DATASET/$TRACE/$DATETIME"
# mv "tmp/$DATASET/$TRACE/*" "tmp/$DATASET/$TRACE/$DATETIME/"
find "tmp/$DATASET/$TRACE" -maxdepth 1 -type f -name '*' -exec mv -n {} "tmp/$DATASET/$TRACE/$DATETIME" \;
