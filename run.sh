#!/bin/bash

set -euo pipefail

DATETIME="$(date +%Y-%m-%d-%H-%M-%S-%3N)"

DATASET=$1
TRACE=$2

# sudo -E ./build/debug/hypervision conf/$DATASET/$TRACE.json cp | tee "eval/logs/$DATASET/$TRACE/$TRACE-$DATETIME.log"
# sudo -E ./build/debug/hypervision conf/$DATASET/$TRACE.json cp > flows_all.txt
sudo -E gdb -ex="set confirm off" -ex=r --args ./build/debug/hypervision conf/$DATASET/$TRACE.json cp | tee "eval/logs/$DATASET/$TRACE/$TRACE-$DATETIME.log"
# sudo -E gdb -ex="set confirm off" -ex="break src/sample.h:448" -ex=r --args ./build/debug/hypervision conf/$DATASET/$TRACE.json cp | tee "eval/logs/$DATASET/$TRACE/$TRACE-$DATETIME.log"
