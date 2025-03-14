#!/bin/bash

set -euo pipefail

DATETIME="$(date +%Y-%m-%d-%H-%M-%S-%3N)"

DATASET=""
TRACE=""

sudo -E ./build/release/hypervision conf/$DATASET/$TRACE.json | tee "eval/logs/$DATASET/$TRACE/$TRACE-$DATETIME.log"
