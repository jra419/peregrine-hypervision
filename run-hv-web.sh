#!/bin/bash

set -euo pipefail

DATETIME="$(date +%Y-%m-%d-%H-%M-%S-%3N)"

sudo -E ./build/debug/hypervision conf/hypervision/web/agentinject-1.json cp | tee "eval/logs/hypervision/web/agentinject/agentinject-1-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/web/agentinject-64.json cp | tee "eval/logs/hypervision/web/agentinject/agentinject-64-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/web/agentinject-256.json cp | tee "eval/logs/hypervision/web/agentinject/agentinject-256-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/web/agentinject-1024.json cp | tee "eval/logs/hypervision/web/agentinject/agentinject-1024-$DATETIME.log"

sudo -E ./build/debug/hypervision conf/hypervision/web/codeinject-1.json cp | tee "eval/logs/hypervision/web/codeinject/codeinject-1-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/web/codeinject-64.json cp | tee "eval/logs/hypervision/web/codeinject/codeinject-64-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/web/codeinject-256.json cp | tee "eval/logs/hypervision/web/codeinject/codeinject-256-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/web/codeinject-1024.json cp | tee "eval/logs/hypervision/web/codeinject/codeinject-1024-$DATETIME.log"

sudo -E ./build/debug/hypervision conf/hypervision/web/csfr-1.json cp | tee "eval/logs/hypervision/web/csfr/csfr-1-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/web/csfr-64.json cp | tee "eval/logs/hypervision/web/csfr/csfr-64-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/web/csfr-256.json cp | tee "eval/logs/hypervision/web/csfr/csfr-256-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/web/csfr-1024.json cp | tee "eval/logs/hypervision/web/csfr/csfr-1024-$DATETIME.log"

sudo -E ./build/debug/hypervision conf/hypervision/web/paraminject-1.json cp | tee "eval/logs/hypervision/web/paraminject/paraminject-1-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/web/paraminject-64.json cp | tee "eval/logs/hypervision/web/paraminject/paraminject-64-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/web/paraminject-256.json cp | tee "eval/logs/hypervision/web/paraminject/paraminject-256-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/web/paraminject-1024.json cp | tee "eval/logs/hypervision/web/paraminject/paraminject-1024-$DATETIME.log"

sudo -E ./build/debug/hypervision conf/hypervision/web/spam1-1.json cp | tee "eval/logs/hypervision/web/spam1/spam1-1-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/web/spam1-64.json cp | tee "eval/logs/hypervision/web/spam1/spam1-64-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/web/spam1-256.json cp | tee "eval/logs/hypervision/web/spam1/spam1-256-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/web/spam1-1024.json cp | tee "eval/logs/hypervision/web/spam1/spam1-1024-$DATETIME.log"

sudo -E ./build/debug/hypervision conf/hypervision/web/spam50-1.json cp | tee "eval/logs/hypervision/web/spam50/spam50-1-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/web/spam50-64.json cp | tee "eval/logs/hypervision/web/spam50/spam50-64-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/web/spam50-256.json cp | tee "eval/logs/hypervision/web/spam50/spam50-256-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/web/spam50-1024.json cp | tee "eval/logs/hypervision/web/spam50/spam50-1024-$DATETIME.log"

sudo -E ./build/debug/hypervision conf/hypervision/web/spam100-1.json cp | tee "eval/logs/hypervision/web/spam100/spam100-1-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/web/spam100-64.json cp | tee "eval/logs/hypervision/web/spam100/spam100-64-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/web/spam100-256.json cp | tee "eval/logs/hypervision/web/spam100/spam100-256-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/web/spam100-1024.json cp | tee "eval/logs/hypervision/web/spam100/spam100-1024-$DATETIME.log"

sudo -E ./build/debug/hypervision conf/hypervision/web/sslscan-1.json cp | tee "eval/logs/hypervision/web/sslscan/sslscan-1-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/web/sslscan-64.json cp | tee "eval/logs/hypervision/web/sslscan/sslscan-64-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/web/sslscan-256.json cp | tee "eval/logs/hypervision/web/sslscan/sslscan-256-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/web/sslscan-1024.json cp | tee "eval/logs/hypervision/web/sslscan/sslscan-1024-$DATETIME.log"

sudo -E ./build/debug/hypervision conf/hypervision/web/webshell-1.json cp | tee "eval/logs/hypervision/web/webshell/webshell-1-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/web/webshell-64.json cp | tee "eval/logs/hypervision/web/webshell/webshell-64-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/web/webshell-256.json cp | tee "eval/logs/hypervision/web/webshell/webshell-256-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/web/webshell-1024.json cp | tee "eval/logs/hypervision/web/webshell/webshell-1024-$DATETIME.log"

sudo -E ./build/debug/hypervision conf/hypervision/web/xss-1.json cp | tee "eval/logs/hypervision/web/xss/xss-1-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/web/xss-64.json cp | tee "eval/logs/hypervision/web/xss/xss-64-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/web/xss-256.json cp | tee "eval/logs/hypervision/web/xss/xss-256-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/web/xss-1024.json cp | tee "eval/logs/hypervision/web/xss/xss-1024-$DATETIME.log"

