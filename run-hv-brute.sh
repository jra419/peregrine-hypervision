#!/bin/bash

set -euo pipefail

DATETIME="$(date +%Y-%m-%d-%H-%M-%S-%3N)"

sudo -E ./build/debug/hypervision conf/hypervision/brute/charrdos-1.json cp | tee "eval/logs/hypervision/brute/charrdos/charrdos-1-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/brute/charrdos-64.json cp | tee "eval/logs/hypervision/brute/charrdos/charrdos-64-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/brute/charrdos-256.json cp | tee "eval/logs/hypervision/brute/charrdos/charrdos-256-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/brute/charrdos-1024.json cp | tee "eval/logs/hypervision/brute/charrdos/charrdos-1024-$DATETIME.log"

sudo -E ./build/debug/hypervision conf/hypervision/brute/cldaprdos-1.json cp | tee "eval/logs/hypervision/brute/cldaprdos/cldaprdos-1-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/brute/cldaprdos-64.json cp | tee "eval/logs/hypervision/brute/cldaprdos/cldaprdos-64-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/brute/cldaprdos-256.json cp | tee "eval/logs/hypervision/brute/cldaprdos/cldaprdos-256-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/brute/cldaprdos-1024.json cp | tee "eval/logs/hypervision/brute/cldaprdos/cldaprdos-1024-$DATETIME.log"

sudo -E ./build/debug/hypervision conf/hypervision/brute/dnsrdos-1.json cp | tee "eval/logs/hypervision/brute/dnsrdos/dnsrdos-1-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/brute/dnsrdos-64.json cp | tee "eval/logs/hypervision/brute/dnsrdos/dnsrdos-64-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/brute/dnsrdos-256.json cp | tee "eval/logs/hypervision/brute/dnsrdos/dnsrdos-256-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/brute/dnsrdos-1024.json cp | tee "eval/logs/hypervision/brute/dnsrdos/dnsrdos-1024-$DATETIME.log"

sudo -E ./build/debug/hypervision conf/hypervision/brute/dnsscan-1.json cp | tee "eval/logs/hypervision/brute/dnsscan/dnsscan-1-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/brute/dnsscan-64.json cp | tee "eval/logs/hypervision/brute/dnsscan/dnsscan-64-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/brute/dnsscan-256.json cp | tee "eval/logs/hypervision/brute/dnsscan/dnsscan-256-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/brute/dnsscan-1024.json cp | tee "eval/logs/hypervision/brute/dnsscan/dnsscan-1024-$DATETIME.log"

sudo -E ./build/debug/hypervision conf/hypervision/brute/httpscan-1.json cp | tee "eval/logs/hypervision/brute/httpscan/httpscan-1-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/brute/httpscan-64.json cp | tee "eval/logs/hypervision/brute/httpscan/httpscan-64-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/brute/httpscan-256.json cp | tee "eval/logs/hypervision/brute/httpscan/httpscan-256-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/brute/httpscan-1024.json cp | tee "eval/logs/hypervision/brute/httpscan/httpscan-1024-$DATETIME.log"

sudo -E ./build/debug/hypervision conf/hypervision/brute/httpsscan-1.json cp | tee "eval/logs/hypervision/brute/httpsscan/httpsscan-1-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/brute/httpsscan-64.json cp | tee "eval/logs/hypervision/brute/httpsscan/httpsscan-64-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/brute/httpsscan-256.json cp | tee "eval/logs/hypervision/brute/httpsscan/httpsscan-256-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/brute/httpsscan-1024.json cp | tee "eval/logs/hypervision/brute/httpsscan/httpsscan-1024-$DATETIME.log"

sudo -E ./build/debug/hypervision conf/hypervision/brute/icmpscan-1.json cp | tee "eval/logs/hypervision/brute/icmpscan/icmpscan-1-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/brute/icmpscan-64.json cp | tee "eval/logs/hypervision/brute/icmpscan/icmpscan-64-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/brute/icmpscan-256.json cp | tee "eval/logs/hypervision/brute/icmpscan/icmpscan-256-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/brute/icmpscan-1024.json cp | tee "eval/logs/hypervision/brute/icmpscan/icmpscan-1024-$DATETIME.log"

sudo -E ./build/debug/hypervision conf/hypervision/brute/icmpsdos-1.json cp | tee "eval/logs/hypervision/brute/icmpsdos/icmpsdos-1-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/brute/icmpsdos-64.json cp | tee "eval/logs/hypervision/brute/icmpsdos/icmpsdos-64-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/brute/icmpsdos-256.json cp | tee "eval/logs/hypervision/brute/icmpsdos/icmpsdos-256-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/brute/icmpsdos-1024.json cp | tee "eval/logs/hypervision/brute/icmpsdos/icmpsdos-1024-$DATETIME.log"

sudo -E ./build/debug/hypervision conf/hypervision/brute/memcachedrdos-1.json cp | tee "eval/logs/hypervision/brute/memcachedrdos/memcachedrdos-1-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/brute/memcachedrdos-64.json cp | tee "eval/logs/hypervision/brute/memcachedrdos/memcachedrdos-64-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/brute/memcachedrdos-256.json cp | tee "eval/logs/hypervision/brute/memcachedrdos/memcachedrdos-256-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/brute/memcachedrdos-1024.json cp | tee "eval/logs/hypervision/brute/memcachedrdos/memcachedrdos-1024-$DATETIME.log"

sudo -E ./build/debug/hypervision conf/hypervision/brute/ntprdos-1.json cp | tee "eval/logs/hypervision/brute/ntprdos/ntprdos-1-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/brute/ntprdos-64.json cp | tee "eval/logs/hypervision/brute/ntprdos/ntprdos-64-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/brute/ntprdos-256.json cp | tee "eval/logs/hypervision/brute/ntprdos/ntprdos-256-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/brute/ntprdos-1024.json cp | tee "eval/logs/hypervision/brute/ntprdos/ntprdos-1024-$DATETIME.log"

sudo -E ./build/debug/hypervision conf/hypervision/brute/ntpscan-1.json cp | tee "eval/logs/hypervision/brute/ntpscan/ntpscan-1-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/brute/ntpscan-64.json cp | tee "eval/logs/hypervision/brute/ntpscan/ntpscan-64-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/brute/ntpscan-256.json cp | tee "eval/logs/hypervision/brute/ntpscan/ntpscan-256-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/brute/ntpscan-1024.json cp | tee "eval/logs/hypervision/brute/ntpscan/ntpscan-1024-$DATETIME.log"

sudo -E ./build/debug/hypervision conf/hypervision/brute/riprdos-1.json cp | tee "eval/logs/hypervision/brute/riprdos/riprdos-1-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/brute/riprdos-64.json cp | tee "eval/logs/hypervision/brute/riprdos/riprdos-64-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/brute/riprdos-256.json cp | tee "eval/logs/hypervision/brute/riprdos/riprdos-256-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/brute/riprdos-1024.json cp | tee "eval/logs/hypervision/brute/riprdos/riprdos-1024-$DATETIME.log"

sudo -E ./build/debug/hypervision conf/hypervision/brute/sqlscan-1.json cp | tee "eval/logs/hypervision/brute/sqlscan/sqlscan-1-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/brute/sqlscan-64.json cp | tee "eval/logs/hypervision/brute/sqlscan/sqlscan-64-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/brute/sqlscan-256.json cp | tee "eval/logs/hypervision/brute/sqlscan/sqlscan-256-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/brute/sqlscan-1024.json cp | tee "eval/logs/hypervision/brute/sqlscan/sqlscan-1024-$DATETIME.log"

sudo -E ./build/debug/hypervision conf/hypervision/brute/ssdprdos-1.json cp | tee "eval/logs/hypervision/brute/ssdprdos/ssdprdos-1-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/brute/ssdprdos-64.json cp | tee "eval/logs/hypervision/brute/ssdprdos/ssdprdos-64-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/brute/ssdprdos-256.json cp | tee "eval/logs/hypervision/brute/ssdprdos/ssdprdos-256-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/brute/ssdprdos-1024.json cp | tee "eval/logs/hypervision/brute/ssdprdos/ssdprdos-1024-$DATETIME.log"

sudo -E ./build/debug/hypervision conf/hypervision/brute/sshscan-1.json cp | tee "eval/logs/hypervision/brute/sshscan/sshscan-1-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/brute/sshscan-64.json cp | tee "eval/logs/hypervision/brute/sshscan/sshscan-64-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/brute/sshscan-256.json cp | tee "eval/logs/hypervision/brute/sshscan/sshscan-256-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/brute/sshscan-1024.json cp | tee "eval/logs/hypervision/brute/sshscan/sshscan-1024-$DATETIME.log"

sudo -E ./build/debug/hypervision conf/hypervision/brute/synsdos-1.json cp | tee "eval/logs/hypervision/brute/synsdos/synsdos-1-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/brute/synsdos-64.json cp | tee "eval/logs/hypervision/brute/synsdos/synsdos-64-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/brute/synsdos-256.json cp | tee "eval/logs/hypervision/brute/synsdos/synsdos-256-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/brute/synsdos-1024.json cp | tee "eval/logs/hypervision/brute/synsdos/synsdos-1024-$DATETIME.log"

sudo -E ./build/debug/hypervision conf/hypervision/brute/udpsdos-1.json cp | tee "eval/logs/hypervision/brute/udpsdos/udpsdos-1-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/brute/udpsdos-64.json cp | tee "eval/logs/hypervision/brute/udpsdos/udpsdos-64-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/brute/udpsdos-256.json cp | tee "eval/logs/hypervision/brute/udpsdos/udpsdos-256-$DATETIME.log"
sudo -E ./build/debug/hypervision conf/hypervision/brute/udpsdos-1024.json cp | tee "eval/logs/hypervision/brute/udpsdos/udpsdos-1024-$DATETIME.log"
