#!/bin/bash

set -euo pipefail

COUNT=$1

for i in $(seq $COUNT); do
	DATETIME="$(date +%Y-%m-%d-%H-%M-%S-%3N)"

	sudo -E ./build/debug/hypervision conf/hypervision/misc/ackport-1.json cp | tee "eval/logs/hypervision/misc/ackport/ackport-1-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/misc/ackport-64.json cp | tee "eval/logs/hypervision/misc/ackport/ackport-64-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/misc/ackport-256.json cp | tee "eval/logs/hypervision/misc/ackport/ackport-256-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/misc/ackport-1024.json cp | tee "eval/logs/hypervision/misc/ackport/ackport-1024-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/misc/ackport-2048.json cp | tee "eval/logs/hypervision/misc/ackport/ackport-2048-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/misc/ackport-4096.json cp | tee "eval/logs/hypervision/misc/ackport/ackport-4096-$DATETIME.log"

	sudo -E ./build/debug/hypervision conf/hypervision/misc/lrtcpdos05-1.json cp | tee "eval/logs/hypervision/misc/lrtcpdos05/lrtcpdos05-1-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/misc/lrtcpdos05-64.json cp | tee "eval/logs/hypervision/misc/lrtcpdos05/lrtcpdos05-64-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/misc/lrtcpdos05-256.json cp | tee "eval/logs/hypervision/misc/lrtcpdos05/lrtcpdos05-256-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/misc/lrtcpdos05-1024.json cp | tee "eval/logs/hypervision/misc/lrtcpdos05/lrtcpdos05-1024-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/misc/lrtcpdos05-2048.json cp | tee "eval/logs/hypervision/misc/lrtcpdos05/lrtcpdos05-2048-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/misc/lrtcpdos05-4096.json cp | tee "eval/logs/hypervision/misc/lrtcpdos05/lrtcpdos05-4096-$DATETIME.log"

	sudo -E ./build/debug/hypervision conf/hypervision/misc/lrtcpdos10-1.json cp | tee "eval/logs/hypervision/misc/lrtcpdos10/lrtcpdos10-1-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/misc/lrtcpdos10-64.json cp | tee "eval/logs/hypervision/misc/lrtcpdos10/lrtcpdos10-64-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/misc/lrtcpdos10-256.json cp | tee "eval/logs/hypervision/misc/lrtcpdos10/lrtcpdos10-256-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/misc/lrtcpdos10-1024.json cp | tee "eval/logs/hypervision/misc/lrtcpdos10/lrtcpdos10-1024-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/misc/lrtcpdos10-2048.json cp | tee "eval/logs/hypervision/misc/lrtcpdos10/lrtcpdos10-2048-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/misc/lrtcpdos10-4096.json cp | tee "eval/logs/hypervision/misc/lrtcpdos10/lrtcpdos10-4096-$DATETIME.log"

	sudo -E ./build/debug/hypervision conf/hypervision/misc/sshpwdla-1.json cp | tee "eval/logs/hypervision/misc/sshpwdla/sshpwdla-1-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/misc/sshpwdla-64.json cp | tee "eval/logs/hypervision/misc/sshpwdla/sshpwdla-64-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/misc/sshpwdla-256.json cp | tee "eval/logs/hypervision/misc/sshpwdla/sshpwdla-256-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/misc/sshpwdla-1024.json cp | tee "eval/logs/hypervision/misc/sshpwdla/sshpwdla-1024-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/misc/sshpwdla-2048.json cp | tee "eval/logs/hypervision/misc/sshpwdla/sshpwdla-2048-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/misc/sshpwdla-4096.json cp | tee "eval/logs/hypervision/misc/sshpwdla/sshpwdla-4096-$DATETIME.log"

	sudo -E ./build/debug/hypervision conf/hypervision/misc/sshpwdmd-1.json cp | tee "eval/logs/hypervision/misc/sshpwdmd/sshpwdmd-1-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/misc/sshpwdmd-64.json cp | tee "eval/logs/hypervision/misc/sshpwdmd/sshpwdmd-64-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/misc/sshpwdmd-256.json cp | tee "eval/logs/hypervision/misc/sshpwdmd/sshpwdmd-256-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/misc/sshpwdmd-1024.json cp | tee "eval/logs/hypervision/misc/sshpwdmd/sshpwdmd-1024-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/misc/sshpwdmd-2048.json cp | tee "eval/logs/hypervision/misc/sshpwdmd/sshpwdmd-2048-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/misc/sshpwdmd-4096.json cp | tee "eval/logs/hypervision/misc/sshpwdmd/sshpwdmd-4096-$DATETIME.log"

	sudo -E ./build/debug/hypervision conf/hypervision/misc/sshpwdsm-1.json cp | tee "eval/logs/hypervision/misc/sshpwdsm/sshpwdsm-1-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/misc/sshpwdsm-64.json cp | tee "eval/logs/hypervision/misc/sshpwdsm/sshpwdsm-64-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/misc/sshpwdsm-256.json cp | tee "eval/logs/hypervision/misc/sshpwdsm/sshpwdsm-256-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/misc/sshpwdsm-1024.json cp | tee "eval/logs/hypervision/misc/sshpwdsm/sshpwdsm-1024-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/misc/sshpwdsm-2048.json cp | tee "eval/logs/hypervision/misc/sshpwdsm/sshpwdsm-2048-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/misc/sshpwdsm-4096.json cp | tee "eval/logs/hypervision/misc/sshpwdsm/sshpwdsm-4096-$DATETIME.log"

	sudo -E ./build/debug/hypervision conf/hypervision/misc/telnetpwdla-1.json cp | tee "eval/logs/hypervision/misc/telnetpwdla/telnetpwdla-1-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/misc/telnetpwdla-64.json cp | tee "eval/logs/hypervision/misc/telnetpwdla/telnetpwdla-64-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/misc/telnetpwdla-256.json cp | tee "eval/logs/hypervision/misc/telnetpwdla/telnetpwdla-256-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/misc/telnetpwdla-1024.json cp | tee "eval/logs/hypervision/misc/telnetpwdla/telnetpwdla-1024-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/misc/telnetpwdla-2048.json cp | tee "eval/logs/hypervision/misc/telnetpwdla/telnetpwdla-2048-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/misc/telnetpwdla-4096.json cp | tee "eval/logs/hypervision/misc/telnetpwdla/telnetpwdla-4096-$DATETIME.log"

	sudo -E ./build/debug/hypervision conf/hypervision/misc/telnetpwdmd-1.json cp | tee "eval/logs/hypervision/misc/telnetpwdmd/telnetpwdmd-1-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/misc/telnetpwdmd-64.json cp | tee "eval/logs/hypervision/misc/telnetpwdmd/telnetpwdmd-64-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/misc/telnetpwdmd-256.json cp | tee "eval/logs/hypervision/misc/telnetpwdmd/telnetpwdmd-256-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/misc/telnetpwdmd-1024.json cp | tee "eval/logs/hypervision/misc/telnetpwdmd/telnetpwdmd-1024-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/misc/telnetpwdla-2048.json cp | tee "eval/logs/hypervision/misc/telnetpwdla/telnetpwdla-2048-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/misc/telnetpwdla-4096.json cp | tee "eval/logs/hypervision/misc/telnetpwdla/telnetpwdla-4096-$DATETIME.log"

	sudo -E ./build/debug/hypervision conf/hypervision/misc/telnetpwdsm-1.json cp | tee "eval/logs/hypervision/misc/telnetpwdsm/telnetpwdsm-1-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/misc/telnetpwdsm-64.json cp | tee "eval/logs/hypervision/misc/telnetpwdsm/telnetpwdsm-64-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/misc/telnetpwdsm-256.json cp | tee "eval/logs/hypervision/misc/telnetpwdsm/telnetpwdsm-256-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/misc/telnetpwdsm-1024.json cp | tee "eval/logs/hypervision/misc/telnetpwdsm/telnetpwdsm-1024-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/misc/telnetpwdsm-2048.json cp | tee "eval/logs/hypervision/misc/telnetpwdsm/telnetpwdsm-2048-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/misc/telnetpwdsm-4096.json cp | tee "eval/logs/hypervision/misc/telnetpwdsm/telnetpwdsm-4096-$DATETIME.log"
done
