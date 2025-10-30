#!/bin/bash

set -euo pipefail

COUNT=$1

for i in $(seq $COUNT); do
	DATETIME="$(date +%Y-%m-%d-%H-%M-%S-%3N)"

	sudo -E ./build/debug/hypervision conf/hypervision/lrscan/dns_lrscan-1.json cp | tee "eval/logs/hypervision/lrscan/dns_lrscan/dns_lrscan-1-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/lrscan/dns_lrscan-64.json cp | tee "eval/logs/hypervision/lrscan/dns_lrscan/dns_lrscan-64-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/lrscan/dns_lrscan-256.json cp | tee "eval/logs/hypervision/lrscan/dns_lrscan/dns_lrscan-256-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/lrscan/dns_lrscan-1024.json cp | tee "eval/logs/hypervision/lrscan/dns_lrscan/dns_lrscan-1024-$DATETIME.log"

	sudo -E ./build/debug/hypervision conf/hypervision/lrscan/http_lrscan-1.json cp | tee "eval/logs/hypervision/lrscan/http_lrscan/http_lrscan-1-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/lrscan/http_lrscan-64.json cp | tee "eval/logs/hypervision/lrscan/http_lrscan/http_lrscan-64-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/lrscan/http_lrscan-256.json cp | tee "eval/logs/hypervision/lrscan/http_lrscan/http_lrscan-256-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/lrscan/http_lrscan-1024.json cp | tee "eval/logs/hypervision/lrscan/http_lrscan/http_lrscan-1024-$DATETIME.log"

	sudo -E ./build/debug/hypervision conf/hypervision/lrscan/icmp_lrscan-1.json cp | tee "eval/logs/hypervision/lrscan/icmp_lrscan/icmp_lrscan-1-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/lrscan/icmp_lrscan-64.json cp | tee "eval/logs/hypervision/lrscan/icmp_lrscan/icmp_lrscan-64-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/lrscan/icmp_lrscan-256.json cp | tee "eval/logs/hypervision/lrscan/icmp_lrscan/icmp_lrscan-256-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/lrscan/icmp_lrscan-1024.json cp | tee "eval/logs/hypervision/lrscan/icmp_lrscan/icmp_lrscan-1024-$DATETIME.log"

	sudo -E ./build/debug/hypervision conf/hypervision/lrscan/netbios_lrscan-1.json cp | tee "eval/logs/hypervision/lrscan/netbios_lrscan/netbios_lrscan-1-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/lrscan/netbios_lrscan-64.json cp | tee "eval/logs/hypervision/lrscan/netbios_lrscan/netbios_lrscan-64-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/lrscan/netbios_lrscan-256.json cp | tee "eval/logs/hypervision/lrscan/netbios_lrscan/netbios_lrscan-256-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/lrscan/netbios_lrscan-1024.json cp | tee "eval/logs/hypervision/lrscan/netbios_lrscan/netbios_lrscan-1024-$DATETIME.log"

	sudo -E ./build/debug/hypervision conf/hypervision/lrscan/rdp_lrscan-1.json cp | tee "eval/logs/hypervision/lrscan/rdp_lrscan/rdp_lrscan-1-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/lrscan/rdp_lrscan-64.json cp | tee "eval/logs/hypervision/lrscan/rdp_lrscan/rdp_lrscan-64-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/lrscan/rdp_lrscan-256.json cp | tee "eval/logs/hypervision/lrscan/rdp_lrscan/rdp_lrscan-256-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/lrscan/rdp_lrscan-1024.json cp | tee "eval/logs/hypervision/lrscan/rdp_lrscan/rdp_lrscan-1024-$DATETIME.log"

	sudo -E ./build/debug/hypervision conf/hypervision/lrscan/smtp_lrscan-1.json cp | tee "eval/logs/hypervision/lrscan/smtp_lrscan/smtp_lrscan-1-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/lrscan/smtp_lrscan-64.json cp | tee "eval/logs/hypervision/lrscan/smtp_lrscan/smtp_lrscan-64-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/lrscan/smtp_lrscan-256.json cp | tee "eval/logs/hypervision/lrscan/smtp_lrscan/smtp_lrscan-256-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/lrscan/smtp_lrscan-1024.json cp | tee "eval/logs/hypervision/lrscan/smtp_lrscan/smtp_lrscan-1024-$DATETIME.log"

	sudo -E ./build/debug/hypervision conf/hypervision/lrscan/snmp_lrscan-1.json cp | tee "eval/logs/hypervision/lrscan/snmp_lrscan/snmp_lrscan-1-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/lrscan/snmp_lrscan-64.json cp | tee "eval/logs/hypervision/lrscan/snmp_lrscan/snmp_lrscan-64-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/lrscan/snmp_lrscan-256.json cp | tee "eval/logs/hypervision/lrscan/snmp_lrscan/snmp_lrscan-256-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/lrscan/snmp_lrscan-1024.json cp | tee "eval/logs/hypervision/lrscan/snmp_lrscan/snmp_lrscan-1024-$DATETIME.log"

	sudo -E ./build/debug/hypervision conf/hypervision/lrscan/ssh_lrscan-1.json cp | tee "eval/logs/hypervision/lrscan/ssh_lrscan/ssh_lrscan-1-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/lrscan/ssh_lrscan-64.json cp | tee "eval/logs/hypervision/lrscan/ssh_lrscan/ssh_lrscan-64-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/lrscan/ssh_lrscan-256.json cp | tee "eval/logs/hypervision/lrscan/ssh_lrscan/ssh_lrscan-256-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/lrscan/ssh_lrscan-1024.json cp | tee "eval/logs/hypervision/lrscan/ssh_lrscan/ssh_lrscan-1024-$DATETIME.log"

	sudo -E ./build/debug/hypervision conf/hypervision/lrscan/telnet_lrscan-1.json cp | tee "eval/logs/hypervision/lrscan/telnet_lrscan/telnet_lrscan-1-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/lrscan/telnet_lrscan-64.json cp | tee "eval/logs/hypervision/lrscan/telnet_lrscan/telnet_lrscan-64-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/lrscan/telnet_lrscan-256.json cp | tee "eval/logs/hypervision/lrscan/telnet_lrscan/telnet_lrscan-256-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/lrscan/telnet_lrscan-1024.json cp | tee "eval/logs/hypervision/lrscan/telnet_lrscan/telnet_lrscan-1024-$DATETIME.log"

	sudo -E ./build/debug/hypervision conf/hypervision/lrscan/vlc_lrscan-1.json cp | tee "eval/logs/hypervision/lrscan/vlc_lrscan/vlc_lrscan-1-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/lrscan/vlc_lrscan-64.json cp | tee "eval/logs/hypervision/lrscan/vlc_lrscan/vlc_lrscan-64-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/lrscan/vlc_lrscan-256.json cp | tee "eval/logs/hypervision/lrscan/vlc_lrscan/vlc_lrscan-256-$DATETIME.log"
	sudo -E ./build/debug/hypervision conf/hypervision/lrscan/vlc_lrscan-1024.json cp | tee "eval/logs/hypervision/lrscan/vlc_lrscan/vlc_lrscan-1024-$DATETIME.log"
done
