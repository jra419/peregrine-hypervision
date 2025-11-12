#!/bin/sh

./analyzer-single.py -d hypervision -c lrscan -t dns_lrscan -f dns_lrscan-0-cp-dp-sim-timeout-5-sampl-1
./analyzer-single.py -d hypervision -c lrscan -t dns_lrscan -f dns_lrscan-0-cp-dp-sim-timeout-5-sampl-64
./analyzer-single.py -d hypervision -c lrscan -t dns_lrscan -f dns_lrscan-0-cp-dp-sim-timeout-5-sampl-256
./analyzer-single.py -d hypervision -c lrscan -t dns_lrscan -f dns_lrscan-0-cp-dp-sim-timeout-5-sampl-1024

./analyzer-single.py -d hypervision -c lrscan -t http_lrscan -f http_lrscan-0-cp-dp-sim-timeout-5-sampl-1
./analyzer-single.py -d hypervision -c lrscan -t http_lrscan -f http_lrscan-0-cp-dp-sim-timeout-5-sampl-64
./analyzer-single.py -d hypervision -c lrscan -t http_lrscan -f http_lrscan-0-cp-dp-sim-timeout-5-sampl-256
./analyzer-single.py -d hypervision -c lrscan -t http_lrscan -f http_lrscan-0-cp-dp-sim-timeout-5-sampl-1024

./analyzer-single.py -d hypervision -c lrscan -t icmp_lrscan -f icmp_lrscan-0-cp-dp-sim-timeout-5-sampl-1
./analyzer-single.py -d hypervision -c lrscan -t icmp_lrscan -f icmp_lrscan-0-cp-dp-sim-timeout-5-sampl-64
./analyzer-single.py -d hypervision -c lrscan -t icmp_lrscan -f icmp_lrscan-0-cp-dp-sim-timeout-5-sampl-256
./analyzer-single.py -d hypervision -c lrscan -t icmp_lrscan -f icmp_lrscan-0-cp-dp-sim-timeout-5-sampl-1024

./analyzer-single.py -d hypervision -c lrscan -t netbios_lrscan -f netbios_lrscan-0-cp-dp-sim-timeout-5-sampl-1
./analyzer-single.py -d hypervision -c lrscan -t netbios_lrscan -f netbios_lrscan-0-cp-dp-sim-timeout-5-sampl-64
./analyzer-single.py -d hypervision -c lrscan -t netbios_lrscan -f netbios_lrscan-0-cp-dp-sim-timeout-5-sampl-256
./analyzer-single.py -d hypervision -c lrscan -t netbios_lrscan -f netbios_lrscan-0-cp-dp-sim-timeout-5-sampl-1024

./analyzer-single.py -d hypervision -c lrscan -t rdp_lrscan -f rdp_lrscan-0-cp-dp-sim-timeout-5-sampl-1
./analyzer-single.py -d hypervision -c lrscan -t rdp_lrscan -f rdp_lrscan-0-cp-dp-sim-timeout-5-sampl-64
./analyzer-single.py -d hypervision -c lrscan -t rdp_lrscan -f rdp_lrscan-0-cp-dp-sim-timeout-5-sampl-256
./analyzer-single.py -d hypervision -c lrscan -t rdp_lrscan -f rdp_lrscan-0-cp-dp-sim-timeout-5-sampl-1024

./analyzer-single.py -d hypervision -c lrscan -t smtp_lrscan -f smtp_lrscan-0-cp-dp-sim-timeout-5-sampl-1
./analyzer-single.py -d hypervision -c lrscan -t smtp_lrscan -f smtp_lrscan-0-cp-dp-sim-timeout-5-sampl-64
./analyzer-single.py -d hypervision -c lrscan -t smtp_lrscan -f smtp_lrscan-0-cp-dp-sim-timeout-5-sampl-256
./analyzer-single.py -d hypervision -c lrscan -t smtp_lrscan -f smtp_lrscan-0-cp-dp-sim-timeout-5-sampl-1024

./analyzer-single.py -d hypervision -c lrscan -t snmp_lrscan -f snmp_lrscan-0-cp-dp-sim-timeout-5-sampl-1
./analyzer-single.py -d hypervision -c lrscan -t snmp_lrscan -f snmp_lrscan-0-cp-dp-sim-timeout-5-sampl-64
./analyzer-single.py -d hypervision -c lrscan -t snmp_lrscan -f snmp_lrscan-0-cp-dp-sim-timeout-5-sampl-256
./analyzer-single.py -d hypervision -c lrscan -t snmp_lrscan -f snmp_lrscan-0-cp-dp-sim-timeout-5-sampl-1024

./analyzer-single.py -d hypervision -c lrscan -t ssh_lrscan -f ssh_lrscan-0-cp-dp-sim-timeout-5-sampl-1
./analyzer-single.py -d hypervision -c lrscan -t ssh_lrscan -f ssh_lrscan-0-cp-dp-sim-timeout-5-sampl-64
./analyzer-single.py -d hypervision -c lrscan -t ssh_lrscan -f ssh_lrscan-0-cp-dp-sim-timeout-5-sampl-256
./analyzer-single.py -d hypervision -c lrscan -t ssh_lrscan -f ssh_lrscan-0-cp-dp-sim-timeout-5-sampl-1024

./analyzer-single.py -d hypervision -c lrscan -t telnet_lrscan -f telnet_lrscan-0-cp-dp-sim-timeout-5-sampl-1
./analyzer-single.py -d hypervision -c lrscan -t telnet_lrscan -f telnet_lrscan-0-cp-dp-sim-timeout-5-sampl-64
./analyzer-single.py -d hypervision -c lrscan -t telnet_lrscan -f telnet_lrscan-0-cp-dp-sim-timeout-5-sampl-256
./analyzer-single.py -d hypervision -c lrscan -t telnet_lrscan -f telnet_lrscan-0-cp-dp-sim-timeout-5-sampl-1024

./analyzer-single.py -d hypervision -c lrscan -t vlc_lrscan -f vlc_lrscan-0-cp-dp-sim-timeout-5-sampl-1
./analyzer-single.py -d hypervision -c lrscan -t vlc_lrscan -f vlc_lrscan-0-cp-dp-sim-timeout-5-sampl-64
./analyzer-single.py -d hypervision -c lrscan -t vlc_lrscan -f vlc_lrscan-0-cp-dp-sim-timeout-5-sampl-256
./analyzer-single.py -d hypervision -c lrscan -t vlc_lrscan -f vlc_lrscan-0-cp-dp-sim-timeout-5-sampl-1024
