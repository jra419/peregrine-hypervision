#pragma once

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>

#include <string>

#define IP_PROTO_ICMP 1
#define IP_PROTO_TCP 6
#define IP_PROTO_UDP 17

#define MAX_PACKET_SIZE 10000

namespace hypervision {

typedef uint8_t mac_t[6];
typedef uint32_t ipv4_t;
typedef uint16_t port_t;

struct eth_hdr_t {
	mac_t dst_mac;
	mac_t src_mac;
	uint16_t eth_type;
} __attribute__((packed));

struct ipv4_hdr_t {
	uint8_t ihl : 4;
	uint8_t version : 4;
	uint8_t ecn : 2;
	uint8_t dscp : 6;
	uint16_t tot_len;
	uint16_t id;
	uint16_t frag_off;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t check;
	ipv4_t src_ip;
	ipv4_t dst_ip;
} __attribute__((packed));

struct tcp_hdr_t {
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t seq_no;
	uint32_t ack_no;
	uint16_t opts;
	uint16_t window;
	uint16_t checksum;
	uint16_t urgent_ptr;
} __attribute__((packed));

struct udp_hdr_t {
	port_t src_port;
	port_t dst_port;
	uint16_t length;
	uint16_t checksum;
} __attribute__((packed));

struct icmp_hdr_t {
	uint8_t type;
	uint8_t code;
	uint16_t checksum;
} __attribute__((packed));

struct peregrine_hdr_t {
	uint32_t ts_start_0;
	uint32_t ts_end_0;
	uint32_t ts_agg_0;
	uint32_t ip_src_0;
	uint32_t ip_dst_0;
	uint32_t proto_0;
	uint32_t ports_0;
	uint32_t syn_ack_0;
	uint32_t fin_rst_0;
	uint32_t cnt_0;
	uint32_t len_0;
	uint8_t  long_0;
	uint32_t ts_start_1;
	uint32_t ts_end_1;
	uint32_t ts_agg_1;
	uint32_t ip_src_1;
	uint32_t ip_dst_1;
	uint32_t proto_1;
	uint32_t ports_1;
	uint32_t syn_ack_1;
	uint32_t fin_rst_1;
	uint32_t cnt_1;
	uint32_t len_1;
	uint8_t  long_1;
	uint32_t ts_start_2;
	uint32_t ts_end_2;
	uint32_t ts_agg_2;
	uint32_t ip_src_2;
	uint32_t ip_dst_2;
	uint32_t proto_2;
	uint32_t ports_2;
	uint32_t syn_ack_2;
	uint32_t fin_rst_2;
	uint32_t cnt_2;
	uint32_t len_2;
	uint8_t  long_2;
	uint32_t ts_start_3;
	uint32_t ts_end_3;
	uint32_t ts_agg_3;
	uint32_t ip_src_3;
	uint32_t ip_dst_3;
	uint32_t proto_3;
	uint32_t ports_3;
	uint32_t syn_ack_3;
	uint32_t fin_rst_3;
	uint32_t cnt_3;
	uint32_t len_3;
	uint8_t  long_3;
} __attribute__((packed));

struct peregrine_bin_len_hdr_t {
	uint32_t bin_0_0_a;
	uint32_t bin_0_0_b;
	uint32_t bin_0_1_a;
	uint32_t bin_0_1_b;
	uint32_t bin_0_2_a;
	uint32_t bin_0_2_b;
	uint32_t bin_0_3_a;
	uint32_t bin_0_3_b;
	uint32_t bin_1_0_a;
	uint32_t bin_1_0_b;
	uint32_t bin_1_1_a;
	uint32_t bin_1_1_b;
	uint32_t bin_1_2_a;
	uint32_t bin_1_2_b;
	uint32_t bin_1_3_a;
	uint32_t bin_1_3_b;
	uint32_t bin_2_0_a;
	uint32_t bin_2_0_b;
	uint32_t bin_2_1_a;
	uint32_t bin_2_1_b;
	uint32_t bin_2_2_a;
	uint32_t bin_2_2_b;
	uint32_t bin_2_3_a;
	uint32_t bin_2_3_b;
	uint32_t bin_3_0_a;
	uint32_t bin_3_0_b;
	uint32_t bin_3_1_a;
	uint32_t bin_3_1_b;
	uint32_t bin_3_2_a;
	uint32_t bin_3_2_b;
	uint32_t bin_3_3_a;
	uint32_t bin_3_3_b;
	uint32_t bin_4_0_a;
	uint32_t bin_4_0_b;
	uint32_t bin_4_1_a;
	uint32_t bin_4_1_b;
	uint32_t bin_4_2_a;
	uint32_t bin_4_2_b;
	uint32_t bin_4_3_a;
	uint32_t bin_4_3_b;
} __attribute__((packed));

struct peregrine_bin_ts_hdr_t {
	uint32_t bin_0_0_a;
	uint32_t bin_0_0_b;
	uint32_t bin_0_1_a;
	uint32_t bin_0_1_b;
	uint32_t bin_0_2_a;
	uint32_t bin_0_2_b;
	uint32_t bin_0_3_a;
	uint32_t bin_0_3_b;
	uint32_t bin_1_0_a;
	uint32_t bin_1_0_b;
	uint32_t bin_1_1_a;
	uint32_t bin_1_1_b;
	uint32_t bin_1_2_a;
	uint32_t bin_1_2_b;
	uint32_t bin_1_3_a;
	uint32_t bin_1_3_b;
	uint32_t bin_2_0_a;
	uint32_t bin_2_0_b;
	uint32_t bin_2_1_a;
	uint32_t bin_2_1_b;
	uint32_t bin_2_2_a;
	uint32_t bin_2_2_b;
	uint32_t bin_2_3_a;
	uint32_t bin_2_3_b;
	uint32_t bin_3_0_a;
	uint32_t bin_3_0_b;
	uint32_t bin_3_1_a;
	uint32_t bin_3_1_b;
	uint32_t bin_3_2_a;
	uint32_t bin_3_2_b;
	uint32_t bin_3_3_a;
	uint32_t bin_3_3_b;
	uint32_t bin_4_0_a;
	uint32_t bin_4_0_b;
	uint32_t bin_4_1_a;
	uint32_t bin_4_1_b;
	uint32_t bin_4_2_a;
	uint32_t bin_4_2_b;
	uint32_t bin_4_3_a;
	uint32_t bin_4_3_b;
} __attribute__((packed));

std::string mac_to_str(mac_t mac);
std::string ip_to_str(ipv4_t ip);
std::string port_to_str(port_t port);

struct pkt_hdr_t {
	uint8_t buffer[MAX_PACKET_SIZE];

	eth_hdr_t* get_l2() const { return (eth_hdr_t*)((uint8_t*)buffer); }

	size_t get_l2_size() const { return sizeof(eth_hdr_t); }

	ipv4_hdr_t* get_l3() const {
		auto l2_hdr = get_l2();
		auto l2_hdr_size = get_l2_size();
		return (ipv4_hdr_t*)((uint8_t*)l2_hdr + l2_hdr_size);
	}

	size_t get_l3_size() const { return sizeof(ipv4_hdr_t); }

	std::pair<void*, uint16_t> get_l4() const {
		auto ip_hdr = get_l3();
		auto ip_size = get_l3_size();

		switch (ip_hdr->protocol) {
			case IP_PROTO_TCP: {
				return std::pair<void*, uint16_t>((uint8_t*)ip_hdr + ip_size, IP_PROTO_TCP);
			} break;
			case IP_PROTO_UDP: {
				return std::pair<void*, uint16_t>((uint8_t*)ip_hdr + ip_size, IP_PROTO_UDP);
			} break;
			case IP_PROTO_ICMP: {
				return std::pair<void*, uint16_t>((uint8_t*)ip_hdr + ip_size, IP_PROTO_ICMP);
			} break;
			default: {
				printf("\n*** Not TCP/UDP/ICMP packet! ***\n");
				exit(1);
			} break;
		}
	}

	bool has_valid_protocol() const {
		auto ip_hdr = get_l3();
		return (ip_hdr->protocol == IP_PROTO_TCP ||
				ip_hdr->protocol == IP_PROTO_UDP ||
				ip_hdr->protocol == IP_PROTO_ICMP);
	}

	size_t get_l4_size() const {
		auto ip_hdr = get_l3();

		switch (ip_hdr->protocol) {
			case IP_PROTO_TCP: { return sizeof(tcp_hdr_t); } break;
			case IP_PROTO_UDP: { return sizeof(udp_hdr_t); } break;
			case IP_PROTO_ICMP: { return sizeof(icmp_hdr_t); } break;
			default: { return 0; } break;
		}
	}

	size_t get_peregrine_hdr_size() const {
		return sizeof(peregrine_hdr_t);
	}

	peregrine_hdr_t* get_peregrine_hdr() const {
		auto l4_hdr = get_l4();
		auto l4_hdr_size = get_l4_size();

		if (l4_hdr_size == 0) {
			printf(
				"\n*** Not a TCP/UDP/ICMP packet! Can't extract the Peregrine header. ***\n");
			exit(1);
		}

		auto peregrine_hdr = (uint8_t*)l4_hdr.first + l4_hdr_size;
		return static_cast<peregrine_hdr_t*>((void*)peregrine_hdr);
	}

	size_t get_peregrine_bin_len_hdr_size() const {
		return sizeof(peregrine_bin_len_hdr_t);
	}

	peregrine_bin_len_hdr_t* get_peregrine_bin_len_hdr() const {
		auto peregrine_hdr = get_peregrine_hdr();
		auto peregrine_hdr_size = get_peregrine_hdr_size();

		if (peregrine_hdr_size == 0) {
			printf("\n*** Not a peregrine hdr packet! Can't extract the bin len header. ***\n");
			exit(1);
		}

		auto peregrine_bin_len_hdr = (uint8_t*)peregrine_hdr + peregrine_hdr_size;
		return static_cast<peregrine_bin_len_hdr_t*>((void*)peregrine_bin_len_hdr);
	}

	size_t get_peregrine_bin_ts_hdr_size() const {
		return sizeof(peregrine_bin_ts_hdr_t);
	}

	peregrine_bin_ts_hdr_t* get_peregrine_bin_ts_hdr() const {
		auto peregrine_bin_len_hdr = get_peregrine_bin_len_hdr();
		auto peregrine_bin_len_hdr_size = get_peregrine_bin_len_hdr_size();

		if (peregrine_bin_len_hdr_size == 0) {
			printf("\n*** Not a peregrine bin len hdr packet!\
					Can't extract the bin ts header. ***\n");
			exit(1);
		}

		auto peregrine_bin_ts_hdr = (uint8_t*)peregrine_bin_len_hdr + peregrine_bin_len_hdr_size;
		return static_cast<peregrine_bin_ts_hdr_t*>((void*)peregrine_bin_ts_hdr);
	}

	void print_hdr_base() {
		auto eth_hdr = get_l2();
		auto ip_hdr = get_l3();
		auto l4_hdr = get_l4();

		printf("### Ethernet ###\n");
		printf("# src	%02x:%02x:%02x:%02x:%02x:%02x\n", eth_hdr->src_mac[0],
			   eth_hdr->src_mac[1], eth_hdr->src_mac[2], eth_hdr->src_mac[3],
			   eth_hdr->src_mac[4], eth_hdr->src_mac[5]);
		printf("# dst	%02x:%02x:%02x:%02x:%02x:%02x\n", eth_hdr->dst_mac[0],
			   eth_hdr->dst_mac[1], eth_hdr->dst_mac[2], eth_hdr->dst_mac[3],
			   eth_hdr->dst_mac[4], eth_hdr->dst_mac[5]);
		printf("# type	0x%x\n", ntohs(eth_hdr->eth_type));

		printf("### IP ###\n");
		printf("# ihl		%u\n", (ip_hdr->ihl & 0x0f));
		printf("# version	%u\n", (ip_hdr->ihl & 0xf0) >> 4);
		printf("# tos		%u\n", ip_hdr->version);
		printf("# len		%u\n", ntohs(ip_hdr->tot_len));
		printf("# id		%u\n", ntohs(ip_hdr->id));
		printf("# off		%u\n", ntohs(ip_hdr->frag_off));
		printf("# ttl		%u\n", ip_hdr->ttl);
		printf("# proto		%u\n", ip_hdr->protocol);
		printf("# chksum	0x%x\n", ntohs(ip_hdr->check));
		printf("# src		%u.%u.%u.%u\n", (ip_hdr->src_ip >> 0) & 0xff,
			   (ip_hdr->src_ip >> 8) & 0xff, (ip_hdr->src_ip >> 16) & 0xff,
			   (ip_hdr->src_ip >> 24) & 0xff);
		printf("# dst		%u.%u.%u.%u\n", (ip_hdr->dst_ip >> 0) & 0xff,
			   (ip_hdr->dst_ip >> 8) & 0xff, (ip_hdr->dst_ip >> 16) & 0xff,
			   (ip_hdr->dst_ip >> 24) & 0xff);

		switch (l4_hdr.second) {
			case IP_PROTO_TCP: {
				auto tcp_hdr = static_cast<tcp_hdr_t*>(l4_hdr.first);
				printf("### TCP ###\n");
				printf("# sport		%u\n", ntohs(tcp_hdr->src_port));
				printf("# dport		%u\n", ntohs(tcp_hdr->dst_port));
			} break;
			case IP_PROTO_UDP: {
				auto udp_hdr = static_cast<udp_hdr_t*>(l4_hdr.first);
				printf("### UDP ###\n");
				printf("# sport		%u\n", ntohs(udp_hdr->src_port));
				printf("# dport		%u\n", ntohs(udp_hdr->dst_port));
			} break;
			case IP_PROTO_ICMP: {
				auto icmp_hdr = static_cast<icmp_hdr_t*>(l4_hdr.first);
				printf("### ICMP ###\n");
				printf("# type		%u\n", icmp_hdr->type);
				printf("# code		%u\n", icmp_hdr->code);
			} break;
			default: {
				printf("\nError: Not a TCP/UDP/ICMP packet.\n");
			} break;
		}
	}

	void print_peregrine_hdr() {
		if (!has_valid_protocol()) { return; }

		auto peregrine_hdr = get_peregrine_hdr();

		printf("### Peregrine ###\n");
		printf("# ts_start_0	%u\n", ntohl(peregrine_hdr->ts_start_0));
		printf("# ts_end_0		%u\n", ntohl(peregrine_hdr->ts_end_0));
		printf("# ts_agg_0		%u\n", ntohl(peregrine_hdr->ts_agg_0));
		printf("# ip_src_0		%u.%u.%u.%u\n",
			   (peregrine_hdr->ip_src_0 >> 0) & 0xff,
			   (peregrine_hdr->ip_src_0 >> 8) & 0xff,
			   (peregrine_hdr->ip_src_0 >> 16) & 0xff,
			   (peregrine_hdr->ip_src_0 >> 24) & 0xff);
		printf("# ip_dst_0		%u.%u.%u.%u\n",
			   (peregrine_hdr->ip_dst_0 >> 0) & 0xff,
			   (peregrine_hdr->ip_dst_0 >> 8) & 0xff,
			   (peregrine_hdr->ip_dst_0 >> 16) & 0xff,
			   (peregrine_hdr->ip_dst_0 >> 24) & 0xff);
		printf("# proto_0		%u\n", ntohl(peregrine_hdr->proto_0));
		printf("# ports_0		%u\n", ntohl(peregrine_hdr->ports_0));
		printf("# syn_ack_0		%u\n", ntohl(peregrine_hdr->syn_ack_0));
		printf("# fin_rst_0		%u\n", ntohl(peregrine_hdr->fin_rst_0));
		printf("# cnt_0			%u\n", ntohl(peregrine_hdr->cnt_0));
		printf("# len_0			%u\n", ntohl(peregrine_hdr->len_0));
		printf("# long_0		%u\n", ntohl(peregrine_hdr->long_0));
		printf("# ts_start_1	%u\n", ntohl(peregrine_hdr->ts_start_1));
		printf("# ts_end_1		%u\n", ntohl(peregrine_hdr->ts_end_1));
		printf("# ts_agg_1		%u\n", ntohl(peregrine_hdr->ts_agg_1));
		printf("# ip_src_1		%u.%u.%u.%u\n",
			   (peregrine_hdr->ip_src_1 >> 0) & 0xff,
			   (peregrine_hdr->ip_src_1 >> 8) & 0xff,
			   (peregrine_hdr->ip_src_1 >> 16) & 0xff,
			   (peregrine_hdr->ip_src_1 >> 24) & 0xff);
		printf("# ip_dst_1		%u.%u.%u.%u\n",
			   (peregrine_hdr->ip_dst_1 >> 0) & 0xff,
			   (peregrine_hdr->ip_dst_1 >> 8) & 0xff,
			   (peregrine_hdr->ip_dst_1 >> 16) & 0xff,
			   (peregrine_hdr->ip_dst_1 >> 24) & 0xff);
		printf("# proto_1		%u\n", ntohl(peregrine_hdr->proto_1));
		printf("# ports_1		%u\n", ntohl(peregrine_hdr->ports_1));
		printf("# syn_ack_1		%u\n", ntohl(peregrine_hdr->syn_ack_1));
		printf("# fin_rst_1		%u\n", ntohl(peregrine_hdr->fin_rst_1));
		printf("# cnt_1			%u\n", ntohl(peregrine_hdr->cnt_1));
		printf("# len_1			%u\n", ntohl(peregrine_hdr->len_1));
		printf("# long_1		%u\n", ntohl(peregrine_hdr->long_1));
		printf("# ts_start_2	%u\n", ntohl(peregrine_hdr->ts_start_2));
		printf("# ts_end_2		%u\n", ntohl(peregrine_hdr->ts_end_2));
		printf("# ts_agg_2		%u\n", ntohl(peregrine_hdr->ts_agg_2));
		printf("# ip_src_2		%u.%u.%u.%u\n",
			   (peregrine_hdr->ip_src_2 >> 0) & 0xff,
			   (peregrine_hdr->ip_src_2 >> 8) & 0xff,
			   (peregrine_hdr->ip_src_2 >> 16) & 0xff,
			   (peregrine_hdr->ip_src_2 >> 24) & 0xff);
		printf("# ip_dst_2		%u.%u.%u.%u\n",
			   (peregrine_hdr->ip_dst_2 >> 0) & 0xff,
			   (peregrine_hdr->ip_dst_2 >> 8) & 0xff,
			   (peregrine_hdr->ip_dst_2 >> 16) & 0xff,
			   (peregrine_hdr->ip_dst_2 >> 24) & 0xff);
		printf("# proto_2		%u\n", ntohl(peregrine_hdr->proto_2));
		printf("# ports_2		%u\n", ntohl(peregrine_hdr->ports_2));
		printf("# syn_ack_2		%u\n", ntohl(peregrine_hdr->syn_ack_2));
		printf("# fin_rst_2		%u\n", ntohl(peregrine_hdr->fin_rst_2));
		printf("# cnt_2			%u\n", ntohl(peregrine_hdr->cnt_2));
		printf("# len_2			%u\n", ntohl(peregrine_hdr->len_2));
		printf("# long_2		%u\n", ntohl(peregrine_hdr->long_2));
		printf("# ts_start_3	%u\n", ntohl(peregrine_hdr->ts_start_3));
		printf("# ts_end_3		%u\n", ntohl(peregrine_hdr->ts_end_3));
		printf("# ts_agg_3		%u\n", ntohl(peregrine_hdr->ts_agg_3));
		printf("# ip_src_3		%u.%u.%u.%u\n",
			   (peregrine_hdr->ip_src_3 >> 0) & 0xff,
			   (peregrine_hdr->ip_src_3 >> 8) & 0xff,
			   (peregrine_hdr->ip_src_3 >> 16) & 0xff,
			   (peregrine_hdr->ip_src_3 >> 24) & 0xff);
		printf("# ip_dst_3		%u.%u.%u.%u\n",
			   (peregrine_hdr->ip_dst_3 >> 0) & 0xff,
			   (peregrine_hdr->ip_dst_3 >> 8) & 0xff,
			   (peregrine_hdr->ip_dst_3 >> 16) & 0xff,
			   (peregrine_hdr->ip_dst_3 >> 24) & 0xff);
		printf("# proto_3		%u\n", ntohl(peregrine_hdr->proto_3));
		printf("# ports_3		%u\n", ntohl(peregrine_hdr->ports_3));
		printf("# syn_ack_3		%u\n", ntohl(peregrine_hdr->syn_ack_3));
		printf("# fin_rst_3		%u\n", ntohl(peregrine_hdr->fin_rst_3));
		printf("# cnt_3			%u\n", ntohl(peregrine_hdr->cnt_3));
		printf("# len_3			%u\n", ntohl(peregrine_hdr->len_3));
		printf("# long_3		%u\n", ntohl(peregrine_hdr->long_3));
	}

	void print_peregrine_bin_len_hdr() {
		if (!has_valid_protocol()) { return; }

		auto bin_len_hdr = get_peregrine_bin_len_hdr();

		printf("### Peregrine bin len ###\n");
		printf("# bin_0_0_a		%u\n", ntohl(bin_len_hdr->bin_0_0_a));
		printf("# bin_0_0_b		%u\n", ntohl(bin_len_hdr->bin_0_0_b));
		printf("# bin_0_1_a		%u\n", ntohl(bin_len_hdr->bin_0_1_a));
		printf("# bin_0_1_b		%u\n", ntohl(bin_len_hdr->bin_0_1_b));
		printf("# bin_0_2_a		%u\n", ntohl(bin_len_hdr->bin_0_2_a));
		printf("# bin_0_2_b		%u\n", ntohl(bin_len_hdr->bin_0_2_b));
		printf("# bin_0_3_a		%u\n", ntohl(bin_len_hdr->bin_0_3_a));
		printf("# bin_0_3_b		%u\n", ntohl(bin_len_hdr->bin_0_3_b));
		printf("# bin_1_0_a		%u\n", ntohl(bin_len_hdr->bin_1_0_a));
		printf("# bin_1_0_b		%u\n", ntohl(bin_len_hdr->bin_1_0_b));
		printf("# bin_1_1_a		%u\n", ntohl(bin_len_hdr->bin_1_1_a));
		printf("# bin_1_1_b		%u\n", ntohl(bin_len_hdr->bin_1_1_b));
		printf("# bin_1_2_a		%u\n", ntohl(bin_len_hdr->bin_1_2_a));
		printf("# bin_1_2_b		%u\n", ntohl(bin_len_hdr->bin_1_2_b));
		printf("# bin_1_3_a		%u\n", ntohl(bin_len_hdr->bin_1_3_a));
		printf("# bin_1_3_b		%u\n", ntohl(bin_len_hdr->bin_1_3_b));
		printf("# bin_2_0_a		%u\n", ntohl(bin_len_hdr->bin_2_0_a));
		printf("# bin_2_0_b		%u\n", ntohl(bin_len_hdr->bin_2_0_b));
		printf("# bin_2_1_a		%u\n", ntohl(bin_len_hdr->bin_2_1_a));
		printf("# bin_2_1_b		%u\n", ntohl(bin_len_hdr->bin_2_1_b));
		printf("# bin_2_2_a		%u\n", ntohl(bin_len_hdr->bin_2_2_a));
		printf("# bin_2_2_b		%u\n", ntohl(bin_len_hdr->bin_2_2_b));
		printf("# bin_2_3_a		%u\n", ntohl(bin_len_hdr->bin_2_3_a));
		printf("# bin_2_3_b		%u\n", ntohl(bin_len_hdr->bin_2_3_b));
		printf("# bin_3_0_a		%u\n", ntohl(bin_len_hdr->bin_3_0_a));
		printf("# bin_3_0_b		%u\n", ntohl(bin_len_hdr->bin_3_0_b));
		printf("# bin_3_1_a		%u\n", ntohl(bin_len_hdr->bin_3_1_a));
		printf("# bin_3_1_b		%u\n", ntohl(bin_len_hdr->bin_3_1_b));
		printf("# bin_3_2_a		%u\n", ntohl(bin_len_hdr->bin_3_2_a));
		printf("# bin_3_2_b		%u\n", ntohl(bin_len_hdr->bin_3_2_b));
		printf("# bin_3_3_a		%u\n", ntohl(bin_len_hdr->bin_3_3_a));
		printf("# bin_3_3_b		%u\n", ntohl(bin_len_hdr->bin_3_3_b));
		printf("# bin_4_0_a		%u\n", ntohl(bin_len_hdr->bin_4_0_a));
		printf("# bin_4_0_b		%u\n", ntohl(bin_len_hdr->bin_4_0_b));
		printf("# bin_4_1_a		%u\n", ntohl(bin_len_hdr->bin_4_1_a));
		printf("# bin_4_1_b		%u\n", ntohl(bin_len_hdr->bin_4_1_b));
		printf("# bin_4_2_a		%u\n", ntohl(bin_len_hdr->bin_4_2_a));
		printf("# bin_4_2_b		%u\n", ntohl(bin_len_hdr->bin_4_2_b));
		printf("# bin_4_3_a		%u\n", ntohl(bin_len_hdr->bin_4_3_a));
		printf("# bin_4_3_b		%u\n", ntohl(bin_len_hdr->bin_4_3_b));
	}

	void print_peregrine_bin_ts_hdr() {
		if (!has_valid_protocol()) { return; }

		auto bin_ts_hdr = get_peregrine_bin_ts_hdr();

		printf("### Peregrine bin ts ###\n");
		printf("# bin_0_0_a		%u\n", ntohl(bin_ts_hdr->bin_0_0_a));
		printf("# bin_0_0_b		%u\n", ntohl(bin_ts_hdr->bin_0_0_b));
		printf("# bin_0_1_a		%u\n", ntohl(bin_ts_hdr->bin_0_1_a));
		printf("# bin_0_1_b		%u\n", ntohl(bin_ts_hdr->bin_0_1_b));
		printf("# bin_0_2_a		%u\n", ntohl(bin_ts_hdr->bin_0_2_a));
		printf("# bin_0_2_b		%u\n", ntohl(bin_ts_hdr->bin_0_2_b));
		printf("# bin_0_3_a		%u\n", ntohl(bin_ts_hdr->bin_0_3_a));
		printf("# bin_0_3_b		%u\n", ntohl(bin_ts_hdr->bin_0_3_b));
		printf("# bin_1_0_a		%u\n", ntohl(bin_ts_hdr->bin_1_0_a));
		printf("# bin_1_0_b		%u\n", ntohl(bin_ts_hdr->bin_1_0_b));
		printf("# bin_1_1_a		%u\n", ntohl(bin_ts_hdr->bin_1_1_a));
		printf("# bin_1_1_b		%u\n", ntohl(bin_ts_hdr->bin_1_1_b));
		printf("# bin_1_2_a		%u\n", ntohl(bin_ts_hdr->bin_1_2_a));
		printf("# bin_1_2_b		%u\n", ntohl(bin_ts_hdr->bin_1_2_b));
		printf("# bin_1_3_a		%u\n", ntohl(bin_ts_hdr->bin_1_3_a));
		printf("# bin_1_3_b		%u\n", ntohl(bin_ts_hdr->bin_1_3_b));
		printf("# bin_2_0_a		%u\n", ntohl(bin_ts_hdr->bin_2_0_a));
		printf("# bin_2_0_b		%u\n", ntohl(bin_ts_hdr->bin_2_0_b));
		printf("# bin_2_1_a		%u\n", ntohl(bin_ts_hdr->bin_2_1_a));
		printf("# bin_2_1_b		%u\n", ntohl(bin_ts_hdr->bin_2_1_b));
		printf("# bin_2_2_a		%u\n", ntohl(bin_ts_hdr->bin_2_2_a));
		printf("# bin_2_2_b		%u\n", ntohl(bin_ts_hdr->bin_2_2_b));
		printf("# bin_2_3_a		%u\n", ntohl(bin_ts_hdr->bin_2_3_a));
		printf("# bin_2_3_b		%u\n", ntohl(bin_ts_hdr->bin_2_3_b));
		printf("# bin_3_0_a		%u\n", ntohl(bin_ts_hdr->bin_3_0_a));
		printf("# bin_3_0_b		%u\n", ntohl(bin_ts_hdr->bin_3_0_b));
		printf("# bin_3_1_a		%u\n", ntohl(bin_ts_hdr->bin_3_1_a));
		printf("# bin_3_1_b		%u\n", ntohl(bin_ts_hdr->bin_3_1_b));
		printf("# bin_3_2_a		%u\n", ntohl(bin_ts_hdr->bin_3_2_a));
		printf("# bin_3_2_b		%u\n", ntohl(bin_ts_hdr->bin_3_2_b));
		printf("# bin_3_3_a		%u\n", ntohl(bin_ts_hdr->bin_3_3_a));
		printf("# bin_3_3_b		%u\n", ntohl(bin_ts_hdr->bin_3_3_b));
		printf("# bin_4_0_a		%u\n", ntohl(bin_ts_hdr->bin_4_0_a));
		printf("# bin_4_0_b		%u\n", ntohl(bin_ts_hdr->bin_4_0_b));
		printf("# bin_4_1_a		%u\n", ntohl(bin_ts_hdr->bin_4_1_a));
		printf("# bin_4_1_b		%u\n", ntohl(bin_ts_hdr->bin_4_1_b));
		printf("# bin_4_2_a		%u\n", ntohl(bin_ts_hdr->bin_4_2_a));
		printf("# bin_4_2_b		%u\n", ntohl(bin_ts_hdr->bin_4_2_b));
		printf("# bin_4_3_a		%u\n", ntohl(bin_ts_hdr->bin_4_3_a));
		printf("# bin_4_3_b		%u\n", ntohl(bin_ts_hdr->bin_4_3_b));
	}
} __attribute__((packed));

};	// namespace hypervision
