#pragma once

#include <vector>
#include <netinet/in.h>
#include <stdint.h>

#include "pkt_hdr.h"

namespace hypervision {

struct sample_t {
	bool valid;

	uint32_t	ts_start_0;
	uint32_t	ts_end_0;
	uint32_t	ts_agg_0;
	uint32_t	ip_src_0;
	uint32_t	ip_dst_0;
	uint32_t	proto_0;
	uint32_t	ports_0;
	uint32_t	syn_ack_0;
	uint32_t	fin_rst_0;
	uint32_t	cnt_0;
	uint32_t	len_0;
	uint8_t		long_0;
	uint32_t	ts_start_1;
	uint32_t	ts_end_1;
	uint32_t	ts_agg_1;
	uint32_t	ip_src_1;
	uint32_t	ip_dst_1;
	uint32_t	proto_1;
	uint32_t	ports_1;
	uint32_t	syn_ack_1;
	uint32_t	fin_rst_1;
	uint32_t	cnt_1;
	uint32_t	len_1;
	uint8_t		long_1;
	uint32_t	ts_start_2;
	uint32_t	ts_end_2;
	uint32_t	ts_agg_2;
	uint32_t	ip_src_2;
	uint32_t	ip_dst_2;
	uint32_t	proto_2;
	uint32_t	ports_2;
	uint32_t	syn_ack_2;
	uint32_t	fin_rst_2;
	uint32_t	cnt_2;
	uint32_t	len_2;
	uint8_t		long_2;
	uint32_t	ts_start_3;
	uint32_t	ts_end_3;
	uint32_t	ts_agg_3;
	uint32_t	ip_src_3;
	uint32_t	ip_dst_3;
	uint32_t	proto_3;
	uint32_t	ports_3;
	uint32_t	syn_ack_3;
	uint32_t	fin_rst_3;
	uint32_t	cnt_3;
	uint32_t	len_3;
	uint8_t		long_3;

	uint32_t bin_len_0_0_a;
	uint32_t bin_len_0_0_b;
	uint32_t bin_len_0_1_a;
	uint32_t bin_len_0_1_b;
	uint32_t bin_len_0_2_a;
	uint32_t bin_len_0_2_b;
	uint32_t bin_len_0_3_a;
	uint32_t bin_len_0_3_b;
	uint32_t bin_len_1_0_a;
	uint32_t bin_len_1_0_b;
	uint32_t bin_len_1_1_a;
	uint32_t bin_len_1_1_b;
	uint32_t bin_len_1_2_a;
	uint32_t bin_len_1_2_b;
	uint32_t bin_len_1_3_a;
	uint32_t bin_len_1_3_b;
	uint32_t bin_len_2_0_a;
	uint32_t bin_len_2_0_b;
	uint32_t bin_len_2_1_a;
	uint32_t bin_len_2_1_b;
	uint32_t bin_len_2_2_a;
	uint32_t bin_len_2_2_b;
	uint32_t bin_len_2_3_a;
	uint32_t bin_len_2_3_b;
	uint32_t bin_len_3_0_a;
	uint32_t bin_len_3_0_b;
	uint32_t bin_len_3_1_a;
	uint32_t bin_len_3_1_b;
	uint32_t bin_len_3_2_a;
	uint32_t bin_len_3_2_b;
	uint32_t bin_len_3_3_a;
	uint32_t bin_len_3_3_b;
	uint32_t bin_len_4_0_a;
	uint32_t bin_len_4_0_b;
	uint32_t bin_len_4_1_a;
	uint32_t bin_len_4_1_b;
	uint32_t bin_len_4_2_a;
	uint32_t bin_len_4_2_b;
	uint32_t bin_len_4_3_a;
	uint32_t bin_len_4_3_b;

	uint32_t bin_ts_0_0_a;
	uint32_t bin_ts_0_0_b;
	uint32_t bin_ts_0_1_a;
	uint32_t bin_ts_0_1_b;
	uint32_t bin_ts_0_2_a;
	uint32_t bin_ts_0_2_b;
	uint32_t bin_ts_0_3_a;
	uint32_t bin_ts_0_3_b;
	uint32_t bin_ts_1_0_a;
	uint32_t bin_ts_1_0_b;
	uint32_t bin_ts_1_1_a;
	uint32_t bin_ts_1_1_b;
	uint32_t bin_ts_1_2_a;
	uint32_t bin_ts_1_2_b;
	uint32_t bin_ts_1_3_a;
	uint32_t bin_ts_1_3_b;
	uint32_t bin_ts_2_0_a;
	uint32_t bin_ts_2_0_b;
	uint32_t bin_ts_2_1_a;
	uint32_t bin_ts_2_1_b;
	uint32_t bin_ts_2_2_a;
	uint32_t bin_ts_2_2_b;
	uint32_t bin_ts_2_3_a;
	uint32_t bin_ts_2_3_b;
	uint32_t bin_ts_3_0_a;
	uint32_t bin_ts_3_0_b;
	uint32_t bin_ts_3_1_a;
	uint32_t bin_ts_3_1_b;
	uint32_t bin_ts_3_2_a;
	uint32_t bin_ts_3_2_b;
	uint32_t bin_ts_3_3_a;
	uint32_t bin_ts_3_3_b;
	uint32_t bin_ts_4_0_a;
	uint32_t bin_ts_4_0_b;
	uint32_t bin_ts_4_1_a;
	uint32_t bin_ts_4_1_b;
	uint32_t bin_ts_4_2_a;
	uint32_t bin_ts_4_2_b;
	uint32_t bin_ts_4_3_a;
	uint32_t bin_ts_4_3_b;

	sample_t(pkt_hdr_t* pkt, size_t pkt_size) {
		valid = pkt->has_valid_protocol();

		if (!valid) {
			printf("Invalid protocol packet. Ignoring.\n");
			return;
		}

		#ifdef DEBUG
			pkt->print_hdr_base();
		#endif

		valid =
			(pkt_size >= (pkt->get_l2_size()
						  + pkt->get_l3_size()
						  + pkt->get_l4_size()
						  + pkt->get_peregrine_hdr_size()
						  + pkt->get_peregrine_bin_len_hdr_size()
						  + pkt->get_peregrine_bin_ts_hdr_size()));

		if (!valid) {
			printf("Packet too small. Ignoring.\n");
			return;
		}

		auto l2 = pkt->get_l2();
		auto l3 = pkt->get_l3();

		auto peregrine_hdr	= pkt->get_peregrine_hdr();
		auto bin_len_hdr	= pkt->get_peregrine_bin_len_hdr();
		auto bin_ts_hdr		= pkt->get_peregrine_bin_ts_hdr();

		#ifdef DEBUG
			pkt->print_peregrine_hdr();
			pkt->print_peregrine_bin_len_hdr();
			pkt->print_peregrine_bin_ts_hdr();
		#endif

		ts_start_0	= ntohl(peregrine_hdr->ts_start_0);
		ts_end_0	= ntohl(peregrine_hdr->ts_end_0);
		ts_agg_0	= ntohl(peregrine_hdr->ts_agg_0);
		ip_src_0	= peregrine_hdr->ip_src_0;
		ip_dst_0	= peregrine_hdr->ip_dst_0;
		proto_0		= ntohl(peregrine_hdr->proto_0);
		ports_0		= ntohl(peregrine_hdr->ports_0);
		syn_ack_0	= ntohl(peregrine_hdr->syn_ack_0);
		fin_rst_0	= ntohl(peregrine_hdr->fin_rst_0);
		cnt_0		= ntohl(peregrine_hdr->cnt_0);
		len_0		= ntohl(peregrine_hdr->len_0);
		long_0		= ntohl(peregrine_hdr->long_0);
		ts_start_1	= ntohl(peregrine_hdr->ts_start_1);
		ts_end_1	= ntohl(peregrine_hdr->ts_end_1);
		ts_agg_1	= ntohl(peregrine_hdr->ts_agg_1);
		ip_src_1	= peregrine_hdr->ip_src_1;
		ip_dst_1	= peregrine_hdr->ip_dst_1;
		proto_1		= ntohl(peregrine_hdr->proto_1);
		ports_1		= ntohl(peregrine_hdr->ports_1);
		syn_ack_1	= ntohl(peregrine_hdr->syn_ack_1);
		fin_rst_1	= ntohl(peregrine_hdr->fin_rst_1);
		cnt_1		= ntohl(peregrine_hdr->cnt_1);
		len_1		= ntohl(peregrine_hdr->len_1);
		long_1		= ntohl(peregrine_hdr->long_1);
		ts_start_2	= ntohl(peregrine_hdr->ts_start_2);
		ts_end_2	= ntohl(peregrine_hdr->ts_end_2);
		ts_agg_2	= ntohl(peregrine_hdr->ts_agg_2);
		ip_src_2	= peregrine_hdr->ip_src_2;
		ip_dst_2	= peregrine_hdr->ip_dst_2;
		proto_2		= ntohl(peregrine_hdr->proto_2);
		ports_2		= ntohl(peregrine_hdr->ports_2);
		syn_ack_2	= ntohl(peregrine_hdr->syn_ack_2);
		fin_rst_2	= ntohl(peregrine_hdr->fin_rst_2);
		cnt_2		= ntohl(peregrine_hdr->cnt_2);
		len_2		= ntohl(peregrine_hdr->len_2);
		long_2		= ntohl(peregrine_hdr->long_2);
		ts_start_3	= ntohl(peregrine_hdr->ts_start_3);
		ts_end_3	= ntohl(peregrine_hdr->ts_end_3);
		ts_agg_3	= ntohl(peregrine_hdr->ts_agg_3);
		ip_src_3	= peregrine_hdr->ip_src_3;
		ip_dst_3	= peregrine_hdr->ip_dst_3;
		proto_3		= ntohl(peregrine_hdr->proto_3);
		ports_3		= ntohl(peregrine_hdr->ports_3);
		syn_ack_3	= ntohl(peregrine_hdr->syn_ack_3);
		fin_rst_3	= ntohl(peregrine_hdr->fin_rst_3);
		cnt_3		= ntohl(peregrine_hdr->cnt_3);
		len_3		= ntohl(peregrine_hdr->len_3);
		long_3		= ntohl(peregrine_hdr->long_3);

		bin_len_0_0_a	= ntohl(bin_len_hdr->bin_0_0_a);
		bin_len_0_0_b	= ntohl(bin_len_hdr->bin_0_0_b);
		bin_len_0_1_a	= ntohl(bin_len_hdr->bin_0_1_a);
		bin_len_0_1_b	= ntohl(bin_len_hdr->bin_0_1_b);
		bin_len_0_2_a	= ntohl(bin_len_hdr->bin_0_2_a);
		bin_len_0_2_b	= ntohl(bin_len_hdr->bin_0_2_b);
		bin_len_0_3_a	= ntohl(bin_len_hdr->bin_0_3_a);
		bin_len_0_3_b	= ntohl(bin_len_hdr->bin_0_3_b);
		bin_len_1_0_a	= ntohl(bin_len_hdr->bin_1_0_a);
		bin_len_1_0_b	= ntohl(bin_len_hdr->bin_1_0_b);
		bin_len_1_1_a	= ntohl(bin_len_hdr->bin_1_1_a);
		bin_len_1_1_b	= ntohl(bin_len_hdr->bin_1_1_b);
		bin_len_1_2_a	= ntohl(bin_len_hdr->bin_1_2_a);
		bin_len_1_2_b	= ntohl(bin_len_hdr->bin_1_2_b);
		bin_len_1_3_a	= ntohl(bin_len_hdr->bin_1_3_a);
		bin_len_1_3_b	= ntohl(bin_len_hdr->bin_1_3_b);
		bin_len_2_0_a	= ntohl(bin_len_hdr->bin_2_0_a);
		bin_len_2_0_b	= ntohl(bin_len_hdr->bin_2_0_b);
		bin_len_2_1_a	= ntohl(bin_len_hdr->bin_2_1_a);
		bin_len_2_1_b	= ntohl(bin_len_hdr->bin_2_1_b);
		bin_len_2_2_a	= ntohl(bin_len_hdr->bin_2_2_a);
		bin_len_2_2_b	= ntohl(bin_len_hdr->bin_2_2_b);
		bin_len_2_3_a	= ntohl(bin_len_hdr->bin_2_3_a);
		bin_len_2_3_b	= ntohl(bin_len_hdr->bin_2_3_b);
		bin_len_3_0_a	= ntohl(bin_len_hdr->bin_3_0_a);
		bin_len_3_0_b	= ntohl(bin_len_hdr->bin_3_0_b);
		bin_len_3_1_a	= ntohl(bin_len_hdr->bin_3_1_a);
		bin_len_3_1_b	= ntohl(bin_len_hdr->bin_3_1_b);
		bin_len_3_2_a	= ntohl(bin_len_hdr->bin_3_2_a);
		bin_len_3_2_b	= ntohl(bin_len_hdr->bin_3_2_b);
		bin_len_3_3_a	= ntohl(bin_len_hdr->bin_3_3_a);
		bin_len_3_3_b	= ntohl(bin_len_hdr->bin_3_3_b);
		bin_len_4_0_a	= ntohl(bin_len_hdr->bin_4_0_a);
		bin_len_4_0_b	= ntohl(bin_len_hdr->bin_4_0_b);
		bin_len_4_1_a	= ntohl(bin_len_hdr->bin_4_1_a);
		bin_len_4_1_b	= ntohl(bin_len_hdr->bin_4_1_b);
		bin_len_4_2_a	= ntohl(bin_len_hdr->bin_4_2_a);
		bin_len_4_2_b	= ntohl(bin_len_hdr->bin_4_2_b);
		bin_len_4_3_a	= ntohl(bin_len_hdr->bin_4_3_a);
		bin_len_4_3_b	= ntohl(bin_len_hdr->bin_4_3_b);

		bin_ts_0_0_a	= ntohl(bin_ts_hdr->bin_0_0_a);
		bin_ts_0_0_b	= ntohl(bin_ts_hdr->bin_0_0_b);
		bin_ts_0_1_a	= ntohl(bin_ts_hdr->bin_0_1_a);
		bin_ts_0_1_b	= ntohl(bin_ts_hdr->bin_0_1_b);
		bin_ts_0_2_a	= ntohl(bin_ts_hdr->bin_0_2_a);
		bin_ts_0_2_b	= ntohl(bin_ts_hdr->bin_0_2_b);
		bin_ts_0_3_a	= ntohl(bin_ts_hdr->bin_0_3_a);
		bin_ts_0_3_b	= ntohl(bin_ts_hdr->bin_0_3_b);
		bin_ts_1_0_a	= ntohl(bin_ts_hdr->bin_1_0_a);
		bin_ts_1_0_b	= ntohl(bin_ts_hdr->bin_1_0_b);
		bin_ts_1_1_a	= ntohl(bin_ts_hdr->bin_1_1_a);
		bin_ts_1_1_b	= ntohl(bin_ts_hdr->bin_1_1_b);
		bin_ts_1_2_a	= ntohl(bin_ts_hdr->bin_1_2_a);
		bin_ts_1_2_b	= ntohl(bin_ts_hdr->bin_1_2_b);
		bin_ts_1_3_a	= ntohl(bin_ts_hdr->bin_1_3_a);
		bin_ts_1_3_b	= ntohl(bin_ts_hdr->bin_1_3_b);
		bin_ts_2_0_a	= ntohl(bin_ts_hdr->bin_2_0_a);
		bin_ts_2_0_b	= ntohl(bin_ts_hdr->bin_2_0_b);
		bin_ts_2_1_a	= ntohl(bin_ts_hdr->bin_2_1_a);
		bin_ts_2_1_b	= ntohl(bin_ts_hdr->bin_2_1_b);
		bin_ts_2_2_a	= ntohl(bin_ts_hdr->bin_2_2_a);
		bin_ts_2_2_b	= ntohl(bin_ts_hdr->bin_2_2_b);
		bin_ts_2_3_a	= ntohl(bin_ts_hdr->bin_2_3_a);
		bin_ts_2_3_b	= ntohl(bin_ts_hdr->bin_2_3_b);
		bin_ts_3_0_a	= ntohl(bin_ts_hdr->bin_3_0_a);
		bin_ts_3_0_b	= ntohl(bin_ts_hdr->bin_3_0_b);
		bin_ts_3_1_a	= ntohl(bin_ts_hdr->bin_3_1_a);
		bin_ts_3_1_b	= ntohl(bin_ts_hdr->bin_3_1_b);
		bin_ts_3_2_a	= ntohl(bin_ts_hdr->bin_3_2_a);
		bin_ts_3_2_b	= ntohl(bin_ts_hdr->bin_3_2_b);
		bin_ts_3_3_a	= ntohl(bin_ts_hdr->bin_3_3_a);
		bin_ts_3_3_b	= ntohl(bin_ts_hdr->bin_3_3_b);
		bin_ts_4_0_a	= ntohl(bin_ts_hdr->bin_4_0_a);
		bin_ts_4_0_b	= ntohl(bin_ts_hdr->bin_4_0_b);
		bin_ts_4_1_a	= ntohl(bin_ts_hdr->bin_4_1_a);
		bin_ts_4_1_b	= ntohl(bin_ts_hdr->bin_4_1_b);
		bin_ts_4_2_a	= ntohl(bin_ts_hdr->bin_4_2_a);
		bin_ts_4_2_b	= ntohl(bin_ts_hdr->bin_4_2_b);
		bin_ts_4_3_a	= ntohl(bin_ts_hdr->bin_4_3_a);
		bin_ts_4_3_b	= ntohl(bin_ts_hdr->bin_4_3_b);
	}
};

} // namespace hypervision
