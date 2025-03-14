#include "hypervision.hpp"

namespace hypervision {

std::atomic<bool> running(true);

std::unordered_map<uint8_t, uint32_t> dict_bin_ts = {
	{0, 16},
	{1, 32},
	{2, 48},
	{3, 64},
	{4, 80},
	{5, 96},
	{6, 112},
	{7, 128},
	{8, 144},
	{9, 160}
};

std::unordered_map<uint8_t, uint32_t> dict_bin_len = {
	{0, 256},
	{1, 512},
	{2, 768},
	{3, 1024},
	{4, 1280},
	{5, 1536},
	{6, 1792},
	{7, 2048},
	{8, 2304},
	{9, 2560}
};

void Hypervision::start_stream(void) {
	interface = jin_main["packet_listen"]["interface"];
	Listener p_listener(interface);


	std::thread listener_thread(&Hypervision::listener, this, std::ref(p_listener));
	auto last_ts = std::chrono::steady_clock::now();

	while (true) {
		auto cur_ts         = std::chrono::steady_clock::now();
		auto elapsed_time   = std::chrono::duration_cast<std::chrono::seconds>(cur_ts - last_ts);

		if (elapsed_time.count() > max_time) {
			std::cout << "Epoch " << std::to_string(epoch_cntr)
					  << ": No samples received." << std::endl;
			running = false;
			listener_thread.join();
			break;
		} else {
			if (cur_cntr >= epoch_cntr) {
				std::cout << "Epoch " << std::to_string(cur_epoch)
						  << ": " << std::to_string(sampl_vec.size())
						  << " Samples received." << std::endl;
				sampl_vec_cur = sampl_vec;
				sampl_vec.clear();
				cur_epoch++;

				cur_cntr	= 0;
				last_ts		= cur_ts;
			}
		}

		process_received_pkts();

		#ifdef DEBUG
			LOGF("Split datasets.");
		#endif
		const auto p_dataset_constructor = make_shared<BasicDataset>(parse_result);
		p_dataset_constructor->configure_via_json(jin_main["dataset_construct"]);
		p_dataset_constructor->do_dataset_construct();
		label = p_dataset_constructor->get_label();

		#ifdef DEBUG
			LOGF("Construct edge.");
		#endif
		const auto p_edge_constructor = make_shared<edge_constructor>(parse_result);
		p_edge_constructor->config_via_json(jin_main["edge_construct"]);
		p_edge_constructor->do_construct();
		tie(p_short_edges, p_long_edges) = p_edge_constructor->get_edge();

		#ifdef DEBUG
			LOGF("Construct Graph.");
		#endif
		const auto p_graph = make_shared<traffic_graph>(p_short_edges, p_long_edges);
		p_graph->config_via_json(jin_main["graph_analyze"]);
		p_graph->parse_edge();
		#ifdef DEBUG
			LOGF("Graph Detect.");
		#endif
		p_graph->graph_detect();
		p_loss = p_graph->get_final_pkt_score(label);

		if (save_result_enable) {
			do_save_stream(save_result_name, save_result_path);
		}

		parse_result.clear();
	}
}

void Hypervision::process_received_pkts(void) {
	for (size_t i = 0; i < sampl_vec_cur.size(); ++i) {
		decltype(flow::ts_start)	ts_start;
		decltype(flow::ts_end)		ts_end;
		decltype(flow::ts_agg)		ts_agg;
		pkt_addr4_t					ip_src, ip_dst;
		pkt_port_t					port_src, port_dst;
		pkt_proto_t					proto;
		uint32_t					proto_num = 0;
		pkt_cnt_t					cnt;
		pkt_len_t					len;
		pkt_code_t					code = 0;
		pkt_flag_t					flag_syn, flag_ack, flag_fin, flag_rst;
		uint8_t						flow_long;
		std::vector<uint32_t>		bin_len(2, 0);
		uint32_t					bin_len_num_pos;
		std::vector<uint32_t>		bin_ts(2, 0);

		if (sampl_vec_cur.at(i).ts_start_0 != 0) {
			ts_start	= sampl_vec_cur.at(i).ts_start_0;
			ts_end		= sampl_vec_cur.at(i).ts_end_0;
			ts_agg		= sampl_vec_cur.at(i).ts_agg_0;
			ip_src		= sampl_vec_cur.at(i).ip_src_0;
			ip_dst		= sampl_vec_cur.at(i).ip_dst_0;
			proto		= sampl_vec_cur.at(i).proto_0;
			port_src	= static_cast<uint16_t>(sampl_vec_cur.at(i).ports_0 >> 16);
			port_dst	= static_cast<uint16_t>(sampl_vec_cur.at(i).ports_0 & 0xFFFF);
			flag_syn	= static_cast<uint16_t>(sampl_vec_cur.at(i).syn_ack_0 >> 16);
			flag_ack	= static_cast<uint16_t>(sampl_vec_cur.at(i).syn_ack_0 & 0xFFFF);
			flag_fin	= static_cast<uint16_t>(sampl_vec_cur.at(i).fin_rst_0 >> 16);
			flag_rst	= static_cast<uint16_t>(sampl_vec_cur.at(i).fin_rst_0 & 0xFFFF);
			cnt			= sampl_vec_cur.at(i).cnt_0;
			len			= sampl_vec_cur.at(i).len_0;
			flow_long	= sampl_vec_cur.at(i).long_0;
			if (sampl_vec_cur.at(i).proto_0 == 0) {
				set_pkt_type_code(code, pkt_type_t::ICMP);
				proto_num = cnt;
			} else if (sampl_vec_cur.at(i).proto_0 == 6) {
				set_pkt_type_code(code, pkt_type_t::UDP);
				proto_num = cnt;
			} else if (sampl_vec_cur.at(i).proto_0 == 17) {
				if (flag_syn >= flag_ack && flag_syn >= flag_fin && flag_syn >= flag_rst) {
					set_pkt_type_code(code, pkt_type_t::TCP_SYN);
					proto_num = flag_syn;
				} else if (flag_ack >= flag_syn && flag_ack >= flag_fin && flag_ack >= flag_rst) {
					set_pkt_type_code(code, pkt_type_t::TCP_ACK);
					proto_num = flag_ack;
				} else if (flag_fin >= flag_syn && flag_fin >= flag_ack && flag_fin >= flag_rst) {
					set_pkt_type_code(code, pkt_type_t::TCP_FIN);
					proto_num = flag_fin;
				} else {
					set_pkt_type_code(code, pkt_type_t::TCP_RST);
					proto_num = flag_rst;
				}
			} else {
				set_pkt_type_code(code, pkt_type_t::UNKNOWN);
			}
			auto bin_len_tmp = val_and_num(sampl_vec_cur.at(i).bin_len_0_0_a,
										   sampl_vec_cur.at(i).bin_len_0_0_b,
										   sampl_vec_cur.at(i).bin_len_1_0_a,
										   sampl_vec_cur.at(i).bin_len_1_0_b,
										   sampl_vec_cur.at(i).bin_len_2_0_a,
										   sampl_vec_cur.at(i).bin_len_2_0_b,
										   sampl_vec_cur.at(i).bin_len_3_0_a,
										   sampl_vec_cur.at(i).bin_len_3_0_b,
										   sampl_vec_cur.at(i).bin_len_4_0_a,
										   sampl_vec_cur.at(i).bin_len_4_0_b);
			bin_len[0] = bin_len_tmp.first;
			bin_len[1] = dict_bin_len[bin_len_tmp.second];
			auto bin_ts_tmp = val_and_num(sampl_vec_cur.at(i).bin_ts_0_0_a,
										  sampl_vec_cur.at(i).bin_ts_0_0_b,
										  sampl_vec_cur.at(i).bin_ts_1_0_a,
										  sampl_vec_cur.at(i).bin_ts_1_0_b,
										  sampl_vec_cur.at(i).bin_ts_2_0_a,
										  sampl_vec_cur.at(i).bin_ts_2_0_b,
										  sampl_vec_cur.at(i).bin_ts_3_0_a,
										  sampl_vec_cur.at(i).bin_ts_3_0_b,
										  sampl_vec_cur.at(i).bin_ts_4_0_a,
										  sampl_vec_cur.at(i).bin_ts_4_0_b);
			bin_ts[0] = bin_ts_tmp.first;
			bin_ts[1] = dict_bin_ts[bin_ts_tmp.second];
			bin_len_num_pos = greater_than_zero(sampl_vec_cur.at(i).bin_len_0_0_a,
												sampl_vec_cur.at(i).bin_len_0_0_b,
												sampl_vec_cur.at(i).bin_len_1_0_a,
												sampl_vec_cur.at(i).bin_len_1_0_b,
												sampl_vec_cur.at(i).bin_len_2_0_a,
												sampl_vec_cur.at(i).bin_len_2_0_b,
												sampl_vec_cur.at(i).bin_len_3_0_a,
												sampl_vec_cur.at(i).bin_len_3_0_b,
												sampl_vec_cur.at(i).bin_len_4_0_a,
												sampl_vec_cur.at(i).bin_len_4_0_b);
			auto cur_flow = flow(ip_src, ip_dst, proto, proto_num, port_src, port_dst, ts_start,
								 ts_end, ts_agg, flag_syn, flag_ack, flag_fin, flag_rst, code, cnt, len, flow_long, bin_len, bin_len_num_pos, bin_ts);
			parse_result.push_back(std::make_shared<flow>(cur_flow));
		}
		if (sampl_vec_cur.at(i).ts_start_1 != 0) {
			ts_start	= sampl_vec_cur.at(i).ts_start_1;
			ts_end		= sampl_vec_cur.at(i).ts_end_1;
			ts_agg		= sampl_vec_cur.at(i).ts_agg_1;
			ip_src		= sampl_vec_cur.at(i).ip_src_1;
			ip_dst		= sampl_vec_cur.at(i).ip_dst_1;
			proto		= sampl_vec_cur.at(i).proto_1;
			port_src	= static_cast<uint16_t>(sampl_vec_cur.at(i).ports_1 >> 16);
			port_dst	= static_cast<uint16_t>(sampl_vec_cur.at(i).ports_1 & 0xFFFF);
			flag_syn	= static_cast<uint16_t>(sampl_vec_cur.at(i).syn_ack_1 >> 16);
			flag_ack	= static_cast<uint16_t>(sampl_vec_cur.at(i).syn_ack_1 & 0xFFFF);
			flag_fin	= static_cast<uint16_t>(sampl_vec_cur.at(i).fin_rst_1 >> 16);
			flag_rst	= static_cast<uint16_t>(sampl_vec_cur.at(i).fin_rst_1 & 0xFFFF);
			cnt			= sampl_vec_cur.at(i).cnt_1;
			len			= sampl_vec_cur.at(i).len_1;
			flow_long	= sampl_vec_cur.at(i).long_1;
			if (sampl_vec_cur.at(i).proto_1 == 0) {
				set_pkt_type_code(code, pkt_type_t::ICMP);
			} else if (sampl_vec_cur.at(i).proto_1 == 6) {
				set_pkt_type_code(code, pkt_type_t::UDP);
			} else if (sampl_vec_cur.at(i).proto_1 == 17) {
				if (flag_syn >= flag_ack && flag_syn >= flag_fin && flag_syn >= flag_rst) {
					set_pkt_type_code(code, pkt_type_t::TCP_SYN);
				} else if (flag_ack >= flag_syn && flag_ack >= flag_fin && flag_ack >= flag_rst) {
					set_pkt_type_code(code, pkt_type_t::TCP_ACK);
				} else if (flag_fin >= flag_syn && flag_fin >= flag_ack && flag_fin >= flag_rst) {
					set_pkt_type_code(code, pkt_type_t::TCP_FIN);
				} else {
					set_pkt_type_code(code, pkt_type_t::TCP_RST);
				}
			} else {
				set_pkt_type_code(code, pkt_type_t::UNKNOWN);
			}
			auto bin_len_tmp = val_and_num(sampl_vec_cur.at(i).bin_len_0_1_a,
										   sampl_vec_cur.at(i).bin_len_0_1_b,
										   sampl_vec_cur.at(i).bin_len_1_1_a,
										   sampl_vec_cur.at(i).bin_len_1_1_b,
										   sampl_vec_cur.at(i).bin_len_2_1_a,
										   sampl_vec_cur.at(i).bin_len_2_1_b,
										   sampl_vec_cur.at(i).bin_len_3_1_a,
										   sampl_vec_cur.at(i).bin_len_3_1_b,
										   sampl_vec_cur.at(i).bin_len_4_1_a,
										   sampl_vec_cur.at(i).bin_len_4_1_b);
			bin_len[0] = bin_len_tmp.first;
			bin_len[1] = dict_bin_len[bin_len_tmp.second];
			auto bin_ts_tmp = val_and_num(sampl_vec_cur.at(i).bin_ts_0_1_a,
										  sampl_vec_cur.at(i).bin_ts_0_1_b,
										  sampl_vec_cur.at(i).bin_ts_1_1_a,
										  sampl_vec_cur.at(i).bin_ts_1_1_b,
										  sampl_vec_cur.at(i).bin_ts_2_1_a,
										  sampl_vec_cur.at(i).bin_ts_2_1_b,
										  sampl_vec_cur.at(i).bin_ts_3_1_a,
										  sampl_vec_cur.at(i).bin_ts_3_1_b,
										  sampl_vec_cur.at(i).bin_ts_4_1_a,
										  sampl_vec_cur.at(i).bin_ts_4_1_b);
			bin_ts[0] = bin_ts_tmp.first;
			bin_ts[1] = dict_bin_ts[bin_ts_tmp.second];
			bin_len_num_pos = greater_than_zero(sampl_vec_cur.at(i).bin_len_0_1_a,
												sampl_vec_cur.at(i).bin_len_0_1_b,
												sampl_vec_cur.at(i).bin_len_1_1_a,
												sampl_vec_cur.at(i).bin_len_1_1_b,
												sampl_vec_cur.at(i).bin_len_2_1_a,
												sampl_vec_cur.at(i).bin_len_2_1_b,
												sampl_vec_cur.at(i).bin_len_3_1_a,
												sampl_vec_cur.at(i).bin_len_3_1_b,
												sampl_vec_cur.at(i).bin_len_4_1_a,
												sampl_vec_cur.at(i).bin_len_4_1_b);
			auto cur_flow = flow(ip_src, ip_dst, proto, proto_num, port_src, port_dst, ts_start,
								 ts_end, ts_agg, flag_syn, flag_ack, flag_fin, flag_rst, code, cnt, len, flow_long, bin_len, bin_len_num_pos, bin_ts);
			parse_result.push_back(std::make_shared<flow>(cur_flow));
		}
		if (sampl_vec_cur.at(i).ts_start_2 != 0) {
			ts_start	= sampl_vec_cur.at(i).ts_start_2;
			ts_end		= sampl_vec_cur.at(i).ts_end_2;
			ts_agg		= sampl_vec_cur.at(i).ts_agg_2;
			ip_src		= sampl_vec_cur.at(i).ip_src_2;
			ip_dst		= sampl_vec_cur.at(i).ip_dst_2;
			proto		= sampl_vec_cur.at(i).proto_2;
			port_src	= static_cast<uint16_t>(sampl_vec_cur.at(i).ports_2 >> 16);
			port_dst	= static_cast<uint16_t>(sampl_vec_cur.at(i).ports_2 & 0xFFFF);
			flag_syn	= static_cast<uint16_t>(sampl_vec_cur.at(i).syn_ack_2 >> 16);
			flag_ack	= static_cast<uint16_t>(sampl_vec_cur.at(i).syn_ack_2 & 0xFFFF);
			flag_fin	= static_cast<uint16_t>(sampl_vec_cur.at(i).fin_rst_2 >> 16);
			flag_rst	= static_cast<uint16_t>(sampl_vec_cur.at(i).fin_rst_2 & 0xFFFF);
			cnt			= sampl_vec_cur.at(i).cnt_2;
			len			= sampl_vec_cur.at(i).len_2;
			flow_long	= sampl_vec_cur.at(i).long_2;
			if (sampl_vec_cur.at(i).proto_2 == 0) {
				set_pkt_type_code(code, pkt_type_t::ICMP);
			} else if (sampl_vec_cur.at(i).proto_2 == 6) {
				set_pkt_type_code(code, pkt_type_t::UDP);
			} else if (sampl_vec_cur.at(i).proto_2 == 17) {
				if (flag_syn >= flag_ack && flag_syn >= flag_fin && flag_syn >= flag_rst) {
					set_pkt_type_code(code, pkt_type_t::TCP_SYN);
				} else if (flag_ack >= flag_syn && flag_ack >= flag_fin && flag_ack >= flag_rst) {
					set_pkt_type_code(code, pkt_type_t::TCP_ACK);
				} else if (flag_fin >= flag_syn && flag_fin >= flag_ack && flag_fin >= flag_rst) {
					set_pkt_type_code(code, pkt_type_t::TCP_FIN);
				} else {
					set_pkt_type_code(code, pkt_type_t::TCP_RST);
				}
			} else {
				set_pkt_type_code(code, pkt_type_t::UNKNOWN);
			}
			auto bin_len_tmp = val_and_num(sampl_vec_cur.at(i).bin_len_0_2_a,
										   sampl_vec_cur.at(i).bin_len_0_2_b,
										   sampl_vec_cur.at(i).bin_len_1_2_a,
										   sampl_vec_cur.at(i).bin_len_1_2_b,
										   sampl_vec_cur.at(i).bin_len_2_2_a,
										   sampl_vec_cur.at(i).bin_len_2_2_b,
										   sampl_vec_cur.at(i).bin_len_3_2_a,
										   sampl_vec_cur.at(i).bin_len_3_2_b,
										   sampl_vec_cur.at(i).bin_len_4_2_a,
										   sampl_vec_cur.at(i).bin_len_4_2_b);
			bin_len[0] = bin_len_tmp.first;
			bin_len[1] = dict_bin_len[bin_len_tmp.second];
			auto bin_ts_tmp = val_and_num(sampl_vec_cur.at(i).bin_ts_0_2_a,
										  sampl_vec_cur.at(i).bin_ts_0_2_b,
										  sampl_vec_cur.at(i).bin_ts_1_2_a,
										  sampl_vec_cur.at(i).bin_ts_1_2_b,
										  sampl_vec_cur.at(i).bin_ts_2_2_a,
										  sampl_vec_cur.at(i).bin_ts_2_2_b,
										  sampl_vec_cur.at(i).bin_ts_3_2_a,
										  sampl_vec_cur.at(i).bin_ts_3_2_b,
										  sampl_vec_cur.at(i).bin_ts_4_2_a,
										  sampl_vec_cur.at(i).bin_ts_4_2_b);
			bin_ts[0] = bin_ts_tmp.first;
			bin_ts[1] = dict_bin_ts[bin_ts_tmp.second];
			bin_len_num_pos = greater_than_zero(sampl_vec_cur.at(i).bin_len_0_2_a,
												sampl_vec_cur.at(i).bin_len_0_2_b,
												sampl_vec_cur.at(i).bin_len_1_2_a,
												sampl_vec_cur.at(i).bin_len_1_2_b,
												sampl_vec_cur.at(i).bin_len_2_2_a,
												sampl_vec_cur.at(i).bin_len_2_2_b,
												sampl_vec_cur.at(i).bin_len_3_2_a,
												sampl_vec_cur.at(i).bin_len_3_2_b,
												sampl_vec_cur.at(i).bin_len_4_2_a,
												sampl_vec_cur.at(i).bin_len_4_2_b);
			auto cur_flow = flow(ip_src, ip_dst, proto, proto_num, port_src, port_dst, ts_start,
								 ts_end, ts_agg, flag_syn, flag_ack, flag_fin, flag_rst, code, cnt, len, flow_long, bin_len, bin_len_num_pos, bin_ts);
			parse_result.push_back(std::make_shared<flow>(cur_flow));
		}
		if (sampl_vec_cur.at(i).ts_start_3 != 0) {
			ts_start	= sampl_vec_cur.at(i).ts_start_3;
			ts_end		= sampl_vec_cur.at(i).ts_end_3;
			ts_agg		= sampl_vec_cur.at(i).ts_agg_3;
			ip_src		= sampl_vec_cur.at(i).ip_src_3;
			ip_dst		= sampl_vec_cur.at(i).ip_dst_3;
			proto		= sampl_vec_cur.at(i).proto_3;
			port_src	= static_cast<uint16_t>(sampl_vec_cur.at(i).ports_3 >> 16);
			port_dst	= static_cast<uint16_t>(sampl_vec_cur.at(i).ports_3 & 0xFFFF);
			flag_syn	= static_cast<uint16_t>(sampl_vec_cur.at(i).syn_ack_3 >> 16);
			flag_ack	= static_cast<uint16_t>(sampl_vec_cur.at(i).syn_ack_3 & 0xFFFF);
			flag_fin	= static_cast<uint16_t>(sampl_vec_cur.at(i).fin_rst_3 >> 16);
			flag_rst	= static_cast<uint16_t>(sampl_vec_cur.at(i).fin_rst_3 & 0xFFFF);

			cnt			= sampl_vec_cur.at(i).cnt_3;
			len			= sampl_vec_cur.at(i).len_3;
			flow_long	= sampl_vec_cur.at(i).long_3;
			if (sampl_vec_cur.at(i).proto_3 == 0) {
				set_pkt_type_code(code, pkt_type_t::ICMP);
			} else if (sampl_vec_cur.at(i).proto_3 == 6) {
				set_pkt_type_code(code, pkt_type_t::UDP);
			} else if (sampl_vec_cur.at(i).proto_3 == 17) {
				if (flag_syn >= flag_ack && flag_syn >= flag_fin && flag_syn >= flag_rst) {
					set_pkt_type_code(code, pkt_type_t::TCP_SYN);
				} else if (flag_ack >= flag_syn && flag_ack >= flag_fin && flag_ack >= flag_rst) {
					set_pkt_type_code(code, pkt_type_t::TCP_ACK);
				} else if (flag_fin >= flag_syn && flag_fin >= flag_ack && flag_fin >= flag_rst) {
					set_pkt_type_code(code, pkt_type_t::TCP_FIN);
				} else {
					set_pkt_type_code(code, pkt_type_t::TCP_RST);
				}
			} else {
				set_pkt_type_code(code, pkt_type_t::UNKNOWN);
			}
			auto bin_len_tmp = val_and_num(sampl_vec_cur.at(i).bin_len_0_3_a,
										   sampl_vec_cur.at(i).bin_len_0_3_b,
										   sampl_vec_cur.at(i).bin_len_1_3_a,
										   sampl_vec_cur.at(i).bin_len_1_3_b,
										   sampl_vec_cur.at(i).bin_len_2_3_a,
										   sampl_vec_cur.at(i).bin_len_2_3_b,
										   sampl_vec_cur.at(i).bin_len_3_3_a,
										   sampl_vec_cur.at(i).bin_len_3_3_b,
										   sampl_vec_cur.at(i).bin_len_4_3_a,
										   sampl_vec_cur.at(i).bin_len_4_3_b);
			bin_len[0] = bin_len_tmp.first;
			bin_len[1] = dict_bin_len[bin_len_tmp.second];
			auto bin_ts_tmp = val_and_num(sampl_vec_cur.at(i).bin_ts_0_3_a,
										  sampl_vec_cur.at(i).bin_ts_0_3_b,
										  sampl_vec_cur.at(i).bin_ts_1_3_a,
										  sampl_vec_cur.at(i).bin_ts_1_3_b,
										  sampl_vec_cur.at(i).bin_ts_2_3_a,
										  sampl_vec_cur.at(i).bin_ts_2_3_b,
										  sampl_vec_cur.at(i).bin_ts_3_3_a,
										  sampl_vec_cur.at(i).bin_ts_3_3_b,
										  sampl_vec_cur.at(i).bin_ts_4_3_a,
										  sampl_vec_cur.at(i).bin_ts_4_3_b);
			bin_ts[0] = bin_ts_tmp.first;
			bin_ts[1] = dict_bin_ts[bin_ts_tmp.second];
			bin_len_num_pos = greater_than_zero(sampl_vec_cur.at(i).bin_len_0_3_a,
												sampl_vec_cur.at(i).bin_len_0_3_b,
												sampl_vec_cur.at(i).bin_len_1_3_a,
												sampl_vec_cur.at(i).bin_len_1_3_b,
												sampl_vec_cur.at(i).bin_len_2_3_a,
												sampl_vec_cur.at(i).bin_len_2_3_b,
												sampl_vec_cur.at(i).bin_len_3_3_a,
												sampl_vec_cur.at(i).bin_len_3_3_b,
												sampl_vec_cur.at(i).bin_len_4_3_a,
												sampl_vec_cur.at(i).bin_len_4_3_b);
			auto cur_flow = flow(ip_src, ip_dst, proto, proto_num, port_src, port_dst, ts_start,
								 ts_end, ts_agg, flag_syn, flag_ack, flag_fin, flag_rst, code, cnt, len, flow_long, bin_len, bin_len_num_pos, bin_ts);
			parse_result.push_back(std::make_shared<flow>(cur_flow));
		}
	}
}

template<typename... Args>
uint32_t Hypervision::greater_than_zero(Args... args) {
	uint32_t count = 0;
	((args > 0 ? ++count : count), ...);
	return count;
}

std::pair<uint32_t, uint32_t> Hypervision::val_and_num(uint32_t b0, uint32_t b1, uint32_t b2,
													   uint32_t b3, uint32_t b4, uint32_t b5,
													   uint32_t b6, uint32_t b7, uint32_t b8,
													   uint32_t b9) {
	uint32_t num		= b0;
	uint32_t val		= 0;
	uint32_t values[]	= {b0, b1, b2, b3, b4, b5, b6, b7, b8, b9};

	for (uint32_t i = 0; i < 10; ++i) {
		if (values[i] > num) {
			num = values[i];
			val = i;
		}
	}

	return std::make_pair(num, val);
}

void Hypervision::listener(Listener& p_listener) {
	while (running) {
		auto p_sampl = p_listener.receive_sample();
		if (p_sampl.valid) {
			cur_cntr++;
			sampl_vec.push_back(p_sampl);
		}
	}
}

void Hypervision::config_via_json(const nlohmann::json& jin) {
	try {
		if (
			jin.count("packet_listen") &&
			jin.count("dataset_construct") &&
			jin.count("flow_construct") &&
			jin.count("edge_construct") &&
			jin.count("graph_analyze") &&
			jin.count("result_save")) {
				jin_main = jin;
			} else {
				throw logic_error("Incomplete json configuration.");
			}
			const auto j_listen = jin["packet_listen"];
			const auto j_save	= jin["result_save"];
			if (j_listen.count("max_time")) {
				save_result_enable =
						static_cast<decltype(max_time)>(j_save["max_time"]);
			}
			if (j_listen.count("epoch_cntr")) {
				save_result_enable =
						static_cast<decltype(epoch_cntr)>(j_save["epoch_cntr"]);
			}
			if (j_save.count("save_result_enable")) {
				save_result_enable =
						static_cast<decltype(save_result_enable)>(j_save["save_result_enable"]);
			}
			if (j_save.count("save_result_name")) {
				save_result_name =
						static_cast<decltype(save_result_name)>(j_save["save_result_name"]);
			}
			if (j_save.count("save_result_path")) {
				save_result_path =
						static_cast<decltype(save_result_path)>(j_save["save_result_path"]);
			}
	} catch (const exception& e) {
		FATAL_ERROR(e.what());
	}
}

void Hypervision::do_save_stream(const string& save_name, const string& save_path) {
	ofstream _f(save_path + "/" + save_name + "-" + std::to_string(epoch_cntr) + ".csv");
	if (_f.is_open()) {
		try {
			_f << setprecision(4);
			_f << "ip_src,ip_dst,proto,port_src,port_dst,label,loss" << '\n';
			for (size_t i = 0; i < label.size(); ++i) {
				const string ip_src =
					get_str_addr(tuple_get_src_addr(parse_result.at(i)->flow_id));
				const string ip_dst =
					get_str_addr(tuple_get_dst_addr(parse_result.at(i)->flow_id));
				const string ip_proto = std::to_string(parse_result.at(i)->proto);
				const string port_src =
					std::to_string(tuple_get_src_port(parse_result.at(i)->flow_id));
				const string port_dst =
					std::to_string(tuple_get_dst_port(parse_result.at(i)->flow_id));
				_f << ip_src << ','
				   << ip_dst << ','
				   << ip_proto << ','
				   << port_src << ','
				   << port_dst << ','
				   << label.at(i) << ','
				   << p_loss->at(i) << '\n';
				if (i % 1000 == 0) {
					_f << flush;
				}
			}
		} catch (const exception& e) {
			FATAL_ERROR(e.what());
		}
		_f.close();
	} else {
		FATAL_ERROR("File Error.");
	}
}

}
