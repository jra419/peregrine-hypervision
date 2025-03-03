#pragma once

#include "packet_parse/packet_basic.hpp"
#include "packet_parse/packet_info.hpp"
#include "packet_parse/packet_listener.hpp"
#include "flow_construct/explicit_constructor.hpp"
#include "graph_analyze/edge_constructor.hpp"
#include "graph_analyze/graph_define.hpp"
#include <pcapplusplus/Device.h>

#include <memory>
#include <string>
#include <iostream>
#include <atomic>
#include <thread>
#include <unistd.h>
#include <typeinfo>

namespace hypervision {

std::atomic<bool> running(true);

class HypervisionDetector {

private:
	json jin_main;
	string file_path = "";
	string interface = "";
	int epoch_cntr = 0;
	int test_cntr = 0;

	shared_ptr<vector<shared_ptr<basic_packet>>> p_parse_result;
	vector<basic_packet4> parse_result;

	vector<sample_t> sampl_vec, sampl_vec_cur;
	shared_ptr<vector<sample_t>> p_sampl_vec;

	shared_ptr<binary_label_t> p_label;
	binary_label_t label;
	shared_ptr<vector<double_t> > p_loss;

	shared_ptr<vector<shared_ptr<basic_flow> > > p_flow;

	shared_ptr<vector<shared_ptr<short_edge> > > p_short_edges;
	shared_ptr<vector<shared_ptr<long_edge> > > p_long_edges;

	bool save_result_enable = false;
	string save_result_name = "tmp";
	string save_result_path = "../tmp/default.json";

public:

	void start_stream(void) {
		__START_FTIMMER__

		interface = jin_main["packet_listen"]["interface"];
		PacketListener p_packet_listener(interface);

		int empty_epoch_cntr = 0;

		// Listen to a network interface and capture packets.
		// All packets will be added to the packet vector.
		std::thread worker(&HypervisionDetector::listener, this, std::ref(p_packet_listener));

		// If more than x time has elapsed, process all the packets in the buffer.
		while(true) {
			sleep(20);
			epoch_cntr++;

			// If no sample arrived, reset the timer.
			if (sampl_vec.empty()) {
				std::cout << "Epoch " << std::to_string(epoch_cntr)
						  << ": No samples received." << std::endl;
				empty_epoch_cntr++;
				// If too many epochs have elapsed without any sample, terminate the capture.
				if(empty_epoch_cntr > 9) {
					running = false;
					worker.join();
					break;
				}
				continue;
			} else {
				std::cout << "Epoch " << std::to_string(epoch_cntr)
						  << ": " << std::to_string(sampl_vec.size())
						  << " Samples received." << std::endl;
				std::cout << "test: " << std::to_string(test_cntr) << std::endl;
				sampl_vec_cur = sampl_vec;
				// Reset sampl_vec to start filling the next epoch.
				sampl_vec.clear();
				test_cntr = 0;
				empty_epoch_cntr = 0;
			}

			// Create basic_packets from all the received samples.
			std::cout << "BEGIN sample vec cur size: "
					  << std::to_string(sampl_vec_cur.size()) << std::endl;
			std::cout << "BEGIN parse result size: "
					  << std::to_string(parse_result.size()) << std::endl;

			process_received_pkts();

			std::cout << "END sample vec cur size: "
					  << std::to_string(sampl_vec_cur.size()) << std::endl;
			std::cout << "END parse result size: "
					  << std::to_string(parse_result.size()) << std::endl;

			LOGF("Split datasets.");
			const auto p_dataset_constructor = make_shared<BasicDataset>(parse_result);
			p_dataset_constructor->configure_via_json(jin_main["dataset_construct"]);
			p_dataset_constructor->do_dataset_construct();
			label = p_dataset_constructor->get_label();

			LOGF("Construct flow.");
			const auto p_flow_constructor = make_shared<explicit_flow_constructor>(parse_result);
			p_flow_constructor->config_via_json(jin_main["flow_construct"]);
			p_flow_constructor->construct_flow();
			p_flow_constructor->dump_flow_statistic();
			p_flow = p_flow_constructor->get_constructed_raw_flow();

			LOGF("Construct edge.");
			const auto p_edge_constructor = make_shared<edge_constructor>(p_flow);
			p_edge_constructor->config_via_json(jin_main["edge_construct"]);
			p_edge_constructor->do_construct();
			// LOGF("Dump short edges.");
			// p_edge_constructor->dump_short_edge();
			// LOGF("Dump long edges.");
			// p_edge_constructor->dump_long_edge();
			tie(p_short_edges, p_long_edges) = p_edge_constructor->get_edge();

			LOGF("Construct Graph.");
			const auto p_graph = make_shared<traffic_graph>(p_short_edges, p_long_edges);
			LOGF("Config via json.");
			p_graph->config_via_json(jin_main["graph_analyze"]);
			LOGF("Parse Edge.");
			p_graph->parse_edge();
			// p_graph->dump_graph_statistic();
			// p_graph->dump_edge_anomly();
			// p_graph->dump_vertex_anomly();
			LOGF("Graph Detect.");
			p_graph->graph_detect();
			LOGF("Get final pkt score.");
			// p_loss = p_graph->get_final_pkt_score(p_label);
			p_loss = p_graph->get_final_pkt_score(label);

			if (save_result_enable) {
				do_save_stream(save_result_name, save_result_path);
			}

			// Clear the packet vector after each epoch.
			parse_result.clear();

			__STOP_FTIMER__
			__PRINTF_EXE_TIME__
		}
	}

	void process_received_pkts() {
		for (size_t i = 0; i < sampl_vec_cur.size(); ++i) {
			pkt_addr4_t ip_src, ip_dst;
			pkt_port_t port_src, port_dst;
			pkt_proto_t proto;
			pkt_cnt_t cnt;
			pkt_len_t len;
			pkt_code_t code;

			if (sampl_vec_cur.at(i).ts_start_0 != 0) {
				const decltype(basic_packet::ts_start) ts_start
						= sampl_vec_cur.at(i).ts_start_0;
				const decltype(basic_packet::ts_end) ts_end
						= sampl_vec_cur.at(i).ts_end_0;
				ip_src = sampl_vec_cur.at(i).ip_src_0;
				ip_dst = sampl_vec_cur.at(i).ip_dst_0;
				proto = sampl_vec_cur.at(i).proto_0;
				port_src = static_cast<uint16_t>(sampl_vec_cur.at(i).ports_0 >> 16);
				port_dst = static_cast<uint16_t>(sampl_vec_cur.at(i).ports_0 & 0xFFFF);
				cnt = sampl_vec_cur.at(i).cnt_0;
				len = sampl_vec_cur.at(i).len_0;
				if (sampl_vec_cur.at(i).proto_0 == 0) {
					set_pkt_type_code(code, pkt_type_t::ICMP);
				} else if (sampl_vec_cur.at(i).proto_0 == 6) {
					set_pkt_type_code(code, pkt_type_t::UDP);
				} else if (sampl_vec_cur.at(i).proto_0 == 17) {
					// Mark all packets as type TCP_SYN, since this value won't be used.
					set_pkt_type_code(code, pkt_type_t::TCP_SYN);
				} else {
					set_pkt_type_code(code, pkt_type_t::UNKNOWN);
				}
				auto pkt = basic_packet4(ip_src, ip_dst, proto, port_src, port_dst,
										 ts_start, ts_end, code, cnt, len);
				parse_result.push_back(pkt);
			}
			if (sampl_vec_cur.at(i).flow_ts_start_1 != 0) {
				ip_src = sampl_vec_cur.at(i).flow_ip_src_1;
				ip_dst = sampl_vec_cur.at(i).flow_ip_dst_1;
				proto = sampl_vec_cur.at(i).flow_proto_1;
				port_src = static_cast<uint16_t>(sampl_vec_cur.at(i).flow_ports_1 >> 16);
				port_dst = static_cast<uint16_t>(sampl_vec_cur.at(i).flow_ports_1 & 0xFFFF);
				const decltype(basic_packet::ts_start) ts_start
						= sampl_vec_cur.at(i).flow_ts_start_1;
				// const decltype(basic_packet::ts_start) ts_start
				//	   = get_time_spec(sampl_vec_cur.at(i).flow_ts_start_1);
				const decltype(basic_packet::ts_end) ts_end
						= sampl_vec_cur.at(i).flow_ts_end_1;
				// const decltype(basic_packet::ts_end) ts_end
				//	   = get_time_spec(sampl_vec_cur.at(i).flow_ts_end_1);
				cnt = sampl_vec_cur.at(i).flow_cnt_1;
				len = sampl_vec_cur.at(i).flow_len_1;
				if (sampl_vec_cur.at(i).flow_proto_1 == 0) {
					set_pkt_type_code(code, pkt_type_t::ICMP);
				} else if (sampl_vec_cur.at(i).flow_proto_1 == 6) {
					set_pkt_type_code(code, pkt_type_t::UDP);
				} else if (sampl_vec_cur.at(i).flow_proto_1 == 17) {
					// Mark all packets as type TCP_SYN, since this value won't be used.
					// The flow constructor will be correctly marked as TCP.
					set_pkt_type_code(code, pkt_type_t::TCP_SYN);
				} else {
					set_pkt_type_code(code, pkt_type_t::UNKNOWN);
				}
				auto pkt = basic_packet4(ip_src, ip_dst, proto, port_src, port_dst,
											ts_start, ts_end, code, cnt, len);
				parse_result.push_back(pkt);
			}
			if (sampl_vec_cur.at(i).flow_ts_start_2 != 0) {
				ip_src = sampl_vec_cur.at(i).flow_ip_src_2;
				ip_dst = sampl_vec_cur.at(i).flow_ip_dst_2;
				proto = sampl_vec_cur.at(i).flow_proto_2;
				port_src = static_cast<uint16_t>(sampl_vec_cur.at(i).flow_ports_2 >> 16);
				port_dst = static_cast<uint16_t>(sampl_vec_cur.at(i).flow_ports_2 & 0xFFFF);
				// const decltype(basic_packet::ts_start) ts_start
				//	   = get_time_spec(sampl_vec_cur.at(i).flow_ts_start_2);
				const decltype(basic_packet::ts_start) ts_start
						= sampl_vec_cur.at(i).flow_ts_start_2;
				// const decltype(basic_packet::ts_end) ts_end
				//	   = get_time_spec(sampl_vec_cur.at(i).flow_ts_end_2);
				const decltype(basic_packet::ts_end) ts_end
						= sampl_vec_cur.at(i).flow_ts_end_2;
				cnt = sampl_vec_cur.at(i).flow_cnt_2;
				len = sampl_vec_cur.at(i).flow_len_2;
				if (sampl_vec_cur.at(i).flow_proto_2 == 0) {
					set_pkt_type_code(code, pkt_type_t::ICMP);
				} else if (sampl_vec_cur.at(i).flow_proto_2 == 6) {
					set_pkt_type_code(code, pkt_type_t::UDP);
				} else if (sampl_vec_cur.at(i).flow_proto_2 == 17) {
					// Mark all packets as type TCP_SYN, since this value won't be used.
					// The flow constructor will be correctly marked as TCP.
					set_pkt_type_code(code, pkt_type_t::TCP_SYN);
				} else {
					set_pkt_type_code(code, pkt_type_t::UNKNOWN);
				}
				auto pkt = basic_packet4(ip_src, ip_dst, proto, port_src, port_dst,
											ts_start, ts_end, code, cnt, len);
				parse_result.push_back(pkt);
			}
			if (sampl_vec_cur.at(i).flow_ts_start_3 != 0) {
				ip_src = sampl_vec_cur.at(i).flow_ip_src_3;
				ip_dst = sampl_vec_cur.at(i).flow_ip_dst_3;
				proto = sampl_vec_cur.at(i).flow_proto_3;
				port_src = static_cast<uint16_t>(sampl_vec_cur.at(i).flow_ports_3 >> 16);
				port_dst = static_cast<uint16_t>(sampl_vec_cur.at(i).flow_ports_3 & 0xFFFF);
				// const decltype(basic_packet::ts_start) ts_start
				//	   = get_time_spec(sampl_vec_cur.at(i).flow_ts_start_3);
				const decltype(basic_packet::ts_start) ts_start
						= sampl_vec_cur.at(i).flow_ts_start_3;
				// const decltype(basic_packet::ts_end) ts_end
				//	   = get_time_spec(sampl_vec_cur.at(i).flow_ts_end_3);
				const decltype(basic_packet::ts_end) ts_end
						= sampl_vec_cur.at(i).flow_ts_end_3;
				cnt = sampl_vec_cur.at(i).flow_cnt_3;
				len = sampl_vec_cur.at(i).flow_len_3;
				if (sampl_vec_cur.at(i).flow_proto_3 == 0) {
					set_pkt_type_code(code, pkt_type_t::ICMP);
				} else if (sampl_vec_cur.at(i).flow_proto_3 == 6) {
					set_pkt_type_code(code, pkt_type_t::UDP);
				} else if (sampl_vec_cur.at(i).flow_proto_3 == 17) {
					// Mark all packets as type TCP_SYN, since this value won't be used.
					// The flow constructor will be correctly marked as TCP.
					set_pkt_type_code(code, pkt_type_t::TCP_SYN);
				} else {
					set_pkt_type_code(code, pkt_type_t::UNKNOWN);
				}
				auto pkt = basic_packet4(ip_src, ip_dst, proto, port_src, port_dst,
											ts_start, ts_end, code, cnt, len);
				parse_result.push_back(pkt);
			}
		}
	}

	void listener(PacketListener& p_packet_listener) {
		while (running) {
			auto p_sampl = p_packet_listener.receive_sample();
			test_cntr++;
			sampl_vec.push_back(p_sampl);
		}
	}

	void config_via_json(const json & jin) {
		try {
			if (
				jin.count("dataset_construct") &&
				jin.count("flow_construct") &&
				jin.count("edge_construct") &&
				jin.count("graph_analyze") &&
				jin.count("result_save")) {
					jin_main = jin;
				} else {
					throw logic_error("Incomplete json configuration.");
				}
				const auto j_save = jin["result_save"];
				if (j_save.count("save_result_enable")) {
					save_result_enable = static_cast<decltype(save_result_enable)>(j_save["save_result_enable"]);
				}
				if (j_save.count("save_result_name")) {
					save_result_name = static_cast<decltype(save_result_name)>(j_save["save_result_name"]);
				}
				if (j_save.count("save_result_path")) {
					save_result_path = static_cast<decltype(save_result_path)>(j_save["save_result_path"]);
				}
		} catch (const exception & e) {
			FATAL_ERROR(e.what());
		}
	}

	void do_save_stream(const string & save_name, const string & save_path) {
		__START_FTIMMER__

		ofstream _f(save_path + "/" + save_name + "-" + std::to_string(epoch_cntr) + ".csv");
		if (_f.is_open()) {
			try {
				_f << setprecision(4);
				_f << "ip_src,ip_dst,proto,port_src,port_dst,label,loss" << '\n';
				for (size_t i = 0; i < label.size(); ++i) {
					const string ip_src =
						get_str_addr(tuple_get_src_addr(parse_result.at(i).flow_id));
					const string ip_dst =
						get_str_addr(tuple_get_dst_addr(parse_result.at(i).flow_id));
					const string ip_proto = std::to_string(parse_result.at(i).proto);
					const string port_src =
						std::to_string(tuple_get_src_port(parse_result.at(i).flow_id));
					const string port_dst =
						std::to_string(tuple_get_dst_port(parse_result.at(i).flow_id));
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
			} catch(const exception & e) {
				FATAL_ERROR(e.what());
			}
			_f.close();
		} else {
			FATAL_ERROR("File Error.");
		}

		__STOP_FTIMER__
		__PRINTF_EXE_TIME__
	}
};

}
