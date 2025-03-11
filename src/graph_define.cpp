#include "graph_define.hpp"

using namespace hypervision;

auto traffic_graph::is_huge_short_edge(const addr_t addr) const -> bool {
	if ((short_edge_in.count(addr) && short_edge_in.at(addr).size() > huge_short_line) ||
		(short_edge_out.count(addr)  && short_edge_out.at(addr).size() > huge_short_line)) {
		return true;
	} else {
		return false;
	}
}

auto traffic_graph::is_huge_agg_short_edge(const addr_t & addr) const -> bool {
	if (short_edge_in_agg.count(addr)) {
		for (auto idx : short_edge_in_agg.at(addr))
			if (p_short_edge->at(idx)->get_agg_size() > huge_agg_short_line) {
				return true;
			}
	}

	if (short_edge_out_agg.count(addr)) {
		for (auto idx : short_edge_out_agg.at(addr))
			if (p_short_edge->at(idx)->get_agg_size() > huge_agg_short_line) {
				return true;
			}
	}

	return false;
}

void traffic_graph::dump_vertex_anomly(void) const {
	size_t va = 0, vga = 0;
	for(const auto & add: vertex_set_short) {
		if (is_huge_short_edge(add)) {
			++ va;
		}
		if (is_huge_agg_short_edge(add)) {
			++ vga;
		}
	}
	LOGF("Invalid vertex: %ld, Invalide aggregate: %ld.", va, vga);
}

auto traffic_graph::get_final_pkt_score(const binary_label_t p_label) ->
		const decltype(p_pkt_score) {
	if (p_pkt_score != nullptr) {
		WARN("Previous result overlap.");
	}

	p_pkt_score = make_shared<score_t>();
	fill_n(back_inserter(*p_pkt_score), p_label.size(), -1);
	for (size_t i = 0; i < p_long_edge->size(); ++ i) {
		const auto ref = p_long_edge->at(i)->get_raw_flow();
		const auto res = p_long_edge_score->at(i) + offset_l;
		p_pkt_score->at(i) = res;
	}

	for (size_t i = 0; i < p_short_edge->size(); ++i) {
		for (size_t j = 0; j < p_short_edge->at(i)->get_agg_size(); ++ j) {
			const auto ref = p_short_edge->at(i)->get_flow_index(j);
			const auto res = p_short_edge_score->at(i) + offset_s;
			p_pkt_score->at(j) = res;
		}
	}

	const auto p_loss = p_pkt_score;
	assert(p_loss->size() == p_label.size());
	double_t res_abnormal = 0.0;
	double_t res_normal = 0.0;
	size_t n_abnormal = count(p_label.begin(), p_label.end(), true);
	size_t n_normal = p_label.size() - n_abnormal;
	for (size_t i = 0; i < p_loss->size(); ++ i) {
		res_normal += ((double_t) !p_label.at(i)) * p_loss->at(i);
		res_abnormal += ((double_t) p_label.at(i)) * p_loss->at(i);
	}
	cout << res_abnormal / n_abnormal << endl;
	cout << res_normal / n_normal << endl;

	return p_pkt_score;
}

void traffic_graph::config_via_json(const nlohmann::json & jin) {
	try {
		if (jin.count("uc")) {
			uc = static_cast<decltype(uc)>(jin["uc"]);
		}
		if (jin.count("vc")) {
			vc = static_cast<decltype(vc)>(jin["vc"]);
		}

		if (jin.count("ul")) {
			ul = static_cast<decltype(ul)>(jin["ul"]);
		}
		if (jin.count("vl")) {
			vl = static_cast<decltype(vl)>(jin["vl"]);
		}

		if (jin.count("us")) {
			us = static_cast<decltype(us)>(jin["us"]);
		}
		if (jin.count("vs")) {
			vs = static_cast<decltype(vs)>(jin["vs"]);
		}

		if (jin.count("al")) {
			al = static_cast<decltype(al)>(jin["al"]);
		}
		if (jin.count("bl")) {
			bl = static_cast<decltype(bl)>(jin["bl"]);
		}
		if (jin.count("cl")) {
			cl = static_cast<decltype(cl)>(jin["cl"]);
		}

		if (jin.count("as")) {
			as = static_cast<decltype(as)>(jin["as"]);
		}
		if (jin.count("bs")) {
			bs = static_cast<decltype(bs)>(jin["bs"]);
		}
		if (jin.count("cs")) {
			cs = static_cast<decltype(cs)>(jin["cs"]);
		}

		if (jin.count("offset_l")) {
			offset_l = static_cast<decltype(offset_l)>(jin["offset_l"]);
		}
		if (jin.count("offset_s")) {
			offset_s = static_cast<decltype(offset_s)>(jin["offset_s"]);
		}
		if (jin.count("select_ratio")) {
			select_ratio = static_cast<decltype(select_ratio)>(jin["select_ratio"]);
			if (select_ratio < EPS) {
				FATAL_ERROR("The select ratio is lower than 0.");
			}
		}
		if (jin.count("proto_cluster")) {
			proto_cluster = static_cast<decltype(proto_cluster)>(jin["proto_cluster"]);
		}
	} catch (const exception & e) {
		FATAL_ERROR(e.what());
	}
}
