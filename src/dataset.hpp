#pragma once

#include "common.hpp"
#include "flow.hpp"

namespace hypervision {

using binary_label_t = vector<bool>;

class BasicDataset {

private:
	vector<shared_ptr<flow>> parse_result;
	vector<shared_ptr<flow>> parse_train, parse_test;
	double_t train_ratio = 0.25;
	uint32_t train_num = 0;
	uint32_t sampl = 1;

	binary_label_t label;
	uint32_t attack_time_after = 0;
	shared_ptr<vector<string> > p_attacker_src4;
	shared_ptr<vector<string> > p_attacker_dst4;
	shared_ptr<vector<pair<string, string> > > p_attacker_srcdst4;

	string export_data_path = "";
	string export_label_path = "";

	string load_data_path = "";
	string load_label_path = "";

public:
	BasicDataset() {}
	BasicDataset(const decltype(parse_result) parse_result,
				  const double_t train_ratio=0.25, const double_t attack_time_after=0.0):
				  parse_result(parse_result), train_ratio(train_ratio), attack_time_after(attack_time_after) {}

	void set_attacker_mach_list(const decltype(p_attacker_src4) p_attacker_src4=nullptr,
								const decltype(p_attacker_dst4) p_attacker_dst4=nullptr,
								const decltype(p_attacker_srcdst4) p_attacker_srcdst4=nullptr) {
		this->p_attacker_src4 = p_attacker_src4;
		this->p_attacker_dst4 = p_attacker_dst4;
		this->p_attacker_srcdst4 = p_attacker_srcdst4;
	}

	void set_attacker_mach_list(const vector<string> & attacker_src4={},
								const vector<string> & attacker_dst4={},
								const vector<pair<string, string> > & attacker_srcdst4={}) {
		p_attacker_src4 = make_shared<decltype(p_attacker_src4)::element_type>
								(attacker_src4.cbegin(), attacker_src4.cend());
		p_attacker_dst4 = make_shared<decltype(p_attacker_dst4)::element_type>
								(attacker_dst4.cbegin(), attacker_dst4.cend());
		p_attacker_srcdst4 = make_shared<decltype(p_attacker_srcdst4)::element_type>
								(attacker_srcdst4.cbegin(), attacker_srcdst4.cend());
	}

	void do_dataset_construct(size_t multiplex=64);
	void configure_via_json(const nlohmann::json & jin);

	inline auto get_train_test_dataset(void) const -> pair<decltype(parse_train), decltype(parse_train)> {
		return {parse_train, parse_test};
	}

	inline auto get_label(void) const -> decltype(label) {
		return label;
	}

	inline auto get_raw_pkt(void) const -> decltype(parse_result) {
		return parse_result;
	}
};

}
