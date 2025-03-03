#pragma once

#include "../common.hpp"
#include "../packet_parse/packet_basic.hpp"

namespace hypervision {

using binary_label_t = vector<bool>;

class BasicDataset {

private:
    vector<basic_packet4> parse_result;
    vector<basic_packet4> parse_train, parse_test;
    double_t train_ratio = 0.25;
    uint32_t train_num = 0;
    uint32_t sampl = 1;

    binary_label_t label;
    double_t attack_time_after = 0.0;
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
    void configure_via_json(const json & jin);

    inline auto get_train_test_dataset(void) const -> pair<decltype(parse_train), decltype(parse_train)> {
        return {parse_train, parse_test};
    }

    inline auto get_label(void) const -> decltype(label) {
        return label;
    }

    inline auto get_raw_pkt(void) const -> decltype(parse_result) {
        return parse_result;
    }

    void import_dataset() {
        __START_FTIMMER__
        ifstream _ifd(load_data_path);
        vector<string> string_temp;
        uint32_t count = 0;
        while (true) {
            string _s;
            if (getline(_ifd, _s)) {
                count++;
                if (count <= train_num) {
                    string_temp.push_back(_s);
                }
                else if (count > train_num && count % sampl == 0) {
                    string_temp.push_back(_s);
                } else {
                    continue;
                }
            } else {
                break;
            }
        }
        _ifd.close();
        size_t num_pkt = string_temp.size();
        LOGF("Num pkts: %lu", num_pkt);

        // const size_t multiplex_num = 64;
        const size_t multiplex_num = 1;
        const u_int32_t part_size = ceil(((double) num_pkt) / ((double) multiplex_num));
        vector<pair<size_t, size_t> > _assign;
        for (size_t core = 0, idx = 0; core < multiplex_num; ++ core, idx = min(idx + part_size, num_pkt)) {
            _assign.push_back({idx, min(idx + part_size, num_pkt)});
        }
        mutex add_m;
        auto __f = [&] (size_t _from, size_t _to) -> void {
            for (size_t i = _from; i < _to; ++ i) {
                const string & str = string_temp[i];
                if (str[0] == '4') {
                    const auto make_pkt = make_shared<basic_packet4>(str);
                } else {
                    const auto make_pkt = make_shared<basic_packet_bad>();
                }
            }
        };

        vector<thread> vt;
        for (size_t core = 0; core < multiplex_num; ++core) {
            vt.emplace_back(__f, _assign[core].first, _assign[core].second);
        }

        for (auto & t : vt)
            t.join();

        ifstream _ifl(load_label_path);
        string ll;
        _ifl >> ll;
        uint32_t count_label = 0;
        for (const char a: ll) {
            count_label++;
            // if (count_label <= train_num) {
            //     p_label->push_back(a == '1');
            // }
            // if (count_label > train_num && count_label % sampl == 0) {
            //     p_label->push_back(a == '1');
            // } else {
            //     continue;
            // }
        }
        _ifl.close();
        // assert(p_label->size() == p_parse_result->size());

        __STOP_FTIMER__
        __PRINTF_EXE_TIME__
    }
};

}
