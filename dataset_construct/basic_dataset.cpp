#include "basic_dataset.hpp"

using namespace hypervision;

// Used to split p_parse_result, which contains all the processed packets,
// into train/test sets (p_parse_train, p_parse_test), and then to generate
// the trace labels (based on the attacker addresses defined in the config file).
// Both p_parse_train and p_parse_test are only used here, the later analysis is
// performed on p_parse_result only.
// The original implementation generated labels for p_parse_test only,
// resulting in an error at a later phase, since the graph analysis is performed
// for the entire p_parse_result.
// This is most likely a bug (no train/test separation is used later in the code)
// I've changed it so that the labels are generated for all packets.
void BasicDataset::do_dataset_construct(size_t multiplex) {
    __START_FTIMMER__

    if (parse_result.empty()) {
        FATAL_ERROR("Parsed dataset not found.");
    }
    if (!parse_train.empty() || !parse_test.empty() || !label.empty()) {
        WARN("The construction of dataset has already be done.");
    }

    size_t line = ceil(parse_result.size() * train_ratio);
    parse_train.insert(parse_train.begin(), parse_result.begin(), parse_result.begin() + line);
    parse_test.insert(parse_test.begin(), parse_result.begin(), parse_result.end());
    LOGF("[Train set: %8ld packets]", parse_train.size());

    fill_n(back_inserter(label), parse_test.size(), false);

    const u_int32_t part_size = ceil(((double) parse_test.size()) / ((double) multiplex));
    vector<pair<size_t, size_t> > _assign;
    for (size_t core = 0, idx = 0; core < multiplex; ++ core, idx += part_size) {
        _assign.push_back({idx, min(idx + part_size, parse_test.size())});
    }
    mutex add_m;
    double_t cur_time = GET_DOUBLE_TS(parse_test.at(0).ts);
    auto __f = [&] (size_t _from, size_t _to) -> void {
        vector<size_t> _index_to_label;
        for (size_t i = _from; i < _to; ++ i) {
            const auto ref = parse_test.at(i);
            if (GET_DOUBLE_TS(ref.ts) - cur_time - attack_time_after > EPS) {
                // if (p_attacker_src4 != nullptr && test_pkt_type_code(ref.tp, pkt_type_t::IPv4)) {
                if (p_attacker_src4 != nullptr) {
                    const auto p_packet = parse_test.at(i);
                    const string _addr = get_str_addr(tuple_get_src_addr(p_packet.flow_id));
                    for (const string & st: *p_attacker_src4) {
                        if (_addr.find(st) != string::npos) {
                            _index_to_label.push_back(i);
                            break;
                        }
                    }
                }

                // if (p_attacker_dst4 != nullptr && test_pkt_type_code(ref.tp, pkt_type_t::IPv4)) {
                if (p_attacker_dst4 != nullptr) {
                    const auto p_packet = parse_test.at(i);
                    const string _addr = get_str_addr(tuple_get_dst_addr(p_packet.flow_id));
                    for (const string & st: *p_attacker_dst4) {
                        if (_addr.find(st) != string::npos) {
                            _index_to_label.push_back(i);
                            break;
                        }
                    }
                }

                // if (p_attacker_srcdst4 != nullptr && test_pkt_type_code(ref.tp, pkt_type_t::IPv4)) {
                if (p_attacker_srcdst4 != nullptr) {
                    const auto p_packet = parse_test.at(i);
                    const string _srcaddr = get_str_addr(tuple_get_src_addr(p_packet.flow_id));
                    const string _dstaddr = get_str_addr(tuple_get_dst_addr(p_packet.flow_id));
                    for (const pair<string, string> & stp: *p_attacker_srcdst4) {
                        if (_srcaddr.find(stp.first) != string::npos && _dstaddr.find(stp.second) != string::npos) {
                            _index_to_label.push_back(i);
                            break;
                        }
                    }
                }
            }
        }

        add_m.lock();
        for (const auto _v: _index_to_label) {
            label.at(_v) = true;
        }
        add_m.unlock();
    };

    vector<thread> vt;
    for (size_t core = 0; core < multiplex; ++core) {
        vt.emplace_back(__f, _assign[core].first, _assign[core].second);
    }

    for (auto & t : vt)
        t.join();

    size_t num_malicious = count(label.begin(), label.end(), true);
    LOGF("[test  set: %8ld packets]", parse_test.size());
    LOGF("[%8ld benign (%4.2lf%%), %8ld malicious (%4.2lf%%)]",
        parse_test.size() - num_malicious,
        100.0 * (parse_test.size() - num_malicious) /  parse_test.size(),
        num_malicious, 100.0 * (num_malicious) /  parse_test.size());

    __STOP_FTIMER__
    __PRINTF_EXE_TIME__
}

void BasicDataset::configure_via_json(const json & jin) {
    try {
        if (jin.count("train_ratio")) {
            train_ratio = static_cast<decltype(train_ratio)>(jin["train_ratio"]);
            LOGF("[Train ratio: %f]", train_ratio);
            if (train_ratio < -EPS) {
                FATAL_ERROR("Ratio of training data is lower than 0.");
            }
        }
        if (jin.count("attack_time_after")) {
            attack_time_after = static_cast<decltype(attack_time_after)>(jin["attack_time_after"]);
        }
        if (jin.count("train_num")) {
            train_num = static_cast<decltype(train_num)>(jin["train_num"]);
        }
        if (jin.count("sampl")) {
            sampl = static_cast<decltype(sampl)>(jin["sampl"]);
        }

        if (jin.count("data_path")) {
            load_data_path = static_cast<decltype(load_data_path)>(jin["data_path"]);
        }
        if (jin.count("label_path")) {
            load_label_path = static_cast<decltype(load_label_path)>(jin["label_path"]);
        }

        if (jin.count("attacker_src4") && jin["attacker_src4"].size() != 0) {
            if (p_attacker_src4 != nullptr) {
                WARN("Reconfigure attacker source IPv4 list");
            }
            p_attacker_src4 = make_shared<decltype(p_attacker_src4)::element_type>();
            const auto _ls = jin["attacker_src4"];
            for (const auto & _l: _ls) {
                p_attacker_src4->push_back(static_cast<string>(_l));
            }
        }

        if (jin.count("attacker_dst4") && jin["attacker_dst4"].size() != 0) {
            if (p_attacker_dst4 != nullptr) {
                WARN("Reconfigure attacker destination IPv4 list");
            }
            p_attacker_dst4 = make_shared<decltype(p_attacker_dst4)::element_type>();
            const auto _ls = jin["attacker_dst4"];
            for (const auto & _l: _ls) {
                p_attacker_dst4->push_back(static_cast<string>(_l));
            }
        }

        if (jin.count("attacker_srcdst4") && jin["attacker_srcdst4"].size() != 0) {
            if (p_attacker_srcdst4 != nullptr) {
                WARN("Reconfigure attacker source-destination IPv4 list");
            }
            p_attacker_srcdst4 = make_shared<decltype(p_attacker_srcdst4)::element_type>();
            const auto _ls = jin["attacker_srcdst4"];
            for (const auto & _l: _ls) {
                if (_l.size() != 2) {
                    LOGF("[l size: %ld]", _l.size());
                    FATAL_ERROR("Wrong configuration format.");
                }
                p_attacker_srcdst4->push_back({static_cast<string>(_l[0]), static_cast<string>(_l[1])});
            }
        }
    } catch(const exception & e) {
        FATAL_ERROR(e.what());
    }
}
