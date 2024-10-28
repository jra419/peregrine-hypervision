#pragma once

#include "../common.hpp"
#include "pcpp_common.hpp"
#include "packet_basic.hpp"
#include "packet_info.hpp"
#include "pcapplusplus/PcapLiveDeviceList.h"
#include <memory>
#include <pcapplusplus/Device.h>

using namespace std;

namespace Hypervision {

class packet_listener final  {
private:
    const string target_interface;
    shared_ptr<pcpp::IPcapDevice::PcapStats> p_parse_state;
    shared_ptr<vector<shared_ptr<basic_packet> > > p_parse_result;
    shared_ptr<pcpp::RawPacketVector> p_packet_vec;

public:
    auto parse_raw_packet() -> decltype(p_packet_vec);
    auto parse_basic_packet_fast(size_t multiplex=16) -> decltype(p_parse_result);
    void start_capture(std::string);
    void type_statistic(void) const;

    packet_listener(const packet_listener &) = delete;
    packet_listener & operator=(const packet_listener &) = delete;
    virtual ~packet_listener() {}

    explicit packet_listener(const string & s): target_interface(s) {
        start_capture(s.c_str());
    }

    auto inline get_packet_vector() const -> const decltype(p_packet_vec) {
        if (p_packet_vec) {
            return p_packet_vec;
        } else {
            return nullptr;
        }
    }

    auto inline get_basic_packet_rep() const -> const decltype(p_parse_result) {
        if (p_parse_result) {
            return p_parse_result;
        } else {
            WARN("Void parse results returned.");
            return nullptr;
        }
    }
};

}
