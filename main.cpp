#include <gflags/gflags.h>

#include "common.hpp"
#include "./graph_analyze/detector_main.hpp"

using namespace std;

// DEFINE_string(config, "../configuration/lrscan/http_lrscan.json",  "Configuration file location.");

int main(int argc, char * argv[]) {
    __START_FTIMMER__

    std::string config_path;
    std::string exec_type;

    config_path = std::string(argv[1]);
    exec_type = std::string(argv[2]);

    google::ParseCommandLineFlags(&argc, &argv, true);

    json config_j;
    try {
        // ifstream fin(FLAGS_config, ios::in);
        ifstream fin(config_path, ios::in);
        fin >> config_j;
    } catch (const exception & e) {
        FATAL_ERROR(e.what());
    }

    auto hv1 = make_shared<Hypervision::hypervision_detector>();
    hv1->config_via_json(config_j);
    if(exec_type == "batch") {
        hv1->start_batch();
    } else {
        hv1->start_stream();
    }

    __STOP_FTIMER__
    __PRINTF_EXE_TIME__

    return 0;
}
