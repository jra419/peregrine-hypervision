#include "common.hpp"
#include "detector_main.hpp"

using namespace std;

int main(int argc, char * argv[]) {
    __START_FTIMMER__

    std::string config_path;

    config_path = std::string(argv[1]);

    json config_j;
    try {
        ifstream fin(config_path);
        fin >> config_j;
    } catch (const exception & e) {
        FATAL_ERROR(e.what());
    }

    auto hv1 = make_shared<hypervision::HypervisionDetector>();
    hv1->config_via_json(config_j);
    hv1->start_stream();

    __STOP_FTIMER__
    __PRINTF_EXE_TIME__

    return 0;
}
