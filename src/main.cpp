#include "common.hpp"
#include "hypervision.hpp"

using namespace std;

int main(int argc, char * argv[]) {
	std::string config_path;

	config_path = std::string(argv[1]);

	nlohmann::json config_j;
	try {
		ifstream fin(config_path);
		fin >> config_j;
	} catch (const exception & e) {
		FATAL_ERROR(e.what());
	}

	auto hv1 = make_shared<hypervision::Hypervision>();

	hv1->config_via_json(config_j);
	hv1->start_stream();

	return 0;
}
