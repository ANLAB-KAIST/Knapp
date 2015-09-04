#include "testcfg.hh"
#include "utils.hh"
#include "types.hh"
#include "json/json.h"
#include <string>
#include <sstream>
#include <vector>
#include <rte_atomic.h>



std::vector<MappingInfo> desc = {
	MappingInfo("rx_queues_to_ports", "rx_queue", "port"),
	MappingInfo("rx_queues_to_io_cores", "rx_queue", "io_core"),
	MappingInfo("io_cores_to_input_queues", "io_core", "input_queue"),
	MappingInfo("input_queues_to_accelerator_threads", "input_queue", "accelerator_thread"),
	MappingInfo("accelerator_threads_to_completion_queues", "accelerator_thread", "completion_queue"),
	MappingInfo("completion_queues_to_io_cores", "completion_queue", "io_core")
};

std::string join(std::vector<int>& vec) {
	std::stringstream ss;
	ss << "[";
	for(unsigned i = 0; i < vec.size(); i++) {
		if ( i != 0 ) {
			ss << ", " << vec[i];
		} else {
			ss << vec[i];
		}
	}
	ss << "]";
	return ss.str();
}

void print_mapping(std::vector<struct mapping>& vec, std::string& srcname, std::string& dstname) {
	for ( unsigned i = 0; i < vec.size(); i++ ) {
		printf("%ss %s maps to %ss %s with '%s' mapping\n", srcname.c_str(), join(vec[i].src).c_str(), dstname.c_str(), join(vec[i].dest).c_str(), (vec[i].policy == MAPPING_1_TO_1 ? "one-to-one" : "round-robin"));
	}
}

int main() {
	std::string cfgfile = "config.json";
	Json::Value config = parse_config(cfgfile);
	fprintf(stderr, "Parse successful\n");
	for(unsigned i = 0; i < desc.size(); i++) {
		std::vector<struct mapping> v;
		//fprintf(stderr, "Accessing '%s'...\n", desc[i]->name.c_str());
		Json::Value& numa = config[1];
		//fprintf(stderr, "CP 000000\n");
		Json::Value& to_resolv = numa[desc[i].name];
		//fprintf(stderr, "CP 000000000\n");
		resolve_mapping(to_resolv, v);
		print_mapping(v, desc[i].srcname, desc[i].dstname);
	}
	return 0;
}
