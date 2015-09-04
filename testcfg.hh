#include <string>

class MappingInfo {
public:
	MappingInfo() {}
	MappingInfo(std::string _name, std::string src, std::string dst)
		: name(_name), srcname(src), dstname(dst) 	{}
	std::string name;
	std::string srcname;
	std::string dstname;
};
