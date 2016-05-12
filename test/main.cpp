#define CATCH_CONFIG_RUNNER 1
#include "catch.hpp"
#include "platform.h"

int main(int argc, char** argv)
{
	securefs::FileSystemService service;
	service.ensure_directory("tmp", 0755);
    Catch::Session s;
    return s.run(argc, argv);
}
