#define CATCH_CONFIG_RUNNER 1
#include "catch.hpp"
#include "platform.h"

namespace securefs
{

int test_main(int argc, const char* const* argv)
{
    securefs::FileSystemService service;
    service.ensure_directory("tmp", 0755);
    Catch::Session s;
    return s.run(argc, argv);
}
}