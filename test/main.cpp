#define CATCH_CONFIG_RUNNER 1
#include "catch.hpp"
#include "platform.h"

int main(int argc, char** argv)
{
    securefs::platform_specific_initialize();
    securefs::OSService::get_default().ensure_directory("tmp", 0755);
    Catch::Session s;
    return s.run(argc, argv);
}
