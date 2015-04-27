#ifdef UNIT_TEST
#define CATCH_CONFIG_RUNNER 1
#include "catch.hpp"
#else
#include "commands.h"
#endif

int main(int argc, char** argv)
{
#ifdef UNIT_TEST
    Catch::Session s;
    return s.run(argc, argv);
#else
    return securefs::commands_main(argc, argv);
#endif
}
