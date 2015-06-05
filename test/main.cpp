#define CATCH_CONFIG_RUNNER 1
#include "catch.hpp"

int main(int argc, char** argv)
{
    Catch::Session s;
    return s.run(argc, argv);
}
