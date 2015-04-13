#define CATCH_CONFIG_RUNNER 1
#include "catch.hpp"

#include "interfaces.h"
#include "exceptions.h"
#include "streams.h"

int main(int argc, char** argv) { return Catch::Session().run(argc, argv); }
