#include "catch.hpp"
#include "utils.h"

TEST_CASE("Test endian")
{
    using namespace securefs;

    uint32_t a = 0xABCDEF;
    byte raw[4];
    to_little_endian(a, raw);
    REQUIRE(raw[0] == 0xEF);
    REQUIRE(raw[1] == 0xCD);
    REQUIRE(raw[2] == 0xAB);
    REQUIRE(raw[3] == 0);
    REQUIRE(from_little_endian<uint32_t>(raw) == 0xABCDEF);
}

TEST_CASE("Test split")
{
    REQUIRE((securefs::split("/tmp//abcde/123/", '/')
             == std::vector<std::string>{"tmp", "abcde", "123"}));
    REQUIRE((securefs::split("", 'a')).empty());
    REQUIRE((securefs::split("//////", '/')).empty());
}
