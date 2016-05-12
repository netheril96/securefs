#include "catch.hpp"
#include "myutils.h"

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
    REQUIRE((securefs::split("bal/dd9", '/') == std::vector<std::string>{"bal", "dd9"}));
    REQUIRE((securefs::split("cdafadfm", ' ') == std::vector<std::string>{"cdafadfm"}));
    REQUIRE((securefs::split("", 'a')).empty());
    REQUIRE((securefs::split("//////", '/')).empty());
}

TEST_CASE("Test conversion of hex")
{
    securefs::id_type id;
    securefs::generate_random(id.data(), id.size());
    auto hex = securefs::hexify(id);
    securefs::id_type id_copy;
    securefs::parse_hex(hex, id_copy.data(), id_copy.size());
    REQUIRE(memcmp(id.data(), id_copy.data(), id.size()) == 0);
}

TEST_CASE("Test hkdf")
{
    const byte key[] = {0x1d,
                        0x8e,
                        0x2a,
                        0xec,
                        0x9,
                        0xd3,
                        0x29,
                        0x1a,
                        0x15,
                        0xa5,
                        0x8,
                        0x78,
                        0x6a,
                        0x2f,
                        0xdc,
                        0x28};
    const byte salt[] = {0x0,
                         0x32,
                         0xb2,
                         0x36,
                         0x1,
                         0x41,
                         0x5b,
                         0x4f,
                         0x93,
                         0x96,
                         0xff,
                         0xde,
                         0x5e,
                         0xb7,
                         0xa5,
                         0x3c};
    const byte true_derived_key[]
        = {0x49, 0x68, 0xbe, 0xf9, 0x9c, 0x95, 0x12, 0x73, 0xd0, 0x76, 0x4d, 0x66, 0x71, 0x37, 0xb,
           0x6d, 0x76, 0xa8, 0xc9, 0xd7, 0xee, 0x7f, 0x64, 0xe3, 0xc0, 0xb7, 0x13, 0x4f, 0xff, 0xf9,
           0xa3, 0x15, 0x1c, 0x2c, 0x72, 0x86, 0x47, 0x72, 0xdb, 0xd2, 0xf3, 0x22, 0x7d, 0xd2, 0xb6,
           0x7d, 0x83, 0x33, 0xad, 0x64, 0xf2, 0xe7, 0xb9, 0xcd, 0x7b, 0x7,  0xa,  0x86, 0xa4, 0xa3,
           0x6d, 0x20, 0xa4, 0xc5, 0x43, 0x9d, 0x90, 0x0,  0xe5, 0xcd, 0x6,  0x53, 0x1d, 0xe5, 0xbb,
           0x1e, 0xe0, 0xdb, 0x65, 0x2d, 0x75, 0x21, 0xbe, 0x2e, 0xc9, 0xbd, 0x5a, 0x8f, 0xa2, 0xf7,
           0x5,  0x1d, 0x88, 0xc,  0x26, 0x3a, 0x71, 0x5,  0x2d, 0x2};
    byte test_derived[sizeof(true_derived_key)];
    const char* info = "hkdf-example";
    securefs::hkdf(key,
                   sizeof(key),
                   salt,
                   sizeof(salt),
                   info,
                   strlen(info),
                   test_derived,
                   sizeof(test_derived));
    REQUIRE(memcmp(test_derived, true_derived_key, sizeof(test_derived)) == 0);
}
