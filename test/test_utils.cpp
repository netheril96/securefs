#ifdef UNIT_TEST
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

TEST_CASE("Test conversion of hex")
{
    securefs::id_type id;
    securefs::generate_random(id.data(), id.size());
    auto hex = securefs::hexify(id);
    securefs::id_type id_copy;
    securefs::parse_hex(hex, id_copy.data(), id_copy.size());
    REQUIRE(memcmp(id.data(), id_copy.data(), id.size()) == 0);
}

TEST_CASE("Test AES-CTR")
{
    securefs::key_type key{};
    const char data[] = "hello, world\n";
    char ciphertext[sizeof(data)];
    byte IV[16] = {};
    securefs::aes_ctr(data, sizeof(data), key.data(), key.size(), IV, sizeof(IV), ciphertext);
    securefs::aes_ctr(ciphertext, sizeof(ciphertext), key.data(), key.size(), IV, sizeof(IV), ciphertext);
    REQUIRE(memcmp(data, ciphertext, sizeof(data)) == 0);
}
#endif
