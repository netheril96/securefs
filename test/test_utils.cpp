#include "crypto.h"
#include "crypto_wrappers.h"
#include "myutils.h"
#include "platform.h"

#include <doctest/doctest.h>

#include <cryptopp/base32.h>

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

TEST_CASE("Test conversion of hex")
{
    securefs::id_type id;
    securefs::libcrypto::generate_random(securefs::MutableRawBuffer(id.data(), id.size()));
    auto hex = securefs::hexify(id);
    securefs::id_type id_copy;
    securefs::parse_hex(hex, id_copy.data(), id_copy.size());
    REQUIRE(memcmp(id.data(), id_copy.data(), id.size()) == 0);
}

TEST_CASE("Base32")
{
    CryptoPP::Base32Encoder enc;
    const byte from[] = "hello";
    byte out[256] = {}, out2[256] = {};
    enc.Put(from, sizeof(from));
    enc.MessageEnd();
    enc.Get(out, sizeof(out));

    enc.Initialize();
    enc.Put(from, sizeof(from));
    enc.MessageEnd();
    enc.Get(out2, sizeof(out2));
    CAPTURE(out);
    CAPTURE(out2);
    REQUIRE(strcmp((char*)out, (char*)out2) == 0);
}

TEST_CASE("our base32")
{
    std::string input, output, decoded;
    input.reserve(128);
    for (size_t i = 0; i < 128; ++i)
    {
        if (i > 0)
        {
            input.resize(i, 0);
            securefs::libcrypto::generate_random(securefs::MutableRawBuffer(input));
        }
        securefs::base32_encode((const byte*)input.data(), i, output);
        CAPTURE(output);
        securefs::base32_decode(output.data(), output.size(), decoded);
        CHECK(input == decoded);
    }
}

TEST_CASE("our base32 against CryptoPP")
{
    std::string input, output;
    char buffer[4000];
    input.reserve(128);
    for (size_t i = 0; i < 128; ++i)
    {
        if (i > 0)
        {
            input.resize(i, 0);
            securefs::libcrypto::generate_random(securefs::MutableRawBuffer(input));
        }
        securefs::base32_encode((const byte*)input.data(), i, output);

        CryptoPP::Base32Encoder enc;
        enc.Put((const byte*)input.data(), input.size());
        enc.MessageEnd();
        memset(buffer, 0, sizeof(buffer));
        enc.Get((byte*)buffer, sizeof(buffer));
        CHECK(output == buffer);
    }
}

TEST_CASE("is_ascii")
{
    REQUIRE(securefs::is_ascii(""));
    REQUIRE(securefs::is_ascii("a"));
    REQUIRE(securefs::is_ascii("abd;df-135j~"));
    REQUIRE(securefs::is_ascii("\x7f"));
    REQUIRE(securefs::is_ascii("abc\x11"));

    REQUIRE(!securefs::is_ascii("\xe8\xb0\xb7\xe6\xad\x8c"));
    REQUIRE(!securefs::is_ascii("\x41\xcc\x88\x66\x66\x69\x6e"));
    REQUIRE(!securefs::is_ascii("\x80"));
}
