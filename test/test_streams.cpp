#include "catch.hpp"

#include "streams.h"

#include <vector>
#include <random>
#include <algorithm>

#include <unistd.h>

static void test(securefs::StreamBase& stream, unsigned times)
{
    char temp_template[] = "/tmp/test_streams.XXXXXX";
    securefs::POSIXFileStream posix_stream(mkstemp(temp_template));
    posix_stream.resize(0);
    stream.resize(0);

    std::vector<byte> data(4096 * 5);
    std::vector<byte> buffer(data), posix_buffer(data);
    std::mt19937 mt{std::random_device{}()};

    {
        std::uniform_int_distribution<byte> dist;
        for (auto&& b : data)
            b = dist(mt);
    }

    std::uniform_int_distribution<int> flags_dist(0, 4);
    std::uniform_int_distribution<size_t> length_dist(0, 7 * 4096 + 1);
    for (size_t i = 0; i < times; ++i)
    {
        auto a = length_dist(mt);
        auto b = length_dist(mt);

        switch (flags_dist(mt))
        {
        case 0:
            stream.write(data.data(), a, std::min<size_t>(b, data.size()));
            posix_stream.write(data.data(), a, std::min<size_t>(b, data.size()));
            break;

        case 1:
        {
            std::fill(buffer.begin(), buffer.end(), 0xFF);
            posix_buffer = buffer;
            stream.read(buffer.data(), a, std::min<size_t>(b, buffer.size()));
            posix_stream.read(posix_buffer.data(), a, std::min<size_t>(b, posix_buffer.size()));
            auto equal = (buffer == posix_buffer);
            REQUIRE(equal);
            break;
        }

        case 2:
            REQUIRE(stream.size() == posix_stream.size());
            break;

        case 3:
            stream.resize(a);
            posix_stream.resize(a);
            break;

        case 4:
            stream.flush();
            posix_stream.flush();

        default:
            break;
        }
    }
}

TEST_CASE("Test streams")
{
    char temp_template[] = "/tmp/C6AD402F-B5FD-430A-BB2E-90006B22A1B8.XXXXXX";
    auto hmac_stream = securefs::make_stream_hmac(
        std::make_shared<securefs::SecureParam>(),
        std::make_shared<securefs::POSIXFileStream>(mkstemp(temp_template)),
        true);
    test(*hmac_stream, 5000);
}
