#include "catch.hpp"

#include "streams.h"

#include <vector>
#include <random>
#include <algorithm>
#include <string.h>

#include <unistd.h>
#include <fcntl.h>

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

namespace securefs
{
namespace dummy
{
    // The "encryption" scheme of this class is horribly insecure
    // Only for testing the algorithms in CryptStream
    class DummpyCryptStream : public CryptStream
    {
    protected:
        void encrypt(offset_type block_number,
                     const void* input,
                     void* output,
                     length_type length) override
        {
            auto a = static_cast<byte>(block_number);
            for (length_type i = 0; i < length; ++i)
            {
                static_cast<byte*>(output)[i] = (static_cast<const byte*>(input)[i]) ^ a;
            }
        }

        void decrypt(offset_type block_number,
                     const void* input,
                     void* output,
                     length_type length) override
        {
            return encrypt(block_number, input, output, length);
        }

    public:
        explicit DummpyCryptStream(std::shared_ptr<StreamBase> stream, length_type block_size)
            : CryptStream(std::move(stream), block_size)
        {
        }
    };
}
}

void dump_contents(const std::vector<byte>& bytes, const char* filename)
{
    securefs::POSIXFileStream fs(::open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0600));
    fs.write(bytes.data(), 0, bytes.size());
}

TEST_CASE("Test streams")
{
    char temp_template[] = "/tmp/C6AD402F-B5FD-430A-BB2E-90006B22A1B8.XXXXXX";

    auto param = std::make_shared<securefs::SecureParam>();
    memset(param->key.data(), 0xFF, param->key.size());
    memset(param->id.data(), 0xFF, param->id.size());

    auto posix_stream = std::make_shared<securefs::POSIXFileStream>(mkstemp(temp_template));
    {
        auto hmac_stream = securefs::make_stream_hmac(param, posix_stream, true);
        test(*hmac_stream, 5000);
    }
    {
        securefs::dummy::DummpyCryptStream ds(posix_stream, 19);
        test(ds, 5000);
    }
    {
        char temp_template[] = "/tmp/42127B9D-4F88-4489-956C-05BE32340B77.XXXXXX";
        auto meta_posix_stream
            = std::make_shared<securefs::POSIXFileStream>(mkstemp(temp_template));
        auto aes_gcm_stream
            = securefs::make_cryptstream_aes_gcm(posix_stream, meta_posix_stream, param, true);
        std::vector<byte> header(aes_gcm_stream.second->header_length(), 5);
        aes_gcm_stream.second->write_header(header.data(), header.size());
        test(*aes_gcm_stream.first, 1000);
        aes_gcm_stream.second->flush_header();
        aes_gcm_stream.second->read_header(header.data(), header.size());
        REQUIRE(securefs::is_all_equal(header.begin(), header.end(), 5));
        test(*aes_gcm_stream.first, 3000);
    }
}
