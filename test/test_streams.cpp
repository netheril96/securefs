#include "catch.hpp"

#include "platform.h"
#include "streams.h"

#include <algorithm>
#include <random>
#include <stdint.h>
#include <string.h>
#include <vector>

static void test(securefs::StreamBase& stream, unsigned times)
{
    securefs::FileSystemService service;

    auto posix_stream_impl = service.open_file_stream(
        service.temp_name("tmp/", "stream"), O_RDWR | O_CREAT | O_EXCL, 0644);
    auto&& posix_stream = *posix_stream_impl;

    posix_stream.resize(0);
    stream.resize(0);

    std::vector<byte> data(4096 * 5);
    std::vector<byte> buffer(data), posix_buffer(data);
    std::mt19937 mt{std::random_device{}()};

    {
        std::uniform_int_distribution<unsigned> dist;
        for (auto&& b : data)
            b = static_cast<byte>(dist(mt));
    }

    std::uniform_int_distribution<int> flags_dist(0, 4);
    std::uniform_int_distribution<int> length_dist(0, 7 * 4096 + 1);
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
            posix_buffer = buffer;
            auto read_sz = stream.read(buffer.data(), a, std::min<size_t>(b, buffer.size()));
            auto posix_read_sz = posix_stream.read(
                posix_buffer.data(), a, std::min<size_t>(b, posix_buffer.size()));
            auto equal = (read_sz == posix_read_sz)
                && (memcmp(buffer.data(), posix_buffer.data(), read_sz) == 0);
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

// Used for debugging
void dump_contents(const std::vector<byte>& bytes, const char* filename, size_t max_size)
{
    securefs::FileSystemService service;
    auto fs = service.open_file_stream(filename, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    fs->write(bytes.data(), 0, max_size);
}

TEST_CASE("Test streams")
{
    securefs::FileSystemService service;

    auto filename = service.temp_name("tmp/", ".stream");

    securefs::key_type key;
    securefs::id_type id;
    memset(key.data(), 0xff, key.size());
    memset(id.data(), 0xee, id.size());
    auto posix_stream = service.open_file_stream(filename, O_RDWR | O_CREAT | O_EXCL, 0644);

    {
        auto hmac_stream = securefs::make_stream_hmac(key, id, posix_stream, true);
        test(*hmac_stream, 5000);
    }
    {
        posix_stream->resize(0);
        securefs::dummy::DummpyCryptStream ds(posix_stream, 8000);
        test(ds, 5000);
    }
    {
        auto meta_posix_stream = service.open_file_stream(
            service.temp_name("tmp/", "metastream"), O_RDWR | O_CREAT | O_EXCL, 0644);
        auto aes_gcm_stream = securefs::make_cryptstream_aes_gcm(
            posix_stream, meta_posix_stream, key, key, id, true, 4096, 12);
        std::vector<byte> header(aes_gcm_stream.second->max_header_length() - 1, 5);
        aes_gcm_stream.second->write_header(header.data(), header.size());
        test(*aes_gcm_stream.first, 1000);
        aes_gcm_stream.second->flush_header();
        aes_gcm_stream.second->read_header(header.data(), header.size());
        REQUIRE(securefs::is_all_equal(header.begin(), header.end(), 5));
        test(*aes_gcm_stream.first, 3000);
    }
}
