#include "catch.hpp"

#include "crypto.h"
#include "lite_stream.h"
#include "logger.h"
#include "platform.h"
#include "streams.h"

#include <algorithm>
#include <array>
#include <random>
#include <stdint.h>
#include <string.h>
#include <vector>

using securefs::OSService;

static std::mt19937& get_random_number_engine()
{
    struct Initializer
    {
        std::mt19937 mt;

        Initializer()
        {
            uint32_t data[64];
            ::securefs::generate_random(data, sizeof(data));
            std::seed_seq seq(std::begin(data), std::end(data));
            mt.seed(seq);
        }
    };

    static Initializer initializer;
    return initializer.mt;
}

static void test(securefs::StreamBase& stream, unsigned times)
{
    auto posix_stream_impl = OSService::get_default().open_file_stream(
        OSService::temp_name("tmp/", "stream"), O_RDWR | O_CREAT | O_EXCL, 0644);
    auto&& posix_stream = *posix_stream_impl;

    posix_stream.resize(0);
    stream.resize(0);

    std::vector<byte> data(4096 * 5);
    std::vector<byte> buffer(data), posix_buffer(data);
    auto& mt = get_random_number_engine();

    {
        std::uniform_int_distribution<unsigned> dist(0, 255);
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
            REQUIRE(read_sz == posix_read_sz);
            REQUIRE(memcmp(buffer.data(), posix_buffer.data(), read_sz) == 0);
            break;
        }

        case 2:
            REQUIRE(stream.size() == posix_stream.size());
            break;

        case 3:
            stream.resize(a);
            posix_stream.resize(a);
            REQUIRE(stream.size() == a);
            REQUIRE(posix_stream.size() == a);
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

    class DummyBlockStream : public BlockBasedStream
    {
    private:
        static const size_t BLOCK_SIZE;
        std::vector<std::vector<byte>> m_buffer;

    public:
        explicit DummyBlockStream() : BlockBasedStream(BLOCK_SIZE) {}
        ~DummyBlockStream() {}

        length_type size() const override
        {
            if (m_buffer.empty())
                return 0;
            return (m_buffer.size() - 1) * BLOCK_SIZE + m_buffer.back().size();
        }

        void flush() override { return; }

        bool is_sparse() const noexcept override { return false; }

    protected:
        length_type read_block(offset_type block_number, void* output) override
        {
            if (block_number >= m_buffer.size())
                return 0;
            memcpy(output, m_buffer[block_number].data(), m_buffer[block_number].size());
            return m_buffer[block_number].size();
        }

        void write_block(offset_type block_number, const void* input, length_type length) override
        {
            for (size_t i = m_buffer.size(); i <= block_number; ++i)
            {
                m_buffer.emplace_back(BLOCK_SIZE, static_cast<byte>(0));
            }
            m_buffer[block_number].resize(length);
            memcpy(m_buffer[block_number].data(), input, length);
        }

        void adjust_logical_size(length_type length) override
        {
            if (length == 0)
            {
                m_buffer.clear();
                return;
            }
            auto num_blocks = (length + (BLOCK_SIZE - 1)) / BLOCK_SIZE;
            auto residue = length % BLOCK_SIZE;
            if (num_blocks > m_buffer.size())
            {
                for (auto i = m_buffer.size(); i < num_blocks; ++i)
                {
                    m_buffer.emplace_back(BLOCK_SIZE, 0);
                }
            }
            else if (num_blocks < m_buffer.size())
            {
                m_buffer.resize(num_blocks);
            }
            m_buffer.back().resize(residue ? residue : BLOCK_SIZE);
        }
    };

    const size_t DummyBlockStream::BLOCK_SIZE = 1000;
}    // namespace dummy
}    // namespace securefs

// Used for debugging
void dump_contents(const std::vector<byte>& bytes, const char* filename, size_t max_size)
{
    auto fs = securefs::OSService::get_default().open_file_stream(
        filename, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    fs->write(bytes.data(), 0, max_size);
}

TEST_CASE("Test streams")
{
    auto filename = OSService::temp_name("tmp/", ".stream");

    securefs::key_type key(0xf4);
    securefs::id_type id(0xee);
    auto posix_stream
        = OSService::get_default().open_file_stream(filename, O_RDWR | O_CREAT | O_EXCL, 0644);

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
        auto meta_posix_stream = OSService::get_default().open_file_stream(
            OSService::temp_name("tmp/", "metastream"), O_RDWR | O_CREAT | O_EXCL, 0644);
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
    {
        securefs::dummy::DummyBlockStream dbs;
        test(dbs, 3001);
    }
    {
        posix_stream->resize(0);
        securefs::PaddedStream ps(posix_stream, 16);
        test(ps, 1000);
    }
    {
        securefs::PaddedStream ps(posix_stream, 16);
        test(ps, 1000);
    }
    CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption padding_aes(key.data(), key.size());
    auto test_lite_stream = [&](unsigned block_size, unsigned iv_size, unsigned padding_size)
    {
        CAPTURE(block_size);
        CAPTURE(iv_size);
        CAPTURE(padding_size);

        auto filename = OSService::temp_name("tmp/", "litestream");
        {
            auto underlying_stream = OSService::get_default().open_file_stream(
                filename, O_RDWR | O_CREAT | O_EXCL, 0644);
            securefs::lite::AESGCMCryptStream lite_stream(
                underlying_stream, key, block_size, iv_size, true, padding_size, &padding_aes);
            INFO_LOG("Actual padding size: %u", lite_stream.get_padding_size());

            const byte test_data[] = "Hello, world";
            byte output[4096];
            lite_stream.write(test_data, 0, sizeof(test_data));
            REQUIRE(lite_stream.read(output, 0, sizeof(output)) == sizeof(test_data));
            REQUIRE(memcmp(test_data, output, sizeof(test_data)) == 0);
            test(lite_stream, 1001);
        }
        {
            auto underlying_stream
                = OSService::get_default().open_file_stream(filename, O_RDWR, 0644);
            securefs::lite::AESGCMCryptStream lite_stream(
                underlying_stream, key, block_size, iv_size, true, padding_size, &padding_aes);
            INFO_LOG("Actual padding size: %u", lite_stream.get_padding_size());
            test(lite_stream, 1001);
        }
    };

    test_lite_stream(4096, 12, 0);
    test_lite_stream(333, 16, 0);
    test_lite_stream(333, 12, 14);
    test_lite_stream(4096, 12, 1);
    test_lite_stream(4096, 12, 32);

    {
        // Test that the `padding_aes` is stateless
        CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption second_padding_aes(key.data(), key.size());
        byte plaintext[16], ciphertext[16], second_ciphertext[16];
        securefs::generate_random(plaintext, sizeof(plaintext));
        padding_aes.ProcessData(ciphertext, plaintext, sizeof(ciphertext));
        second_padding_aes.ProcessData(second_ciphertext, plaintext, sizeof(second_ciphertext));
        REQUIRE(memcmp(ciphertext, second_ciphertext, sizeof(ciphertext)) == 0);
    }
}
