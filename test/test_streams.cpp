#include <cstring>
#include <doctest/doctest.h>

#include "crypto.h"
#include "crypto_wrappers.h"
#include "lite_stream.h"
#include "logger.h"
#include "myutils.h"
#include "platform.h"
#include "streams.h"
#include "test_common.h"

#include <algorithm>
#include <random>
#include <string.h>
#include <vector>

using securefs::OSService;

namespace securefs
{
namespace
{
    class MemoryStream : public StreamBase
    {
    private:
        std::vector<unsigned char> m_buffer;

    public:
        explicit MemoryStream() { m_buffer.reserve(1u << 20); }

        length_type read(void* output, offset_type offset, length_type length) override
        {
            if (offset >= m_buffer.size() || length <= 0)
            {
                return 0;
            }
            auto read_sz = std::min<length_type>(length, m_buffer.size() - offset);
            memcpy(output, m_buffer.data() + offset, read_sz);
            return read_sz;
        }

        void write(const void* input, offset_type offset, length_type length) override
        {
            if (length <= 0)
            {
                return;
            }
            if (offset + length > m_buffer.size())
            {
                m_buffer.resize(offset + length);
            }
            memcpy(m_buffer.data() + offset, input, length);
        }

        length_type size() const override { return m_buffer.size(); }

        void flush() override {}

        void resize(length_type size) override { m_buffer.resize(size); }
        bool is_sparse() const noexcept override { return true; }
    };
}    // namespace
}    // namespace securefs

static void test(securefs::StreamBase& stream, unsigned times)
{
    std::string_view stream_type_name = typeid(stream).name();
    CAPTURE(stream_type_name);
    securefs::MemoryStream memory_stream;
    stream.resize(0);

    std::vector<byte> data(4096 * 5);
    std::vector<byte> buffer(data), memory_buffer(data);
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
            memory_stream.write(data.data(), a, std::min<size_t>(b, data.size()));
            break;

        case 1:
        {
            memory_buffer = buffer;
            auto read_sz = stream.read(buffer.data(), a, std::min<size_t>(b, buffer.size()));
            auto memory_read_sz = memory_stream.read(
                memory_buffer.data(), a, std::min<size_t>(b, memory_buffer.size()));
            CHECK(read_sz == memory_read_sz);
            if (read_sz == memory_read_sz)
                CHECK(memcmp(buffer.data(), memory_buffer.data(), read_sz) == 0);
            break;
        }

        case 2:
            CHECK(stream.size() == memory_stream.size());
            break;

        case 3:
            stream.resize(a);
            memory_stream.resize(a);
            CHECK(stream.size() == size_t(a));
            CHECK(memory_stream.size() == size_t(a));
            break;

        case 4:
            stream.flush();
            memory_stream.flush();

        default:
            break;
        }
    }
}

namespace securefs::dummy
{

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
    length_type
    read_multi_blocks(offset_type start_block, offset_type end_block, void* output) override
    {
        length_type result = 0;
        for (offset_type b = start_block; b < end_block; ++b)
        {
            if (b >= m_buffer.size())
            {
                return result;
            }
            memcpy(output, m_buffer[b].data(), m_buffer[b].size());
            result += m_buffer[b].size();
            output = static_cast<char*>(output) + m_buffer[b].size();
        }
        return result;
    }
    void write_multi_blocks(offset_type start_block,
                            offset_type end_block,
                            offset_type end_residue,
                            const void* input) override
    {
        for (size_t i = m_buffer.size(); i < end_block; ++i)
        {
            m_buffer.emplace_back(BLOCK_SIZE, static_cast<byte>(0));
        }
        for (offset_type b = start_block; b < end_block; ++b)
        {
            m_buffer.at(b).resize(BLOCK_SIZE);
            memcpy(m_buffer[b].data(), input, BLOCK_SIZE);
            input = static_cast<const char*>(input) + BLOCK_SIZE;
        }
        if (end_residue > 0)
        {
            if (m_buffer.size() <= end_block)
            {
                m_buffer.emplace_back(end_residue, static_cast<byte>(0));
            }
            auto&& end_buffer = m_buffer[end_block];
            if (end_buffer.size() < end_residue)
            {
                end_buffer.resize(end_residue);
            }
            memcpy(end_buffer.data(), input, end_residue);
        }
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
}    // namespace securefs::dummy

// Used for debugging
void dump_contents(const std::vector<byte>& bytes, const char* filename, size_t max_size)
{
    auto fs = securefs::OSService::get_default().open_file_stream(
        filename, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    fs->write(bytes.data(), 0, max_size);
}

TEST_CASE("Test streams")
{
    securefs::key_type key(0xf4);
    securefs::id_type id(0xee);
    {
        auto filename = OSService::temp_name("tmp/", ".stream");
        auto posix_stream
            = OSService::get_default().open_file_stream(filename, O_RDWR | O_CREAT | O_EXCL, 0644);
        test(*posix_stream, 4000);
    }
    {
        auto hmac_stream
            = securefs::make_stream_hmac(key, id, std::make_shared<securefs::MemoryStream>(), true);
        test(*hmac_stream, 5000);
    }
    {
        auto aes_gcm_stream
            = securefs::make_cryptstream_aes_gcm(std::make_shared<securefs::MemoryStream>(),
                                                 std::make_shared<securefs::MemoryStream>(),
                                                 key,
                                                 key,
                                                 id,
                                                 true,
                                                 4096,
                                                 12);
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
        securefs::PaddedStream ps(std::make_shared<securefs::MemoryStream>(), 16);
        test(ps, 1000);
    }
    {
        securefs::WriteCachedStream ws(std::make_shared<securefs::MemoryStream>(), 4000);
        test(ws, 1000);
    }
    CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption padding_aes(key.data(), key.size());
    auto test_lite_stream = [&](unsigned block_size, unsigned iv_size, unsigned padding_size)
    {
        CAPTURE(block_size);
        CAPTURE(iv_size);
        CAPTURE(padding_size);

        auto memory_stream = std::make_shared<securefs::MemoryStream>();
        {
            securefs::lite::AESGCMCryptStream lite_stream(
                memory_stream, key, block_size, iv_size, true, padding_size, &padding_aes);
            INFO_LOG("Actual padding size: %u", lite_stream.get_padding_size());

            const byte test_data[] = "Hello, world";
            byte output[4096];
            lite_stream.write(test_data, 0, sizeof(test_data));
            REQUIRE(lite_stream.read(output, 0, sizeof(output)) == sizeof(test_data));
            REQUIRE(memcmp(test_data, output, sizeof(test_data)) == 0);
            test(lite_stream, 1001);
        }
        {
            securefs::lite::AESGCMCryptStream lite_stream(
                memory_stream, key, block_size, iv_size, true, padding_size, &padding_aes);
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
        securefs::libcrypto::generate_random(securefs::MutableRawBuffer(plaintext));
        padding_aes.ProcessData(ciphertext, plaintext, sizeof(ciphertext));
        second_padding_aes.ProcessData(second_ciphertext, plaintext, sizeof(second_ciphertext));
        REQUIRE(memcmp(ciphertext, second_ciphertext, sizeof(ciphertext)) == 0);
    }
}
