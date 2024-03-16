#include "lite_stream.h"
#include "crypto.h"
#include "logger.h"
#include "myutils.h"

#include <algorithm>
#include <cryptopp/aes.h>
#include <cryptopp/integer.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>

#include <cstdint>
#include <utility>
#include <vector>

namespace securefs::lite
{
namespace
{
    const offset_type MAX_BLOCKS = (1ULL << 31) - 1;

    class DefaultParamsCalculator final : public AESGCMCryptStream::ParamCalculator
    {
    public:
        explicit DefaultParamsCalculator(const key_type& master_key,
                                         unsigned max_padding_size,
                                         CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption* padding_aes
                                         = nullptr)
            : ecenc(master_key.data(), master_key.size())
            , padding_aes(padding_aes)
            , max_padding_size(max_padding_size)
        {
        }
        virtual void compute_session_key(const std::array<unsigned char, 16>& id,
                                         std::array<unsigned char, 16>& outkey) override
        {
            ecenc.ProcessData(outkey.data(), id.data(), id.size());
        }

        virtual unsigned compute_padding(const std::array<unsigned char, 16>& id) override
        {
            if (!max_padding_size || !padding_aes)
            {
                return 0;
            }
            return default_compute_padding(max_padding_size, *padding_aes, id.data(), id.size());
        }

    private:
        CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption ecenc;
        CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption* padding_aes;
        unsigned max_padding_size;
    };
    template <typename T>
    T& as_lvalue(T&& val)
    {
        return val;
    }

}    // namespace
std::string CorruptedStreamException::message() const { return "Stream is corrupted"; }

AESGCMCryptStream::AESGCMCryptStream(std::shared_ptr<StreamBase> stream,
                                     const key_type& master_key,
                                     unsigned block_size,
                                     unsigned iv_size,
                                     bool check,
                                     unsigned max_padding_size,
                                     CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption* padding_aes)
    : AESGCMCryptStream(
        std::move(stream),
        as_lvalue(DefaultParamsCalculator(master_key, max_padding_size, padding_aes)),
        block_size,
        iv_size,
        check)
{
}

AESGCMCryptStream::AESGCMCryptStream(std::shared_ptr<StreamBase> stream,
                                     ParamCalculator& calc,
                                     unsigned block_size,
                                     unsigned iv_size,
                                     bool check)
    : BlockBasedStream(block_size)
    , m_stream(std::move(stream))
    , m_iv_size(iv_size)
    , m_padding_size(0)
    , m_check(check)
{
    if (m_iv_size < 12 || m_iv_size > 32)
        throwInvalidArgumentException("IV size too small or too large");
    if (!m_stream)
        throwInvalidArgumentException("Null stream");
    if (block_size < 32)
        throwInvalidArgumentException("Block size too small");

    std::array<byte, get_id_size()> id, session_key;
    auto rc = m_stream->read(id.data(), 0, id.size());

    if (rc == 0)
    {
        generate_random(id.data(), id.size());
        m_stream->write(id.data(), 0, id.size());
        m_padding_size = calc.compute_padding(id);
        m_auxiliary.resize(sizeof(std::uint32_t) + m_padding_size, 0);
        if (m_padding_size)
        {
            generate_random(m_auxiliary.data(), m_auxiliary.size());
            m_stream->write(m_auxiliary.data() + sizeof(std::uint32_t), id.size(), m_padding_size);
        }
    }
    else if (rc != id.size())
    {
        throwInvalidArgumentException("Underlying stream has invalid ID size");
    }
    else
    {
        m_padding_size = calc.compute_padding(id);
        m_auxiliary.resize(sizeof(std::uint32_t) + m_padding_size, 0);
        if (m_padding_size
            && m_stream->read(m_auxiliary.data() + sizeof(std::uint32_t), id.size(), m_padding_size)
                != m_padding_size)
            throwInvalidArgumentException("Invalid padding in the underlying file");
    }

    if (m_padding_size > 0)
    {
        TRACE_LOG("Stream padded with %u bytes", m_padding_size);
    }

    calc.compute_session_key(id, session_key);
    // The null iv is only a placeholder; it will replaced during encryption and decryption
    const byte null_iv[12] = {0};
    m_encryptor.SetKeyWithIV(
        session_key.data(), session_key.size(), null_iv, array_length(null_iv));
    m_decryptor.SetKeyWithIV(
        session_key.data(), session_key.size(), null_iv, array_length(null_iv));
}

AESGCMCryptStream::~AESGCMCryptStream() {}

void AESGCMCryptStream::flush() { m_stream->flush(); }

bool AESGCMCryptStream::is_sparse() const noexcept { return m_stream->is_sparse(); }

length_type
AESGCMCryptStream::read_multi_blocks(offset_type start_block, offset_type end_block, void* output)
{
    if (end_block > MAX_BLOCKS)
        throw StreamTooLongException(MAX_BLOCKS * get_block_size(), end_block * get_block_size());
    std::vector<unsigned char> buffer((end_block - start_block) * get_underlying_block_size());
    length_type rc = m_stream->read(buffer.data(),
                                    get_header_size() + get_underlying_block_size() * start_block,
                                    buffer.size());
    length_type transformed_read_len = 0;

    for (length_type i = 0; i < rc; i += get_underlying_block_size())
    {
        auto this_block_underlying_size = std::min(get_underlying_block_size(), rc - i);
        if (this_block_underlying_size <= get_mac_size() + get_iv_size())
        {
            return transformed_read_len;
        }
        auto this_block_virtual_size = this_block_underlying_size - get_mac_size() - get_iv_size();
        auto* start_data = buffer.data() + i;
        auto* end_data = start_data + this_block_underlying_size;

        transformed_read_len += this_block_virtual_size;

        if (std::all_of(start_data, end_data, [](byte b) { return b == 0; }))
        {
            memset(output, 0, this_block_virtual_size);
        }
        else
        {
            if (is_all_zeros(start_data, get_iv_size()))
            {
                WARN_LOG("Null IV for block number %d indicates a potential bug in securefs",
                         i / get_underlying_block_size() + start_block);
            }
            to_little_endian(
                static_cast<std::uint32_t>(i / get_underlying_block_size() + start_block),
                m_auxiliary.data());
            bool success = m_decryptor.DecryptAndVerify(static_cast<byte*>(output),
                                                        end_data - get_mac_size(),
                                                        get_mac_size(),
                                                        start_data,
                                                        static_cast<int>(get_iv_size()),
                                                        m_auxiliary.data(),
                                                        m_auxiliary.size(),
                                                        start_data + get_iv_size(),
                                                        this_block_virtual_size);

            if (m_check && !success)
                throw LiteMessageVerificationException();
        }
        output = static_cast<byte*>(output) + this_block_virtual_size;
    }
    return transformed_read_len;
}

void AESGCMCryptStream::write_multi_blocks(offset_type start_block,
                                           offset_type end_block,
                                           offset_type end_residue,
                                           const void* input)
{
    if (end_block > MAX_BLOCKS)
        throw StreamTooLongException(MAX_BLOCKS * get_block_size(), end_block * get_block_size());

    std::vector<unsigned char> buffer(
        (end_block - start_block) * get_underlying_block_size()
        + (end_residue <= 0 ? 0 : end_residue + get_iv_size() + get_mac_size()));
    for (length_type i = 0; i < buffer.size();)
    {
        auto this_block_underlying_size = std::min(get_underlying_block_size(), buffer.size() - i);
        auto this_block_virtual_size = this_block_underlying_size - get_mac_size() - get_iv_size();
        if (this_block_virtual_size > 0)
        {
            auto* start_data = buffer.data() + i;
            auto* end_data = start_data + this_block_underlying_size;
            auto* iv = start_data;
            auto* ciphertext = iv + get_iv_size();
            auto* mac = end_data - get_mac_size();
            to_little_endian(static_cast<uint32_t>(start_block + i / get_underlying_block_size()),
                             m_auxiliary.data());
            do
            {
                generate_random(iv, get_iv_size());
            } while (is_all_zeros(iv, get_iv_size()));
            m_encryptor.EncryptAndAuthenticate(ciphertext,
                                               mac,
                                               get_mac_size(),
                                               iv,
                                               static_cast<int>(get_iv_size()),
                                               m_auxiliary.data(),
                                               m_auxiliary.size(),
                                               static_cast<const byte*>(input),
                                               this_block_virtual_size);
        }
        input = static_cast<const byte*>(input) + this_block_virtual_size;
        i += this_block_underlying_size;
    }
    m_stream->write(buffer.data(),
                    start_block * get_underlying_block_size() + get_header_size(),
                    buffer.size());
}

length_type AESGCMCryptStream::size() const
{
    auto underlying_size = m_stream->size();
    return underlying_size <= get_header_size()
        ? 0
        : calculate_real_size(underlying_size - m_padding_size, m_block_size, m_iv_size);
}

void AESGCMCryptStream::adjust_logical_size(length_type length)
{
    auto new_blocks = length / get_block_size();
    auto residue = length % get_block_size();
    m_stream->resize(get_header_size() + new_blocks * get_underlying_block_size()
                     + (residue > 0 ? residue + get_iv_size() + get_mac_size() : 0));
}

length_type AESGCMCryptStream::calculate_real_size(length_type underlying_size,
                                                   length_type block_size,
                                                   length_type iv_size) noexcept
{
    auto id_size = get_id_size();
    auto underlying_block_size = block_size + iv_size + get_mac_size();
    if (underlying_size <= id_size)
        return 0;
    underlying_size -= id_size;
    auto num_blocks = underlying_size / underlying_block_size;
    auto residue = underlying_size % underlying_block_size;
    return num_blocks * block_size
        + (residue > (iv_size + get_mac_size()) ? residue - iv_size - get_mac_size() : 0);
}
unsigned default_compute_padding(unsigned max_padding,
                                 CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption& padding_aes,
                                 const byte* id,
                                 size_t id_size)
{
    if (!max_padding)
    {
        return 0;
    }
    CryptoPP::FixedSizeAlignedSecBlock<byte, 16> transformed;
    padding_aes.ProcessData(transformed.data(), id, id_size);
    CryptoPP::Integer integer(transformed.data(),
                              transformed.size(),
                              CryptoPP::Integer::UNSIGNED,
                              CryptoPP::BIG_ENDIAN_ORDER);
    return static_cast<unsigned>(integer.Modulo(max_padding + 1));
}
}    // namespace securefs::lite
