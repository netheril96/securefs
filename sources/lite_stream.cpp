#include "lite_stream.h"
#include "crypto.h"
#include "logger.h"

#include <cryptopp/aes.h>
#include <cryptopp/integer.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>

namespace securefs
{
namespace lite
{
    namespace
    {
        const offset_type MAX_BLOCKS = (1ULL << 31) - 1;
        unsigned compute_padding(unsigned max_padding,
                                 CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption* padding_aes,
                                 const byte* id,
                                 size_t id_size)
        {
            if (!max_padding || !padding_aes)
            {
                return 0;
            }
            CryptoPP::FixedSizeAlignedSecBlock<byte, 16> transformed;
            padding_aes->ProcessData(transformed.data(), id, id_size);
            CryptoPP::Integer integer(transformed.data(),
                                      transformed.size(),
                                      CryptoPP::Integer::UNSIGNED,
                                      CryptoPP::BIG_ENDIAN_ORDER);
            return static_cast<unsigned>(integer.Modulo(max_padding + 1));
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

        warn_if_key_not_random(master_key, __FILE__, __LINE__);

        CryptoPP::FixedSizeAlignedSecBlock<byte, get_id_size()> id, session_key;
        auto rc = m_stream->read(id.data(), 0, id.size());

        if (rc == 0)
        {
            generate_random(id.data(), id.size());
            m_stream->write(id.data(), 0, id.size());
            m_padding_size = compute_padding(max_padding_size, padding_aes, id.data(), id.size());
            m_auxiliary.reset(new byte[sizeof(std::uint32_t) + m_padding_size]);
            if (m_padding_size)
            {
                generate_random(m_auxiliary.get(), sizeof(std::uint32_t) + m_padding_size);
                m_stream->write(
                    m_auxiliary.get() + sizeof(std::uint32_t), id.size(), m_padding_size);
            }
        }
        else if (rc != id.size())
        {
            throwInvalidArgumentException("Underlying stream has invalid ID size");
        }
        else
        {
            m_padding_size = compute_padding(max_padding_size, padding_aes, id.data(), id.size());
            m_auxiliary.reset(new byte[sizeof(std::uint32_t) + m_padding_size]);
            if (m_padding_size
                && m_stream->read(
                       m_auxiliary.get() + sizeof(std::uint32_t), id.size(), m_padding_size)
                    != m_padding_size)
                throwInvalidArgumentException("Invalid padding in the underlying file");
        }

        if (max_padding_size > 0)
        {
            TRACE_LOG("Stream padded with %u bytes", m_padding_size);
        }

        CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption ecenc(master_key.data(), master_key.size());
        ecenc.ProcessData(session_key.data(), id.data(), id.size());

        m_buffer.reset(new byte[get_underlying_block_size()]);

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

    length_type AESGCMCryptStream::read_block(offset_type block_number, void* output)
    {
        if (block_number > MAX_BLOCKS)
            throw StreamTooLongException(MAX_BLOCKS * get_block_size(),
                                         block_number * get_block_size());

        length_type rc
            = m_stream->read(m_buffer.get(),
                             get_header_size() + get_underlying_block_size() * block_number,
                             get_underlying_block_size());
        if (rc <= get_mac_size() + get_iv_size())
            return 0;

        if (rc > get_underlying_block_size())
            throwInvalidArgumentException("Invalid read");

        auto out_size = rc - get_iv_size() - get_mac_size();

        if (is_all_zeros(m_buffer.get(), rc))
        {
            memset(output, 0, get_block_size());
            return out_size;
        }

        to_little_endian(static_cast<std::uint32_t>(block_number), m_auxiliary.get());

        bool success = m_decryptor.DecryptAndVerify(static_cast<byte*>(output),
                                                    m_buffer.get() + rc - get_mac_size(),
                                                    get_mac_size(),
                                                    m_buffer.get(),
                                                    static_cast<int>(get_iv_size()),
                                                    m_auxiliary.get(),
                                                    sizeof(std::uint32_t) + m_padding_size,
                                                    m_buffer.get() + get_iv_size(),
                                                    out_size);

        if (m_check && !success)
            throw LiteMessageVerificationException();

        return out_size;
    }

    void
    AESGCMCryptStream::write_block(offset_type block_number, const void* input, length_type size)
    {
        if (block_number > MAX_BLOCKS)
            throw StreamTooLongException(MAX_BLOCKS * get_block_size(),
                                         block_number * get_block_size());

        auto underlying_offset = block_number * get_underlying_block_size() + get_header_size();
        auto underlying_size = size + get_iv_size() + get_mac_size();

        if (is_all_zeros(input, size))
        {
            memset(m_buffer.get(), 0, underlying_size);
            m_stream->write(m_buffer.get(), underlying_offset, underlying_size);
            return;
        }

        to_little_endian(static_cast<std::uint32_t>(block_number), m_auxiliary.get());

        do
        {
            generate_random(m_buffer.get(), get_iv_size());
        } while (is_all_zeros(m_buffer.get(), get_iv_size()));

        m_encryptor.EncryptAndAuthenticate(m_buffer.get() + get_iv_size(),
                                           m_buffer.get() + get_iv_size() + size,
                                           get_mac_size(),
                                           m_buffer.get(),
                                           static_cast<int>(get_iv_size()),
                                           m_auxiliary.get(),
                                           sizeof(std::uint32_t) + m_padding_size,
                                           static_cast<const byte*>(input),
                                           size);

        m_stream->write(m_buffer.get(), underlying_offset, underlying_size);
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
}    // namespace lite
}    // namespace securefs
