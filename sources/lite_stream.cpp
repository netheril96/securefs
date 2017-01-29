#include "lite_stream.h"

namespace securefs
{
namespace lite
{
    std::string CorruptedStreamException::message() const { return "Stream is corrupted"; }

    const char* CorruptedStreamException::type_name() const noexcept
    {
        return "CorruptedStreamException";
    }

    static const offset_type MAX_BLOCKS = 1ULL << 31;

    AESGCMCryptStream::AESGCMCryptStream(std::shared_ptr<StreamBase> stream,
                                         const key_type& master_key,
                                         unsigned int block_size,
                                         unsigned iv_size,
                                         bool check)
        : BlockBasedStream(block_size)
        , m_stream(std::move(stream))
        , m_iv_size(iv_size)
        , m_check(check)
    {
        if (m_iv_size < 12 || m_iv_size > 32)
            throwInvalidArgumentException("IV size too small or too large");
        if (!m_stream)
            throwInvalidArgumentException("Null stream");
        if (block_size < 32)
            throwInvalidArgumentException("Block size too small");

        key_type header;
        auto rc = m_stream->read(header.data(), 0, header.size());
        if (rc == 0)
        {
            generate_random(m_session_key.data(), m_session_key.size());
            byte_xor(m_session_key.data(), master_key.data(), header.data(), header.size());
            m_stream->write(header.data(), 0, header.size());
        }
        else if (rc == header.size())
        {
            byte_xor(header.data(), master_key.data(), m_session_key.data(), m_session_key.size());
        }
        else
        {
            throwInvalidArgumentException("Underlying stream has invalid header size");
        }

        m_buffer.reset(new byte[get_underlying_block_size()]);
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

        byte auxiliary[sizeof(std::uint32_t)];
        to_little_endian(static_cast<std::uint32_t>(block_number), auxiliary);

        bool success = aes_gcm_decrypt(m_buffer.get() + get_iv_size(),
                                       out_size,
                                       auxiliary,
                                       sizeof(auxiliary),
                                       m_session_key.data(),
                                       m_session_key.size(),
                                       m_buffer.get(),
                                       get_iv_size(),
                                       m_buffer.get() + rc - get_mac_size(),
                                       get_mac_size(),
                                       output);
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

        byte auxiliary[sizeof(std::uint32_t)];
        to_little_endian(static_cast<std::uint32_t>(block_number), auxiliary);

        do
        {
            generate_random(m_buffer.get(), get_iv_size());
        } while (is_all_zeros(m_buffer.get(), get_iv_size()));

        aes_gcm_encrypt(input,
                        size,
                        auxiliary,
                        sizeof(auxiliary),
                        m_session_key.data(),
                        m_session_key.size(),
                        m_buffer.get(),
                        get_iv_size(),
                        m_buffer.get() + get_iv_size() + size,
                        get_mac_size(),
                        m_buffer.get() + get_iv_size());

        m_stream->write(m_buffer.get(),
                        block_number * get_underlying_block_size() + get_header_size(),
                        size + get_iv_size() + get_mac_size());
    }

    length_type AESGCMCryptStream::size() const
    {
        return calculate_real_size(m_stream->size(), get_block_size(), get_iv_size());
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
        auto header_size = get_header_size();
        auto underlying_block_size = block_size + iv_size + get_mac_size();
        if (underlying_size <= header_size)
            return 0;
        underlying_size -= header_size;
        auto num_blocks = underlying_size / underlying_block_size;
        auto residue = underlying_size % underlying_block_size;
        return num_blocks * block_size
            + (residue > (iv_size + get_mac_size()) ? residue - iv_size - get_mac_size() : 0);
    }
}
}
