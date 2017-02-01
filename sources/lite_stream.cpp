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

    static const offset_type MAX_BLOCKS = (1ULL << 31) - 1;

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

        CryptoPP::FixedSizeAlignedSecBlock<byte, securefs::KEY_LENGTH> header, session_key;
        auto rc = m_stream->read(header.data(), 0, header.size());
        if (rc == 0)
        {
            generate_random(session_key.data(), session_key.size());
            CryptoPP::xorbuf(header.data(), master_key.data(), session_key.data(), KEY_LENGTH);
            m_stream->write(header.data(), 0, header.size());
        }
        else if (rc == header.size())
        {
            CryptoPP::xorbuf(session_key.data(), master_key.data(), header.data(), KEY_LENGTH);
        }
        else
        {
            throwInvalidArgumentException("Underlying stream has invalid header size");
        }

        m_buffer.reset(new byte[get_underlying_block_size()]);

        // The null iv is only a placeholder; it will replaced during encryption and decryption
        const byte null_iv[12] = {0};
        m_encryptor.SetKeyWithIV(session_key.data(), session_key.size(), null_iv, sizeof(null_iv));
        m_decryptor.SetKeyWithIV(session_key.data(), session_key.size(), null_iv, sizeof(null_iv));
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

        bool success = m_decryptor.DecryptAndVerify(static_cast<byte*>(output),
                                                    m_buffer.get() + rc - get_mac_size(),
                                                    get_mac_size(),
                                                    m_buffer.get(),
                                                    static_cast<int>(get_iv_size()),
                                                    auxiliary,
                                                    sizeof(auxiliary),
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

        byte auxiliary[sizeof(std::uint32_t)];
        to_little_endian(static_cast<std::uint32_t>(block_number), auxiliary);

        do
        {
            generate_random(m_buffer.get(), get_iv_size());
        } while (is_all_zeros(m_buffer.get(), get_iv_size()));

        m_encryptor.EncryptAndAuthenticate(m_buffer.get() + get_iv_size(),
                                           m_buffer.get() + get_iv_size() + size,
                                           get_mac_size(),
                                           m_buffer.get(),
                                           static_cast<int>(get_iv_size()),
                                           auxiliary,
                                           sizeof(auxiliary),
                                           static_cast<const byte*>(input),
                                           size);

        m_stream->write(m_buffer.get(), underlying_offset, underlying_size);
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
