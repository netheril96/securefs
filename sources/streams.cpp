#include "streams.h"
#include "crypto.h"
#include "crypto_wrappers.h"
#include "exceptions.h"
#include "myutils.h"

#include <algorithm>
#include <array>
#include <assert.h>
#include <cryptopp/secblockfwd.h>
#include <cstdint>
#include <cstring>
#include <memory>
#include <stdint.h>
#include <string.h>
#include <utility>

#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/hmac.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rng.h>
#include <cryptopp/salsa.h>
#include <cryptopp/secblock.h>
#include <cryptopp/sha.h>
#include <variant>
#include <vector>

namespace securefs
{
namespace internal
{
    class InvalidHMACStreamException : public InvalidFormatException
    {
    private:
        id_type m_id;
        std::string m_msg;

    public:
        explicit InvalidHMACStreamException(const id_type& id, std::string msg)
        {
            memcpy(m_id.data(), id.data(), id.size());
            m_msg.swap(msg);
        }

        std::string message() const override { return m_msg; }
    };

    class HMACStream final : public StreamBase
    {
    private:
        key_type m_key;
        id_type m_id;
        std::shared_ptr<StreamBase> m_stream;
        bool is_dirty;

        typedef CryptoPP::HMAC<CryptoPP::SHA256> hmac_calculator_type;

        static const size_t hmac_length = hmac_calculator_type::DIGESTSIZE;

    private:
        const id_type& id() const noexcept { return m_id; }
        const key_type& key() const noexcept { return m_key; }

        void run_mac(CryptoPP::MessageAuthenticationCode& calculator)
        {
            calculator.Update(id().data(), id().size());
            std::array<byte, 4096> buffer;
            offset_type off = hmac_length;
            while (true)
            {
                auto rc = m_stream->read(buffer.data(), off, buffer.size());
                if (rc == 0)
                    break;
                calculator.Update(buffer.data(), rc);
                off += rc;
            }
        }

    public:
        explicit HMACStream(const key_type& key_,
                            const id_type& id_,
                            std::shared_ptr<StreamBase> stream,
                            bool check = true)
            : m_key(key_), m_id(id_), m_stream(std::move(stream)), is_dirty(false)
        {
            if (!m_stream)
                throwVFSException(EFAULT);
            if (check)
            {
                std::array<byte, hmac_length> hmac;
                auto rc = m_stream->read(hmac.data(), 0, hmac.size());
                if (rc == 0)
                    return;
                if (rc != hmac_length)
                    throw InvalidHMACStreamException(
                        id(), "The header field for stream is not of enough length");
                hmac_calculator_type calculator;
                calculator.SetKey(key().data(), key().size());
                run_mac(calculator);
                if (!calculator.Verify(hmac.data()))
                    throw InvalidHMACStreamException(id(), "HMAC mismatch");
            }
        }

        ~HMACStream()
        {
            try
            {
                flush();
            }
            catch (...)
            {
                // ignore
            }
        }

        void flush() override
        {
            if (!is_dirty)
                return;
            hmac_calculator_type calculator;
            calculator.SetKey(key().data(), key().size());
            run_mac(calculator);
            std::array<byte, hmac_length> hmac;
            calculator.Final(hmac.data());
            m_stream->write(hmac.data(), 0, hmac.size());
            m_stream->flush();
            is_dirty = false;
        }

        length_type size() const override
        {
            auto sz = m_stream->size();
            if (sz < hmac_length)
                return 0;
            return sz - hmac_length;
        }

        length_type read(void* output, offset_type off, length_type len) override
        {
            return m_stream->read(output, off + hmac_length, len);
        }

        void write(const void* input, offset_type off, length_type len) override
        {
            m_stream->write(input, off + hmac_length, len);
            is_dirty = true;
        }

        void resize(length_type len) override
        {
            m_stream->resize(len + hmac_length);
            is_dirty = true;
        }

        bool is_sparse() const noexcept override { return m_stream->is_sparse(); }
    };
}    // namespace internal

std::shared_ptr<StreamBase> make_stream_hmac(const key_type& key_,
                                             const id_type& id_,
                                             std::shared_ptr<StreamBase> stream,
                                             bool check)
{
    return std::make_shared<internal::HMACStream>(key_, id_, std::move(stream), check);
}

namespace
{
    template <typename T>
    std::pair<T, T> divmod(T x, T y)
    {
        return std::make_pair(x / y, x % y);
    }
}    // namespace

length_type BlockBasedStream::read(void* output, offset_type offset, length_type length)
{
    if (length <= 0)
    {
        return length;
    }
    auto [start_block, start_residue] = divmod(offset, m_block_size);
    auto [end_block, end_residue] = divmod(offset + length, m_block_size);
    if (start_residue == 0 && end_residue == 0)
    {
        return read_multi_blocks(start_block, end_block, output);
    }

    CryptoPP::AlignedSecByteBlock buffer((end_block - start_block + (end_residue > 0))
                                         * m_block_size);
    auto read_len = read_multi_blocks(start_block, end_block + (end_residue > 0), buffer.data());
    if (read_len <= start_residue)
    {
        return 0;
    }
    auto copy_len = std::min(read_len - start_residue, length);
    memcpy(output, buffer.data() + start_residue, copy_len);
    return copy_len;
}

void BlockBasedStream::write(const void* input, offset_type offset, length_type length)
{
    if (length <= 0)
    {
        return;
    }
    auto current_size = this->size();
    if (offset > current_size)
        unchecked_resize(current_size, offset);

    unchecked_write(input, offset, length);
}

void BlockBasedStream::unchecked_write(std::variant<const void*, ZeroFillTag> input,
                                       offset_type offset,
                                       length_type length)
{
    if (length <= 0)
    {
        return;
    }
    auto [start_block, start_residue] = divmod(offset, m_block_size);
    auto [end_block, end_residue] = divmod(offset + length, m_block_size);
    if (start_residue == 0 && end_residue == 0)
    {
        std::visit(
            Overload{[this, start_block = start_block, end_block = end_block](const ZeroFillTag&)
                     {
                         std::vector<unsigned char> buffer((end_block - start_block) * m_block_size,
                                                           0);
                         write_multi_blocks(start_block, end_block, 0, buffer.data());
                     },
                     [this, start_block = start_block, end_block = end_block](const void* data)
                     { write_multi_blocks(start_block, end_block, 0, data); }},
            input);
        return;
    }
    CryptoPP::AlignedSecByteBlock buffer((end_block - start_block + (end_residue > 0))
                                         * m_block_size);
    std::fill(buffer.begin(), buffer.end(), 0);
    if (start_residue > 0 && start_block < end_block)
    {
        (void)read_multi_blocks(start_block, start_block + 1, buffer.data());
    }
    length_type effective_end_residue = 0;
    if (end_residue > 0)
    {
        effective_end_residue
            = std::max(end_residue,
                       read_multi_blocks(end_block,
                                         end_block + 1,
                                         buffer.data() + (end_block - start_block) * m_block_size));
    }
    assert(start_residue + length <= buffer.size());
    std::visit(Overload{[](const ZeroFillTag&) {},
                        [&buffer, start_residue = start_residue, length](const void* data)
                        { memcpy(buffer.data() + start_residue, data, length); }},
               input);
    write_multi_blocks(start_block, end_block, effective_end_residue, buffer.data());
}

void BlockBasedStream::zero_fill(offset_type offset, offset_type finish)
{
    unchecked_write(ZeroFillTag(), offset, finish - offset);
}

void BlockBasedStream::resize(length_type new_size) { unchecked_resize(size(), new_size); }

void BlockBasedStream::unchecked_resize(length_type current_size, length_type new_size)
{
    if (new_size == current_size)
        return;
    else if (new_size < current_size)
    {
        auto residue = new_size % m_block_size;
        auto block_num = new_size / m_block_size;
        if (residue > 0)
        {
            CryptoPP::AlignedSecByteBlock buffer(m_block_size);
            memset(buffer.data(), 0, buffer.size());
            (void)read_multi_blocks(block_num, block_num + 1, buffer.data());
            write_multi_blocks(block_num, block_num, residue, buffer.data());
        }
    }
    else
    {
        auto old_block_num = current_size / m_block_size;
        auto new_block_num = new_size / m_block_size;
        if (!is_sparse() || old_block_num == new_block_num)
            zero_fill(current_size, new_size);
        else
        {
            zero_fill(current_size, old_block_num * m_block_size + m_block_size);
        }
    }
    adjust_logical_size(new_size);
}

namespace internal
{
    class AESGCMCryptStream final : public BlockBasedStream, public HeaderBase
    {
    public:
        int get_iv_size() const noexcept { return m_iv_size; }

        unsigned get_mac_size() const noexcept { return 16; }

        unsigned get_meta_size() const noexcept { return get_iv_size() + get_mac_size(); }

        unsigned get_header_size() const noexcept { return m_header_size; }

        unsigned get_encrypted_header_size() const noexcept
        {
            return get_header_size() + get_iv_size() + get_mac_size();
        }

        static const int64_t max_block_number = 1 << 30;

    private:
        CryptoPP::GCM<CryptoPP::AES>::Encryption m_enc;
        CryptoPP::GCM<CryptoPP::AES>::Decryption m_dec;
        std::shared_ptr<StreamBase> m_stream;
        HMACStream m_metastream;
        id_type m_id;
        unsigned m_iv_size, m_header_size;
        bool m_check;

    private:
        length_type meta_position_for_iv(offset_type block_num) const noexcept
        {
            return get_encrypted_header_size() + get_meta_size() * (block_num);
        }

        void check_block_number(offset_type block_number)
        {
            if (block_number > max_block_number)
                throw StreamTooLongException(max_block_number * this->m_block_size,
                                             block_number * this->m_block_size);
        }

        const id_type& id() const noexcept { return m_id; }

    public:
        explicit AESGCMCryptStream(std::shared_ptr<StreamBase> data_stream,
                                   std::shared_ptr<StreamBase> meta_stream,
                                   const key_type& data_key,
                                   const key_type& meta_key,
                                   const id_type& id_,
                                   bool check,
                                   unsigned block_size,
                                   unsigned iv_size,
                                   unsigned header_size)
            : BlockBasedStream(block_size)
            , m_stream(std::move(data_stream))
            , m_metastream(meta_key, id_, std::move(meta_stream), check)
            , m_id(id_)
            , m_iv_size(iv_size)
            , m_header_size(header_size)
            , m_check(check)
        {
            const byte null_iv[12] = {};
            m_enc.SetKeyWithIV(data_key.data(), data_key.size(), null_iv, array_length(null_iv));
            m_dec.SetKeyWithIV(data_key.data(), data_key.size(), null_iv, array_length(null_iv));
            warn_if_key_not_random(data_key, __FILE__, __LINE__);
            warn_if_key_not_random(meta_key, __FILE__, __LINE__);
        }

    protected:
        void write_multi_blocks(offset_type start_block,
                                offset_type end_block,
                                offset_type end_residue,
                                const void* input) override
        {
            check_block_number(end_block);

            std::vector<byte> buffer((m_block_size + get_meta_size()) * (end_block - start_block)
                                     + (end_residue <= 0 ? 0 : end_residue + get_meta_size()));
            auto* data_buffer = buffer.data();
            auto data_buffer_size = m_block_size * (end_block - start_block) + end_residue;
            auto* meta_buffer = buffer.data() + data_buffer_size;
            for (length_type i = 0; i < data_buffer_size;)
            {
                assert(data_buffer <= buffer.data() + data_buffer_size);
                assert(data_buffer <= buffer.data() + buffer.size());
                assert(meta_buffer <= buffer.data() + buffer.size());
                do
                {
                    libcrypto::generate_random(MutableRawBuffer(meta_buffer, get_iv_size()));
                } while (is_all_zeros(meta_buffer, get_iv_size()));
                auto this_block_size = std::min(m_block_size, data_buffer_size - i);
                assert(data_buffer + this_block_size <= buffer.data() + buffer.size());
                assert(meta_buffer + get_meta_size() <= buffer.data() + buffer.size());
                m_enc.EncryptAndAuthenticate(data_buffer,
                                             meta_buffer + get_iv_size(),
                                             get_mac_size(),
                                             meta_buffer,
                                             static_cast<int>(get_iv_size()),
                                             id().data(),
                                             id().size(),
                                             static_cast<const byte*>(input),
                                             this_block_size);
                data_buffer += this_block_size;
                meta_buffer += get_meta_size();
                input = static_cast<const byte*>(input) + this_block_size;
                i += this_block_size;
            }
            m_stream->write(buffer.data(), start_block * m_block_size, data_buffer_size);
            m_metastream.write(buffer.data() + data_buffer_size,
                               meta_position_for_iv(start_block),
                               buffer.size() - data_buffer_size);
        }

        length_type
        read_multi_blocks(offset_type start_block, offset_type end_block, void* output) override
        {
            if (start_block == end_block)
                return 0;
            check_block_number(end_block);
            std::vector<byte> buffer((end_block - start_block) * (m_block_size + get_meta_size()));
            auto* data_buffer = buffer.data();
            auto data_buffer_size = (end_block - start_block) * m_block_size;
            auto* meta_buffer = data_buffer + data_buffer_size;
            auto meta_buffer_size = buffer.size() - data_buffer_size;

            auto data_read_len
                = m_stream->read(data_buffer, start_block * m_block_size, data_buffer_size);
            auto meta_read_len = m_metastream.read(
                meta_buffer, meta_position_for_iv(start_block), meta_buffer_size);
            if (data_read_len <= 0)
            {
                return 0;
            }
            if (meta_read_len % get_meta_size() != 0)
            {
                throw MessageVerificationException(id(), start_block * m_block_size);
            }
            memset(output, 0, data_buffer_size);

            for (length_type i = 0; i < data_read_len;)
            {
                auto this_block_size = std::min(m_block_size, data_read_len - i);
                DEFER({
                    i += this_block_size;
                    data_buffer += this_block_size;
                    meta_buffer += get_meta_size();
                    output = static_cast<byte*>(output) + this_block_size;
                });
                if (is_all_zeros(meta_buffer, get_meta_size())
                    && is_all_zeros(data_buffer, this_block_size))
                {
                    continue;
                }
                bool success = m_dec.DecryptAndVerify(static_cast<byte*>(output),
                                                      meta_buffer + get_iv_size(),
                                                      get_mac_size(),
                                                      meta_buffer,
                                                      static_cast<int>(get_iv_size()),
                                                      id().data(),
                                                      id().size(),
                                                      data_buffer,
                                                      this_block_size);
                if (!success & m_check)
                {
                    throw MessageVerificationException(id(), i + start_block * m_block_size);
                }
            }
            return data_read_len;
        }

        void adjust_logical_size(length_type length) override
        {
            m_stream->resize(length);
            auto block_num = (length + this->m_block_size - 1) / this->m_block_size;
            m_metastream.resize(meta_position_for_iv(block_num));
        }

    public:
        bool is_sparse() const noexcept override
        {
            return m_stream->is_sparse() && m_metastream.is_sparse();
        }

        void flush() override
        {
            m_stream->flush();
            m_metastream.flush();
        }

        length_type size() const override { return m_stream->size(); }

    private:
        length_type unchecked_read_header(void* output)
        {
            auto buffer = make_unique_array<byte>(get_encrypted_header_size());
            auto rc = m_metastream.read(buffer.get(), 0, get_encrypted_header_size());
            if (rc == 0)
                return 0;
            if (rc != get_encrypted_header_size())
                throw CorruptedMetaDataException(id(), "Not enough header field");

            byte* iv = buffer.get();
            byte* mac = iv + get_iv_size();
            byte* ciphertext = mac + get_mac_size();
            m_dec.DecryptAndVerify(static_cast<byte*>(output),
                                   mac,
                                   get_mac_size(),
                                   iv,
                                   get_iv_size(),
                                   id().data(),
                                   id().size(),
                                   ciphertext,
                                   get_header_size());
            return get_header_size();
        }

        void unchecked_write_header(const void* input)
        {
            auto buffer = make_unique_array<byte>(get_encrypted_header_size());
            byte* iv = buffer.get();
            byte* mac = iv + get_iv_size();
            byte* ciphertext = mac + get_mac_size();
            libcrypto::generate_random(MutableRawBuffer(iv, get_iv_size()));

            m_enc.EncryptAndAuthenticate(ciphertext,
                                         mac,
                                         get_mac_size(),
                                         iv,
                                         get_iv_size(),
                                         id().data(),
                                         id().size(),
                                         static_cast<const byte*>(input),
                                         get_header_size());
            m_metastream.write(buffer.get(), 0, get_encrypted_header_size());
        }

    public:
        bool read_header(void* output, length_type length) override
        {
            if (length > get_header_size())
                throwInvalidArgumentException("Header too long");
            if (length == get_header_size())
                return unchecked_read_header(output) == length;

            CryptoPP::AlignedSecByteBlock buffer(get_header_size());
            auto rc = unchecked_read_header(buffer.data());
            memcpy(output, buffer.data(), std::min(length, rc));
            return rc != 0;
        }

        length_type max_header_length() const noexcept override { return get_header_size(); }

        void write_header(const void* input, length_type length) override
        {
            if (length > get_header_size())
                throwInvalidArgumentException("Header too long");

            if (length == get_header_size())
                return unchecked_write_header(input);

            CryptoPP::AlignedSecByteBlock buffer(get_header_size());
            memcpy(buffer.data(), input, length);
            memset(buffer.data() + length, 0, buffer.size() - length);
            unchecked_write_header(buffer.data());
        }

        void flush_header() override { m_metastream.flush(); }
    };
}    // namespace internal

std::pair<std::shared_ptr<StreamBase>, std::shared_ptr<HeaderBase>>
make_cryptstream_aes_gcm(std::shared_ptr<StreamBase> data_stream,
                         std::shared_ptr<StreamBase> meta_stream,
                         const key_type& data_key,
                         const key_type& meta_key,
                         const id_type& id_,
                         bool check,
                         unsigned block_size,
                         unsigned iv_size,
                         unsigned header_size)
{
    auto stream = std::make_shared<internal::AESGCMCryptStream>(std::move(data_stream),
                                                                std::move(meta_stream),
                                                                data_key,
                                                                meta_key,
                                                                id_,
                                                                check,
                                                                block_size,
                                                                iv_size,
                                                                header_size);
    return {stream, stream};
}

PaddedStream::PaddedStream(std::shared_ptr<StreamBase> delegate, unsigned padding_size)
    : m_delegate(std::move(delegate)), m_padding_size(padding_size)
{
    if (m_delegate->size() < padding_size)
    {
        auto buffer = make_unique_array<byte>(padding_size);
        libcrypto::generate_random(MutableRawBuffer(buffer.get(), padding_size));
        m_delegate->write(buffer.get(), 0, padding_size);
    }
}

PaddedStream::~PaddedStream() {}

length_type WriteCachedStream::read(void* output, offset_type offset, length_type length)
{
    if (cached_length_ == 0)
    {
        return delegate_->read(output, offset, length);
    }
    if (offset >= cached_length_ + cached_start_ || offset + length <= cached_start_)
    {
        return delegate_->read(output, offset, length);
    }
    if (offset >= cached_start_ && offset + length <= cached_start_ + cached_length_)
    {
        memcpy(output, buffer_.data() + (offset - cached_start_), length);
        return length;
    }
    if (offset >= cached_start_)
    {
        auto copy_length = cached_length_ - (offset - cached_start_);
        memcpy(output, buffer_.data() + (offset - cached_start_), copy_length);
        return copy_length
            + delegate_->read(static_cast<char*>(output) + copy_length,
                              offset + copy_length,
                              length - copy_length);
    }
    auto copy_length = offset + length - cached_start_;
    memset(output, 0, length);
    [[maybe_unused]] auto read_amount = delegate_->read(output, offset, length - copy_length);
    memcpy(static_cast<char*>(output) + (length - copy_length), buffer_.data(), copy_length);
    return length;
}
void WriteCachedStream::write(const void* input, offset_type offset, length_type length)
{
    if (cached_length_ == 0)
    {
        return delegate_->write(input, offset, length);
    }
    if (offset >= cached_start_ && offset + length <= cached_start_ + buffer_.size())
    {
        memcpy(buffer_.data() + (offset - cached_start_), input, length);
        return;
    }
    flush_cache();
    delegate_->write(input, offset, length);
}
void WriteCachedStream::flush_cache()
{
    if (cached_length_ == 0)
    {
        return;
    }
    delegate_->write(buffer_.data(), cached_start_, cached_length_);
    cached_length_ = 0;
    cached_start_ = 0;
}
}    // namespace securefs
