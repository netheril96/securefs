#include "streams.h"

#include <utility>
#include <algorithm>
#include <array>
#include <string.h>
#include <assert.h>
#include <memory>

#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>
#include <cryptopp/secblock.h>
#include <cryptopp/salsa.h>

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

        const char* type_name() const noexcept override { return "InvalidHMACStreamException"; }
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
                NULL_EXCEPT();
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
}

std::shared_ptr<StreamBase> make_stream_hmac(const key_type& key_,
                                             const id_type& id_,
                                             std::shared_ptr<StreamBase> stream,
                                             bool check)
{
    return std::make_shared<internal::HMACStream>(key_, id_, std::move(stream), check);
}

length_type CryptStream::read_block(offset_type block_number, void* output)
{
    auto rc = m_stream->read(output, block_number * m_block_size, m_block_size);
    if (rc == 0)
        return 0;
    decrypt(block_number, output, output, rc);
    return rc;
}

length_type
CryptStream::read_block(offset_type block_number, void* output, offset_type begin, offset_type end)
{
    assert(begin <= m_block_size && end <= m_block_size);

    if (begin == 0 && end == m_block_size)
        return read_block(block_number, output);

    if (begin >= end)
        return 0;

    CryptoPP::AlignedSecByteBlock buffer(m_block_size);
    auto rc = read_block(block_number, buffer.data());
    if (rc <= begin)
        return 0;
    end = std::min<offset_type>(end, rc);
    memcpy(output, buffer.data() + begin, end - begin);
    return end - begin;
}

void CryptStream::write_block(offset_type block_number, const void* input, length_type length)
{
    assert(length <= m_block_size);
    std::unique_ptr<byte[]> buffer(
        new byte[length]);    // Ciphertext needs not be cleared after use
    encrypt(block_number, input, buffer.get(), length);
    m_stream->write(buffer.get(), block_number * m_block_size, length);
}

void CryptStream::read_then_write_block(offset_type block_number,
                                        const void* input,
                                        offset_type begin,
                                        offset_type end)
{
    assert(begin <= m_block_size && end <= m_block_size);

    if (begin == 0 && end == m_block_size)
        return write_block(block_number, input, m_block_size);
    if (begin >= end)
        return;

    CryptoPP::AlignedSecByteBlock buffer(m_block_size);
    auto rc = read_block(block_number, buffer.data());
    memcpy(buffer.data() + begin, input, end - begin);
    write_block(block_number, buffer.data(), std::max<length_type>(rc, end));
}

length_type CryptStream::read(void* output, offset_type offset, length_type length)
{
    length_type total = 0;

    while (length > 0)
    {
        auto block_num = offset / m_block_size;
        auto start_of_block = block_num * m_block_size;
        auto begin = offset - start_of_block;
        auto end = std::min<offset_type>(m_block_size, offset + length - start_of_block);
        auto rc = read_block(block_num, output, begin, end);
        total += rc;
        if (rc < end - begin)
            return total;
        output = static_cast<byte*>(output) + rc;
        offset += rc;
        length -= rc;
    }

    return total;
}

void CryptStream::write(const void* input, offset_type offset, length_type length)
{
    auto current_size = this->size();
    if (offset > current_size)
        resize(offset);

    unchecked_write(input, offset, length);
}

void CryptStream::unchecked_write(const void* input, offset_type offset, length_type length)
{
    while (length > 0)
    {
        auto block_num = offset / m_block_size;
        auto start_of_block = block_num * m_block_size;
        auto begin = offset - start_of_block;
        auto end = std::min<offset_type>(m_block_size, offset + length - start_of_block);
        read_then_write_block(block_num, input, begin, end);
        auto rc = end - begin;
        input = static_cast<const byte*>(input) + rc;
        offset += rc;
        length -= rc;
    }
}

void CryptStream::zero_fill(offset_type offset, offset_type finish)
{
    std::unique_ptr<byte[]> zeros(new byte[m_block_size]);
    memset(zeros.get(), 0, m_block_size);
    while (offset < finish)
    {
        auto block_num = offset / m_block_size;
        auto start_of_block = block_num * m_block_size;
        auto begin = offset - start_of_block;
        auto end = std::min<offset_type>(m_block_size, finish - start_of_block);
        read_then_write_block(block_num, zeros.get(), begin, end);
        auto rc = end - begin;
        offset += rc;
    }
}

void CryptStream::resize(length_type new_size)
{
    auto current_size = this->size();
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
            (void)read_block(block_num, buffer.data());
            write_block(block_num, buffer.data(), residue);
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
            // No need to encrypt zeros in the middle
            zero_fill(new_block_num * m_block_size, new_size);
        }
    }
    m_stream->resize(new_size);
}

namespace internal
{
    class AESGCMCryptStream final : public CryptStream, public HeaderBase
    {
    public:
        static const size_t IV_SIZE = 32, MAC_SIZE = 16, HEADER_SIZE = 32;
        static const size_t ENCRYPTED_HEADER_SIZE = HEADER_SIZE + IV_SIZE + MAC_SIZE;

    private:
        std::unique_ptr<HMACStream> m_metastream;
        key_type m_key;
        id_type m_id;
        bool m_check;

    private:
        length_type meta_position_for_iv(offset_type block_num) const noexcept
        {
            return ENCRYPTED_HEADER_SIZE + (IV_SIZE + MAC_SIZE) * (block_num);
        }
        const id_type& id() const noexcept { return m_id; }
        const key_type& key() const noexcept { return m_key; }

    public:
        explicit AESGCMCryptStream(std::shared_ptr<StreamBase> data_stream,
                                   std::shared_ptr<StreamBase> meta_stream,
                                   const key_type& key_,
                                   const id_type& id_,
                                   bool check)
            : CryptStream(data_stream, BLOCK_SIZE), m_id(id_), m_check(check)
        {
            byte generated_keys[KEY_LENGTH * 2];
            const char* info = "AESGCMCryptStream";
            hkdf(key_.data(),
                 key_.size(),
                 id_.data(),
                 id_.size(),
                 info,
                 strlen(info),
                 generated_keys,
                 sizeof(generated_keys));
            memcpy(m_key.data(), generated_keys, KEY_LENGTH);
            key_type hmac_key;
            memcpy(hmac_key.data(), generated_keys + KEY_LENGTH, KEY_LENGTH);
            m_metastream.reset(new HMACStream(hmac_key, id_, std::move(meta_stream), m_check));
        }

    protected:
        void encrypt(offset_type block_number,
                     const void* input,
                     void* output,
                     length_type length) override
        {
            if (length == 0)
                return;

            byte buffer[IV_SIZE + MAC_SIZE];
            byte* iv = buffer;
            byte* mac = iv + IV_SIZE;

            do
            {
                generate_random(iv, IV_SIZE);
            } while (is_all_zeros(iv, IV_SIZE));    // Null IVs are markers for sparse blocks
            aes_gcm_encrypt(input,
                            length,
                            id().data(),
                            id().size(),
                            key().data(),
                            key().size(),
                            iv,
                            IV_SIZE,
                            mac,
                            MAC_SIZE,
                            output);
            auto pos = meta_position_for_iv(block_number);
            m_metastream->write(buffer, pos, sizeof(buffer));
        }

        void decrypt(offset_type block_number,
                     const void* input,
                     void* output,
                     length_type length) override
        {
            if (length == 0)
                return;

            byte buffer[IV_SIZE + MAC_SIZE];
            auto pos = meta_position_for_iv(block_number);
            if (m_metastream->read(buffer, pos, sizeof(buffer)) != sizeof(buffer))
                throw CorruptedMetaDataException(id(), "MAC/IV not found");

            const byte* iv = buffer;
            byte* mac = buffer + IV_SIZE;

            if (is_all_zeros(iv, IV_SIZE))
            {
                memset(output, 0, length);
                return;
            }
            bool success = aes_gcm_decrypt(input,
                                           length,
                                           id().data(),
                                           id().size(),
                                           key().data(),
                                           key().size(),
                                           iv,
                                           IV_SIZE,
                                           mac,
                                           MAC_SIZE,
                                           output);
            if (m_check && !success)
                throw MessageVerificationException(id(), block_number * m_block_size);
        }

    public:
        bool is_sparse() const noexcept override
        {
            return m_stream->is_sparse() && m_metastream->is_sparse();
        }

        void resize(length_type new_size) override
        {
            CryptStream::resize(new_size);
            auto num_blocks = (new_size + m_block_size - 1) / m_block_size;
            m_metastream->resize(ENCRYPTED_HEADER_SIZE + num_blocks * (IV_SIZE + MAC_SIZE));
        }

        void flush() override
        {
            CryptStream::flush();
            m_metastream->flush();
        }

    private:
        length_type unchecked_read_header(void* output)
        {
            byte buffer[ENCRYPTED_HEADER_SIZE];
            auto rc = m_metastream->read(buffer, 0, sizeof(buffer));
            if (rc == 0)
                return 0;
            if (rc != sizeof(buffer))
                throw CorruptedMetaDataException(id(), "Not enough header field");

            byte* iv = buffer;
            byte* mac = iv + IV_SIZE;
            byte* ciphertext = mac + MAC_SIZE;
            aes_gcm_decrypt(ciphertext,
                            HEADER_SIZE,
                            id().data(),
                            id().size(),
                            key().data(),
                            key().size(),
                            iv,
                            IV_SIZE,
                            mac,
                            MAC_SIZE,
                            output);
            return sizeof(buffer);
        }

        void unchecked_write_header(const void* input)
        {
            byte buffer[ENCRYPTED_HEADER_SIZE];
            byte* iv = buffer;
            byte* mac = iv + IV_SIZE;
            byte* ciphertext = mac + MAC_SIZE;
            generate_random(iv, IV_SIZE);

            aes_gcm_encrypt(input,
                            HEADER_SIZE,
                            id().data(),
                            id().size(),
                            key().data(),
                            key().size(),
                            iv,
                            IV_SIZE,
                            mac,
                            MAC_SIZE,
                            ciphertext);
            m_metastream->write(buffer, 0, sizeof(buffer));
        }

    public:
        bool read_header(void* output, length_type length) override
        {
            if (length > HEADER_SIZE)
                throw InvalidArgumentException("Header too long");
            if (length == HEADER_SIZE)
                return unchecked_read_header(output);

            CryptoPP::AlignedSecByteBlock buffer(HEADER_SIZE);
            auto rc = unchecked_read_header(buffer.data());
            memcpy(output, buffer.data(), std::min(length, rc));
            return rc != 0;
        }

        length_type max_header_length() const noexcept override { return HEADER_SIZE; }

        void write_header(const void* input, length_type length) override
        {
            if (length > HEADER_SIZE)
                throw InvalidArgumentException("Header too long");

            if (length == HEADER_SIZE)
                return unchecked_write_header(input);

            CryptoPP::AlignedSecByteBlock buffer(HEADER_SIZE);
            memcpy(buffer.data(), input, length);
            memset(buffer.data() + length, 0, buffer.size() - length);
            unchecked_write_header(buffer.data());
        }

        void flush_header() override { m_metastream->flush(); }
    };
}

std::pair<std::shared_ptr<CryptStream>, std::shared_ptr<HeaderBase>>
make_cryptstream_aes_gcm(std::shared_ptr<StreamBase> data_stream,
                         std::shared_ptr<StreamBase> meta_stream,
                         const key_type& key_,
                         const id_type& id_,
                         bool check)
{
    auto stream = std::make_shared<internal::AESGCMCryptStream>(
        std::move(data_stream), std::move(meta_stream), key_, id_, check);
    return {stream, stream};
}

namespace internal
{
    class Salsa20Stream : public StreamBase
    {
    public:
        static const char* MAGIC;
        static const size_t MAGIC_LEN = 16;

    private:
        class Header
        {
        public:
            uint32_t iterations;
            byte IV[8];
            byte salt[36];

            static const size_t HEADER_LEN = Salsa20Stream::MAGIC_LEN + sizeof(iterations)
                + sizeof(IV) + sizeof(salt);

            void to_bytes(byte buffer[HEADER_LEN])
            {
                memcpy(buffer, MAGIC, Salsa20Stream::MAGIC_LEN);
                buffer += Salsa20Stream::MAGIC_LEN;
                to_little_endian(iterations, buffer);
                buffer += sizeof(iterations);
                memcpy(buffer, IV, sizeof(IV));
                buffer += sizeof(IV);
                memcpy(buffer, salt, sizeof(salt));
            }

            bool from_bytes(const byte buffer[HEADER_LEN])
            {
                if (memcmp(buffer, Salsa20Stream::MAGIC, Salsa20Stream::MAGIC_LEN))
                    return false;
                buffer += Salsa20Stream::MAGIC_LEN;
                iterations = from_little_endian<decltype(iterations)>(buffer);
                buffer += sizeof(iterations);
                memcpy(IV, buffer, sizeof(IV));
                buffer += sizeof(IV);
                memcpy(salt, buffer, sizeof(salt));
                return true;
            }
        };

    private:
        std::shared_ptr<StreamBase> m_stream;
        CryptoPP::Salsa20::Encryption m_cipher;

    private:
        void unchecked_write(const void* data, offset_type off, length_type len)
        {
            std::unique_ptr<byte[]> buffer(new byte[len]);
            m_cipher.Seek(off);
            m_cipher.ProcessString(buffer.get(), static_cast<const byte*>(data), len);
            m_stream->write(buffer.get(), off + HEADER_LEN, len);
        }

        void zero_fill(length_type pos)
        {
            auto sz = size();
            if (pos > sz)
            {
                auto gap_len = pos - sz;
                std::unique_ptr<byte[]> buffer(new byte[gap_len]);
                memset(buffer.get(), 0, gap_len);
                m_cipher.Seek(sz);
                m_cipher.ProcessString(buffer.get(), gap_len);
                m_stream->write(buffer.get(), sz + HEADER_LEN, gap_len);
            }
        }

    public:
        static const size_t HEADER_LEN = Header::HEADER_LEN;

    public:
        explicit Salsa20Stream(std::shared_ptr<StreamBase> stream,
                               const void* password,
                               size_t pass_len)
            : m_stream(std::move(stream))
        {
            if (!m_stream)
                NULL_EXCEPT();

            if (strlen(MAGIC) != MAGIC_LEN)
                UNREACHABLE();

            byte buffer[HEADER_LEN];
            Header m_header;
            key_type m_key;

            if (m_stream->read(buffer, 0, sizeof(buffer)) == sizeof(buffer))
            {
                if (!m_header.from_bytes(buffer))
                    throw std::runtime_error("Incorrect file type");
            }
            else
            {
                generate_random(m_header.IV, sizeof(m_header.IV));
                generate_random(m_header.salt, sizeof(m_header.salt));
                m_header.iterations = 20000;
                m_header.to_bytes(buffer);
                m_stream->resize(0);
                m_stream->write(buffer, 0, sizeof(buffer));
            }

            pbkdf_hmac_sha256(password,
                              pass_len,
                              m_header.salt,
                              sizeof(m_header.salt),
                              m_header.iterations,
                              0,
                              m_key.data(),
                              m_key.size());
            m_cipher.SetKeyWithIV(m_key.data(), m_key.size(), m_header.IV, sizeof(m_header.IV));
        }

        length_type read(void* buffer, offset_type off, length_type len) override
        {
            auto real_len = m_stream->read(buffer, off + HEADER_LEN, len);
            if (real_len == 0)
                return 0;
            m_cipher.Seek(off);
            m_cipher.ProcessString(static_cast<byte*>(buffer), real_len);
            return real_len;
        }

        void write(const void* data, offset_type off, length_type len) override
        {
            if (len == 0)
                return;
            zero_fill(off);
            unchecked_write(data, off, len);
        }

        length_type size() const override
        {
            auto sz = m_stream->size();
            return sz <= HEADER_LEN ? 0 : sz - HEADER_LEN;
        }
        void flush() override { return m_stream->flush(); }
        void resize(length_type len)
        {
            zero_fill(len);
            return m_stream->resize(len + HEADER_LEN);
        }
    };

    const char* Salsa20Stream::MAGIC = "securefs:salsa20";
}

std::shared_ptr<StreamBase>
make_stream_salsa20(std::shared_ptr<StreamBase> stream, const void* password, size_t pass_len)
{
    return std::make_shared<internal::Salsa20Stream>(std::move(stream), password, pass_len);
}
}
