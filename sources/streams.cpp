#include "streams.h"

#include <utility>
#include <algorithm>
#include <array>
#include <cstring>
#include <cassert>
#include <memory>

#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>
#include <cryptopp/secblock.h>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/osrng.h>

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
            std::memcpy(m_id.data(), id.data(), id.size());
            m_msg.swap(msg);
        }

        const char* type_name() const noexcept override { return "InvalidHMACStreamException"; }
        std::string message() const override { return m_msg; }
    };

    class HMACStream final : public StreamBase
    {
    private:
        std::shared_ptr<const SecureParam> m_param;
        std::shared_ptr<StreamBase> m_stream;
        bool is_dirty;

        typedef CryptoPP::HMAC<CryptoPP::SHA256> hmac_calculator_type;

        static const size_t hmac_length = hmac_calculator_type::DIGESTSIZE;

        void run_mac(CryptoPP::MessageAuthenticationCode& calculator)
        {
            calculator.Update(m_param->id.data(), m_param->id.size());
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
        explicit HMACStream(std::shared_ptr<const SecureParam> param,
                            std::shared_ptr<StreamBase> stream,
                            bool check = true)
            : m_param(std::move(param)), m_stream(std::move(stream)), is_dirty(false)
        {
            if (!m_param || !m_stream)
                NULL_EXCEPT();
            if (check)
            {
                std::array<byte, hmac_length> hmac;
                auto rc = m_stream->read(hmac.data(), 0, hmac.size());
                if (rc == 0)
                    return;
                if (rc != hmac_length)
                    throw InvalidHMACStreamException(
                        m_param->id, "The header field for stream is not of enough length");
                hmac_calculator_type calculator;
                calculator.SetKey(m_param->key.data(), m_param->key.size());
                run_mac(calculator);
                if (!calculator.Verify(hmac.data()))
                    throw InvalidHMACStreamException(m_param->id, "HMAC mismatch");
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
            calculator.SetKey(m_param->key.data(), m_param->key.size());
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

std::shared_ptr<StreamBase> make_stream_hmac(std::shared_ptr<const SecureParam> param,
                                             std::shared_ptr<StreamBase> stream,
                                             bool check)
{
    return std::make_shared<internal::HMACStream>(std::move(param), std::move(stream), check);
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
    std::memcpy(output, buffer.data() + begin, end - begin);
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
    std::memcpy(buffer.data() + begin, input, end - begin);
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
    std::memset(zeros.get(), 0, m_block_size);
    while (offset < finish)
    {
        auto block_num = offset / m_block_size;
        auto start_of_block = block_num * m_block_size;
        auto begin = offset - start_of_block;
        auto end = std::min<offset_type>(m_block_size, finish - start_of_block);
        read_then_write_block(block_num, zeros.get(), begin, end);
        auto rc = end - begin;
        offset += rc;
        finish -= rc;
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
            std::memset(buffer.data(), 0, buffer.size());
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
        typedef CryptoPP::GCM<CryptoPP::AES> AES_GCM;

        static const size_t IV_SIZE = 32, MAC_SIZE = 16, HEADER_SIZE = 32;
        static const size_t ENCRYPTED_HEADER_SIZE = HEADER_SIZE + IV_SIZE + MAC_SIZE;

    private:
        AES_GCM::Encryption m_encryptor;
        AES_GCM::Decryption m_decryptor;
        HMACStream m_metastream;
        std::shared_ptr<const SecureParam> m_param;
        bool m_check;

    private:
        length_type meta_position_for_iv(offset_type block_num) const noexcept
        {
            return ENCRYPTED_HEADER_SIZE + (IV_SIZE + MAC_SIZE) * (block_num);
        }

    public:
        explicit AESGCMCryptStream(std::shared_ptr<StreamBase> data_stream,
                                   std::shared_ptr<StreamBase> meta_stream,
                                   std::shared_ptr<const SecureParam> param,
                                   bool check)
            : CryptStream(data_stream, BLOCK_SIZE)
            , m_metastream(param, meta_stream, check)
            , m_param(param)
            , m_check(check)
        {
            byte null_iv[IV_SIZE];
            std::memset(null_iv, 0, sizeof(null_iv));
            m_encryptor.SetKeyWithIV(
                m_param->key.data(), m_param->key.size(), null_iv, sizeof(null_iv));
            m_decryptor.SetKeyWithIV(
                m_param->key.data(), m_param->key.size(), null_iv, sizeof(null_iv));
        }

    protected:
        void encrypt(offset_type block_number,
                     const void* input,
                     void* output,
                     length_type length) override
        {
            if (length == 0)
                return;

            thread_local CryptoPP::AutoSeededRandomPool random_pool;
            byte iv[IV_SIZE];
            byte mac[MAC_SIZE];
            do
            {
                random_pool.GenerateBlock(iv, sizeof(iv));
            } while (is_all_zeros(iv, sizeof(iv)));    // Null IVs are markers for sparse blocks
            m_encryptor.EncryptAndAuthenticate(static_cast<byte*>(output),
                                               mac,
                                               sizeof(mac),
                                               iv,
                                               sizeof(iv),
                                               m_param->id.data(),
                                               m_param->id.size(),
                                               static_cast<const byte*>(input),
                                               length);
            auto iv_pos = meta_position_for_iv(block_number);
            auto mac_pos = iv_pos + IV_SIZE;
            m_metastream.write(iv, iv_pos, sizeof(iv));
            m_metastream.write(mac, mac_pos, sizeof(mac));
        }

        void decrypt(offset_type block_number,
                     const void* input,
                     void* output,
                     length_type length) override
        {
            if (length == 0)
                return;

            byte iv[IV_SIZE];
            byte mac[MAC_SIZE];
            auto iv_pos = meta_position_for_iv(block_number);
            auto mac_pos = iv_pos + IV_SIZE;
            if (m_metastream.read(iv, iv_pos, sizeof(iv)) != sizeof(iv))
                throw CorruptedMetaDataException(m_param->id, "No IV found");
            if (m_metastream.read(mac, mac_pos, sizeof(mac)) != sizeof(mac))
                throw CorruptedMetaDataException(m_param->id, "No MAC found");
            if (is_all_zeros(iv, sizeof(iv)))
            {
                std::memset(output, 0, length);
                return;
            }
            bool success = m_decryptor.DecryptAndVerify(static_cast<byte*>(output),
                                                        mac,
                                                        sizeof(mac),
                                                        iv,
                                                        sizeof(iv),
                                                        m_param->id.data(),
                                                        m_param->id.size(),
                                                        static_cast<const byte*>(input),
                                                        length);
            if (m_check && !success)
                throw MessageVerificationException(m_param->id, block_number * m_block_size);
        }

    public:
        bool is_sparse() const noexcept override
        {
            return m_stream->is_sparse() && m_metastream.is_sparse();
        }

        void resize(length_type new_size) override
        {
            CryptStream::resize(new_size);
            auto num_blocks = (new_size + m_block_size - 1) / m_block_size;
            m_metastream.resize(ENCRYPTED_HEADER_SIZE + num_blocks * (IV_SIZE + MAC_SIZE));
        }

        void flush() override
        {
            CryptStream::flush();
            m_metastream.flush();
        }

    public:
        void read_header(void* output, length_type length) override
        {
            if (length != HEADER_SIZE)
                throw InvalidArgumentException("Length mismatch");
            byte buffer[ENCRYPTED_HEADER_SIZE];
            if (m_metastream.read(buffer, 0, sizeof(buffer)) != sizeof(buffer))
                throw CorruptedMetaDataException(m_param->id, "Not enough header field");
            m_decryptor.DecryptAndVerify(static_cast<byte*>(output),
                                         buffer + IV_SIZE,
                                         MAC_SIZE,
                                         buffer,
                                         IV_SIZE,
                                         m_param->id.data(),
                                         m_param->id.size(),
                                         buffer + IV_SIZE + MAC_SIZE,
                                         HEADER_SIZE);
        }

        length_type header_length() const noexcept override { return HEADER_SIZE; }

        void write_header(const void* input, length_type length) override
        {
            if (length != HEADER_SIZE)
                throw InvalidArgumentException("Length mismatch");

            byte buffer[ENCRYPTED_HEADER_SIZE];
            thread_local CryptoPP::AutoSeededRandomPool random_pool;
            random_pool.GenerateBlock(buffer, IV_SIZE);
            m_encryptor.EncryptAndAuthenticate(buffer + IV_SIZE + MAC_SIZE,
                                               buffer + IV_SIZE,
                                               MAC_SIZE,
                                               buffer,
                                               IV_SIZE,
                                               m_param->id.data(),
                                               m_param->id.size(),
                                               static_cast<const byte*>(input),
                                               length);
            m_metastream.write(buffer, 0, sizeof(buffer));
        }
    };
}

std::pair<std::shared_ptr<CryptStream>, std::shared_ptr<HeaderBase>>
make_cryptstream_aes_gcm(std::shared_ptr<StreamBase> data_stream,
                         std::shared_ptr<StreamBase> meta_stream,
                         std::shared_ptr<const SecureParam> param,
                         bool check)
{
    auto stream = std::make_shared<internal::AESGCMCryptStream>(
        std::move(data_stream), std::move(meta_stream), std::move(param), check);
    return {stream, stream};
}
}
