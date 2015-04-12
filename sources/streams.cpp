#include "streams.h"

#include <utility>
#include <algorithm>
#include <array>
#include <cstring>

#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>

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
    };
}

std::shared_ptr<StreamBase> make_stream_hmac(std::shared_ptr<const SecureParam> param,
                                             std::shared_ptr<StreamBase> stream,
                                             bool check)
{
    return std::make_shared<internal::HMACStream>(std::move(param), std::move(stream), check);
}
}
