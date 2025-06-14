#include "crypto_wrappers.h"
#include "exceptions.h"
#include "myutils.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <string>
#include <vector>

namespace securefs::libcrypto
{

class OpenSSLException : public securefs::ExceptionBase
{
private:
    std::vector<unsigned long> m_err_codes;

public:
    OpenSSLException()
    {
        unsigned long err_code;
        while ((err_code = ERR_get_error()) != 0)
        {
            m_err_codes.push_back(err_code);
        }
    }

    std::string message() const override
    {
        std::string msg;
        for (unsigned long err_code : m_err_codes)
        {
            char buf[256];
            ERR_error_string_n(err_code, buf, sizeof(buf));
            if (!msg.empty())
                msg += "; ";
            msg += buf;
        }
        return msg;
    }

    int error_number() const noexcept override { return EIO; }
};

void generate_random(MutableRawBuffer output)
{
    if (ABSL_PREDICT_FALSE(RAND_bytes(output.data(), checked_cast<int>(output.size())) != 1))
    {
        throw OpenSSLException();
    }
}

void pbkdf2_hmac_sha256(ConstRawBuffer password,
                        ConstRawBuffer salt,
                        unsigned int iterations,
                        MutableRawBuffer derived)
{
    if (ABSL_PREDICT_FALSE(PKCS5_PBKDF2_HMAC(reinterpret_cast<const char*>(password.data()),
                                             checked_cast<int>(password.size()),
                                             salt.data(),
                                             checked_cast<int>(salt.size()),
                                             iterations,
                                             EVP_sha256(),
                                             checked_cast<int>(derived.size()),
                                             derived.data())
                           != 1))
    {
        throw OpenSSLException();
    }
}
}    // namespace securefs::libcrypto
