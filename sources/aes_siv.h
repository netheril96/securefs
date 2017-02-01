#pragma once

#include <cryptopp/aes.h>
#include <cryptopp/cmac.h>
#include <cryptopp/modes.h>

#include <stddef.h>

namespace securefs
{
// Implementation of AES-SIV according to https://tools.ietf.org/html/rfc5297
class AES_SIV
{
public:
    AES_SIV(const AES_SIV&) = delete;
    AES_SIV(AES_SIV&&) = delete;
    AES_SIV& operator=(const AES_SIV&) = delete;
    AES_SIV& operator=(AES_SIV&&) = delete;

private:
    CryptoPP::CMAC<CryptoPP::AES> m_cmac;
    CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption m_ctr;

public:
    static constexpr size_t IV_SIZE = 16;

public:
    explicit AES_SIV(const void* key, size_t size);
    ~AES_SIV();

    void s2v(const void* plaintext,
             size_t text_len,
             const void* additional_data,
             size_t additional_len,
             void* iv);

    void encrypt_and_authenticate(const void* plaintext,
                                  size_t text_len,
                                  const void* additional_data,
                                  size_t additional_len,
                                  void* ciphertext,
                                  void* siv);

    bool decrypt_and_verify(const void* ciphertext,
                            size_t text_len,
                            const void* additional_data,
                            size_t additional_len,
                            void* plaintext,
                            const void* siv);
};
}
