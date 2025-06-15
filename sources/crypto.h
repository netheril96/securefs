#pragma once

#include "platform.h"

#include <cryptopp/aes.h>
#include <cryptopp/cmac.h>
#include <cryptopp/modes.h>

#include <stddef.h>
#include <stdint.h>

namespace securefs
{
// Implementation of AES-SIV according to https://tools.ietf.org/html/rfc5297
class AES_SIV
{
private:
    Mutex m_mutex;
    CryptoPP::CMAC<CryptoPP::AES> m_cmac ABSL_GUARDED_BY(m_mutex);
    CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption m_ctr ABSL_GUARDED_BY(m_mutex);

private:
    void s2v(const void* plaintext,
             size_t text_len,
             const void* additional_data,
             size_t additional_len,
             void* iv) ABSL_EXCLUSIVE_LOCKS_REQUIRED(m_mutex);

public:
    static constexpr size_t IV_SIZE = 16;

public:
    explicit AES_SIV(const void* key, size_t size);
    ~AES_SIV();

    DISABLE_COPY_MOVE(AES_SIV);

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

void hmac_sha256_calculate(const void* message,
                           size_t msg_len,
                           const void* key,
                           size_t key_len,
                           void* mac,
                           size_t mac_len);

bool hmac_sha256_verify(const void* message,
                        size_t msg_len,
                        const void* key,
                        size_t key_len,
                        const void* mac,
                        size_t mac_len);

}    // namespace securefs
