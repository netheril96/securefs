#include "crypto.h"
#include "exceptions.h"

#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/hmac.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/rng.h>
#include <cryptopp/sha.h>

// Some of the following codes are copied from https://github.com/arktronic/aes-siv.
// The licence follows:

// This project is licensed under the OSI-approved ISC License:
//
// Copyright (c) 2015 ARKconcepts / Sasha Kotlyar
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
// REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
// FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
// INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
// LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
// OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
// PERFORMANCE OF THIS SOFTWARE.

namespace securefs
{

static const byte aes256_siv_zero_block[AES_SIV::IV_SIZE] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

static const byte aes256_cmac_Rb[AES_SIV::IV_SIZE] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87};

static const byte aes256_iso_pad = 0x80;    // 0b10000000

static void aes256_bitshift_left(byte* buf, const size_t len)
{
    if (!len)
        return;
    for (size_t i = 0; i < len - 1; ++i)
    {
        buf[i] = static_cast<byte>((static_cast<unsigned>(buf[i]) << 1u)
                                   | ((static_cast<unsigned>(buf[i + 1]) >> 7u) & 1u));
    }
    buf[len - 1] = buf[len - 1] << 1u;
}

static void aes256_siv_dbl(byte* block)
{
    bool need_xor = (block[0] >> 7u) == 1u;
    aes256_bitshift_left(block, 16);
    if (need_xor)
        CryptoPP::xorbuf(block, aes256_cmac_Rb, 16);
}

AES_SIV::AES_SIV(const void* key, size_t size)
    : m_cmac(static_cast<const byte*>(key), size / 2)
    , m_ctr(static_cast<const byte*>(key) + size / 2, size / 2, aes256_siv_zero_block)
{
}

AES_SIV::~AES_SIV() = default;

void AES_SIV::s2v(const void* plaintext,
                  size_t text_len,
                  const void* additional_data,
                  size_t additional_len,
                  void* iv)
{
    byte D[AES_SIV::IV_SIZE];
    m_cmac.CalculateDigest(D, aes256_siv_zero_block, array_length(aes256_siv_zero_block));

    if (additional_data && additional_len)
    {
        aes256_siv_dbl(D);
        byte add_mac[AES_SIV::IV_SIZE];
        m_cmac.CalculateDigest(add_mac, static_cast<const byte*>(additional_data), additional_len);
        CryptoPP::xorbuf(D, add_mac, AES_SIV::IV_SIZE);
    }

    if (text_len >= AES_SIV::IV_SIZE)
    {
        CryptoPP::AlignedSecByteBlock T(static_cast<const byte*>(plaintext), text_len);
        CryptoPP::xorbuf(T.data() + text_len - array_length(D), D, array_length(D));
        m_cmac.CalculateDigest(static_cast<byte*>(iv), T.data(), T.size());
    }
    else
    {
        aes256_siv_dbl(D);
        byte padded[AES_SIV::IV_SIZE];
        memcpy(padded, plaintext, text_len);
        padded[text_len] = aes256_iso_pad;
        for (size_t i = text_len + 1; i < array_length(padded); ++i)
        {
            padded[i] = 0;
        }
        CryptoPP::xorbuf(D, padded, AES_SIV::IV_SIZE);
        m_cmac.CalculateDigest(static_cast<byte*>(iv), D, array_length(D));
    }
}

void AES_SIV::encrypt_and_authenticate(const void* plaintext,
                                       size_t text_len,
                                       const void* additional_data,
                                       size_t additional_len,
                                       void* ciphertext,
                                       void* siv)
{
    s2v(plaintext, text_len, additional_data, additional_len, siv);
    byte modded_iv[AES_SIV::IV_SIZE];
    memcpy(modded_iv, siv, AES_SIV::IV_SIZE);

    // Clear the 31st and 63rd bits in the IV.
    modded_iv[8] &= 0x7fu;
    modded_iv[12] &= 0x7fu;

    m_ctr.Resynchronize(modded_iv, array_length(modded_iv));
    m_ctr.ProcessData(
        static_cast<byte*>(ciphertext), static_cast<const byte*>(plaintext), text_len);
}

bool AES_SIV::decrypt_and_verify(const void* ciphertext,
                                 size_t text_len,
                                 const void* additional_data,
                                 size_t additional_len,
                                 void* plaintext,
                                 const void* siv)
{
    byte temp_iv[AES_SIV::IV_SIZE];
    memcpy(temp_iv, siv, AES_SIV::IV_SIZE);
    // Clear the 31st and 63rd bits in the IV.
    temp_iv[8] &= 0x7fu;
    temp_iv[12] &= 0x7fu;

    m_ctr.Resynchronize(temp_iv, array_length(temp_iv));
    m_ctr.ProcessData(
        static_cast<byte*>(plaintext), static_cast<const byte*>(ciphertext), text_len);

    s2v(plaintext, text_len, additional_data, additional_len, temp_iv);
    return CryptoPP::VerifyBufsEqual(static_cast<const byte*>(siv), temp_iv, AES_SIV::IV_SIZE);
}

void generate_random(void* buffer, size_t size)
{
    static thread_local CryptoPP::AutoSeededRandomPool rng;
    rng.GenerateBlock(static_cast<byte*>(buffer), size);
}

void hmac_sha256_calculate(
    const void* message, size_t msg_len, const void* key, size_t key_len, void* mac, size_t mac_len)
{
    CryptoPP::HMAC<CryptoPP::SHA256> hmac(static_cast<const byte*>(key), key_len);
    hmac.Update(static_cast<const byte*>(message), msg_len);
    hmac.TruncatedFinal(static_cast<byte*>(mac), mac_len);
}

bool hmac_sha256_verify(const void* message,
                        size_t msg_len,
                        const void* key,
                        size_t key_len,
                        const void* mac,
                        size_t mac_len)
{
    CryptoPP::HMAC<CryptoPP::SHA256> hmac(static_cast<const byte*>(key), key_len);
    hmac.Update(static_cast<const byte*>(message), msg_len);
    return hmac.TruncatedVerify(static_cast<const byte*>(mac), mac_len);
}

unsigned int pbkdf_hmac_sha256(const void* password,
                               size_t pass_len,
                               const void* salt,
                               size_t salt_len,
                               unsigned int min_iterations,
                               double min_seconds,
                               void* derived,
                               size_t derive_len)
{
    CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> kdf;
    return kdf.DeriveKey(static_cast<byte*>(derived),
                         derive_len,
                         0,
                         static_cast<const byte*>(password),
                         pass_len,
                         static_cast<const byte*>(salt),
                         salt_len,
                         min_iterations,
                         min_seconds);
}

static void hkdf_expand(const void* distilled_key,
                        size_t dis_len,
                        const void* info,
                        size_t info_len,
                        void* output,
                        size_t out_len)
{
    typedef CryptoPP::HMAC<CryptoPP::SHA256> hmac_type;
    if (out_len > 255 * hmac_type::DIGESTSIZE)
        throwInvalidArgumentException("Output length too large");
    hmac_type calculator(static_cast<const byte*>(distilled_key), dis_len);
    byte* out = static_cast<byte*>(output);
    size_t i = 0, j = 0;
    byte counter = 1;
    while (i + j < out_len)
    {
        calculator.Update(out + i, j);
        calculator.Update(static_cast<const byte*>(info), info_len);
        calculator.Update(&counter, sizeof(counter));
        ++counter;
        auto small_len = std::min<size_t>(out_len - i - j, hmac_type::DIGESTSIZE);
        calculator.TruncatedFinal(out + i + j, small_len);
        i += j;
        j = small_len;
    }
}

void hkdf(const void* key,
          size_t key_len,
          const void* salt,
          size_t salt_len,
          const void* info,
          size_t info_len,
          void* output,
          size_t out_len)
{
    if (salt && salt_len)
    {
        byte distilled_key[32];
        hmac_sha256_calculate(
            key, key_len, salt, salt_len, distilled_key, array_length(distilled_key));
        hkdf_expand(distilled_key, array_length(distilled_key), info, info_len, output, out_len);
    }
    else
    {
        hkdf_expand(key, key_len, info, info_len, output, out_len);
    }
}
}    // namespace securefs
