#include "aes_siv.h"

#include "exceptions.h"

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

static const size_t AES_BLOCK_SIZE = 16;

static const byte aes256_siv_zero_block[AES_BLOCK_SIZE] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

static const byte aes256_cmac_Rb[AES_BLOCK_SIZE] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87};

static const byte aes256_iso_pad = 0x80;    // 0b10000000

static void aes256_bitshift_left(byte* buf, const size_t len)
{
    if (!len)
        return;
    for (size_t i = 0; i < len - 1; ++i)
    {
        buf[i] = static_cast<byte>((buf[i] << 1) | ((buf[i + 1] >> 7) & 1));
    }
    buf[len - 1] = buf[len - 1] << 1;
}

static void aes256_siv_dbl(byte* block)
{
    bool need_xor = (block[0] >> 7) == 1;
    aes256_bitshift_left(block, 16);
    if (need_xor)
        CryptoPP::xorbuf(block, aes256_cmac_Rb, 16);
}

AES_SIV::AES_SIV(const void* key, size_t size)
    : m_cmac(static_cast<const byte*>(key), size / 2)
    , m_ctr(static_cast<const byte*>(key) + size / 2, size / 2, aes256_siv_zero_block)
{
}

AES_SIV::~AES_SIV() {}

void AES_SIV::s2v(const void* plaintext,
                  size_t text_len,
                  const void* additional_data,
                  size_t additional_len,
                  void* iv)
{
    byte D[AES_BLOCK_SIZE];
    m_cmac.CalculateDigest(D, aes256_siv_zero_block, sizeof(aes256_siv_zero_block));

    if (additional_data && additional_len)
    {
        aes256_siv_dbl(D);
        byte add_mac[AES_BLOCK_SIZE];
        m_cmac.CalculateDigest(add_mac, static_cast<const byte*>(additional_data), additional_len);
        CryptoPP::xorbuf(D, add_mac, AES_BLOCK_SIZE);
    }

    if (text_len >= AES_BLOCK_SIZE)
    {
        CryptoPP::AlignedSecByteBlock T(static_cast<const byte*>(plaintext), text_len);
        CryptoPP::xorbuf(T.data() + text_len - sizeof(D), D, sizeof(D));
        m_cmac.CalculateDigest(static_cast<byte*>(iv), T.data(), T.size());
    }
    else
    {
        aes256_siv_dbl(D);
        byte padded[AES_BLOCK_SIZE];
        memcpy(padded, plaintext, text_len);
        padded[text_len] = aes256_iso_pad;
        for (size_t i = text_len + 1; i < sizeof(padded); ++i)
        {
            padded[i] = 0;
        }
        CryptoPP::xorbuf(D, padded, AES_BLOCK_SIZE);
        m_cmac.CalculateDigest(static_cast<byte*>(iv), D, sizeof(D));
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
    byte modded_iv[AES_BLOCK_SIZE];
    memcpy(modded_iv, siv, AES_BLOCK_SIZE);

    // Clear the 31st and 63rd bits in the IV.
    modded_iv[8] &= 0x7f;
    modded_iv[12] &= 0x7f;

    m_ctr.Resynchronize(modded_iv, sizeof(modded_iv));
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
    byte temp_iv[AES_BLOCK_SIZE];
    memcpy(temp_iv, siv, AES_BLOCK_SIZE);
    // Clear the 31st and 63rd bits in the IV.
    temp_iv[8] &= 0x7f;
    temp_iv[12] &= 0x7f;

    m_ctr.Resynchronize(temp_iv, sizeof(temp_iv));
    m_ctr.ProcessData(
        static_cast<byte*>(plaintext), static_cast<const byte*>(ciphertext), text_len);

    s2v(plaintext, text_len, additional_data, additional_len, temp_iv);
    return CryptoPP::VerifyBufsEqual(static_cast<const byte*>(siv), temp_iv, AES_BLOCK_SIZE);
}
}
