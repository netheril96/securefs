#include "utils.h"

#include <cryptopp/osrng.h>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>

namespace securefs
{
void generate_random(void* data, size_t size)
{
    thread_local CryptoPP::AutoSeededRandomPool pool;
    thread_local size_t total = 0;
    pool.GenerateBlock(static_cast<byte*>(data), size);
    total += size;
    if (total > 1024 * 1024)
    {
        total = 0;
        pool.Reseed();
    }
}

void aes_gcm_encrypt(const void* plaintext,
                     size_t text_len,
                     const void* header,
                     size_t header_len,
                     const void* key,
                     size_t key_len,
                     const void* iv,
                     size_t iv_len,
                     void* mac,
                     size_t mac_len,
                     void* ciphertext)
{
    thread_local CryptoPP::GCM<CryptoPP::AES>::Encryption encryptor;
    encryptor.SetKeyWithIV(
        static_cast<const byte*>(key), key_len, static_cast<const byte*>(iv), iv_len);
    encryptor.SpecifyDataLengths(header_len, text_len);
    encryptor.Update(static_cast<const byte*>(header), header_len);
    encryptor.ProcessString(
        static_cast<byte*>(ciphertext), static_cast<const byte*>(plaintext), text_len);
    encryptor.TruncatedFinal(static_cast<byte*>(mac), mac_len);
}

bool aes_gcm_decrypt(const void* ciphertext,
                     size_t text_len,
                     const void* header,
                     size_t header_len,
                     const void* key,
                     size_t key_len,
                     const void* iv,
                     size_t iv_len,
                     const void* mac,
                     size_t mac_len,
                     void* plaintext)
{
    thread_local CryptoPP::GCM<CryptoPP::AES>::Decryption decryptor;
    decryptor.SetKeyWithIV(
        static_cast<const byte*>(key), key_len, static_cast<const byte*>(iv), iv_len);
    decryptor.SpecifyDataLengths(header_len, text_len);
    decryptor.Update(static_cast<const byte*>(header), header_len);
    decryptor.ProcessString(
        static_cast<byte*>(plaintext), static_cast<const byte*>(ciphertext), text_len);
    return decryptor.TruncatedVerify(static_cast<const byte*>(mac), mac_len);
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
}
