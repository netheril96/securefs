#include "utils.h"
#include "exceptions.h"

#include <cryptopp/osrng.h>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>

#include <vector>
#include <algorithm>
#include <string.h>

#include <termios.h>

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
    thread_local std::vector<byte> last_key;    // Avoid expensive table computation by SetKey()

    if (last_key.size() == key_len && memcmp(last_key.data(), key, key_len) == 0)
    {
        encryptor.Resynchronize(static_cast<const byte*>(iv), static_cast<int>(iv_len));
    }
    else
    {
        encryptor.SetKeyWithIV(
            static_cast<const byte*>(key), key_len, static_cast<const byte*>(iv), iv_len);
        last_key.assign(static_cast<const byte*>(key), static_cast<const byte*>(key) + key_len);
    }

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
    thread_local std::vector<byte> last_key;    // Avoid expensive table computation by SetKey()

    if (last_key.size() == key_len && memcmp(last_key.data(), key, key_len) == 0)
    {
        decryptor.Resynchronize(static_cast<const byte*>(iv), static_cast<int>(iv_len));
    }
    else
    {
        decryptor.SetKeyWithIV(
            static_cast<const byte*>(key), key_len, static_cast<const byte*>(iv), iv_len);
        last_key.assign(static_cast<const byte*>(key), static_cast<const byte*>(key) + key_len);
    }

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

size_t secure_read_password(FILE* fp, void* password, size_t max_length)
{
    if (!fp || !password)
        NULL_EXCEPT();

    int fd = fileno(fp);
    struct termios old_termios, new_termios;
    int rc = ::tcgetattr(fd, &old_termios);
    if (rc < 0)
        throw OSException(errno);
    memcpy(&new_termios, &old_termios, sizeof(old_termios));
    new_termios.c_lflag &= ~ECHO;
    rc = ::tcsetattr(fd, TCSAFLUSH, &new_termios);
    if (rc < 0)
        throw OSException(errno);
    return rc;
}
}
