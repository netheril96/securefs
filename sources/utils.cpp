#include "utils.h"
#include "exceptions.h"

#include <cryptopp/osrng.h>
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>
#include <cryptopp/pwdbased.h>

#include <vector>
#include <algorithm>
#include <unordered_map>
#include <string.h>
#include <time.h>

#include <termios.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

namespace securefs
{

/*
 Formatting library for C++

 Copyright (c) 2012 - 2015, Victor Zverovich
 All rights reserved.

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:

 1. Redistributions of source code must retain the above copyright notice, this
 list of conditions and the following disclaimer.
 2. Redistributions in binary form must reproduce the above copyright notice,
 this list of conditions and the following disclaimer in the documentation
 and/or other materials provided with the distribution.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

// Portable thread-safe version of strerror.
// Sets buffer to point to a string describing the error code.
// This can be either a pointer to a string stored in buffer,
// or a pointer to some static immutable string.
// Returns one of the following values:
//   0      - success
//   ERANGE - buffer is not large enough to store the error message
//   other  - failure
// Buffer should be at least of size 1.
static int safe_strerror(int error_code, char*& buffer, size_t buffer_size) noexcept
{
    assert(buffer != 0 && buffer_size != 0);
    int result = 0;
#if ((_POSIX_C_SOURCE >= 200112L || _XOPEN_SOURCE >= 600) && !_GNU_SOURCE) || __ANDROID__
    // XSI-compliant version of strerror_r.
    result = strerror_r(error_code, buffer, buffer_size);
    if (result != 0)
        result = errno;
#elif _GNU_SOURCE
    // GNU-specific version of strerror_r.
    char* message = strerror_r(error_code, buffer, buffer_size);
    // If the buffer is full then the message is probably truncated.
    if (message == buffer && strlen(buffer) == buffer_size - 1)
        result = ERANGE;
    buffer = message;
#elif __MINGW32__
    errno = 0;
    (void)buffer_size;
    buffer = strerror(error_code);
    result = errno;
#elif _WIN32
    result = strerror_s(buffer, buffer_size, error_code);
    // If the buffer is full then the message is probably truncated.
    if (result == 0 && std::strlen(buffer) == buffer_size - 1)
        result = ERANGE;
#else
    result = strerror_r(error_code, buffer, buffer_size);
    if (result == -1)
        result = errno;    // glibc versions before 2.13 return result in errno.
#endif
    return result;
}

std::string sane_strerror(int error_number)
{
    char buffer[4096];
    char* output = buffer;
    int rc = safe_strerror(error_number, output, sizeof(buffer));
    if (rc == 0)
        return std::string(output);
    return fmt::format("Unknown error with code {}", error_number);
}

void parse_hex(const std::string& hex, byte* output, size_t len)
{
    if (hex.size() % 2 != 0)
        throw InvalidArgumentException("Hex string must have an even length");
    if (hex.size() / 2 != len)
        throw InvalidArgumentException("Mismatch hex and raw length");

    for (size_t i = 0; i < hex.size(); i += 2, ++output)
    {
        switch (hex[i])
        {
        case '0':
            *output = 0x0;
            break;
        case '1':
            *output = 0x10;
            break;
        case '2':
            *output = 0x20;
            break;
        case '3':
            *output = 0x30;
            break;
        case '4':
            *output = 0x40;
            break;
        case '5':
            *output = 0x50;
            break;
        case '6':
            *output = 0x60;
            break;
        case '7':
            *output = 0x70;
            break;
        case '8':
            *output = 0x80;
            break;
        case '9':
            *output = 0x90;
            break;
        case 'a':
            *output = 0xa0;
            break;
        case 'b':
            *output = 0xb0;
            break;
        case 'c':
            *output = 0xc0;
            break;
        case 'd':
            *output = 0xd0;
            break;
        case 'e':
            *output = 0xe0;
            break;
        case 'f':
            *output = 0xf0;
            break;
        default:
            throw InvalidArgumentException("Invalid character in hexadecimal string");
        }
        switch (hex[i + 1])
        {
        case '0':
            *output += 0x0;
            break;
        case '1':
            *output += 0x1;
            break;
        case '2':
            *output += 0x2;
            break;
        case '3':
            *output += 0x3;
            break;
        case '4':
            *output += 0x4;
            break;
        case '5':
            *output += 0x5;
            break;
        case '6':
            *output += 0x6;
            break;
        case '7':
            *output += 0x7;
            break;
        case '8':
            *output += 0x8;
            break;
        case '9':
            *output += 0x9;
            break;
        case 'a':
            *output += 0xa;
            break;
        case 'b':
            *output += 0xb;
            break;
        case 'c':
            *output += 0xc;
            break;
        case 'd':
            *output += 0xd;
            break;
        case 'e':
            *output += 0xe;
            break;
        case 'f':
            *output += 0xf;
            break;
        default:
            throw InvalidArgumentException("Invalid character in hexadecimal string");
        }
    }
}

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

void hkdf(const void* key,
          size_t key_len,
          const void* salt,
          size_t salt_len,
          const void* info,
          size_t info_len,
          void* output,
          size_t out_len)
{
    typedef CryptoPP::HMAC<CryptoPP::SHA256> hmac_type;
    if (out_len > 255 * hmac_type::DIGESTSIZE)
        throw InvalidArgumentException("Output length too large");

    byte distilled_key[hmac_type::DIGESTSIZE];
    hmac_sha256_calculate(key, key_len, salt, salt_len, distilled_key, sizeof(distilled_key));

    hmac_type calculator(distilled_key, sizeof(distilled_key));
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

size_t insecure_read_password(FILE* fp, const char* prompt, void* password, size_t max_length)
{
    if (!fp || !password)
        NULL_EXCEPT();

    if (prompt)
    {
        fputs(prompt, stderr);
        fflush(stderr);
    }

    size_t actual_read = 0;
    auto output = static_cast<unsigned char*>(password);

    while (actual_read < max_length)
    {
        int ch = fgetc(fp);
        if (ch == EOF)
        {
            if (feof(fp))
                break;
            if (ferror(fp))
                throw OSException(errno);
        }
        if (ch == '\0' || ch == '\n' || ch == '\r')
            break;
        *output = static_cast<unsigned char>(ch);
        ++output;
        ++actual_read;
    }

    if (actual_read >= max_length)
        fprintf(stderr,
                "Warning: password is longer than %llu and therefore truncated\n",
                static_cast<unsigned long long>(max_length));
    return actual_read;
}

size_t secure_read_password(FILE* fp, const char* prompt, void* password, size_t max_length)
{
    if (!fp || !password)
        NULL_EXCEPT();

    int fd = fileno(fp);
    struct termios old_termios, new_termios;
    int rc = ::tcgetattr(fd, &old_termios);
    if (rc < 0)
        throw OSException(errno);
    if (!(old_termios.c_lflag & ECHO))
        throw InvalidArgumentException("Unechoed terminal");

    memcpy(&new_termios, &old_termios, sizeof(old_termios));
    new_termios.c_lflag &= ~ECHO;
    new_termios.c_lflag |= ECHONL;
    rc = ::tcsetattr(fd, TCSAFLUSH, &new_termios);
    if (rc < 0)
        throw OSException(errno);
    auto retval = insecure_read_password(fp, prompt, password, max_length);
    (void)::tcsetattr(fd, TCSAFLUSH, &old_termios);
    return retval;
}

std::string format_current_time()
{
    struct timeval now;
    (void)gettimeofday(&now, nullptr);
    struct tm tm;
    gmtime_r(&now.tv_sec, &tm);
    return fmt::format("{}-{:02d}-{:02d}T{:02d}:{:02d}:{:02d}.{:06d}Z",
                       tm.tm_year + 1900,
                       tm.tm_mon + 1,
                       tm.tm_mday,
                       tm.tm_hour,
                       tm.tm_min,
                       tm.tm_sec,
                       now.tv_usec);
}

void ensure_directory(int base_fd, const char* dir_name, mode_t mode)
{
    int rc = ::mkdirat(base_fd, dir_name, mode);
    if (rc < 0 && errno != EEXIST)
        throw securefs::OSException(errno);
}
}
