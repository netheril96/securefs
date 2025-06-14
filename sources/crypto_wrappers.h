#pragma once

#include "object.h"
#include <absl/types/span.h>

#include <cstddef>    // For size_t
#include <string>
#include <string_view>
#include <vector>

namespace securefs
{
class MutableRawBuffer : public absl::Span<unsigned char>
{
public:
    using Span::Span;

    explicit MutableRawBuffer(std::string& s) noexcept
        : Span(s.empty() ? nullptr : reinterpret_cast<unsigned char*>(&s[0]), s.length())
    {
    }

    explicit MutableRawBuffer(std::vector<char>& v) noexcept
        : Span(reinterpret_cast<unsigned char*>(v.data()), v.size())
    {
    }

    MutableRawBuffer(char* data, size_t len) noexcept
        : Span(reinterpret_cast<unsigned char*>(data), len)
    {
    }

    template <size_t N>
    MutableRawBuffer(char (&arr)[N]) noexcept : Span(reinterpret_cast<unsigned char*>(arr), N)
    {
    }
};

class ConstRawBuffer : public absl::Span<const unsigned char>
{
public:
    using Span::Span;

    explicit ConstRawBuffer(const std::string& s) noexcept
        : Span(reinterpret_cast<const unsigned char*>(s.data()), s.length())
    {
    }

    explicit ConstRawBuffer(std::string_view sv) noexcept
        : Span(reinterpret_cast<const unsigned char*>(sv.data()), sv.size())
    {
    }

    explicit ConstRawBuffer(const std::vector<char>& v) noexcept
        : Span(reinterpret_cast<const unsigned char*>(v.data()), v.size())
    {
    }

    ConstRawBuffer(const char* data, size_t len) noexcept
        : Span(reinterpret_cast<const unsigned char*>(data), len)
    {
    }

    template <size_t N,
              typename CharT,
              typename = std::enable_if_t<std::is_same_v<std::remove_const_t<CharT>, char>>>
    ConstRawBuffer(CharT (&arr)[N]) noexcept : Span(reinterpret_cast<const unsigned char*>(arr), N)
    {
    }
};

struct AEADEncryptor : public Object
{
    virtual void encrypt_and_authenticate(ConstRawBuffer plain_text,
                                          ConstRawBuffer iv,
                                          MutableRawBuffer mac,
                                          MutableRawBuffer cipher_text)
        = 0;
};

struct AEADDecryptor : public Object
{
    virtual bool decrypt_and_verify(ConstRawBuffer cipher_text,
                                    ConstRawBuffer iv,
                                    ConstRawBuffer mac,
                                    MutableRawBuffer plain_text);
};

struct SIVEncryptor : public Object
{
    virtual void encrypt_and_authenticate(ConstRawBuffer plain_text,
                                          MutableRawBuffer iv,
                                          MutableRawBuffer mac,
                                          MutableRawBuffer cipher_text)
        = 0;
};

struct SIVDecryptor : public AEADDecryptor
{
};

struct BlockCipher : public Object
{
    virtual void encrypt(ConstRawBuffer plain_text, MutableRawBuffer cipher_text) = 0;
    virtual void decrypt(ConstRawBuffer cipher_text, MutableRawBuffer plain_text) = 0;
};

struct Hasher : public Object
{
    virtual size_t hash_size() const = 0;
    virtual void update(ConstRawBuffer data) = 0;
    virtual void finalize(MutableRawBuffer hash) = 0;
    void hash_all(ConstRawBuffer data, MutableRawBuffer hash);
};

namespace libcrypto
{
    void generate_random(MutableRawBuffer output);
    void pbkdf2_hmac_sha256(ConstRawBuffer password,
                            ConstRawBuffer salt,
                            unsigned int iterations,
                            MutableRawBuffer derived);

}    // namespace libcrypto

}    // namespace securefs
