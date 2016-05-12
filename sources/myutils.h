#pragma once
#include <algorithm>
#include <array>
#include <functional>
#include <memory>
#include <stddef.h>
#include <stdexcept>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#ifdef _WIN32
#define __PRETTY_FUNCTION__ __FUNCTION__
#endif

#define DISABLE_COPY_MOVE(cls)                                                                     \
    cls(const cls&) = delete;                                                                      \
    cls(cls&&) = delete;                                                                           \
    cls& operator=(const cls&) = delete;                                                           \
    cls& operator=(cls&&) = delete;

typedef unsigned char byte;

namespace securefs
{
typedef uint64_t length_type;
typedef uint64_t offset_type;

constexpr uint32_t KEY_LENGTH = 32, ID_LENGTH = 32, BLOCK_SIZE = 4096;

template <class T>
inline std::unique_ptr<T[]> make_unique_array(size_t size)
{
    return std::unique_ptr<T[]>(new T[size]);
}

template <class T>
class optional
{
private:
    T value;
    bool inited;

public:
    explicit optional() : value(), inited(false) {}
    explicit optional(T value) : value(std::move(value)), inited(true) {}
    bool is_inited() const noexcept { return inited; }
    T& get()
    {
        if (!is_inited())
            throw std::invalid_argument("Optional not inited");
        return value;
    }
    const T& get() const
    {
        if (!is_inited())
            throw std::invalid_argument("Optional not inited");
        return value;
    }

    optional& operator=(T value)
    {
        this->value = std::move(value);
        inited = true;
        return *this;
    }

    void set_init(bool inited) noexcept { this->inited = inited; }
};

template <class T, size_t Size>
class PODArray
{
private:
    T m_data[Size];

    static_assert(std::is_pod<T>::value, "Only POD types are supported");

public:
    explicit PODArray() { memset(m_data, 0, sizeof(m_data)); }
    explicit PODArray(const T& value) { std::fill(std::begin(m_data), std::end(m_data), value); }
    PODArray(const PODArray& other) { memcpy(m_data, other.m_data, size()); }
    PODArray& operator=(const PODArray& other)
    {
        memmove(m_data, other.m_data, size());
        return *this;
    }
    const T* data() const { return m_data; }
    T* data() { return m_data; }
    static constexpr size_t size() { return Size; };
    bool operator==(const PODArray& other) const
    {
        return memcmp(m_data, other.m_data, size()) == 0;
    }
    bool operator!=(const PODArray& other) const { return !(*this == other); }
};

typedef PODArray<byte, KEY_LENGTH> key_type;
typedef PODArray<byte, ID_LENGTH> id_type;

inline std::string hexify(const byte* data, size_t length)
{
    const char* table = "0123456789abcdef";
    std::string result;
    result.reserve(length * 2);
    for (size_t i = 0; i < length; ++i)
    {
        result += table[data[i] / 16];
        result += table[data[i] % 16];
    }
    return result;
}

void parse_hex(const std::string& hex, byte* output, size_t len);
std::string sane_strerror(int error_number);

template <class ByteContainer>
inline std::string hexify(const ByteContainer& c)
{
    return hexify(c.data(), c.size());
}

template <class Iterator, class T>
inline bool is_all_equal(Iterator begin, Iterator end, const T& value)
{
    while (begin != end)
    {
        if (*begin != value)
            return false;
        ++begin;
    }
    return true;
}

inline bool is_all_zeros(const void* data, size_t len)
{
    auto bytes = static_cast<const byte*>(data);
    return is_all_equal(bytes, bytes + len, 0);
}

template <class T>
inline void to_little_endian(T value, void* output)
{
    typedef typename std::remove_reference<T>::type underlying_type;
    static_assert(std::is_unsigned<underlying_type>::value, "Must be an unsigned integer type");
    auto bytes = static_cast<byte*>(output);
    for (size_t i = 0; i < sizeof(underlying_type); ++i)
    {
        bytes[i] = value >> (8 * i);
    }
}

template <class T>
inline typename std::remove_reference<T>::type from_little_endian(const void* input)
{
    typedef typename std::remove_reference<T>::type underlying_type;
    static_assert(std::is_unsigned<underlying_type>::value, "Must be an unsigned integer type");
    auto bytes = static_cast<const byte*>(input);
    underlying_type value = 0;
    for (size_t i = 0; i < sizeof(T); ++i)
    {
        value |= static_cast<underlying_type>(bytes[i]) << (8 * i);
    }
    return value;
}

bool ends_with(const char* str, size_t size, const char* suffix, size_t suffix_len);
inline bool ends_with(const std::string& str, const std::string& suffix)
{
    return ends_with(str.data(), str.size(), suffix.data(), suffix.size());
}

std::vector<std::string> split(const char* str, size_t length, char separator);

inline std::vector<std::string> split(const std::string& str, char separator)
{
    return split(str.data(), str.size(), separator);
}

inline std::vector<std::string> split(const char* str, char separator)
{
    return split(str, strlen(str), separator);
}

std::string sane_strerror(int error_number);

void generate_random(void* data, size_t size);

inline std::string random_hex_string(size_t size)
{
    auto buffer = make_unique_array<byte>(size);
    generate_random(buffer.get(), size);
    return hexify(buffer.get(), size);
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
                     void* ciphertext);

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
                     void* plaintext);

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

// HMAC based key derivation function (https://tools.ietf.org/html/rfc5869)
// This one is not implemented by Crypto++, so we implement it ourselves
void hkdf(const void* key,
          size_t key_len,
          const void* salt,
          size_t salt_len,
          const void* info,
          size_t info_len,
          void* output,
          size_t out_len);

unsigned int pbkdf_hmac_sha256(const void* password,
                               size_t pass_len,
                               const void* salt,
                               size_t salt_len,
                               unsigned int min_iterations,
                               double min_seconds,
                               void* derived,
                               size_t derive_len);

size_t insecure_read_password(FILE* fp, const char* prompt, void* password, size_t max_length);
size_t secure_read_password(FILE* fp, const char* prompt, void* password, size_t max_length);

std::string format_current_time();

struct id_hash
{
    size_t operator()(const id_type& id) const noexcept
    {
        return from_little_endian<size_t>(id.data() + (id.size() - sizeof(size_t)));
    }
};

std::unordered_set<id_type, id_hash> find_all_ids(const std::string& basedir);

std::string get_user_input_until_enter();

void respond_to_user_action(
    const std::unordered_map<std::string, std::function<void(void)>>& actionMap);
}
