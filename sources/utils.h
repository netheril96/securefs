#pragma once
#include <stddef.h>
#include <stdint.h>
#include <string>
#include <array>
#include <type_traits>
#include <vector>

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

typedef std::array<byte, KEY_LENGTH> key_type;
typedef std::array<byte, ID_LENGTH> id_type;

struct SecureParam
{
    key_type key;
    id_type id;
};

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

template <class Iterator>
inline std::vector<std::string> split(Iterator begin, Iterator end, char separator)
{
    std::vector<std::string> result;
    while (true)
    {
        auto it = std::find(begin, end, separator);
        if (begin != it)
            result.emplace_back(begin, it);
        if (it == end)
            break;
        begin = it;
        ++begin;
    }
    return result;
}

inline std::vector<std::string> split(const std::string& str, char separator)
{
    return split(str.cbegin(), str.cend(), separator);
}

void generate_random(void* data, size_t size);
}
