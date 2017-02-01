#pragma once

#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <stddef.h>
#include <string>
#include <vector>

typedef unsigned char byte;

namespace securefs
{
template <class CharT>
class BasicStringRef
{
private:
    const CharT* m_buffer;
    size_t m_size;

public:
    BasicStringRef() : m_buffer(nullptr), m_size(0) {}
    BasicStringRef(const CharT* str) : m_buffer(str), m_size(std::char_traits<CharT>::length(str))
    {
    }
    BasicStringRef(const std::basic_string<CharT>& str) : m_buffer(str.c_str()), m_size(str.size())
    {
    }
    const CharT* data() const noexcept { return m_buffer; }
    const CharT* c_str() const noexcept { return m_buffer; }
    size_t size() const noexcept { return m_size; }
    size_t length() const noexcept { return m_size; }
    CharT operator[](size_t i) const noexcept { return m_buffer[i]; }
    const CharT* begin() const noexcept { return data(); }
    const CharT* end() const noexcept { return data() + size(); }
    CharT front() const noexcept { return m_buffer[0]; }
    CharT back() const noexcept { return m_buffer[m_size - 1]; }
    bool empty() const noexcept { return size() == 0; }
    std::basic_string<CharT> to_string() const
    {
        return std::basic_string<CharT>(m_buffer, m_size);
    }
    bool starts_with(BasicStringRef<CharT> prefix) const noexcept
    {
        return size() >= prefix.size()
            && std::char_traits<CharT>::compare(data(), prefix.data(), prefix.size()) == 0;
    }
    bool ends_with(BasicStringRef<CharT> suffix) const noexcept
    {
        return size() >= suffix.size()
            && std::char_traits<CharT>::compare(
                   data() + size() - suffix.size(), suffix.data(), suffix.size())
            == 0;
    }
    std::basic_string<CharT> substr(size_t start, size_t count) const
    {
        return std::basic_string<CharT>(data() + start, std::min(size() - start, count));
    }
};

template <class CharT>
inline std::basic_string<CharT> operator+(BasicStringRef<CharT> a, BasicStringRef<CharT> b)
{
    std::basic_string<CharT> result;
    result.reserve(a.size() + b.size());
    result.insert(0, a.data(), a.size());
    result.insert(a.size(), b.data(), b.size());
    return result;
}

template <class CharT>
inline std::basic_string<CharT> operator+(const CharT* a, BasicStringRef<CharT> b)
{
    return BasicStringRef<CharT>(a) + b;
}

template <class CharT>
inline std::basic_string<CharT> operator+(BasicStringRef<CharT> a, const CharT* b)
{
    return a + BasicStringRef<CharT>(b);
}

template <class CharT>
inline std::basic_string<CharT> operator+(const std::basic_string<CharT>& a,
                                          BasicStringRef<CharT> b)
{
    return BasicStringRef<CharT>(a) + b;
}

template <class CharT>
inline std::basic_string<CharT> operator+(BasicStringRef<CharT> a,
                                          const std::basic_string<CharT>& b)
{
    return a + BasicStringRef<CharT>(b);
}

template <class CharT>
bool operator==(BasicStringRef<CharT> a, BasicStringRef<CharT> b)
{
    return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin());
}

template <class CharT>
bool operator!=(BasicStringRef<CharT> a, BasicStringRef<CharT> b)
{
    return !(a == b);
}

template <class CharT>
bool operator==(BasicStringRef<CharT> a, const char* b)
{
    return a == BasicStringRef<CharT>(b);
}

template <class CharT>
bool operator!=(BasicStringRef<CharT> a, const char* b)
{
    return a != BasicStringRef<CharT>(b);
}

typedef BasicStringRef<char> StringRef;
typedef BasicStringRef<wchar_t> WideStringRef;

std::string strprintf(const char* format, ...)
#ifndef WIN32
    __attribute__((format(printf, 1, 2)))
#endif
    ;
std::string vstrprintf(const char* format, va_list args);

std::vector<std::string> split(const char* str, char separator);

std::string hexify(const byte* data, size_t length);
void parse_hex(StringRef hex, byte* output, size_t len);
std::string sane_strerror(int error_number);
std::string errno_to_string();

template <class ByteContainer>
inline std::string hexify(const ByteContainer& c)
{
    return hexify(c.data(), c.size());
}

std::string sane_strerror(int error_number);

#ifdef HAS_CODECVT
std::wstring widen_string(StringRef str);
std::string narrow_string(WideStringRef str);
#endif

std::string unicode_lowercase(StringRef str);

bool is_ascci(StringRef str);
std::string ascii_lowercase(StringRef str);
}
