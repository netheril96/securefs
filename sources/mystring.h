#pragma once

#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <memory>
#include <stddef.h>
#include <string>
#include <vector>

#include <absl/strings/str_format.h>
#include <absl/strings/string_view.h>

typedef unsigned char byte;

namespace securefs
{
// A similar class to absl::string_view, except that this string is always null-terminated.
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
    template <typename UnusedType = typename std::enable_if<std::is_same<CharT, char>::value>::type>
    operator absl::string_view() const noexcept
    {
        return {data(), size()};
    }
    operator std::basic_string<CharT>() const { return {data(), size()}; }
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

inline absl::FormatConvertResult<absl::FormatConversionCharSet::kString>
AbslFormatConvert(const StringRef& p, const absl::FormatConversionSpec& spec, absl::FormatSink* s)
{
    if (spec.conversion_char() == absl::FormatConversionChar::s)
    {
        absl::Format(s, "%s", absl::string_view(p));
    }
    return {true};
}

std::string hexify(const byte* data, size_t length);
void parse_hex(StringRef hex, byte* output, size_t len);

template <class ByteContainer>
inline std::string hexify(const ByteContainer& c)
{
    return hexify(c.data(), c.size());
}

void base32_encode(const byte* input, size_t size, std::string& output);
void base32_decode(const char* input, size_t size, std::string& output);

std::string escape_nonprintable(const char* str, size_t size);
std::string case_fold(StringRef str);

using ManagedCharPointer = std::unique_ptr<const char, void (*)(const char*)>;
ManagedCharPointer transform(StringRef str, bool case_fold, bool nfc);

bool is_ascii(StringRef str);
}    // namespace securefs
