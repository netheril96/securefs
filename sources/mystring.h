#pragma once

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

typedef unsigned char byte;

namespace securefs
{
std::string strprintf(const char* format, ...)
#ifndef WIN32
    __attribute__((format(printf, 1, 2)))
#endif
    ;
std::string vstrprintf(const char* format, va_list args);

bool ends_with(const char* str, size_t size, const char* suffix, size_t suffix_len);
inline bool ends_with(const std::string& str, const std::string& suffix)
{
    return ends_with(str.data(), str.size(), suffix.data(), suffix.size());
}

bool starts_with(const char* str, size_t size, const char* prefix, size_t prefix_len);
inline bool starts_with(const std::string& str, const std::string& prefix)
{
    return starts_with(str.data(), str.size(), prefix.data(), prefix.size());
}

std::vector<std::string> split(const char* str, char separator);

std::string hexify(const byte* data, size_t length);
void parse_hex(const std::string& hex, byte* output, size_t len);
std::string sane_strerror(int error_number);
std::string errno_to_string();

template <class ByteContainer>
inline std::string hexify(const ByteContainer& c)
{
    return hexify(c.data(), c.size());
}

std::string sane_strerror(int error_number);
std::string to_lower(const std::string&);
}