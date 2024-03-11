#pragma once

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <memory>
#include <stddef.h>
#include <string>

#include <absl/strings/str_format.h>
#include <absl/types/variant.h>
#include <string_view>

typedef unsigned char byte;

namespace securefs
{
std::string hexify(const byte* data, size_t length);
void parse_hex(std::string_view hex, byte* output, size_t len);

template <class ByteContainer>
inline std::string hexify(const ByteContainer& c)
{
    return hexify(c.data(), c.size());
}

void base32_encode(const byte* input, size_t size, std::string& output);
void base32_decode(const char* input, size_t size, std::string& output);

bool is_ascii(std::string_view str);
}    // namespace securefs
