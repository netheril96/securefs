#pragma once

#include <absl/strings/str_format.h>
#include <absl/types/span.h>
#include <absl/types/variant.h>

#include <cstdio>
#include <cstring>
#include <stddef.h>
#include <string>
#include <string_view>
#include <vector>

using byte = unsigned char;

namespace securefs
{
std::string hexify(const byte* data, size_t length);
void parse_hex(std::string_view hex, byte* output, size_t len);
std::vector<byte> parse_hex(std::string_view hex);

inline absl::Span<const byte> as_byte_span(std::string_view view)
{
    return {reinterpret_cast<const byte*>(view.data()), view.size()};
}

template <class ByteContainer>
inline std::string hexify(const ByteContainer& c)
{
    return hexify(c.data(), c.size());
}

void base32_encode(const byte* input, size_t size, std::string& output);
void base32_decode(const char* input, size_t size, std::string& output);

bool is_ascii(std::string_view str);
}    // namespace securefs
