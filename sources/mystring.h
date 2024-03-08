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

std::string escape_nonprintable(const char* str, size_t size);
std::string case_fold(std::string_view str);

class MultipleOwnershipString
{
public:
    explicit MultipleOwnershipString(std::string_view view) : holder_(view) {}
    explicit MultipleOwnershipString(char* p) : holder_(std::unique_ptr<char, CFreer>(p)) {}

    std::string_view view() const noexcept { return absl::visit(ViewVisitor(), holder_); }

private:
    struct CFreer
    {
        void operator()(char* p) const noexcept { free(p); }
    };
    absl::variant<std::string_view, std::unique_ptr<char, CFreer>> holder_;

    struct ViewVisitor
    {
        std::string_view operator()(std::string_view view) const noexcept { return view; }
        std::string_view operator()(const std::unique_ptr<char, CFreer>& value) const noexcept
        {
            return value.get();
        }
    };
};

MultipleOwnershipString transform(std::string_view str, bool case_fold, bool nfc);

bool is_ascii(std::string_view str);
}    // namespace securefs
