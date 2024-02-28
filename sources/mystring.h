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
#include <absl/types/variant.h>

typedef unsigned char byte;

namespace securefs
{
std::string hexify(const byte* data, size_t length);
void parse_hex(absl::string_view hex, byte* output, size_t len);

template <class ByteContainer>
inline std::string hexify(const ByteContainer& c)
{
    return hexify(c.data(), c.size());
}

void base32_encode(const byte* input, size_t size, std::string& output);
void base32_decode(const char* input, size_t size, std::string& output);

std::string escape_nonprintable(const char* str, size_t size);
std::string case_fold(absl::string_view str);

class MultipleOwnershipString
{
public:
    explicit MultipleOwnershipString(absl::string_view view) : holder_(view) {}
    explicit MultipleOwnershipString(char* p) : holder_(std::unique_ptr<char, CFreer>(p)) {}

    absl::string_view view() const noexcept { return absl::visit(ViewVisitor(), holder_); }

private:
    struct CFreer
    {
        void operator()(char* p) const noexcept { free(p); }
    };
    absl::variant<absl::string_view, std::unique_ptr<char, CFreer>> holder_;

    struct ViewVisitor
    {
        absl::string_view operator()(absl::string_view view) const noexcept { return view; }
        absl::string_view operator()(const std::unique_ptr<char, CFreer>& value) const noexcept
        {
            return value.get();
        }
    };
};

MultipleOwnershipString transform(absl::string_view str, bool case_fold, bool nfc);

bool is_ascii(absl::string_view str);
}    // namespace securefs
