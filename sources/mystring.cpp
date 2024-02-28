#include "mystring.h"
#include "exceptions.h"
#include "logger.h"
#include "myutils.h"

#include <utf8proc.h>

#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <system_error>

namespace securefs
{

std::string to_lower(const std::string& str)
{
    std::string result = str;
    for (char& c : result)
    {
        if (c >= 'A' && c <= 'Z')
            c += 'a' - 'A';
    }
    return result;
}

void parse_hex(absl::string_view hex, byte* output, size_t len)
{
    if (hex.size() % 2 != 0)
        throwInvalidArgumentException("Hex string must have an even length");
    if (hex.size() / 2 != len)
        throwInvalidArgumentException("Mismatch hex and raw length");

    for (size_t i = 0; i < hex.size(); i += 2, ++output)
    {
        switch (hex[i])
        {
        case '0':
            *output = 0x0;
            break;
        case '1':
            *output = 0x10;
            break;
        case '2':
            *output = 0x20;
            break;
        case '3':
            *output = 0x30;
            break;
        case '4':
            *output = 0x40;
            break;
        case '5':
            *output = 0x50;
            break;
        case '6':
            *output = 0x60;
            break;
        case '7':
            *output = 0x70;
            break;
        case '8':
            *output = 0x80;
            break;
        case '9':
            *output = 0x90;
            break;
        case 'a':
            *output = 0xa0;
            break;
        case 'b':
            *output = 0xb0;
            break;
        case 'c':
            *output = 0xc0;
            break;
        case 'd':
            *output = 0xd0;
            break;
        case 'e':
            *output = 0xe0;
            break;
        case 'f':
            *output = 0xf0;
            break;
        default:
            throwInvalidArgumentException("Invalid character in hexadecimal string");
        }
        switch (hex[i + 1])
        {
        case '0':
            *output += 0x0;
            break;
        case '1':
            *output += 0x1;
            break;
        case '2':
            *output += 0x2;
            break;
        case '3':
            *output += 0x3;
            break;
        case '4':
            *output += 0x4;
            break;
        case '5':
            *output += 0x5;
            break;
        case '6':
            *output += 0x6;
            break;
        case '7':
            *output += 0x7;
            break;
        case '8':
            *output += 0x8;
            break;
        case '9':
            *output += 0x9;
            break;
        case 'a':
            *output += 0xa;
            break;
        case 'b':
            *output += 0xb;
            break;
        case 'c':
            *output += 0xc;
            break;
        case 'd':
            *output += 0xd;
            break;
        case 'e':
            *output += 0xe;
            break;
        case 'f':
            *output += 0xf;
            break;
        default:
            throwInvalidArgumentException("Invalid character in hexadecimal string");
        }
    }
}

bool ends_with(const char* str, size_t size, const char* suffix, size_t suffix_len)
{
    return size >= suffix_len && memcmp(str + size - suffix_len, suffix, suffix_len) == 0;
}

bool starts_with(const char* str, size_t size, const char* prefix, size_t prefix_len)
{
    return size >= prefix_len && memcmp(str, prefix, prefix_len) == 0;
}

std::string hexify(const byte* data, size_t length)
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

static const char* UPPER_BASE32_ALPHABET = "ABCDEFGHIJKMNPQRSTUVWXYZ23456789";
static const char* LOWER_BASE32_ALPHABET = "abcdefghijkmnpqrstuvwxyz23456789";

static size_t get_alphabet_index(byte b, byte next, size_t i)
{
    switch (i)
    {
    case 0:
        return (b >> 3) & 31u;
    case 1:
        return (b >> 2) & 31u;
    case 2:
        return (b >> 1) & 31u;
    case 3:
        return b & 31u;
    case 4:
        return ((b & 15u) << 1u) | (next >> 7u);
    case 5:
        return ((b & 7u) << 2u) | (next >> 6u);
    case 6:
        return ((b & 3u) << 3u) | (next >> 5u);
    case 7:
        return ((b & 1u) << 4u) | (next >> 4u);
    }
    throwInvalidArgumentException("Invalid index within byte");
}

void base32_encode(const byte* input, size_t size, std::string& output)
{
    output.clear();
    output.reserve((size * 8 + 4) / 5);

    for (size_t bit_index = 0; bit_index < size * 8; bit_index += 5)
    {
        size_t byte_index = bit_index / 8, index_within_byte = bit_index % 8;
        byte b = input[byte_index];
        byte next = byte_index + 1 < size ? input[byte_index + 1] : 0;

        size_t alphabet_index = get_alphabet_index(b, next, index_within_byte);
        if (alphabet_index >= 32)
            throw std::out_of_range("base32_encode encounters internal error");

        output.push_back(UPPER_BASE32_ALPHABET[alphabet_index]);
    }
}

static std::pair<unsigned, unsigned> get_base32_pair(unsigned group, size_t i)
{
    switch (i)
    {
    case 0:
        return std::make_pair(group << 3u, 0);
    case 1:
        return std::make_pair(group << 2u, 0);
    case 2:
        return std::make_pair(group << 1u, 0);
    case 3:
        return std::make_pair(group, 0);
    case 4:
        return std::make_pair(group >> 1u, (group & 1u) << 7u);
    case 5:
        return std::make_pair(group >> 2u, (group & 3u) << 6u);
    case 6:
        return std::make_pair(group >> 3u, (group & 7u) << 5u);
    case 7:
        return std::make_pair(group >> 4u, (group & 15u) << 4u);
    }
    throwInvalidArgumentException("Invalid index within byte");
}

void base32_decode(const char* input, size_t size, std::string& output)
{
    output.assign(size * 5 / 8, '\0');
    auto out = (byte*)(output.data());

    for (size_t i = 0; i < size; ++i)
    {
        unsigned group;
        const char* finded = std::strchr(UPPER_BASE32_ALPHABET, input[i]);
        if (finded)
            group = unsigned(finded - UPPER_BASE32_ALPHABET);
        else
        {
            finded = std::strchr(LOWER_BASE32_ALPHABET, input[i]);
            if (finded)
            {
                group = unsigned(finded - LOWER_BASE32_ALPHABET);
            }
            else
            {
                throwInvalidArgumentException("Cannot decode string with base32");
            }
        }

        size_t bit_index = i * 5;
        size_t byte_index = bit_index / 8, index_within_byte = bit_index % 8;
        auto p = get_base32_pair(group, index_within_byte);
        if (byte_index >= output.size())
            throw std::out_of_range("base32 decode encounters internal error");
        out[byte_index] |= p.first;
        if (byte_index + 1 < output.size())
            out[byte_index + 1] |= p.second;
    }
}

std::string escape_nonprintable(const char* str, size_t size)
{
    std::string result;
    result.reserve(size + size / 16);
    for (size_t i = 0; i < size; ++i)
    {
        char c = str[i];
        if (isprint(static_cast<unsigned char>(c)))
        {
            result.push_back(c);
        }
        else
        {
            char tmp[10];
            snprintf(tmp, sizeof(tmp), "\\x%02x", static_cast<unsigned char>(c));
            result.append(tmp);
        }
    }
    return result;
}

bool is_ascii(absl::string_view str)
{
    for (char c : str)
    {
        if (static_cast<signed char>(c) < 0)
        {
            return false;
        }
    }
    return true;
}

MultipleOwnershipString transform(absl::string_view str, bool case_fold, bool nfc)
{
    if (!case_fold && (!nfc || is_ascii(str)))
    {
        return MultipleOwnershipString(str);
    }
    utf8proc_uint8_t* result = nullptr;
    int options = UTF8PROC_STABLE;
    if (case_fold)
    {
        options |= UTF8PROC_CASEFOLD;
    }
    if (nfc)
    {
        options |= UTF8PROC_COMPOSE;
    }
    auto rc = utf8proc_map(reinterpret_cast<const utf8proc_uint8_t*>(str.data()),
                           static_cast<utf8proc_ssize_t>(str.size()),
                           &result,
                           static_cast<utf8proc_option_t>(options));
    if (rc < 0 || !result)
    {
        ERROR_LOG("Failed to transform string \"%s\": %s",
                  escape_nonprintable(str.data(), str.size()).c_str(),
                  utf8proc_errmsg(rc));
        return MultipleOwnershipString(str);
    }
    return MultipleOwnershipString(reinterpret_cast<char*>(result));
}
}    // namespace securefs
