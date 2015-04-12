#pragma once
#include <cstddef>
#include <cstdint>
#include <array>

typedef unsigned char byte;

namespace securefs
{
typedef std::uint64_t length_type;
typedef std::uint64_t offset_type;

constexpr std::uint32_t KEY_LENGTH = 32, IV_LENGTH = 32, ID_LENGTH = 32, MAC_LENGTH = 16,
                        BLOCK_SIZE = 4096;

typedef std::array<byte, KEY_LENGTH> key_type;
typedef std::array<byte, ID_LENGTH> id_type;
typedef std::array<byte, IV_LENGTH> iv_type;
typedef std::array<byte, MAC_LENGTH> mac_type;

struct SecureParam
{
    key_type key;
    id_type id;
};
}
