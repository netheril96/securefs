// This file holds only the common implementation of platform.h
// Most of the real implementations live in unix.cpp or win.cpp

#include "platform.h"

namespace securefs
{
const FileSystemService& FileSystemService::get_default()
{
    static const FileSystemService service;
    return service;
}

std::string FileSystemService::temp_name(const std::string& prefix, const std::string& suffix)
{
    return prefix + random_hex_string(16) + suffix;
}
}
