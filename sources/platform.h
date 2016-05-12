#pragma once
#include "streams.h"

namespace securefs
{
std::shared_ptr<StreamBase> open_file_stream(const char* path, int flags, mode_t mode);
std::shared_ptr<StreamBase> open_file_stream(int basefd, const char* path, int flags, mode_t mode);
}