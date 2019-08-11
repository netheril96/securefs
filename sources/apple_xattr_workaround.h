#pragma once
#ifdef __APPLE__
#include <stddef.h>

namespace securefs
{
void transform_listxattr_result(char* buffer, size_t size);
}
#endif
