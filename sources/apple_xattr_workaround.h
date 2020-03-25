#pragma once
#ifdef __APPLE__
#include <stddef.h>

namespace securefs
{
void transform_listxattr_result(char* buffer, size_t size);

/// If the return value <=0, the caller should eary return with the code. Otherwise, it should
/// continue with the transformed name.
int precheck_getxattr(const char** name);
int precheck_setxattr(const char** name, int* flags);
int precheck_removexattr(const char** name);
}    // namespace securefs
#endif
