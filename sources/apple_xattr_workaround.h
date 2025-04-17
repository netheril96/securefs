#pragma once
#include <stddef.h>

#if __has_include(<sys/xattr.h>)
#include <sys/xattr.h>
#endif

#ifndef ENOATTR
#define ENOATTR 93
#endif

#ifndef XATTR_NOSECURITY
#define XATTR_NOSECURITY 0x0008
#endif

#ifndef XATTR_CREATE
#define XATTR_CREATE 0x0002
#endif

#ifndef XATTR_REPLACE
#define XATTR_REPLACE 0x0004
#endif

namespace securefs::apple_xattr
{
void transform_listxattr_result(char* buffer, size_t size);

/// If the return value <=0, the caller should early return with the code. Otherwise, it should
/// continue with the transformed name.
int precheck_getxattr(const char** name);
int precheck_setxattr(const char** name, int* flags);
int precheck_removexattr(const char** name);
}    // namespace securefs::apple_xattr
