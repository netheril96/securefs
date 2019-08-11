#include "apple_xattr_workaround.h"

#ifdef __APPLE__

namespace securefs
{
void transform_listxattr_result(char* buffer, size_t size);
}

#endif
