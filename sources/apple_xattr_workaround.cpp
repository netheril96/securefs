#include "apple_xattr_workaround.h"

#ifdef __APPLE__

#include <errno.h>
#include <string.h>
#include <sys/xattr.h>

namespace securefs
{
static const char APPLE_FINDER_INFO[] = "com.apple.FinderInfo";
static const char REPLACEMENT_FOR_FINDER_INFO[] = "_securefs.FinderInfo";
static const char APPLE_QUARANTINE[] = "com.apple.quarantine";

static_assert(sizeof(APPLE_FINDER_INFO) == sizeof(REPLACEMENT_FOR_FINDER_INFO),
              "The two \"FinderInfo\" attribute names must have the same size");

void transform_listxattr_result(char* buffer, size_t size)
{
    if (size < sizeof(APPLE_FINDER_INFO))
        return;

    for (size_t i = 0; i <= size - sizeof(APPLE_FINDER_INFO); ++i)
    {
        if (i > 0 && buffer[i - 1] != '\0')
        {
            continue;    // Not a string boundary.
        }
        // The terminating null must be compared too.
        if (memcmp(buffer + i, REPLACEMENT_FOR_FINDER_INFO, sizeof(REPLACEMENT_FOR_FINDER_INFO))
            == 0)
        {
            memcpy(buffer + i, APPLE_FINDER_INFO, sizeof(APPLE_FINDER_INFO));
        }
    }
}

static int precheck_common(const char** name)
{
    if (strcmp(*name, APPLE_FINDER_INFO) == 0)
    {
        *name = REPLACEMENT_FOR_FINDER_INFO;
        return 1;    // No early return.
    }
    if (strcmp(*name, REPLACEMENT_FOR_FINDER_INFO) == 0)
    {
        return -EPERM;
    }
    return 1;
}

int precheck_getxattr(const char** name)
{
    if (strcmp(*name, APPLE_QUARANTINE) == 0)
    {
        return -ENOATTR;
    }
    return precheck_common(name);
}

int precheck_setxattr(const char** name, int* flags)
{
    if (strcmp(*name, APPLE_QUARANTINE) == 0)
    {
        return 0;    // Fakes success of quarantine to work around "XXX is damaged" bug on macOS.
    }
    if (strcmp(*name, APPLE_FINDER_INFO) == 0)
    {
        *name = REPLACEMENT_FOR_FINDER_INFO;
        *flags &= ~(unsigned)XATTR_NOSECURITY;
        return 1;    // No early return.
    }
    if (strcmp(*name, REPLACEMENT_FOR_FINDER_INFO) == 0)
    {
        return -EPERM;
    }
    return 1;
}

int precheck_removexattr(const char** name) { return precheck_common(name); }
}    // namespace securefs

#endif
