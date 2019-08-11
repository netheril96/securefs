#include "apple_xattr_workaround.h"

#ifdef __APPLE__

#include <string.h>

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
}

#endif
