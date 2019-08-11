#include "apple_xattr_workaround.h"
#include "catch.hpp"

#include <string>

template <size_t N>
static std::string to_string(const char (&buffer)[N])
{
    return std::string(buffer, sizeof(buffer));
}

TEST_CASE("transform listxattr result")
{
    {
        char buffer[] = "com.apple.FinderInfo";
        const char canonical_result[] = "com.apple.FinderInfo";
        securefs::transform_listxattr_result(buffer, sizeof(buffer));
        REQUIRE(to_string(buffer) == to_string(canonical_result));
    }
    {
        char buffer[] = "_securefs.FinderInfo";
        const char canonical_result[] = "com.apple.FinderInfo";
        securefs::transform_listxattr_result(buffer, sizeof(buffer));
        REQUIRE(to_string(buffer) == to_string(canonical_result));
    }
    {
        char buffer[] = "_securefs.FinderInfo\0abcde";
        securefs::transform_listxattr_result(buffer, sizeof(buffer));
        const char canonical_result[] = "com.apple.FinderInfo\0abcde";
        REQUIRE(to_string(buffer) == to_string(canonical_result));
    }
    {
        char buffer[] = "abcde\0_securefs.FinderInfo";
        securefs::transform_listxattr_result(buffer, sizeof(buffer));
        const char canonical_result[] = "abcde\0com.apple.FinderInfo";
        REQUIRE(to_string(buffer) == to_string(canonical_result));
    }
    {
        char buffer[] = "abcdefghijklmnopkrstuvwxyz\0_securefs.FinderInfo";
        securefs::transform_listxattr_result(buffer, sizeof(buffer));
        const char canonical_result[] = "abcdefghijklmnopkrstuvwxyz\0com.apple.FinderInfo";
        REQUIRE(to_string(buffer) == to_string(canonical_result));
    }
    {
        char buffer[] = "abcde\0_securefs.FinderInfo\0fgh";
        securefs::transform_listxattr_result(buffer, sizeof(buffer));
        const char canonical_result[] = "abcde\0com.apple.FinderInfo\0fgh";
        REQUIRE(to_string(buffer) == to_string(canonical_result));
    }
}
