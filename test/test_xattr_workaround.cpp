#ifdef __APPLE__
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
        char buffer[] = "";
        const char canonical_result[] = "";
        securefs::transform_listxattr_result(buffer, sizeof(buffer));
        REQUIRE(to_string(buffer) == to_string(canonical_result));
    }
    {
        char buffer[] = "abc";
        const char canonical_result[] = "abc";
        securefs::transform_listxattr_result(buffer, sizeof(buffer));
        REQUIRE(to_string(buffer) == to_string(canonical_result));
    }
    {
        char buffer[] = "a";
        const char canonical_result[] = "a";
        securefs::transform_listxattr_result(buffer, sizeof(buffer));
        REQUIRE(to_string(buffer) == to_string(canonical_result));
    }
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
        char buffer[] = "_securefs.FinderInf";
        const char canonical_result[] = "_securefs.FinderInf";
        securefs::transform_listxattr_result(buffer, sizeof(buffer));
        REQUIRE(to_string(buffer) == to_string(canonical_result));
    }
    {
        char buffer[] = "_securefs.FinderInfoa";
        const char canonical_result[] = "_securefs.FinderInfoa";
        securefs::transform_listxattr_result(buffer, sizeof(buffer));
        REQUIRE(to_string(buffer) == to_string(canonical_result));
    }
    {
        char buffer[] = "_securefs.FinderInfo\0abcde";
        const char canonical_result[] = "com.apple.FinderInfo\0abcde";
        securefs::transform_listxattr_result(buffer, sizeof(buffer));
        REQUIRE(to_string(buffer) == to_string(canonical_result));
    }
    {
        char buffer[] = "abcde\0_securefs.FinderInfo";
        const char canonical_result[] = "abcde\0com.apple.FinderInfo";
        securefs::transform_listxattr_result(buffer, sizeof(buffer));
        REQUIRE(to_string(buffer) == to_string(canonical_result));
    }
    {
        char buffer[] = "abcdefghijklmnopkrstuvwxyz\0_securefs.FinderInfo";
        const char canonical_result[] = "abcdefghijklmnopkrstuvwxyz\0com.apple.FinderInfo";
        securefs::transform_listxattr_result(buffer, sizeof(buffer));
        REQUIRE(to_string(buffer) == to_string(canonical_result));
    }
    {
        char buffer[] = "abcde\0_securefs.FinderInfo\0fgh";
        const char canonical_result[] = "abcde\0com.apple.FinderInfo\0fgh";
        securefs::transform_listxattr_result(buffer, sizeof(buffer));
        REQUIRE(to_string(buffer) == to_string(canonical_result));
    }
}
#endif
