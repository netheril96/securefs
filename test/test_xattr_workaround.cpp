#include "apple_xattr_workaround.h"
#include "myutils.h"

#include <doctest/doctest.h>

#include <string>

template <size_t N>
static std::string to_string(const char (&buffer)[N])
{
    return std::string(buffer, sizeof(buffer));
}

namespace securefs::apple_xattr
{
namespace
{
    TEST_CASE("transform listxattr result")
    {
        if (!is_apple())
        {
            return;
        }
        {
            char buffer[] = "";
            const char canonical_result[] = "";
            transform_listxattr_result(buffer, sizeof(buffer));
            REQUIRE(to_string(buffer) == to_string(canonical_result));
        }
        {
            char buffer[] = "abc";
            const char canonical_result[] = "abc";
            transform_listxattr_result(buffer, sizeof(buffer));
            REQUIRE(to_string(buffer) == to_string(canonical_result));
        }
        {
            char buffer[] = "a";
            const char canonical_result[] = "a";
            transform_listxattr_result(buffer, sizeof(buffer));
            REQUIRE(to_string(buffer) == to_string(canonical_result));
        }
        {
            char buffer[] = "com.apple.FinderInfo";
            const char canonical_result[] = "com.apple.FinderInfo";
            transform_listxattr_result(buffer, sizeof(buffer));
            REQUIRE(to_string(buffer) == to_string(canonical_result));
        }
        {
            char buffer[] = "_securefs.FinderInfo";
            const char canonical_result[] = "com.apple.FinderInfo";
            transform_listxattr_result(buffer, sizeof(buffer));
            REQUIRE(to_string(buffer) == to_string(canonical_result));
        }
        {
            char buffer[] = "_securefs.FinderInf";
            const char canonical_result[] = "_securefs.FinderInf";
            transform_listxattr_result(buffer, sizeof(buffer));
            REQUIRE(to_string(buffer) == to_string(canonical_result));
        }
        {
            char buffer[] = "_securefs.FinderInfoa";
            const char canonical_result[] = "_securefs.FinderInfoa";
            transform_listxattr_result(buffer, sizeof(buffer));
            REQUIRE(to_string(buffer) == to_string(canonical_result));
        }
        {
            char buffer[] = "_securefs.FinderInfo\0abcde";
            const char canonical_result[] = "com.apple.FinderInfo\0abcde";
            transform_listxattr_result(buffer, sizeof(buffer));
            REQUIRE(to_string(buffer) == to_string(canonical_result));
        }
        {
            char buffer[] = "abcde\0_securefs.FinderInfo";
            const char canonical_result[] = "abcde\0com.apple.FinderInfo";
            transform_listxattr_result(buffer, sizeof(buffer));
            REQUIRE(to_string(buffer) == to_string(canonical_result));
        }
        {
            char buffer[] = "abcdefghijklmnopkrstuvwxyz\0_securefs.FinderInfo";
            const char canonical_result[] = "abcdefghijklmnopkrstuvwxyz\0com.apple.FinderInfo";
            transform_listxattr_result(buffer, sizeof(buffer));
            REQUIRE(to_string(buffer) == to_string(canonical_result));
        }
        {
            char buffer[] = "abcde\0_securefs.FinderInfo\0fgh";
            const char canonical_result[] = "abcde\0com.apple.FinderInfo\0fgh";
            transform_listxattr_result(buffer, sizeof(buffer));
            REQUIRE(to_string(buffer) == to_string(canonical_result));
        }
    }
}    // namespace
}    // namespace securefs::apple_xattr
